# maintainer.py
# 项目入口：准备依赖 → 启动 worker → 等消费者 → 首次/增量派发 → 周期检查

from __future__ import annotations

import os
import sys
import time
import shlex
import signal
import socket
import logging
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Set, Tuple, Iterable, Type, List, Optional, Dict

# 初始化全局日志（导入即生效）
from environment.pylogger import pylogger  # noqa: F401
from environment.environ import environ
from helper.database_helper import SessionDB
from engine.get_applications import collect_classes
from helper.tools import compute_session_hash, iter_urls_for_instance, norm_url

# 生产者（派发任务）与巡检
from services import autologin_producer as svc_actors
from services import autologin_checker as svc_checker

logger = logging.getLogger(__name__)

# =============================== 依赖准备 ===============================

def _try_cmd(cmd: str) -> Tuple[bool, str]:
    try:
        logger.info(f"[prepare] run: {cmd}")
        cp = subprocess.run(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=60
        )
        ok = (cp.returncode == 0)
        if not ok:
            logger.warning(f"[prepare] cmd failed rc={cp.returncode} out={cp.stdout}")
        return ok, cp.stdout or ""
    except Exception as e:
        logger.warning(f"[prepare] cmd crashed: {e!r}")
        return False, str(e)

def _tcp_alive(host: str, port: int, timeout=2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def ensure_rabbitmq() -> None:
    host = os.getenv("RABBITMQ_HOST", "127.0.0.1")
    port = int(os.getenv("RABBITMQ_PORT", "5672"))
    if _tcp_alive(host, port):
        logger.info(f"[prepare] rabbitmq already up at {host}:{port}")
        return

    custom = os.getenv("RABBITMQ_START_CMD")
    if custom:
        ok, _ = _try_cmd(custom)
        if ok and _tcp_alive(host, port):
            logger.info("[prepare] rabbitmq started by RABBITMQ_START_CMD")
            return

    sysname = platform.system().lower()
    candidates = (
        ["brew services start rabbitmq"] if "darwin" in sysname else
        ["systemctl start rabbitmq-server", "service rabbitmq-server start"] if "linux" in sysname else
        []
    )
    if not candidates:
        logger.warning("[prepare] unknown platform; set RABBITMQ_START_CMD to start rabbitmq")
        return

    for cmd in candidates:
        ok, _ = _try_cmd(cmd)
        if ok and _tcp_alive(host, port):
            logger.info("[prepare] rabbitmq started.")
            return

    logger.warning("[prepare] rabbitmq may not be running; please start it manually.")

def ensure_mysql() -> None:
    host = os.getenv("MYSQL_HOST", "127.0.0.1")
    port = int(os.getenv("MYSQL_PORT", "3306"))
    if _tcp_alive(host, port):
        logger.info(f"[prepare] mysql already up at {host}:{port}")
        return

    custom = os.getenv("MYSQL_START_CMD")
    if custom:
        ok, _ = _try_cmd(custom)
        if ok and _tcp_alive(host, port):
            logger.info("[prepare] mysql started by MYSQL_START_CMD")
            return

    sysname = platform.system().lower()
    candidates = (
        ["brew services start mysql", "brew services start mysql@8.0","sudo /usr/local/mysql/support-files/mysql.server start"] if "darwin" in sysname else
        ["systemctl start mysql", "systemctl start mysqld", "service mysql start", "service mysqld start"] if "linux" in sysname else
        []
    )
    if not candidates:
        logger.warning("[prepare] unknown platform; set MYSQL_START_CMD to start mysql")
        return

    for cmd in candidates:
        ok, _ = _try_cmd(cmd)
        if ok and _tcp_alive(host, port):
            logger.info("[prepare] mysql started.")
            return

    logger.warning("[prepare] mysql may not be running; please start it manually.")

# =============================== Worker 管理 ===============================

@dataclass
class WorkerProc:
    popen: subprocess.Popen

def start_workers() -> WorkerProc:
    cmd = [sys.executable, "-m", "services.autologin_worker"]
    logger.info(f"[maintainer] starting worker: {shlex.join(cmd)}")
    if os.name == "posix":
        p = subprocess.Popen(cmd, preexec_fn=os.setsid)
    else:
        p = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return WorkerProc(popen=p)

def stop_workers(w: WorkerProc | None) -> None:
    if not w or w.popen.poll() is not None:
        return
    logger.info("[maintainer] stopping worker ...")
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(w.popen.pid), signal.SIGTERM)
        else:
            w.popen.terminate()
    except Exception:
        pass
    try:
        w.popen.wait(timeout=8)
    except Exception:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(w.popen.pid), signal.SIGKILL)
            else:
                w.popen.kill()
        except Exception:
            pass

# =============================== 队列消费者就绪检测（已有） ===============================

def _rmq_params_from_env() -> Dict[str, str]:
    return {
        "host": os.getenv("RABBITMQ_HOST", "127.0.0.1"),
        "port": int(os.getenv("RABBITMQ_PORT", "5672")),
        "vhost": os.getenv("RABBITMQ_VHOST", "/"),
        "user": os.getenv("RABBITMQ_USER", os.getenv("RABBITMQ_DEFAULT_USER", "guest")),
        "password": os.getenv("RABBITMQ_PASSWORD", os.getenv("RABBITMQ_DEFAULT_PASS", "guest")),
    }

def _count_consumers_via_amqp(queue: str) -> Optional[int]:
    """优先：AMQP passive queue.declare 获取 consumer_count。"""
    try:
        import pika  # type: ignore
    except Exception:
        return None
    try:
        p = _rmq_params_from_env()
        cred = pika.PlainCredentials(p["user"], p["password"])
        params = pika.ConnectionParameters(
            host=p["host"], port=p["port"], virtual_host=p["vhost"], credentials=cred, heartbeat=10
        )
        conn = pika.BlockingConnection(params)
        ch = conn.channel()
        m = ch.queue_declare(queue=queue, passive=True)
        consumers = int(getattr(m.method, "consumer_count", 0))
        try:
            ch.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        return consumers
    except Exception as e:
        logger.debug("[maintainer] AMQP consumer_count failed: %r", e)
        return None

def _count_consumers_via_rabbitmqctl(queue: str) -> Optional[int]:
    """兜底：调用 rabbitmqctl list_consumers（需本机工具在 PATH）"""
    try:
        out = subprocess.check_output(["rabbitmqctl", "list_consumers"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    cnt = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if parts and parts[0] == queue:
            cnt += 1
    return cnt

def _count_consumers(queue: str) -> Optional[int]:
    n = _count_consumers_via_amqp(queue)
    if isinstance(n, int):
        return n
    return _count_consumers_via_rabbitmqctl(queue)

def _get_expected_consumers(queue: str) -> int:
    """从 DRAMATIQ 配置推导期望的消费者数量（按进程数）。"""
    try:
        cfg = environ.get_config("DRAMATIQ") or {}
    except Exception:
        cfg = {}
    if queue == "simulate":
        return int(((cfg.get("simulate") or {}).get("processes")) or 2)
    if queue == "http":
        return int(((cfg.get("http") or {}).get("processes")) or 2)
    return 1

def _wait_consumers(queue: str, expected: int, timeout: float = 20.0) -> bool:
    """等待队列消费者数 ≥ 预期值；达到返回 True，超时 False。"""
    if expected <= 0:
        return True
    deadline = time.time() + max(1.0, timeout)
    last = None
    while time.time() < deadline:
        now = _count_consumers(queue)
        if now is not None and now != last:
            logger.info("[maintainer] queue=%s consumers=%s/%s", queue, now, expected)
            last = now
        if isinstance(now, int) and now >= expected:
            return True
        time.sleep(0.4)
    logger.warning("[maintainer] wait consumers timeout: queue=%s consumers=%s/%s", queue, last, expected)
    return False

# =============================== 首次/增量派发 ===============================

def _config_hashes_from_classes(classes: Iterable[Type]) -> Set[str]:
    """基于外部传入的 classes 计算配置哈希集合；URL 先 norm 再哈希。"""
    out: Set[str] = set()
    for cls in classes:
        try:
            inst = cls()
        except Exception as e:
            logger.error(f"[config] instantiate {cls} failed: {e!r}")
            continue

        app = getattr(inst, "application_name", None)
        if not isinstance(app, str) or not app:
            continue

        for _mode, url in iter_urls_for_instance(inst):
            try:
                u = norm_url(url)
                out.add(compute_session_hash(app, u))
            except Exception:
                continue
    return out

def first_boot_or_incremental_update(db: SessionDB) -> None:
    """
    - 首次：ensure_schema → 全量派发
    - 增量：配置集合 - DB 集合 → 仅对子集派发
    """
    db.ensure_schema()
    classes: List[Type] = collect_classes()

    if not db.has_any_sessions():
        logger.warning("[update] first boot detected → full dispatch via actors_producer.start()")
        svc_actors.start(classes=classes)
        return

    conf_set = _config_hashes_from_classes(classes)
    db_set   = db.get_distinct_session_hashes()
    new_hashes = conf_set - db_set

    if not new_hashes:
        logger.warning("[update] no new configuration detected.")
        return

    logger.warning(f"[update] detected {len(new_hashes)} new config items → partial dispatch")
    svc_actors.start(session_hashes=new_hashes, classes=classes)

# =============================== SESSION_CHECKER 计划 & 校验 ===============================

class ConfigError(Exception):
    pass

class CheckPlan(Tuple[str, str, int]):
    """
    mode: once | daily | interval | none
    daily_time: "HH:MM"
    interval_minutes: int(>=1)
    """
    __slots__ = ()
    @property
    def mode(self) -> str: return self[0]
    @property
    def daily_time(self) -> str: return self[1]
    @property
    def interval_minutes(self) -> int: return self[2]

def _parse_hhmm_strict(s: str) -> Tuple[int, int]:
    parts = s.split(":")
    if len(parts) != 2:
        raise ConfigError(f"SESSION_CHECKER.modes.daily.daily_time 必须为 'HH:MM'，当前 {s!r}")
    hh, mm = parts
    if not (hh.isdigit() and mm.isdigit()):
        raise ConfigError(f"SESSION_CHECKER.modes.daily.daily_time 必须为 'HH:MM' 且均为数字，当前 {s!r}")
    h, m = int(hh), int(mm)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ConfigError(f"SESSION_CHECKER.modes.daily.daily_time 超出范围，当前 {s!r}")
    return h, m

def _validate_session_checker_all_v2(raw: Dict[str, dict]) -> None:
    """
    规则：
    - 四种模式参数即使未开启也要全部合法
    - 仅允许一个 open=True
    """
    if not isinstance(raw, dict):
        raise ConfigError("SESSION_CHECKER 必须是 dict。")

    g = raw.get("global")
    if not isinstance(g, dict):
        raise ConfigError("SESSION_CHECKER.global 必须是 dict。")
    http_timeout = g.get("http_timeout")
    if not isinstance(http_timeout, (int, float)) or http_timeout <= 0:
        raise ConfigError("SESSION_CHECKER.global.http_timeout 必须为 >0 的数字。")
    ua = g.get("user_agent")
    if not isinstance(ua, str) or not ua.strip():
        raise ConfigError("SESSION_CHECKER.global.user_agent 必须为非空字符串。")

    modes = raw.get("modes")
    if not isinstance(modes, dict):
        raise ConfigError("SESSION_CHECKER.modes 必须是 dict。")

    for key in ("once", "daily", "interval", "none"):
        if key not in modes or not isinstance(modes[key], dict):
            raise ConfigError(f"SESSION_CHECKER.modes.{key} 必须存在且为 dict。")
        if "open" not in modes[key]:
            raise ConfigError(f"SESSION_CHECKER.modes.{key}.open 必须存在（True/False）。")
        if not isinstance(modes[key]["open"], bool):
            raise ConfigError(f"SESSION_CHECKER.modes.{key}.open 必须为布尔值。")

    dt = modes["daily"].get("daily_time")
    if not isinstance(dt, str) or not dt.strip():
        raise ConfigError("SESSION_CHECKER.modes.daily.daily_time 必须存在且为非空字符串（格式 HH:MM）。")
    _parse_hhmm_strict(dt)

    im = modes["interval"].get("interval_minutes")
    if not isinstance(im, int) or im < 1:
        raise ConfigError("SESSION_CHECKER.modes.interval.interval_minutes 必须为 >=1 的整数（分钟）。")

    opened = [k for k, v in modes.items() if bool(v.get("open"))]

    if len(opened) == 0:
        msg = (
            "SESSION_CHECKER configuration is illegal: All modes are disabled (none open).\n"
            "Please ensure exactly ONE of the following is set to True:\n"
            "  - SESSION_CHECKER.modes.once.open\n"
            "  - SESSION_CHECKER.modes.daily.open\n"
            "  - SESSION_CHECKER.modes.interval.open\n"
            "  - SESSION_CHECKER.modes.none.open"
        )
        raise ConfigError(msg)

    elif len(opened) > 1:
        msg = (
            "SESSION_CHECKER configuration is illegal: Multiple check modes enabled simultaneously: "
            f"{', '.join(opened)}\n"
            "Please ensure exactly ONE of the following is set to True:\n"
            "  - SESSION_CHECKER.modes.once.open\n"
            "  - SESSION_CHECKER.modes.daily.open\n"
            "  - SESSION_CHECKER.modes.interval.open\n"
            "  - SESSION_CHECKER.modes.none.open"
        )
        raise ConfigError(msg)

def load_session_checker_config() -> Tuple[CheckPlan, Dict[str, object]]:
    try:
        raw = environ.get_config("SESSION_CHECKER") or {}
    except Exception as e:
        logger.error("[maintainer] 读取 SESSION_CHECKER 失败：%r", e)
        raise SystemExit(1)

    try:
        _validate_session_checker_all_v2(raw)
    except ConfigError as e:
        logger.error("[maintainer] SESSION_CHECKER configuration error：\n%s", str(e))
        logger.error(
            "example: only open interval:\n"
            "SESSION_CHECKER = {\n"
            "  'global': {'http_timeout': 10.0, 'user_agent': 'autologin-session-checker/1.0'},\n"
            "  'modes': {\n"
            "    'once': {'open': False},\n"
            "    'daily': {'open': False, 'daily_time': '03:30'},\n"
            "    'interval': {'open': True, 'interval_minutes': 15},\n"
            "    'none': {'open': False}\n"
            "  }\n"
            "}"
        )
        raise SystemExit(1)

    g = raw["global"]
    modes = raw["modes"]

    if modes["once"]["open"]:
        plan = CheckPlan(("once", "03:00", 0))
    elif modes["daily"]["open"]:
        plan = CheckPlan(("daily", str(modes["daily"]["daily_time"]).strip(), 0))
    elif modes["interval"]["open"]:
        plan = CheckPlan(("interval", "03:00", int(modes["interval"]["interval_minutes"])))
    else:
        plan = CheckPlan(("none", "03:00", 0))

    global_opts = {
        "http_timeout": float(g["http_timeout"]),
        "user_agent": str(g["user_agent"]).strip(),
    }
    return plan, global_opts

RUNNING = True
def _set_stopping(_signum=None, _frame=None):
    global RUNNING
    RUNNING = False

# =============================== 队列/worker 空闲与监听状态判定 ===============================

def _rmq_env_for_idle():
    return {
        "host": os.getenv("RABBITMQ_HOST", "127.0.0.1"),
        "port": int(os.getenv("RABBITMQ_PORT", "5672")),
        "vhost": os.getenv("RABBITMQ_VHOST", "/"),
        "user": os.getenv("RABBITMQ_USER", os.getenv("RABBITMQ_DEFAULT_USER", "guest")),
        "password": os.getenv("RABBITMQ_PASSWORD", os.getenv("RABBITMQ_DEFAULT_PASS", "guest")),
        "mgmt_host": os.getenv("RABBITMQ_MGMT_HOST", os.getenv("RABBITMQ_HOST", "127.0.0.1")),
        "mgmt_port": int(os.getenv("RABBITMQ_MGMT_PORT", "15672")),
        "mgmt_user": os.getenv("RABBITMQ_MGMT_USER", os.getenv("RABBITMQ_USER", "guest")),
        "mgmt_password": os.getenv("RABBITMQ_MGMT_PASSWORD", os.getenv("RABBITMQ_PASSWORD", "guest")),
        "mgmt_scheme": os.getenv("RABBITMQ_MGMT_SCHEME", "http"),  # http | https
        "ssl": os.getenv("RABBITMQ_SSL", "false").lower() in ("1", "true", "yes"),
    }

def _queue_status_via_mgmt(queue: str) -> Optional[Dict[str, int]]:
    """优先用管理 API 精确获取 ready/unacked/consumers。"""
    cfg = _rmq_env_for_idle()
    base = f"{cfg['mgmt_scheme']}://{cfg['mgmt_host']}:{cfg['mgmt_port']}/api"
    vhost_enc = cfg["vhost"].replace("/", "%2F")
    url = f"{base}/queues/{vhost_enc}/{queue}"
    try:
        import requests  # lazy
        r = requests.get(url, auth=(cfg["mgmt_user"], cfg["mgmt_password"]), timeout=3.0)
        if r.status_code != 200:
            return None
        d = r.json()
        return {
            "messages": int(d.get("messages", 0)),
            "messages_unacknowledged": int(d.get("messages_unacknowledged", 0)),
            "consumers": int(d.get("consumers", 0)),
        }
    except Exception:
        return None

def _queue_status_via_pika(queue: str) -> Optional[Dict[str, int]]:
    """回退：AMQP 被动声明，只有 ready/consumers；unacked 不可见（用 -1 占位）。"""
    try:
        import pika  # type: ignore
    except Exception:
        return None
    try:
        cfg = _rmq_env_for_idle()
        params = pika.ConnectionParameters(
            host=cfg["host"], port=cfg["port"], virtual_host=cfg["vhost"],
            credentials=pika.PlainCredentials(cfg["user"], cfg["password"]),
            ssl=cfg["ssl"],
        )
        conn = pika.BlockingConnection(params)
        ch = conn.channel()
        m = ch.queue_declare(queue=queue, passive=True)
        ready = int(getattr(m.method, "message_count", 0))
        consumers = int(getattr(m.method, "consumer_count", 0))
        try: ch.close()
        except Exception: pass
        try: conn.close()
        except Exception: pass
        return {"messages": ready, "messages_unacknowledged": -1, "consumers": consumers}
    except Exception:
        return None

def _queue_status(queue: str) -> Optional[Dict[str, int]]:
    st = _queue_status_via_mgmt(queue)
    if st is not None:
        return st
    return _queue_status_via_pika(queue)

def _queues_all_idle_and_listening(expected: Dict[str, int]) -> Tuple[bool, Dict[str, Dict[str, int]]]:
    """
    对每个队列：
      - 空闲：messages==0 且 (unacked==0 或不可见 -1)
      - 监听：consumers >= expected[q]
    全部满足 → True
    """
    detail: Dict[str, Dict[str, int]] = {}
    all_ok = True
    for q, exp in expected.items():
        st = _queue_status(q) or {"messages": 999999, "messages_unacknowledged": 999999, "consumers": 0}
        detail[q] = st
        ready = st.get("messages", 0)
        unacked = st.get("messages_unacknowledged", -1)
        consumers = st.get("consumers", 0)

        idle_ok = (ready == 0) and (unacked in (0, -1))
        listen_ok = consumers >= int(exp)
        ok = idle_ok and listen_ok
        if not ok:
            all_ok = False
    return all_ok, detail

def _wait_until_all_idle_and_listening(
    expected: Dict[str, int],
    *,
    poll_interval: float = 1.0,
    stable_polls: int = 3,
    unacked_grace_seconds: float = 5.0,
) -> None:
    """
    一直等到所有队列 空闲+监听，且连续 stable_polls 次满足，然后再额外等待 unacked_grace_seconds。
    （无总超时 → daily/once 需求：自动延后直到满足条件）
    """
    consec = 0
    while RUNNING:
        ok, detail = _queues_all_idle_and_listening(expected)
        if ok:
            consec += 1
            if consec >= stable_polls:
                time.sleep(unacked_grace_seconds)
                logger.warning("[maintainer] all queues idle & listening: %s", detail)
                return
        else:
            consec = 0
        time.sleep(poll_interval)

# =============================== 巡检（四种模式） ===============================

def _invoke_checker_with_globals(global_opts: Dict[str, object]) -> None:
    """把 http_timeout / user_agent 透传给 checker；签名不匹配则无参回退。"""
    try:
        svc_checker.check_once(**global_opts)  # type: ignore[arg-type]
    except TypeError:
        svc_checker.check_once()
    except Exception as e:
        logger.error(f"[checker] crashed: {e!r}", exc_info=True)

def run_checks(plan: CheckPlan, global_opts: Dict[str, object]) -> None:
    """
    once / daily / interval / none
    - once：首次就检查，但要“空闲+监听”。
    - daily：到点后，等待到“空闲+监听”再检查（自动延后）。
    - interval：固定节拍；到点若不满足“空闲+监听”，本次跳过，等下个周期。
    """
    expected = {
        "simulate": _get_expected_consumers("simulate"),
        "http": _get_expected_consumers("http"),
    }

    def guarded_check_blocking():
        # 阻塞到“空闲+监听”
        _wait_until_all_idle_and_listening(expected, poll_interval=1.0, stable_polls=3, unacked_grace_seconds=5.0)
        _invoke_checker_with_globals(global_opts)

    def try_check_nonblocking_or_skip():
        # 即刻判断；不满足则跳过
        ok, detail = _queues_all_idle_and_listening(expected)
        if ok:
            _invoke_checker_with_globals(global_opts)
        else:
            logger.warning("[checker] interval mode tick skipped (queues not idle/listening): %s", detail)

    if plan.mode == "none":
        logger.warning("[checker] mode=none → keep workers alive (no checks).")
        while RUNNING:
            time.sleep(1.0)
        return

    if plan.mode == "once":
        guarded_check_blocking()
        logger.warning("[checker] once mode done → keeping process alive until signal")
        while RUNNING:
            time.sleep(1.0)
        return

    if plan.mode == "interval":
        period = max(1, int(plan.interval_minutes)) * 60  # 分钟→秒
        next_start = time.time()  # 项目初次运行即开始计时
        logger.warning(f"[checker] interval mode started: every {period}s")

        while RUNNING:
            now = time.time()
            if now < next_start:
                # 等待下一次检查时间点
                sleep_for = min(1.0, next_start - now)
                logger.debug(f"[checker] interval mode sleeping {sleep_for:.1f}s until next check @ {next_start:.0f}")
                time.sleep(sleep_for)
                continue

            this_start = time.time()
            logger.info(f"[checker] interval mode check triggered @ {datetime.now().isoformat()}")

            try:
                did_check = try_check_nonblocking_or_skip()  # 返回 True 表示执行，False 表示跳过
                if did_check:
                    logger.info("[checker] interval mode check finished successfully")
                else:
                    logger.warning("[checker] interval mode skipped: worker busy or queue not empty")
            except Exception as e:
                logger.error(f"[checker] interval mode check crashed: {e!r}", exc_info=True)

            # 固定节拍：下一次 = 本次开始 + period（不漂移）
            next_start = this_start + period
            logger.debug(f"[checker] interval mode next check scheduled @ {next_start:.0f}")

            # 若执行过久导致错过多个节拍，直接对齐到最近将来的节拍
            while next_start <= time.time():
                logger.warning(f"[checker] interval mode missed scheduled check @ {next_start:.0f} → skipping to next period")
                next_start += period
        return

    if plan.mode == "daily":
        hh, mm = _parse_hhmm_strict(plan.daily_time)

        def today_target() -> datetime:
            now = datetime.now()
            return now.replace(hour=hh, minute=mm, second=0, microsecond=0)

        tgt = today_target()
        now = datetime.now()
        if now >= tgt:
            logger.warning("[checker] daily mode: already past today's target → run after queues idle/listening")
            guarded_check_blocking()
            tgt = tgt + timedelta(days=1)

        while RUNNING:
            now = datetime.now()
            secs = (tgt - now).total_seconds()
            if secs > 0:
                time.sleep(min(secs, 60))
                continue
            # 到点：等待到空闲+监听再执行（自动延后到任务执行结束）
            guarded_check_blocking()
            tgt = today_target() + timedelta(days=1)

# =============================== 主入口 ===============================

WORKER: WorkerProc | None = None

def _handle_signal(signum, frame):
    logger.warning(f"[maintainer] caught signal {signum}, shutting down ...")
    _set_stopping()
    stop_workers(WORKER)

def main() -> None:
    # 安装信号处理
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # 依赖准备
    ensure_rabbitmq()
    ensure_mysql()

    # 数据库表结构检查
    try:
        DB = SessionDB.from_environ()
        DB.ensure_schema()
        logger.warning("[DB] schema ensured.")
    except Exception as e:
        logger.error(f"[DB] init failed, exiting: {e}")
        raise SystemExit(1)

    # 启动 worker
    global WORKER
    WORKER = start_workers()
    logger.warning("[maintainer] workers launched.")

    # 派发前等待消费者到齐（从 DRAMATIQ.simulate/http 的 processes 推导）
    try:
        sim_expected = _get_expected_consumers("simulate")
        http_expected = _get_expected_consumers("http")
        _wait_consumers("simulate", expected=sim_expected, timeout=20)
        _wait_consumers("http", expected=http_expected, timeout=20)
    except Exception as e:
        logger.debug("[maintainer] wait consumers skipped: %r", e)

    try:
        # 加载巡检计划 + 全局参数
        plan, global_opts = load_session_checker_config()
        logger.warning(
            f"[maintainer] check plan: mode={plan.mode} daily_time={plan.daily_time} "
            f"interval_minutes={plan.interval_minutes} "
            f"http_timeout={global_opts.get('http_timeout')} user_agent={global_opts.get('user_agent')}"
        )

        # 首次/增量派发
        db = SessionDB.from_environ()
        first_boot_or_incremental_update(db)

        # 周期检查（阻塞至退出）
        run_checks(plan, global_opts)
    finally:
        stop_workers(WORKER)
        logger.warning("[maintainer] bye.")


def print_banner():
    banner = r"""
    ██████ ▓█████   ██████   ██████  ██▓ ▒█████   ███▄    █                             
    ▒██    ▒ ▓█   ▀ ▒██    ▒ ▒██    ▒ ▓██▒▒██▒  ██▒ ██ ▀█   █                             
    ░ ▓██▄   ▒███   ░ ▓██▄   ░ ▓██▄   ▒██▒▒██░  ██▒▓██  ▀█ ██▒                            
    ▒   ██▒▒▓█  ▄   ▒   ██▒  ▒   ██▒░██░▒██   ██░▓██▒  ▐▌██▒                            
    ▒██████▒▒░▒████▒▒██████▒▒▒██████▒▒░██░░ ████▓▒░▒██░   ▓██░     Author : K0rz3n                       
    ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒      Email : K0rz3n@163.com                      
    ░ ░▒  ░ ░ ░ ░  ░░ ░▒  ░ ░░ ░▒  ░ ░ ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░     Version: 1.0                      
    ░  ░  ░     ░   ░  ░  ░  ░  ░  ░   ▒ ░░ ░ ░ ▒     ░   ░ ░                             
        ░     ░  ░      ░        ░   ░      ░ ░           ░                             
                                                                                        
    ███▄ ▄███▓ ▄▄▄       ██▓ ███▄    █ ▄▄▄█████▓ ▄▄▄       ██▓ ███▄    █ ▓█████  ██▀███  
    ▓██▒▀█▀ ██▒▒████▄    ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▒████▄    ▓██▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
    ▓██    ▓██░▒██  ▀█▄  ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░▒██  ▀█▄  ▒██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
    ▒██    ▒██ ░██▄▄▄▄██ ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ░██▄▄▄▄██ ░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
    ▒██▒   ░██▒ ▓█   ▓██▒░██░▒██░   ▓██░  ▒██▒ ░  ▓█   ▓██▒░██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
    ░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░   ▒ ▒   ▒ ░░    ▒▒   ▓▒█░░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░░   ░ ▒░    ░      ▒   ▒▒ ░ ▒ ░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
    ░      ░     ░   ▒    ▒ ░   ░   ░ ░   ░        ░   ▒    ▒ ░   ░   ░ ░    ░     ░░   ░ 
        ░         ░  ░ ░           ░                ░  ░ ░           ░    ░  ░   ░     
                                                                                                                                                                                                     
    """
    print(banner)

if __name__ == "__main__":
    print_banner()
    main()


    