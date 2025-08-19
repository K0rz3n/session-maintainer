# 同时启动两组 Dramatiq worker：
#   1) simulate 队列（Playwright）
#   2) http 队列（纯 HTTP）
# 从配置读取：processes / threads ，queue 名仅校验必须分别为 'simulate' / 'http'，启动时强制固定
from __future__ import annotations

import os
import sys
import shlex
import signal
import subprocess
import logging
from typing import Any, Dict, List, Tuple

from environment.pylogger import pylogger  # 统一日志样式
from environment.environ import environ

logger = logging.getLogger(__name__)

MODULE = "services.task_actors"   # dramatiq 入口模块（内含 actors）

# ---------------- 配置加载 & 严格校验 ----------------

class _ConfigError(Exception):
    pass

def _require_int_gt0(d: dict, key: str) -> int:
    if key not in d:
        raise _ConfigError(f"missing key: {key!r}")
    v = d[key]
    if not isinstance(v, int):
        raise _ConfigError(f"{key!r} must be int, got {type(v).__name__}")
    if v <= 0:
        raise _ConfigError(f"{key!r} must be > 0, got {v}")
    return v

def _require_queue_name(d: dict, key: str, expected: str) -> None:
    if key not in d:
        raise _ConfigError(f"missing key: {key!r}")
    val = d[key]
    if not isinstance(val, str) or val.strip() != expected:
        raise _ConfigError(f"{key!r} must be {expected!r}, got {val!r}")

_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

def _normalize_log_level(val: Any, default: str = "INFO") -> str:
    """
    接受 'debug/info/warning/error/critical'（大小写/前后空格均可），返回大写。
    非法值将抛出 _ConfigError。
    """
    if val is None:
        return default
    if not isinstance(val, str):
        raise _ConfigError(f"log-level must be string, got {type(val).__name__}")
    lv = val.strip().upper()
    # 兼容 'WARN'
    if lv == "WARN":
        lv = "WARNING"
    if lv not in _VALID_LEVELS:
        raise _ConfigError(f"unsupported log-level: {val!r}, allowed: {', '.join(sorted(_VALID_LEVELS))}")
    return lv

def _load_worker_cfgs() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    加载配置
    """
    try:
        tree = environ.get_config("DRAMATIQ") or {}
    except Exception as e:
        logger.error("[launcher] load DRAMATIQ config failed: %r", e)
        tree = {}

    # 默认值（仅用于缺省）
    sim_default = {"queue_name": "simulate", "processes": 2, "threads": 1, "log-level": "info"}
    http_default = {"queue_name": "http", "processes": 2, "threads": 4, "log-level": "info"}

    s = dict(sim_default);  s.update(tree.get("simulate") or {})
    h = dict(http_default); h.update(tree.get("http") or {})

    # queue_name 严格校验（但启动时仍强制队列名固定）
    _require_queue_name(s, "queue_name", "simulate")
    _require_queue_name(h, "queue_name", "http")

    try:
        sim_cfg = {
            "queue": "simulate",
            "processes": _require_int_gt0(s, "processes"),
            "threads": _require_int_gt0(s, "threads"),
            "log_level": _normalize_log_level(s.get("log-level"), default="INFO"),
        }
        http_cfg = {
            "queue": "http",
            "processes": _require_int_gt0(h, "processes"),
            "threads": _require_int_gt0(h, "threads"),
            "log_level": _normalize_log_level(h.get("log-level"), default="INFO"),
        }
    except _ConfigError as e:
        logger.error("[launcher] invalid DRAMATIQ.* worker config: %s", e)
        raise SystemExit(1)

    logger.warning(
        "[launcher] effective worker cfg: simulate={processes:%s,threads:%s,log_level:%s} "
        "http={processes:%s,threads:%s,log_level:%s}",
        sim_cfg["processes"], sim_cfg["threads"], sim_cfg["log_level"],
        http_cfg["processes"], http_cfg["threads"], http_cfg["log_level"]
    )
    return sim_cfg, http_cfg

SIM, HTTP = _load_worker_cfgs()

# ---------------- 启动与守护 ----------------

def build_cmd(queue: str, processes: int, threads: int) -> List[str]:
    # --queues 使用固定值，避免配置误改队列名
    return [
        "dramatiq", MODULE,
        "--queues", queue,
        "--processes", str(int(processes)),
        "--threads", str(int(threads)),
        "--skip-logging",
        
    ]

PROCS: List[subprocess.Popen] = []

def start_worker(name: str, cfg: Dict[str, Any]) -> subprocess.Popen:
    cmd = build_cmd(cfg["queue"], cfg["processes"], cfg["threads"])
    print(f"[launcher] starting {name}: {shlex.join(cmd)}")

    # 每组 worker 用不同的 Prometheus 端口，避免冲突
    env = os.environ.copy()
    if name == "simulate":
        env["dramatiq_prom_port"] = "9191"
        env["dramatiq_prom_host"] = "127.0.0.1"
    elif name == "http":
        env["dramatiq_prom_port"] = "9192"
        env["dramatiq_prom_host"] = "127.0.0.1"

    # 设置 dramatiq 的日志级别（通过环境变量，而非 CLI）
    env["DRAMATIQ_LOG_LEVEL"] = str(cfg.get("log_level", "INFO")).upper()

    if os.name == "posix":
        proc = subprocess.Popen(cmd, preexec_fn=os.setsid, env=env)
    else:
        proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, env=env)
    PROCS.append(proc)
    return proc

def terminate_all():
    print("[launcher] terminating all workers ...")
    for p in PROCS:
        if p.poll() is not None:
            continue
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            else:
                p.terminate()
        except Exception:
            pass

def kill_all():
    print("[launcher] killing all workers ...")
    for p in PROCS:
        if p.poll() is not None:
            continue
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            else:
                p.kill()
        except Exception:
            pass

def handle_signal(signum, frame):
    print(f"[launcher] caught signal {signum}, shutting down ...")
    terminate_all()

def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    p_sim = start_worker("simulate", SIM)
    p_http = start_worker("http", HTTP)

    exit_codes: List[int] = []
    try:
        exit_codes.append(p_sim.wait())
        exit_codes.append(p_http.wait())
    except KeyboardInterrupt:
        terminate_all()
    finally:
        terminate_all()
        try: p_sim.wait(timeout=5)
        except Exception: pass
        try: p_http.wait(timeout=5)
        except Exception: pass
        kill_all()

    rc = 0
    for c in exit_codes:
        if c and c != 0:
            rc = c
    sys.exit(rc)

if __name__ == "__main__":
    main()