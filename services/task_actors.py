from __future__ import annotations
import os
import importlib
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import time
import random
import requests
import dramatiq
from environment.environ import environ
from engine.get_sessions import RefreshCookies
from helper.database_helper import SessionDB
from helper.config_validator import (
    validate_http_strict, validate_simulate_strict, summarize_problems
)
from environment.pylogger import pylogger  # 统一日志样式
logger = logging.getLogger(__name__)

# ========================== 配置读取与严格校验 ==========================

class _ConfigError(Exception):
    pass

def _require_type(d: dict, key: str, typ, *, positive: bool | None = None, nonempty: bool | None = None):
    if key not in d:
        raise _ConfigError(f"missing key: {key!r}")
    val = d[key]
    if not isinstance(val, typ):
        raise _ConfigError(f"bad type for {key!r}: expected {typ.__name__}, got {type(val).__name__}")
    if positive is True and isinstance(val, int) and val <= 0:
        raise _ConfigError(f"{key!r} must be > 0, got {val}")
    if nonempty is True and isinstance(val, str) and not val.strip():
        raise _ConfigError(f"{key!r} must be a non-empty string")
    return val

def _load_actor_cfgs() -> Tuple[dict, dict, dict]:
    """
    读取并校验 DRAMATIQ 配置：
    """
    try:
        tree = environ.get_config("DRAMATIQ") or {}
    except Exception as e:
        raise SystemExit(f"[DRAMATIQ] load config failed: {e!r}")

    try:
        if not isinstance(tree, dict):
            raise _ConfigError("DRAMATIQ must be a dict")

        # ---- global ----
        g = tree.get("global")
        if not isinstance(g, dict):
            raise _ConfigError("DRAMATIQ.global must be a dict")
        max_retries   = _require_type(g, "max_retries", int)
        time_limit_ms = _require_type(g, "time_limit_ms", int)
        global_cfg = {"max_retries": int(max_retries), "time_limit_ms": int(time_limit_ms)}

        # ---- simulate ----
        s = tree.get("simulate")
        if not isinstance(s, dict):
            raise _ConfigError("DRAMATIQ.simulate must be a dict")
        s_queue   = _require_type(s, "queue_name", str, nonempty=True).strip()
        s_procs   = _require_type(s, "processes", int, positive=True)
        s_threads = _require_type(s, "threads", int, positive=True)
        if s_queue != "simulate":
            raise _ConfigError(f"simulate.queue_name must be 'simulate', got {s_queue!r}")
        simulate_cfg = {
            "queue_name": s_queue,
            "processes": int(s_procs),
            "threads": int(s_threads),
        }

        # ---- http ----
        h = tree.get("http")
        if not isinstance(h, dict):
            raise _ConfigError("DRAMATIQ.http must be a dict")
        h_queue   = _require_type(h, "queue_name", str, nonempty=True).strip()
        h_procs   = _require_type(h, "processes", int, positive=True)
        h_threads = _require_type(h, "threads", int, positive=True)
        if h_queue != "http":
            raise _ConfigError(f"http.queue_name must be 'http', got {h_queue!r}")
        http_cfg = {
            "queue_name": h_queue,
            "processes": int(h_procs),
            "threads": int(h_threads),
        }

        return global_cfg, simulate_cfg, http_cfg

    except _ConfigError as e:
        logger.error("[DRAMATIQ] invalid config: %s", e)
        raise SystemExit(1)

GLOBAL, SIM, HTTP = _load_actor_cfgs()

# ========================== 数据库初始化 ==========================

DB = None  # type: Optional[SessionDB]

def get_db() -> SessionDB:
    """惰性创建，不在模块导入期触发；不再 ensure_schema（交给 maintainer 统一做一次）"""
    global DB
    if DB is None:
        DB = SessionDB.from_environ()
    return DB

# ========================== 工具与错误类型 ==========================

class NonRetriableError(Exception):
    """用于标记不应重试的永久性错误"""
    pass

def _is_transient_error(exc: Exception) -> bool:
    # 显式识别 requests/urllib3 的典型瞬时异常
    if isinstance(exc, (requests.Timeout, requests.ConnectionError, TimeoutError)):
        return True

    name = exc.__class__.__name__.lower()
    text = (str(exc) or "").lower()

    keywords = [
        # 常见关键词（类名或报错信息里都会出现）
        "timeout", "timed out", "connect timeout", "read timeout",
        "temporarily", "temporary", "try again",
        "connection reset", "connection aborted", "connection refused",
        "max retries exceeded", "proxy", "tls", "ssl",
        "dns", "name or service not known", "no route to host",
        "network", "server error", "5xx", "429", "rate limit",
        "too many requests", "backoff", "unreachable",
    ]
    return any(k in name or k in text for k in keywords)

def _retry_backoff_seconds(attempt: int, *, base: float = 1.5, cap: float = 45.0) -> float:
    """
    指数退避（带抖动），attempt 从 1 开始。
    delay = min(cap, base * 2^(attempt-1) + random[0, base))
    """
    if attempt < 1:
        attempt = 1
    return min(cap, base * (2 ** (attempt - 1)) + random.uniform(0.0, base))




class NonRetriableError(Exception):
    """用于标记不应重试的永久性错误"""
    pass

def _import_instance(class_ref: str):
    """
    将 'a.b.module:ClassName' 解析为实例，用于执行配置严格校验。
    注意：必须是模块路径+类名，中间用冒号分隔。
    """
    if not isinstance(class_ref, str) or ":" not in class_ref:
        raise NonRetriableError(f"bad class_ref: {class_ref!r}")
    mod_name, cls_name = class_ref.split(":", 1)
    try:
        mod = importlib.import_module(mod_name)
    except Exception as e:
        raise NonRetriableError(f"cannot import module {mod_name!r}: {e}")
    try:
        cls = getattr(mod, cls_name)
    except AttributeError:
        raise NonRetriableError(f"module {mod_name!r} has no attribute {cls_name!r}")
    try:
        return cls()  # 要求目标类可无参构造
    except Exception as e:
        raise NonRetriableError(f"instantiate {class_ref!r} failed: {e}")

# ========================== 通用刷新逻辑 ==========================

def _run_refresh(class_ref: str, session_hashes: Optional[List[str]] = None) -> None:
    try:
        msg = dramatiq.get_current_message()
        attempt = (msg.options.get("retries", 0) or 0) + 1
        logger.info(
            f"[update] id={msg.message_id} attempt={attempt} class={class_ref} "
            f"hashes={len(session_hashes or [])}"
        )
    except Exception:
        pass

    try:
        hashes_set: Optional[Set[str]] = set(session_hashes) if session_hashes else None
        enriched_pages = RefreshCookies(class_ref).refresh(session_hashes=hashes_set)

        if not isinstance(enriched_pages, list):
            logger.error("RefreshCookies.refresh() must return List[Dict], got %r", type(enriched_pages))
            raise NonRetriableError("bad return type from RefreshCookies.refresh()")

        affected = get_db().upsert_enriched_pages(enriched_pages)
        logger.warning(f"[DB] upsert affected={affected}")
        return None
    except (KeyboardInterrupt, SystemExit):
        logger.warning("[update] user interrupted → no retry")
        raise
    except Exception as e:
        if _is_transient_error(e):
            # 计算第几次尝试（用于 backoff）
            try:
                msg = dramatiq.get_current_message()
                attempt = (msg.options.get("retries", 0) or 0) + 1  # 第几次尝试（从 1 开始）
            except Exception:
                attempt = 1

            delay = _retry_backoff_seconds(attempt, base=1.5, cap=45.0)
            # 瞬时错误只打印简短告警，不打堆栈；在本 worker 内等待后再交给 Dramatiq 重试
            logger.warning(
                f"[update] transient network error (attempt={attempt}) for {class_ref}, "
                f"will retry after {delay:.1f}s: {e}"
            )
            time.sleep(delay)
            # 重新抛出原异常（非 NonRetriableError），让 Dramatiq 的 Retries 中间件处理重试
            raise
        else:
            # 永久错误：打印 error 并停止重试
            logger.error(f"[update] permanent error, no retry: {e!r}", exc_info=True)
            raise NonRetriableError(str(e))

# ========================== Actors ==========================

# 队列名在运行时固定为 'simulate' / 'http'，即使配置里填正确也不从配置读取，避免误改。
@dramatiq.actor(
    queue_name="simulate",
    max_retries=int(GLOBAL["max_retries"]),
    time_limit=int(GLOBAL["time_limit_ms"]),
    throws=(NonRetriableError, KeyboardInterrupt, SystemExit),
)
def update_simulate(class_ref: str, session_hashes: Optional[List[str]] = None) -> Dict[str, Any]:
    """模拟登录获取会话"""
    # 严格校验 simulate 配置
    try:
        inst = _import_instance(class_ref)
        ok, probs = validate_simulate_strict(inst)
    except Exception as e:
        logger.error("[update] validate simulate crashed for %s: %r", class_ref, e)
        raise NonRetriableError(f"{class_ref} validate simulate crashed")

    if not ok:
        msg = summarize_problems("", probs)
        logger.error("[update] invalid simulate config for %s:\n%s", class_ref, msg)
        raise NonRetriableError(f"{class_ref} invalid simulate config")
    _run_refresh(class_ref, session_hashes)
    return None

@dramatiq.actor(
    queue_name="http",
    max_retries=int(GLOBAL["max_retries"]),
    time_limit=int(GLOBAL["time_limit_ms"]),
    throws=(NonRetriableError, KeyboardInterrupt, SystemExit),
)
def update_http(class_ref: str, session_hashes: Optional[List[str]] = None) -> Dict[str, Any]:
    """HTTP 直连获取会话"""
    # 严格校验 http 配置
    try:
        inst = _import_instance(class_ref)
        ok, probs = validate_http_strict(inst)
    except Exception as e:
        logger.error("[update] validate http crashed for %s: %r", class_ref, e)
        raise NonRetriableError(f"{class_ref} validate http crashed")

    if not ok:
        msg = summarize_problems("", probs)
        logger.error("[update] invalid http config for %s:\n%s", class_ref, msg)
        raise NonRetriableError(f"{class_ref} invalid http config")
    _run_refresh(class_ref, session_hashes)
    return None

@dramatiq.actor(max_retries=int(GLOBAL["max_retries"]))
def on_success(message_data: Dict[str, Any], result: Dict[str, Any]) -> None:
    logger.warning(f"[SUCCESS] id={message_data.get('message_id')} result={result}")

@dramatiq.actor(max_retries=int(GLOBAL["max_retries"]))
def on_failure(message_data: Dict[str, Any], exception_data: Dict[str, Any]) -> None:
    msg_id = message_data.get("message_id")
    retries_done = int(message_data.get("options", {}).get("retries", 0))
    max_retries = int(message_data.get("options", {}).get("max_retries", GLOBAL["max_retries"]))
    err = exception_data.get("message")
    logger.error(f"[FAIL] id={msg_id} retries={retries_done}/{max_retries} error={err!r}")
    if retries_done >= max_retries:
        logger.error(f"[ERROR] id={msg_id} result={err}")