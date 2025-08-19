# 定期校验登录态；失败则触发重新获取 cookie

from __future__ import annotations

import time
import logging
import importlib
from typing import Any, Dict, List, Optional, Tuple

import requests
from urllib import parse

from helper.database_helper import SessionDB
from engine.get_applications import collect_classes
from helper.tools import *

from services.task_actors import update_simulate, update_http

logger = logging.getLogger(__name__)

# 只保留 & 自动补齐
NEEDED_HEADER_KEYS = {"accept", "referer", "user-agent", "content-type"}


def _resolve_resign_to_callable(resign_ref: Optional[str]):
    """
    resign_ref 解析优先级：
    1) 形如 'a.b.module:ClassOrFunc' → 直接 import
    2) 只有一个类名 'Signer' → 尝试 import plugins.sign.signer:Signer  和 plugins.sign.Signer:Signer
       （文件名小写规则 & 原大小写两种都试）
    返回可调用对象：
      - 如果是类，实例化后要求有 .sign(...) 方法（优先用 .sign，否则 __call__）
      - 如果是函数，直接返回函数
    """
    if not resign_ref:
        return None

    candidates: List[Tuple[str, str | None]] = []
    if ":" in resign_ref:
        mod, name = resign_ref.split(":", 1)
        candidates.append((mod, name))
    else:
        cls = resign_ref
        # plugin/sign/signer.py -> class Signer
        candidates.append(("plugins.sign." + cls.lower(), cls))
        candidates.append(("plugins.sign." + cls, cls))

    last_err = None
    for mod_name, symbol in candidates:
        try:
            mod = importlib.import_module(mod_name)
            target = getattr(mod, symbol) if symbol else mod
            # 统一成可调用：
            if hasattr(target, "sign") and callable(getattr(target, "sign")):
                inst = target() if isinstance(target, type) else target
                return getattr(inst, "sign")  # type: ignore[no-any-return]
            if callable(target):
                return target  # 允许函数或可调用实例
        except Exception as e:
            last_err = e
            continue

    if last_err:
        logger.warning("[checker] resign resolver failed for %r: %r", resign_ref, last_err)
    return None

def _maybe_call_resign(
    resign_ref: Optional[str],
    *,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    body: Dict[str, Any],
    url: str,
    application_name: str,
    session_list: List[Dict[str, Any]],
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any], str]:
    """
    如果配置了 session_check_resign，就导入并调用它让它对请求做二次签名/补充。
    统一约定签名函数原型：
        sign(headers, cookies, body, url, application_name, session_list) -> (headers, cookies, body, url) | None
    """
    fn = _resolve_resign_to_callable(resign_ref)
    if not fn:
        return headers, cookies, body, url
    try:
        ret = fn(headers=headers, cookies=cookies, body=body, url=url,
                 application_name=application_name, session_list=session_list)
        if isinstance(ret, tuple) and len(ret) == 4:
            h, c, b, u = ret
            headers = {str(k).lower(): v for k, v in dict(h or {}).items()}
            cookies = dict(c or {})
            body    = dict(b or {})
            url     = str(u or url)
    except Exception as e:
        logger.warning("[checker] resign hook crashed (%s): %r", resign_ref, e)
    return headers, cookies, body, url

def _do_http(
    *,
    method_name: str,
    url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    body: Dict[str, Any],
    body_type: Optional[str],
    timeout: float,
    user_agent: str,
) -> requests.Response:
    method = (method_name or "GET").upper()
    headers = dict(headers or {})
    headers.setdefault("user-agent", user_agent)

    if method == "GET":
        return requests.get(url, headers=headers, cookies=cookies, timeout=timeout)

    if (body_type or "").lower() == "json":
        return requests.post(url, headers=headers, cookies=cookies, json=body or {}, timeout=timeout)
    if (body_type or "").lower() == "form":
        return requests.post(url, headers=headers, cookies=cookies, data=body or {}, timeout=timeout)

    # 未指定时，按 content-type 判断；仍不明确则默认 json
    ct = (headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ct:
        return requests.post(url, headers=headers, cookies=cookies, data=body or {}, timeout=timeout)
    return requests.post(url, headers=headers, cookies=cookies, json=body or {}, timeout=timeout)


# ============== 定位“应该用哪个类去刷新” ==============
def _index_classes_by_app_name() -> Dict[str, str]:
    """
    返回 dict: { application_name: "module:ClassName" }
    class 里已有 application_name 属性。
    """
    mapping: Dict[str, str] = {}
    for cls in collect_classes():
        try:
            inst = cls()
            app = getattr(inst, "application_name", None)
            if isinstance(app, str) and app:
                mapping[app] = f"{cls.__module__}:{cls.__name__}"
        except Exception:
            continue
    return mapping

CLASS_INDEX = None  # 延迟构造

def _ensure_class_index() -> Dict[str, str]:
    """收集类索引（已含白/黑名单过滤），返回 {application_name: class_ref}。"""
    global CLASS_INDEX
    if CLASS_INDEX is None:
        CLASS_INDEX = _index_classes_by_app_name()
    return CLASS_INDEX

# ============== 单次巡检 ==============
def check_once(*, http_timeout: float, user_agent: str) -> None:
    db = SessionDB.from_environ()
    rows = list(db.fetch_latest_sessions_by_hash())
    if not rows:
        logger.info("[checker] no rows to check.")
        return

    # —— 仅检查“可用类”对应的 app（白/黑名单过滤后）——
    class_index = _ensure_class_index()
    allowed_apps = set(class_index.keys())

    before = len(rows)
    rows = [r for r in rows if (r.get("application_name") in allowed_apps)]
    skipped = before - len(rows)
    if skipped > 0:
        logger.warning(
            "[checker] %d rows skipped because application_name not in allowed set (filtered by whitelist/blacklist).",
            skipped
        )

    if not rows:
        logger.info("[checker] no eligible rows after whitelist/blacklist filtering.")
        return

    simulate_refresh_map: Dict[str, set] = {}
    http_refresh_map: Dict[str, set] = {}

    ok = bad = 0
    for r in rows:
        try:
            app         = r.get("application_name")
            method_tag  = (r.get("achieve_method") or "simulation").lower()
            state_check = r.get("session_state_check") or {}
            sess_hash   = r.get("session_hash")

            # 直接用 DB 里的 session_state_check
            url     = state_check.get("session_check_url") or r.get("session_collection_url")
            m_name  = (state_check.get("session_check_method_name") or "GET").upper()
            m_type  = state_check.get("session_check_method_type")
            bench   = state_check.get("session_check_benchmark")
            resign  = state_check.get("session_check_resign")

            headers = dict(state_check.get("session_check_headers") or {})
            cookies = dict(state_check.get("session_check_cookies") or {})    # ← 新增字段
            body    = dict(state_check.get("session_check_body") or {})

            # 若缺 user-agent，给一个兜底（不改变其它头）
            headers = {str(k).lower(): v for k, v in headers.items()}
            headers.setdefault("user-agent", user_agent)

            # 可选：签名二次处理（保留）
            headers, cookies, body, url = _maybe_call_resign(
                resign_ref=resign,
                headers=headers, cookies=cookies, body=body, url=url,
                application_name=app, session_list=r.get("session_list") or [],
            )

            # 发请求
            res = _do_http(
                method_name=m_name,
                url=url,
                headers=headers,
                cookies=cookies,
                body=body,
                body_type=m_type,
                timeout=float(http_timeout),
                user_agent=user_agent,
            )

            try:
                text = res.text or ""
            except Exception:
                text = ""

            if bench and bench in text:
                ok += 1
                logger.info("[checker] OK %s (%s) status=%s len=%s",
                               app, method_tag, res.status_code, len(text))
                try:
                    db.update_check_state(sess_hash, True)
                except Exception:
                    logger.warning("update_check_state(ok) failed.", exc_info=True)
            else:
                bad += 1
                # 失败时同时打印请求包 + 响应
                try:
                    req_dump = format_http_request_dump(
                        method=m_name,
                        final_url=url,
                        headers=headers,
                        cookies=cookies,
                        body_text=body_text_for_dump(m_name, m_type, body),
                    )
                except Exception as _e:
                    req_dump = f"[request dump failed: {_e!r}]"

                resp_text = text if isinstance(text, str) else str(text)

                logger.error(
                    "[checker] FAIL %s (%s) status=%s len=%s → queue refresh\n**Request**:\n%s\n**Response**:\n%s",
                    app, method_tag, res.status_code, len(resp_text), req_dump, resp_text
                )

                try:
                    db.update_check_state(sess_hash, False)
                except Exception:
                    logger.error("update_check_state(fail) failed.", exc_info=True)

                (simulate_refresh_map if method_tag.startswith("sim") else http_refresh_map) \
                    .setdefault(app, set()).add(sess_hash)

        except Exception as e:
            bad += 1
            logger.error("[checker] error on %r: %r", r.get("application_name"), e, exc_info=True)
            try:
                db.update_check_state(r.get("session_hash"), False)
            except Exception:
                logger.error("update_check_state(exception) failed.", exc_info=True)

            app = r.get("application_name")
            method_tag = (r.get("achieve_method") or "simulation").lower()
            sess_hash = r.get("session_hash")
            (simulate_refresh_map if method_tag.startswith("sim") else http_refresh_map) \
                .setdefault(app, set()).add(sess_hash)

    # 派发刷新（保持不变）
    if simulate_refresh_map or http_refresh_map:
        class_index = _ensure_class_index()

        # simulate
        for app, hash_set in simulate_refresh_map.items():
            class_ref = class_index.get(app)
            if not class_ref:
                logger.error("[checker] no class for simulate app=%s (skipped earlier?)", app)
                continue
            try:
                update_simulate.send(class_ref, sorted(hash_set))
                logger.warning("[checker] queued simulate refresh for %s (hashes=%s)", app, len(hash_set))
            except Exception as e:
                logger.error("[checker] queue simulate failed for %s: %r", app, e, exc_info=True)

        # http
        for app, hash_set in http_refresh_map.items():
            class_ref = class_index.get(app)
            if not class_ref:
                logger.error("[checker] no class for http app=%s (skipped earlier?)", app)
                continue
            try:
                update_http.send(class_ref, sorted(hash_set))
                logger.warning("[checker] queued http refresh for %s (hashes=%s)", app, len(hash_set))
            except Exception as e:
                logger.error("[checker] queue http failed for %s: %r", app, e, exc_info=True)

    logger.warning("[checker] done: ok=%d bad=%d total=%d", ok, bad, len(rows))

if __name__ == "__main__":
    # 直接运行文件时给出一个保守默认，便于单测/本地调试
    check_once(http_timeout=10.0, user_agent="autologin-session-checker/1.0")