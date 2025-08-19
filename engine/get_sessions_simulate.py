# -*- coding: utf-8 -*-
from __future__ import annotations

import ast
import gzip
import logging
import importlib
import json
import random
import re
import time
import regex
from urllib import parse
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Protocol, Union, Set
from playwright.sync_api import Page, Locator, BrowserContext

from helper.browser_helper import BrowserHub
from helper.human_helper import HumanPage, attach_human, apply_stealth
from helper.tools import *

logger = logging.getLogger(__name__)

ALLOWED_METHODS = {"GET", "POST"}

# ---- 登录片段协议：login(page) -> None ----
class LoginSnippet(Protocol):
    def __call__(self, page) -> None: ...


# ---- 将所需的全局符号注入到片段 callable 的 __globals__ ----
def _inject_globals_into_callable(fn, extra: dict):
    try:
        f = fn.__func__ if hasattr(fn, "__func__") else fn  # 兼容 bound method
        g = getattr(f, "__globals__", None)
        if isinstance(g, dict):
            for k, v in extra.items():
                g.setdefault(k, v)
    except Exception:
        pass


# ---- 片段加载：callable / 文件 / 代码字符串 / callable_ref ----
def load_login_snippet(
    snippet: Union[LoginSnippet, str, Path, dict],
    *,
    filename_hint: Optional[str] = None,
) -> LoginSnippet:
    inject_symbols = {
        "random": random,
        "time": time,
        "re": re,
        "Page": Page,
        "Locator": Locator,
        # 让片段可直接使用这些“人类交互”能力
        "attach_human": attach_human,
        "HumanPage": HumanPage,
    }

    if callable(snippet):
        _inject_globals_into_callable(snippet, inject_symbols)
        return snippet

    if isinstance(snippet, dict) and snippet.get("kind") == "callable_ref":
        mod_name, class_name = snippet["value"].split(":")
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, class_name)
        obj = cls()
        fn = getattr(obj, "login", None)
        if not callable(fn):
            raise TypeError(f"{snippet['value']} has no callable login(page) method")
        _inject_globals_into_callable(fn, inject_symbols)
        return fn

    # 代码字符串 / 文件
    if isinstance(snippet, (str, Path)) and Path(str(snippet)).exists():
        file_path = Path(str(snippet)).resolve()
        code = file_path.read_text(encoding="utf-8")
        filename = str(file_path)
    else:
        code = str(snippet)
        filename = filename_hint or "<login_snippet>"

    node = ast.parse(code, filename=filename, mode="exec")
    compiled = compile(node, filename=filename, mode="exec")
    ns: Dict[str, Any] = {
        "random": random,
        "time": time,
        "re": re,
        "Page": Page,
        "Locator": Locator,
        "attach_human": attach_human,
        "HumanPage": HumanPage,
    }
    exec(compiled, ns, ns)
    fn = ns.get("login")
    if not callable(fn):
        raise ValueError(f"Login snippet must define a callable `login(page)`. File: {filename}")
    _inject_globals_into_callable(fn, inject_symbols)
    return fn


# ============== Chrome JS运行能力诊断 ==============

def js_sanity_check(page: Page, *, timeout_ms: int = 4000) -> None:
    page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    ok = page.evaluate("""
        () => {
            try {
                const basic = (1+1) === 2;
                const hasDoc = typeof document !== 'undefined' && !!document.body;
                const hasPromise = typeof Promise !== 'undefined';
                const hasFetch = typeof fetch === 'function';
                return basic && hasDoc && hasPromise && hasFetch;
            } catch(e) { return false; }
        }
    """)
    if not ok:
        raise RuntimeError("JavaScript seems not running (sanity check failed).")
    


# ============== 工具函数 ==============

def _decode_gzip_bytes(data: bytes) -> str:
    try:
        buff = BytesIO(data)
        with gzip.GzipFile(fileobj=buff) as f:
            return f.read().decode("utf-8")
    except Exception:
        return data.decode("utf-8", errors="ignore")

def _parse_cookie_header(cookie_header: Optional[str]) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
        else:
            continue
        cookies[k.strip()] = parse.unquote(v.strip())
    return cookies


# 把 context 里与 request_url 匹配的 cookie 拉平为 {name:value}
def _cookies_from_context_for_url(context: BrowserContext, request_url: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        pu = parse.urlparse(request_url)
        host = pu.hostname or ""
        path = pu.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        for ck in context.cookies():
            name = ck.get("name")
            value = ck.get("value", "")
            if not name:
                continue
            dom = (ck.get("domain") or "").lstrip(".").lower()
            req_host = (host or "").lower()

            dom_ok = (dom == req_host) or (dom and req_host.endswith("." + dom))
            if not dom_ok:
                continue

            ck_path = ck.get("path") or "/"
            if not ck_path.startswith("/"):
                ck_path = "/" + ck_path

            if not path.startswith(ck_path.rstrip("/") or "/"):
                continue

            out[name] = value
    except Exception:
        pass
    return out

# 合并 header-cookie 与 context-cookie（header 优先）
def _merge_request_and_context_cookies(
    context: BrowserContext,
    req_headers_map: Dict[str, str],
    request_url: str
) -> Dict[str, str]:
    header_cookie_map = _parse_cookie_header(
        (req_headers_map.get("cookie") or req_headers_map.get("Cookie") or "").strip()
    )
    ctx_cookie_map = _cookies_from_context_for_url(context, request_url)
    merged = dict(ctx_cookie_map)
    merged.update(header_cookie_map)  # header 覆盖 context
    return merged

def _require_body_type_from_headers(headers: Dict[str, str]) -> str:
    ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    if "application/json" in ct:
        return "json"
    if "application/x-www-form-urlencoded" in ct:
        return "form"
    raise ValueError(f"Unsupported Content-Type for POST: {ct!r}.")

def _parse_request_body_to_dict(
    headers: Dict[str, str],
    post_bytes: Optional[bytes],
    post_str: Optional[str]
) -> Optional[Dict[str, Any]]:
    if post_bytes is not None:
        text = _decode_gzip_bytes(post_bytes)
    elif isinstance(post_str, str):
        text = post_str
    else:
        return None

    ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
    if "application/json" in ct:
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else {"__raw__": obj}
        except Exception:
            return {"__raw__": text}
    if "application/x-www-form-urlencoded" in ct:
        try:
            qs = parse.parse_qs(text, keep_blank_values=True)
            return {k: (v[0] if isinstance(v, list) and v else "") for k, v in qs.items()}
        except Exception:
            return {"__raw__": text}
    return {"__raw__": text}


# ============== storage_state 的保存/恢复 ==============

def _restore_storage_state_from_file(context, app_name: str) -> bool:
    """
    恢复 cookies + localStorage（来自 ./.auth/<app>.json）。
    返回 True 表示存在并成功应用了本地状态（cookies/origins 任一成功即可）。
    同一 context 仅恢复一次（防重复）。
    """
    # ------- 防重复：同一 context 只恢复一次 -------
    # _sm_restore_attempted: 是否已经尝试过恢复（避免重复开页、路由等开销）
    # _sm_restore_had_local: 上次是否发现了本地状态（供调用方做快捷判断）
    if getattr(context, "_sm_restore_attempted", False):
        return bool(getattr(context, "_sm_restore_had_local", False))

    state_file = Path("./.auth") / f"{app_name}.json"
    if not state_file.exists():
        logger.info("No saved storage_state for %s, skip restore.", app_name)
        # 标记已尝试，但没有本地状态
        setattr(context, "_sm_restore_attempted", True)
        setattr(context, "_sm_restore_had_local", False)
        return False

    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Load storage_state failed (%s): %r", state_file, e)
        setattr(context, "_sm_restore_attempted", True)
        setattr(context, "_sm_restore_had_local", False)
        return False

    had_any_effect = False  # 是否成功恢复了 cookies/origins 任一项

    # --------- cookies ----------
    cookies = data.get("cookies") or []
    if cookies:
        try:
            context.add_cookies(cookies)
            logger.info("Restored %d cookies from %s", len(cookies), state_file)
            had_any_effect = True
        except Exception as e:
            logger.warning("Restore cookies failed: %r", e)

    # --------- localStorage（origins） ----------
    origins = data.get("origins") or []
    if origins:
        opened_pages: set[Page] = set()

        def _on_new_page(p: Page):
            opened_pages.add(p)
            try:
                p.add_init_script("window.open = () => null; window.alert=()=>{}; window.confirm=()=>true;")
            except Exception:
                pass

        context.on("page", _on_new_page)

        try:
            for origin in origins:
                origin_url = origin.get("origin")
                items = origin.get("localStorage") or []
                if not origin_url or not items:
                    continue

                page = None

                def _fulfill_blank(route):
                    try:
                        route.fulfill(
                            status=200,
                            headers={"content-type": "text/html; charset=utf-8"},
                            body="<!doctype html><html><head></head><body></body></html>",
                        )
                    except Exception:
                        try:
                            route.abort()
                        except Exception:
                            pass

                try:
                    page = context.new_page()
                    opened_pages.add(page)

                    page.add_init_script("""
                        window.open = () => null;
                        window.alert = () => {};
                        window.confirm = () => true;
                        if (navigator.serviceWorker && navigator.serviceWorker.register) {
                            navigator.serviceWorker.register = () =>
                            Promise.resolve({ scope: location.origin, update: () => {} });
                        }
                    """)
                    page.route("**/*", _fulfill_blank)

                    page.goto(origin_url, wait_until="domcontentloaded", timeout=15000)

                    ok_count = 0
                    for kv in items:
                        name = kv.get("name")
                        value = kv.get("value")
                        if name is None or value is None:
                            continue
                        try:
                            page.evaluate("(arg) => localStorage.setItem(arg.name, arg.value)", {"name": name, "value": value})
                            ok_count += 1
                        except Exception:
                            pass

                    logger.info("Restored %d localStorage keys for %s (silent)", ok_count, origin_url)
                    if ok_count > 0:
                        had_any_effect = True

                except Exception as e:
                    logger.warning("Restore localStorage for %s failed: %r", origin_url, e)
                finally:
                    try:
                        if page:
                            try:
                                page.unroute("**/*", _fulfill_blank)
                            except Exception:
                                pass
                            page.close()
                    except Exception:
                        pass

            # 清理可能遗留的页面
            for p in list(opened_pages):
                try:
                    if not p.is_closed():
                        p.close()
                except Exception:
                    pass

        finally:
            try:
                context.off("page", _on_new_page)
            except Exception:
                pass

    # ------- 标记防重复并返回结果 -------
    setattr(context, "_sm_restore_attempted", True)
    setattr(context, "_sm_restore_had_local", bool(had_any_effect))
    return bool(had_any_effect)


def _save_storage_state(context, app_name: str) -> None:
    try:
        backup_dir = Path("./.auth").resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)
        state_file = backup_dir / f"{app_name}.json"
        context.storage_state(path=str(state_file))
        logger.info("Saved storage_state to %s", state_file)
    except Exception as e:
        logger.debug("Save storage_state failed: %r", e)


# ============== 核心采集/嗅探（每次检查/采集均新开 tab） ==============

class LoginHelper:
    def __init__(self, context: BrowserContext):
        self.browser = context.browser
        self.context = context

    def _ensure_context(self):
        if self.context is None:
            raise RuntimeError("Context is not initialized.")
    
    def _wait_for_page_settled(self, page: Page, *, hard_timeout_ms: int = 15000, settle_extra_ms: int = 400):
        try:
            page.wait_for_load_state("networkidle", timeout=hard_timeout_ms)
        except Exception:
            try:
                page.wait_for_load_state("load", timeout=min(10000, hard_timeout_ms))
            except Exception:
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=min(8000, hard_timeout_ms))
                except Exception:
                    pass
        page.wait_for_timeout(random.randint(max(120, settle_extra_ms//2), settle_extra_ms))

    # —— 单 tab 嗅探器：打印所有请求；命中 check_url 后检查响应内是否含 benchmark —— 
    def _sniff_for_benchmark_page(
        self,
        page: Page,
        check_url: str,
        benchmark: str,
        *,
        sniff_ms: int = 7000,
        navigate: Optional[str] = None,
    ) -> bool:
        want = parse.urlparse(check_url)

        def url_match(url: str) -> bool:
            got = parse.urlparse(url)
            return (got.netloc + got.path + (got.query if want.query else "")) == \
                   (want.netloc + want.path + (want.query or ""))

        found = {"ok": False}

        def on_request(req):
            try:
                method = getattr(req, "method", "GET") or "GET"
                if method not in ALLOWED_METHODS:
                    return
                logger.debug("[sniff][req] %s %s", method, req.url)
                if url_match(req.url):
                    headers = getattr(req, "headers", {}) or {}
                    try:
                        pdata = req.post_data or ""
                        plen = len(pdata)
                    except Exception:
                        plen = 0
                    logger.debug("[sniff][req][match] method=%s headers=%s post_len=%s url=%s",
                                method, headers, plen, req.url)
            except Exception:
                pass

        def on_response(resp):
            try:
                # 先判断 URL 是否匹配
                if not url_match(resp.url):
                    return
                # 通过 response 关联的 request 拿到方法
                req = getattr(resp, "request", None)
                method = getattr(req, "method", "GET") if req else "GET"
                if method not in ALLOWED_METHODS:
                    return

                logger.debug("[sniff][resp] %s %s %s", method, resp.status, resp.url)
                try:
                    text = resp.text()
                except Exception:
                    try:
                        text = resp.body().decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""
                logger.debug("[sniff][resp][match] status=%s len=%s url=%s",
                            resp.status, len(text or ""), resp.url)
                if benchmark and (benchmark in (text or "")):
                    logger.debug("[sniff] benchmark FOUND in response of %s", resp.url)
                    found["ok"] = True
            except Exception:
                pass

        page.on("request", on_request)
        page.on("response", on_response)
        try:
            if navigate:
                try:
                    page.goto(navigate, wait_until="domcontentloaded", timeout=20000)
                except Exception:
                    pass
            deadline = time.time() + sniff_ms / 1000.0
            while time.time() < deadline and not found["ok"]:
                page.wait_for_timeout(100)
            return bool(found["ok"])
        finally:
            try:
                page.off("request", on_request)
                page.off("response", on_response)
            except Exception:
                pass

    def _wait_until_quiet(self, page: Page, *, quiet_ms: int = 1000, max_wait_ms: int = 6000) -> bool:
        last_req_ts = time.time()
        def _on_req(_):
            nonlocal last_req_ts
            last_req_ts = time.time()

        page.on("request", _on_req)
        start = time.time()
        try:
            while (time.time() - start) * 1000 < max_wait_ms:
                if (time.time() - last_req_ts) * 1000 >= quiet_ms:
                    return True
                page.wait_for_timeout(120)
            return False
        finally:
            try:
                page.off("request", _on_req)
            except Exception:
                pass

    @staticmethod
    def _match_target_request(want_url: str, got_url: str) -> bool:
        want = parse.urlparse(want_url)
        got  = parse.urlparse(got_url)
        want_path = (want.path or "").rstrip("/")
        got_path  = (got.path or "").rstrip("/")

        if want.query:
            return (got.netloc + got_path + got.query) == (want.netloc + want_path + want.query)
        return (got.netloc + got_path) == (want.netloc + want_path)

    def _check_in_new_tab(self, target_url: str, check_url: str, benchmark: str) -> bool:
        page = self.context.new_page()
        try:
            return self._sniff_for_benchmark_page(
                page,
                check_url,
                benchmark,
                sniff_ms=8000,
                navigate=target_url,
            )
        finally:
            try:
                page.close()
            except Exception:
                pass

    def check_session_url(self, _unused_current_page: Page, session_page_url: str, session_collection_url: str) -> Dict[str, Any]:
        self._ensure_context()

        sniff_ms = 12000
        page = self.context.new_page()
        found = {"req": None, "resp": None}

        def url_match(u: str) -> bool:
            return self._match_target_request(session_collection_url, u)

        def on_request(r):
            try:
                method = getattr(r, "method", "GET") or "GET"
                if method not in ALLOWED_METHODS:
                    return
                logger.debug("[sniff][req] %s %s", method, r.url)
                if url_match(r.url) and not found["req"]:
                    found["req"] = r
            except Exception:
                pass

        def on_response(resp):
            try:
                if not url_match(resp.url):
                    return
                # 只接受与白名单方法对应的响应
                req = getattr(resp, "request", None)
                method = getattr(req, "method", "GET") if req else "GET"
                if method not in ALLOWED_METHODS:
                    return
                if not found["resp"]:
                    found["resp"] = resp
                logger.debug("[sniff][resp] %s %s %s", method, resp.status, resp.url)
            except Exception:
                pass

        page.on("request", on_request)
        page.on("response", on_response)
        try:
            try:
                logger.info("start a new page(tab) to collect sessions: %s", session_page_url)
                page.goto(session_page_url, wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass

            self._wait_for_page_settled(page, hard_timeout_ms=8000, settle_extra_ms=500)

            deadline = time.time() + sniff_ms / 1000.0
            while time.time() < deadline and not (found["req"] and found["resp"]):
                page.wait_for_timeout(100)

            if not found["req"]:
                self._wait_until_quiet(page, quiet_ms=800, max_wait_ms=3000)
                if not found["req"]:
                    raise RuntimeError(f"Check session url failed: {session_collection_url}")

            req = found["req"]
            resp = found["resp"] or (req.response() if req else None)

            try:
                req_method = req.method
            except Exception:
                req_method = "GET"

            try:
                req_headers_map = req.headers or {}
            except Exception:
                req_headers_map = {}

            try:
                req_post_data_bytes = req.post_data_buffer
            except Exception:
                req_post_data_bytes = None

            try:
                req_post_data_str = req.post_data
            except Exception:
                req_post_data_str = None

            # ★ 合并 header 与 context 的 cookies（header 优先）
            req_final_url = req.url
            req_cookies_map = _merge_request_and_context_cookies(self.context, req_headers_map, req_final_url)

            if resp:
                try:
                    txt = resp.text()
                except Exception:
                    try:
                        txt = resp.body().decode("utf-8", errors="ignore")
                    except Exception:
                        txt = ""
                logger.debug("[sniff][match] response_len=%s url=%s", len(txt or ""), resp.url)

            return {
                "req_method": req_method,
                "req_headers_map": req_headers_map,
                "req_cookies_map": req_cookies_map,
                "req_post_data_bytes": req_post_data_bytes,
                "req_post_data_str": req_post_data_str,
                "req_final_url": req_final_url,
            }

        finally:
            try:
                page.off("request", on_request)
                page.off("response", on_response)
            except Exception:
                pass
            try:
                page.close()
            except Exception:
                pass

    # --------- 提取器（基于命中的 Request） ---------
    @staticmethod
    def _extract_from_url(request_url: str, key: str):
        qs = parse.parse_qs(parse.urlparse(request_url).query, keep_blank_values=True)
        vals = qs.get(key)
        if vals:
            return parse.unquote(vals[0]), "url.query"
        return None, None

    @staticmethod
    def _extract_from_cookie(ctx_cookies_map: dict, req_cookies_map: dict, key: str):
        if key in ctx_cookies_map:
            return parse.unquote(ctx_cookies_map[key]), "cookie.context"
        if key in req_cookies_map:
            return parse.unquote(req_cookies_map[key]), "cookie.request"
        return None, None

    @staticmethod
    def _extract_from_header(req_headers_map: dict, key: str, body_text: Optional[str]):
        val = req_headers_map.get(key) or req_headers_map.get(key.lower())
        if isinstance(val, str):
            return parse.unquote(val), "header"
        if body_text:
            m = regex.search(rf"{re_escape(key)}=([^&\s]+)", body_text)
            if m:
                return parse.unquote(m.group(1)), "header.regex"
        return None, None

    @staticmethod
    def _extract_from_body(body_text: Optional[str], key: str):
        if not body_text:
            return None, None
        try:
            data = json.loads(body_text)
            if isinstance(data, dict) and key in data and isinstance(data[key], (str, int, float, bool)):
                return str(data[key]), "body.json"
        except Exception:
            pass
        form = parse.parse_qs(body_text, keep_blank_values=True)
        if key in form and form[key]:
            return parse.unquote(form[key][0]), "body.form"
        m = regex.search(
            rf'(?:(?<={re_escape(key)}=)|(?<="{re_escape(key)}"\s*:\s*"))(?:(?!["])).*?(?=(?:["&\s]|$))',
            body_text,
        )
        if m:
            return parse.unquote(m.group(0)), "body.regex"
        return None, None

    def _collect_one_page(self, page, session_page_item: dict, *, application_name: str) -> dict:
        page_name = session_page_item.get("session_page_name")
        page_url = session_page_item.get("session_page_url")
        collection_url = session_page_item.get("session_collection_url")

        req_info = self.check_session_url(page, page_url, collection_url)

        req_method: str = req_info["req_method"]
        req_headers_map: Dict[str, str] = dict(req_info["req_headers_map"] or {})
        req_cookies_map: Dict[str, str] = dict(req_info["req_cookies_map"] or {})
        req_post_bytes = req_info["req_post_data_bytes"]
        req_post_str = req_info["req_post_data_str"]
        req_final_url = req_info["req_final_url"]

        ctx_cookies_map = {ck["name"]: ck["value"] for ck in self.context.cookies()}

        # 解析 body 文本（便于从 header/body 中“捕获”）
        body_text = None
        if isinstance(req_post_bytes, (bytes, bytearray)):
            body_text = _decode_gzip_bytes(req_post_bytes)
        elif isinstance(req_post_str, str):
            body_text = req_post_str

        m = (req_method or "").upper()
        if m == "GET":
            method_type = None
            session_collection_data = None
        elif m == "POST":
            method_type = _require_body_type_from_headers(req_headers_map)
            session_collection_data = _parse_request_body_to_dict(req_headers_map, req_post_bytes, req_post_str)
        else:
            raise ValueError(f"Unsupported HTTP method captured: {req_method!r}. Only GET/POST are supported.")

        session_collection_method = {"name": m, "type": method_type}
        session_collection_headers = dict(req_headers_map)
        session_collection_cookies = dict(req_cookies_map)

        # ===== 生成 session_list（捕获来源：URL -> Cookie(context/request) -> Header -> Body）=====
        out_session_list: List[Dict[str, Any]] = []
        for raw in session_page_item.get("session_list", []):
            key = raw.get("session_key")
            sid = raw.get("session_id")
            sname = raw.get("session_name")

            val: Optional[str] = None
            src: Optional[str] = None

            if key:
                val, src = self._extract_from_url(req_final_url, key)
                if val is None:
                    val, src = self._extract_from_cookie(ctx_cookies_map, req_cookies_map, key)
                if val is None:
                    val, src = self._extract_from_header(req_headers_map, key, body_text)
                if val is None:
                    val, src = self._extract_from_body(body_text, key)

            out_session_list.append({
                "session_id": sid,
                "session_name": sname,
                "session_key": key,
                "session_value": val,
                "matched_from": src
            })

        # ===== 从配置拿基准/签名 =====
        base_ssc = session_page_item.get("session_state_check") or {}
        bench = base_ssc.get("session_check_benchmark")
        resign = base_ssc.get("session_check_resign")
        if not bench or not resign:
            raise ValueError("session_state_check requires 'session_check_benchmark' and 'session_check_resign'.")

        # 1) headers：仅4个基本头 + session_list/header 字段
        session_check_headers = headers_from_base_and_session_list(
            base_headers=session_collection_headers,
            session_list=out_session_list,
        )
        # 2) cookies：完全来自 session_list/cookie
        session_check_cookies = cookies_from_session_list(out_session_list)

        # 3) body：来源 session_collection_data，并用 session_list/body 覆盖
        session_check_body = None
        if m == "POST":
            session_check_body = body_from_base_and_session_list(
                base_body=session_collection_data if isinstance(session_collection_data, dict) else {},
                session_list=out_session_list,
            )

        # 4) url：来源 session_collection_url，清空原 query，仅用 session_list/url 键值拼接
        session_check_url = url_from_session_url_params(
            base_url=collection_url,
            session_list=out_session_list,
        )

        session_state_check = {
            "session_check_method_name": session_collection_method["name"],
            "session_check_method_type": (session_collection_method["type"] if session_collection_method["name"] != "GET" else None),
            "session_check_url": session_check_url,
            "session_check_headers": session_check_headers,
            "session_check_cookies": session_check_cookies,    # ← 新增
            "session_check_body": session_check_body,
            "session_check_benchmark": bench,
            "session_check_resign": resign,
        }

        result = {
            "application_name": application_name,
            "session_page_name": page_name,
            "session_page_url": page_url,
            "session_collection_url": collection_url,
            "session_collection_url_query": req_final_url,
            "session_collection_method": session_collection_method,
            "session_collection_headers": session_collection_headers,
            "session_collection_cookies": session_collection_cookies,
            "session_collection_data": session_collection_data if m == "POST" else None,
            "session_list": out_session_list,
            "session_state_check": session_state_check,
        }

        # 缺失 key 的提示 & 请求包打印
        missing = [si["session_key"] for si in result["session_list"] if not si.get("session_value")]
        if missing:
            result["session_missing_keys"] = missing  # ← 新增标记，保留原有日志（含 request dump）
            logger.error(
                "Missing sessions on %s(application_name=%s) -> %s: %s",
                result.get("session_page_url"),
                result.get("application_name"),
                result.get("session_collection_url"),
                missing
            )
            try:
                req_dump = format_http_request_dump(
                    method=m,
                    final_url=req_final_url,
                    headers=session_collection_headers,
                    cookies=session_collection_cookies,
                    body_text=body_text,
                )
                logger.error("=== Raw Request Dump ===\n%s\n=== End Request Dump ===", req_dump)

            except Exception as _e:
                logger.debug("format http request dump failed: %r", _e)

        return result


    def _check_logged_in(self, current_page: Page, login_check_page: str, login_check_url: str, benchmark: str) -> bool:
        self._wait_for_page_settled(current_page, hard_timeout_ms=15000, settle_extra_ms=500)
        if self._sniff_for_benchmark_page(current_page, login_check_url, benchmark, sniff_ms=7000):
            return True

        if login_check_page and self._check_in_new_tab(login_check_page, login_check_url, benchmark):
            return True

        self._wait_until_quiet(current_page, quiet_ms=1000, max_wait_ms=6000)
        if login_check_page and self._check_in_new_tab(login_check_page, login_check_url, benchmark):
            return True

        return False

    def run_in_context(
        self,
        *,
        login_page: str,
        login_check_page: str,
        login_check_url: str,
        login_check_benchmark: str,
        session_page_items: Iterable[Dict[str, Any]],
        login_snippet: LoginSnippet,
        application_name: str,
    ) -> List[Dict[str, Any]]:
        self._ensure_context()
       
        # 先尝试恢复本地的持久化状态（如果没有文件会自动跳过）
        has_local_state = _restore_storage_state_from_file(self.context, application_name)


        # 1) 基础校验 + stealth
        page = self.context.new_page()
        try:
            attach_human(page)
            apply_stealth(page)  # ← 使用 helper.human_helper 提供的封装
            page.goto("about:blank")
            js_sanity_check(page, timeout_ms=3000)
        finally:
            try:
                page.close()
            except Exception:
                pass

        # 2) 免登录快速检查
        logged_in = False
        if has_local_state and login_check_page and login_check_url:
            for i in range(3):
                try:
                    logger.info("login-free quick check for the  %s time", str(i+1))
                    if self._check_in_new_tab(login_check_page, login_check_url, login_check_benchmark):
                        logged_in = True
                        break
                except Exception:
                    pass
                time.sleep(random.uniform(0.18, 0.42))

        # 3) 登录流程
        if not logged_in:
            page = self.context.new_page()
            try:
                # ★ 新开的 page 必须 attach_human，否则没有 page.human
                try:
                    attach_human(page)
                except Exception:
                    pass
                try:
                    apply_stealth(page)
                except Exception:
                    pass
                for i in range(5):
                    try:
                        logger.warning("login attempt for the  %s time", str(i+1))
                        page.goto(login_page, wait_until="load", timeout=30000)

                    except Exception:
                        continue
                    page.human.pause(150, 380)
                    _inject_globals_into_callable(login_snippet, {
                        "random": random, "time": time, "re": re,
                        "attach_human": attach_human, "HumanPage": HumanPage,
                    })
                    login_snippet(page)
                    page.human.pause(250, 600)
                    if self._check_logged_in(page, login_check_page, login_check_url, login_check_benchmark):
                        logged_in = True
                        break
                else:
                    raise RuntimeError("login check failed: exhausted all attempts")
            finally:
                try:
                    page.close()
                except Exception:
                    pass

        # 4) 采集
        page = self.context.new_page()
        try:
        # ★ 新开的 page 必须 attach_human，否则没有 page.human
            try:
                attach_human(page)
            except Exception:
                pass
            try:
                apply_stealth(page)
            except Exception:
                pass

            enriched_pages: List[Dict[str, Any]] = []
            for spi in session_page_items:
                enriched = self._collect_one_page(page, spi, application_name=application_name)
                enriched = {
                    "application_name": enriched.get("application_name"),
                    "achieve_method": "simulate",
                    **{k: v for k, v in enriched.items() if k != "application_name"},
                }
                missing = [si["session_key"] for si in enriched["session_list"] if not si.get("session_value")]
                if missing:
                    # 不再因为缺失而跳过；仅在需要时补个标记（_collect_one_page 已经会加）
                    if "session_missing_keys" not in enriched:
                        missing = [si["session_key"] for si in enriched["session_list"] if not si.get("session_value")]
                        if missing:
                            enriched["session_missing_keys"] = missing

                
                enriched_pages.append(enriched)
            return enriched_pages
        finally:
            try:
                page.close()
            except Exception:
                pass
            try:
                _save_storage_state(self.context, application_name)
            except Exception:
                pass


def page_items_filter(
    session_page_items: Iterable[Dict[str, Any]],
    application_name: str,
    session_hashes: Optional[Set[str]] = None
) -> List[Dict[str, Any]]:

    # 1) 规范化 items：把 session_collection_url 统一 norm，后面计算 hash 要用
    normalized_items: List[Dict[str, Any]] = []
    for spi in (session_page_items or []):
        if not isinstance(spi, dict):
            continue
        spi2 = dict(spi)
        spi2["session_collection_url"] = norm_url(spi2.get("session_collection_url"))
        normalized_items.append(spi2)

    # 2) 若传入了 session_hashes，则据此过滤（匹配 app+url 的哈希）
    if session_hashes:
        use_items: List[Dict[str, Any]] = []
        for it in normalized_items:
            url = it.get("session_collection_url") or ""
            h = compute_session_hash(application_name, url)
            if h in session_hashes:
                use_items.append(it)
        if not use_items:
            logger.warning(
                "[simulate] session_hashes provided but no items matched. count=%s",
                len(session_hashes),
            )
    else:
        use_items = normalized_items
    
    return use_items


# ---- 对外入口 ----
class GetCookieItmesSimulate:
    @classmethod
    def get_new_cookies(
        cls,
        simulation_code: Union[LoginSnippet, str, Path, dict],
        login_page: str,
        login_check_page: str,
        login_check_url: str,
        login_check_benchmark: str,
        session_page_items: Iterable[Dict[str, Any]],
        *,
        headless: bool = False,
        snippet_filename_hint: Optional[str] = None,
        application_name: str,
        session_hashes: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        
        use_items = page_items_filter(session_page_items, application_name, session_hashes)

        # 没有要更新的 session_hash, 跳过
        if not use_items:
            return []

        # 加载登录片段 & 跑上下文
        login_snippet = load_login_snippet(simulation_code, filename_hint=snippet_filename_hint)

        hub = BrowserHub.instance()
        with hub.context(application_name=application_name) as ctx:
            helper = LoginHelper(ctx)
            enriched_pages = helper.run_in_context(
                login_page=login_page,
                login_check_page=login_check_page,
                login_check_url=login_check_url,
                login_check_benchmark=login_check_benchmark,
                session_page_items=use_items,
                login_snippet=login_snippet,
                application_name=application_name,
            )

        hub.maybe_close(idle_timeout=10.0)
        return enriched_pages