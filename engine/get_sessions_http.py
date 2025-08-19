import logging
import regex
import requests
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set 
from urllib import parse

from helper.tools import *
from helper.url_normalizer import norm_url

logger = logging.getLogger(__name__)


#  ============ 工具函数 ==============

# ---------- 提取工具 ----------
def _extract_from_url(final_url: str, key: str) -> Tuple[Optional[str], Optional[str]]:
    """从 URL 的 query 中取值。"""
    qs = parse.parse_qs(parse.urlparse(final_url).query, keep_blank_values=True)
    vals = qs.get(key)
    if vals:
        return parse.unquote(vals[0]), "url.query"
    return None, None


def _extract_from_cookie(res: requests.Response, key: str) -> Tuple[Optional[str], Optional[str]]:
    """仅从响应中的 cookies / Set-Cookie 提取值。"""
    if key in res.cookies:
        return res.cookies.get(key), "cookie.response"  # type: ignore[no-any-return]
    raw = res.headers.get("Set-Cookie") or res.headers.get("set-cookie")
    if not raw:
        return None, None
    jar = SimpleCookie()
    try:
        jar.load(raw)
        morsel = jar.get(key)
        if morsel:
            return morsel.value, "cookie.set-cookie"
    except Exception:
        logger.debug("Failed to parse Set-Cookie via SimpleCookie.")
    return None, None


def _extract_from_header(res: requests.Response, key: str, body_text: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """优先从响应头取值；必要时用 body 文本兜底正则。"""
    val = res.headers.get(key)
    if isinstance(val, str):
        return parse.unquote(val), "header"
    if body_text:
        m = regex.search(rf"{regex.escape(key)}=([^&\s]+)", body_text)
        if m:
            return parse.unquote(m.group(1)), "header.regex"
    return None, None


def _extract_from_body(res: requests.Response, key: str) -> Tuple[Optional[str], Optional[str]]:
    """从响应体取值：JSON > form-urlencoded > 兜底正则。"""
    content_type = (res.headers.get("Content-Type") or "").lower()
    text: Optional[str] = None

    # JSON 优先
    if "application/json" in content_type:
        try:
            data = res.json()
            vals = find_values_by_key(data, key)
            if vals:
                return str(vals[0]), "body.json"
        except ValueError:
            try:
                text = res.text
            except Exception:
                text = None
    else:
        try:
            text = res.text
        except Exception:
            text = None

    if text:
        # form-urlencoded
        form = parse.parse_qs(text, keep_blank_values=True)
        if key in form and form[key]:
            return parse.unquote(form[key][0]), "body.form"

        # 兜底 regex：支持 "key":"val" 或 key=val
        m = regex.search(
            rf'(?:(?<={regex.escape(key)}=)|(?<="{regex.escape(key)}"\s*:\s*"))(.*?)(?=(?:["&\s]|$))',
            text,
        )
        if m:
            return parse.unquote(m.group(1)), "body.regex"

    return None, None

# ---------- 基础请求（支持 GET / POST） ----------

def http_request(
    method_name: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    body_type: str = "json",
    timeout: float = 10.0,
) -> requests.Response:
    m = (method_name or "").upper()
    if m not in {"GET", "POST"}:
        raise ValueError(f"Unsupported method: {method_name}. Only GET or POST are supported.")
    if m == "POST" and body_type not in {"json", "form"}:
        raise ValueError(f"Unsupported body_type for POST: {body_type}. Only 'json' or 'form' are supported.")

    headers = headers or {}
    cookies = cookies or {}

    try:
        if m == "GET":
            return requests.get(url, headers=headers, cookies=cookies, timeout=timeout)
        if body_type == "json":
            return requests.post(url, headers=headers, cookies=cookies, json=data, timeout=timeout)
        else:  # "form"
            return requests.post(url, headers=headers, cookies=cookies, data=data, timeout=timeout)
    except requests.RequestException as e:
        raise RuntimeError(f"HTTP request failed: {e}") from e


# ---------- 主类 ----------
class GetCookieItmesHttp:
    @classmethod
    def get_new_cookies(
        cls,
        *,
        application_name: str,
        session_page_name: str,
        session_page_url: str,
        session_collection_url: str,
        session_collection_method: Dict[str, str],
        session_collection_headers: Optional[Dict[str, str]],
        session_collection_cookies: Optional[Dict[str, str]],
        session_collection_data: Optional[Dict[str, Any]],
        session_list: Iterable[Dict[str, Any]],
        session_state_check: Dict[str, Any],
        timeout: float = 10.0,
        session_hashes: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:

        # 0) hash 过滤
        my_hash = compute_session_hash(application_name, session_collection_url)
        if session_hashes and my_hash not in session_hashes:
            logger.info("[http] skip by session_hash filter: %s", my_hash)
            return []

        method_name = (session_collection_method or {}).get("name", "")
        body_type = (session_collection_method or {}).get("type", "")

        m = (method_name or "").upper()
        if m not in {"GET", "POST"}:
            raise ValueError(f"Only GET or POST are supported, got: {method_name!r}")
        if m == "POST" and body_type not in {"json", "form"}:
            raise ValueError(f"Only body_type 'json' or 'form' are supported for POST, got: {body_type!r}")
        if m == "GET":
            body_type = "None"

        # 1) 发一次原始采集请求（保持和以前一致）
        res = http_request(
            m,
            session_collection_url,
            headers=session_collection_headers,
            cookies=session_collection_cookies,
            data=session_collection_data if m == "POST" else None,
            body_type="json" if m == "GET" else body_type,
            timeout=timeout,
        )
        session_collection_url_query = session_collection_url

        try:
            body_text_for_header = res.text
        except Exception:
            body_text_for_header = None

        # 2) 自动探测 session_list（与之前一致）
        out_list: List[Dict[str, Any]] = []
        for item in session_list or []:
            key = item.get("session_key")
            sid = item.get("session_id")
            sname = item.get("session_name")

            val: Optional[str] = None
            src: Optional[str] = None

            if key:
                val, src = _extract_from_url(session_collection_url_query, key)
                if val is None:
                    val, src = _extract_from_cookie(res, key)
                if val is None:
                    val, src = _extract_from_header(res, key, body_text_for_header)
                if val is None:
                    val, src = _extract_from_body(res, key)

            out_list.append({
                "session_id": sid,
                "session_name": sname,
                "session_key": key,
                "session_value": val,
                "matched_from": src
            })

        # 3) 写回的 session_collection_data（保持一致）
        out_session_collection_data = None
        if m == "POST":
            out_session_collection_data = (
                dict(session_collection_data or {})
                if isinstance(session_collection_data, dict)
                else session_collection_data
            )
        
        # ======== 构造  new_session_state_check ================

        # 4)输入的 state_check 里可能有 url/headers/body，按新规则改造：
        inp_ssc = dict(session_state_check or {})
        bench = inp_ssc.get("session_check_benchmark")
        resign = inp_ssc.get("session_check_resign")

        # 1) URL：来源 session_collection_url，根据配置中的URL_NORMALIZER规范化URL后使用 session_list/url 键值拼接
        in_url = inp_ssc.get("session_check_url") or session_collection_url
        session_check_url = url_from_session_url_params(
            base_url=in_url,
            session_list=out_list,
        )

        # 2) headers：来源输入 headers，仅保留4基本头 + session_list/header
        session_check_headers = headers_from_base_and_session_list(
            base_headers=inp_ssc.get("session_check_headers") or {},
            session_list=out_list,
        )

        # 3) cookies：完全来自 session_list/cookie
        session_check_cookies = cookies_from_session_list(out_list)

        # 4) body：来源输入 body，用 session_list/body 覆盖
        session_check_body = None
        if m == "POST":
            session_check_body = body_from_base_and_session_list(
                base_body=inp_ssc.get("session_check_body") if isinstance(inp_ssc.get("session_check_body"), dict) else {},
                session_list=out_list,
            )

        new_session_state_check = {
            "session_check_method_name": m,
            "session_check_method_type": (None if m == "GET" else (body_type if body_type in {"json", "form"} else None)),
            "session_check_url": session_check_url,
            "session_check_headers": session_check_headers,
            "session_check_cookies": session_check_cookies,  # ← 新增
            "session_check_body": session_check_body,
            "session_check_benchmark": bench,
            "session_check_resign": resign,
        }

        enriched_page = {
            "application_name": application_name,
            "achieve_method": "http",
            "session_page_name": session_page_name,
            "session_page_url": session_page_url,
            "session_collection_url": session_collection_url,
            "session_collection_url_query": session_collection_url_query,
            "session_collection_method": {
                "name": m,
                "type": body_type,  # GET 为 "None"，POST 为 "json"/"form"
            },
            "session_collection_headers": dict(session_collection_headers or {}),
            "session_collection_cookies": dict(session_collection_cookies or {}),
            "session_collection_data": out_session_collection_data,
            "session_list": out_list,
            "session_state_check": new_session_state_check,
        }

        # 缺失 key 则放弃
        missing = [si["session_key"] for si in enriched_page["session_list"] if not si.get("session_value")]
        if missing:
            logger.error(
                "Missing sessions on %s(application_name=%s) -> %s: %s",
                enriched_page.get("session_page_url"),
                enriched_page.get("application_name"),
                enriched_page.get("session_collection_url"),
                missing,
            )
            # return []
        # 无论成功与否，都要更新配置到数据库
        return [enriched_page]