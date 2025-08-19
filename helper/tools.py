import requests
import re
import random
import time
import os
import hashlib
import logging
import json 
from urllib import parse
from typing import Any, Dict, Iterable, List, Optional, Tuple, Callable
from collections import Counter, defaultdict
from playwright.sync_api import Page
from helper.url_normalizer import norm_url

from environment.environ import environ

logger = logging.getLogger(__name__)


# ------------- 编码正则的特殊符号 ------------
def re_escape(s: str) -> str:
    return re.escape(s)


# ---------- 在嵌套 dict/list 中递归查找精确 key 的所有值 ----------
def find_values_by_key(obj: Any, key: str) -> List[str]:
    """在嵌套 dict/list 中递归查找精确 key 的所有值。"""
    result: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                result.append(str(v))
            result.extend(find_values_by_key(v, key))
    elif isinstance(obj, list):
        for item in obj:
            result.extend(find_values_by_key(item, key))
    return result


# ---------- 返回随机时间 ----------
def rand_ms(a: int, b: int) -> int:
    return random.randint(a, b)


# ---------- 遍历目录下的 .py 文件名（含扩展名），过滤默认黑名单 ----------
def iter_py_files(dir_path: str) -> Iterable[str]:
    """
    遍历目录下的 .py 文件名（含扩展名），过滤默认黑名单。
    """
    if not os.path.isdir(dir_path):
        return []
    default_black = {"__pycache__", ".DS_Store"}
    for name in os.listdir(dir_path):
        if name in default_black:
            continue
        path = os.path.join(dir_path, name)
        if os.path.isfile(path) and name.endswith(".py") and name != "__init__.py":
            yield name



# ---------- 计算 session_hash 保持和数据库一致 ----------
def compute_session_hash(application_name: Optional[str], session_collection_url: Optional[str]) -> str:
    a = (application_name or "").strip()
    # 用统一的 URL 规范化逻辑
    u = norm_url(session_collection_url).lower()
    base = f"{a}\n{u}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


# ---------- 配置读取  ----------
def cfg(ns: str, defaults: Dict[str, Any]) -> Dict[str, Any]:
    try:
        m = environ.get_config(ns) or {}
    except Exception:
        m = {}
    out = dict(defaults)
    out.update(m)
    return out


# ---------- 获取 login 登录片段可调用对象  ----------
def get_login_callable(obj) -> Callable[[Any], None] | None:
    fn = getattr(obj, "login", None)
    if callable(fn):
        return fn
    cls_fn = getattr(type(obj), "login", None)
    if callable(cls_fn):
        try:
            return cls_fn.__get__(obj, type(obj))
        except Exception:
            return cls_fn
    return None


# ---------- 根据配置class，获取urls  ----------
def iter_urls_for_instance(inst) -> Iterable[Tuple[str, str]]:
    """
    抽取公共逻辑：给定配置类实例，产出 (mode, url) 序列。
    mode in {"simulate","http"}，url 已做 norm_url。
    """
    app = getattr(inst, "application_name", None)
    if not isinstance(app, str) or not app:
        return []

    urls: List[Tuple[str, str]] = []
    login_fn = get_login_callable(inst)

    if login_fn:
        # simulate 分支：遍历 session_page_items
        items = getattr(inst, "session_page_items", []) or []
        for it in items:
            try:
                raw = (it or {}).get("session_collection_url")
                if not raw:
                    continue
                urls.append(("simulate", norm_url(raw)))
            except Exception:
                continue
    else:
        # http 分支：单一 url
        raw = getattr(inst, "session_collection_url", None)
        if raw:
            try:
                urls.append(("http", norm_url(raw)))
            except Exception:
                pass

    return urls


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
    


def cookie_header_from_maps(headers: Dict[str, str], cookies: Dict[str, str]) -> Optional[str]:
    # 1) 若请求头里已带 Cookie，直接用
    for k in ("cookie", "Cookie", "COOKIE"):
        if k in headers and isinstance(headers[k], str) and headers[k].strip():
            return headers[k].strip()
    # 2) 否则用 map 组装
    if not cookies:
        return None
    # 用 '; ' 连接，浏览器常见格式；末尾不加分号
    parts = [f"{k}={v}" for k, v in cookies.items() if isinstance(k, str)]
    return "; ".join(parts) if parts else None

def format_http_request_dump(
    method: str,
    final_url: str,
    headers: Dict[str, str],
    cookies: Dict[str, str],
    body_text: Optional[str],
    *,
    http_version: str = "HTTP/2"
) -> str:
    """
    以“原始请求包”形式输出，示例：
      GET /path?a=1 HTTP/2
      Host: example.com
      Cookie: k1=v1; k2=v2
      Accept: ...
      Content-Type: ...
      X-...
      
      <body if any>
    """
    try:
        pu = parse.urlparse(final_url)
        path = pu.path or "/"
        if pu.query:
            path = f"{path}?{pu.query}"
        host = headers.get("host") or headers.get("Host") or pu.hostname or ""
        # 起始行
        lines = [f"{method.upper()} {path} {http_version}"]
        # Host 行
        if host:
            lines.append(f"Host: {host}")
        # Cookie 行（优先使用请求头中的 Cookie）
        cookie_line = cookie_header_from_maps(headers, cookies)
        if cookie_line:
            lines.append(f"Cookie: {cookie_line}")
        # 其他头（避免重复打印 Host/Cookie；保留原有大小写的 key）
        skip = {"host", "cookie"}
        for k, v in headers.items():
            if k.lower() in skip:
                continue
            if v is None:
                continue
            try:
                # 去掉换行，避免破坏一行一头格式
                vv = str(v).replace("\r", " ").replace("\n", " ").strip()
            except Exception:
                vv = str(v)
            lines.append(f"{k}: {vv}")
        # 空行 + body
        lines.append("")
        if method.upper() == "POST" and body_text:
            lines.append(body_text if isinstance(body_text, str) else str(body_text))
        return "\n".join(lines)
    except Exception as e:
        # 兜底：若格式化失败，也给出基本信息
        return f"{method} {final_url} {http_version}\n# dump failed: {e!r}"
    


def body_text_for_dump(method_name: str, body_type: Optional[str], body: Optional[Dict[str, Any]]) -> Optional[str]:
    """
    根据 method/body_type 生成可打印的 body_text（仅对 POST 有意义）。
    json → JSON 字符串；form → x-www-form-urlencoded；其他返回 None。
    """
    if (method_name or "").upper() != "POST":
        return None
    bt = (body_type or "").lower()
    try:
        if bt == "json":
            return json.dumps(body or {}, ensure_ascii=False)
        if bt == "form":
            return parse.urlencode({k: v for k, v in (body or {}).items()})
    except Exception:
        pass
    return None


# === 请求包构造小工具 ===
BASIC_HEADER_KEYS = {"accept", "referer", "user-agent", "content-type"}

def headers_from_base_and_session_list(
    base_headers: Optional[Dict[str, Any]],
    session_list: Iterable[Dict[str, Any]],
) -> Dict[str, str]:
    """
    仅保留4个基本头 + 把 session_list 中 matched_from 以 'header' 开头的键值追加进去。
    """
    out = {}
    base = {str(k).lower(): v for k, v in dict(base_headers or {}).items()}
    for k in BASIC_HEADER_KEYS:
        if k in base and base[k] not in (None, ""):
            out[k] = str(base[k])

    for it in (session_list or []):
        src = str(it.get("matched_from") or "").lower()
        if not src.startswith("header"):
            continue
        key = it.get("session_key")
        val = it.get("session_value")
        if not key or val is None:
            continue
        out[str(key).lower()] = str(val)
    return out


def cookies_from_session_list(session_list: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """
    完全依赖 session_list：只收集 matched_from 以 'cookie' 开头的键值。
    """
    ck = {}
    for it in (session_list or []):
        src = str(it.get("matched_from") or "").lower()
        if not src.startswith("cookie"):
            continue
        key = it.get("session_key")
        val = it.get("session_value")
        if not key or val is None:
            continue
        ck[str(key)] = str(val)
    return ck


def body_from_base_and_session_list(
    base_body: Optional[Dict[str, Any]],
    session_list: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    以 base_body 为基础（可能来自抓包/配置），用 session_list 中 matched_from 以 'body' 开头的字段覆盖/补齐。
    """
    b = dict(base_body or {})
    for it in (session_list or []):
        src = str(it.get("matched_from") or "").lower()
        if not src.startswith("body"):
            continue
        key = it.get("session_key")
        val = it.get("session_value")
        if not key or val is None:
            continue
        # 保留原类型不强转
        b[str(key)] = val
    return b


def url_from_session_url_params(base_url: str, session_list: Iterable[Dict[str, Any]]) -> str:
    """
    先对 base_url 执行 norm_url（保留/清空 query 的规则由 norm_url 配置决定），
    然后把 session_list 中 matched_from 以 'url' 开头的键值对拼接到 query 末尾。

    若规范化后的 URL 已包含与要追加的键相同的 query key，则抛出异常中止。
    若 session_list 内部含有重复的 key，也抛出异常。
    """
    # 1) 规范化 base_url
    norm = norm_url(base_url)
    pu = parse.urlparse(norm)

    # 2) 解析现有 query
    existing_pairs = parse.parse_qsl(pu.query or "", keep_blank_values=True, strict_parsing=False)
    existing_keys = {k for k, _ in existing_pairs}

    # 3) 从 session_list 收集要追加的 url-* 键值
    additions = []
    add_keys_seen = set()
    for it in (session_list or []):
        src = str(it.get("matched_from") or "").lower()
        if not src.startswith("url"):
            continue
        key = it.get("session_key")
        val = it.get("session_value")
        if not key or val is None:
            continue
        k = str(key)
        v = str(val)

        # 与现有 query 冲突 → 抛错
        if k in existing_keys:
            raise ValueError(
                f"session_check_url construct exception: normalized URL already contains query key {k!r}; "
                "refusing to append duplicated key from session_list."
            )
        # session_list 内部重复 → 抛错
        if k in add_keys_seen:
            raise ValueError(
                f"session_check_url construct exception: session_list contains duplicated query key {k!r}."
            )
        add_keys_seen.add(k)
        additions.append((k, v))

    # 4) 拼接并返回
    new_pairs = existing_pairs + additions
    new_query = parse.urlencode(new_pairs, doseq=True)
    return parse.urlunparse(pu._replace(query=new_query))
