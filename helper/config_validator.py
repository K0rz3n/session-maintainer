from __future__ import annotations
import logging
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# --------- 错误消息构造（区分：缺失 / 名字非法 / 值非法） ---------
def _err_missing(path: str) -> Dict[str, str]:
    return {"path": path, "msg": "missing required field"}

def _err_name_illegal(path: str) -> Dict[str, str]:
    return {"path": path, "msg": "invalid field name"}

def _err_value(path: str, detail: str) -> Dict[str, str]:
    return {"path": path, "msg": f"invalid value: {detail}"}

def summarize_problems(prefix: str, probs: List[Dict[str, str]]) -> str:
    return "\n".join(f"{prefix}{p['path']}: {p['msg']}" for p in probs)

# ---------------------- 工具 ----------------------
def _is_str(x: Any) -> bool:
    return isinstance(x, str)

def _str_nonempty(x: Any) -> bool:
    return isinstance(x, str) and x.strip() != ""

def _is_dict_str_str(d: Any) -> bool:
    if not isinstance(d, dict):
        return False
    return all(isinstance(k, str) and isinstance(v, str) for k, v in d.items())

def _report_unknown_keys(obj: dict, allowed: set[str], base_path: str, problems: List[Dict[str, str]]) -> None:
    for k in obj.keys():
        if k not in allowed:
            problems.append(_err_name_illegal(f"{base_path}.{k}" if base_path else k))

def _has_scheme(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

# ---------------------- HTTP 严格校验 ----------------------
def validate_http_strict(inst: Any) -> Tuple[bool, List[Dict[str, str]]]:
    problems: List[Dict[str, str]] = []

    # 顶层必填字段存在性
    required = [
        "application_name",
        "session_page_name", "session_page_url",
        "session_collection_url", "session_collection_method",
        "session_collection_headers", "session_collection_cookies",
        "session_list",
        "session_state_check",
    ]
    for f in required:
        if not hasattr(inst, f):
            problems.append(_err_missing(f))
    if problems:
        return False, problems

    # 顶层字段取值
    if not _str_nonempty(getattr(inst, "application_name")):
        problems.append(_err_value("application_name", "must be non-empty string"))

    # 允许为空字符串，但必须是 str
    if not _is_str(getattr(inst, "session_page_name")):
        problems.append(_err_value("session_page_name", "must be string (empty allowed)"))
    if not _is_str(getattr(inst, "session_page_url")):
        problems.append(_err_value("session_page_url", "must be string (empty allowed)"))

    if not _str_nonempty(getattr(inst, "session_collection_url")):
        problems.append(_err_value("session_collection_url", "must be non-empty string"))

    # session_collection_method
    scm = getattr(inst, "session_collection_method")
    if not isinstance(scm, dict):
        problems.append(_err_value("session_collection_method", "must be dict with keys: name[, type]"))
    else:
        _report_unknown_keys(scm, {"name", "type"}, "session_collection_method", problems)
        name = (scm.get("name") or "").upper()
        if name not in {"GET", "POST"}:
            problems.append(_err_value("session_collection_method.name", "must be 'GET' or 'POST'"))
        if name == "POST":
            t = scm.get("type")
            if t not in {"json", "form"}:
                problems.append(_err_value("session_collection_method.type", "must be 'json' or 'form'"))

    # headers / cookies
    sch = getattr(inst, "session_collection_headers")
    if not _is_dict_str_str(sch):
        problems.append(_err_value("session_collection_headers", "must be dict[str,str]"))

    scc = getattr(inst, "session_collection_cookies")
    if not _is_dict_str_str(scc):
        problems.append(_err_value("session_collection_cookies", "must be dict[str,str]"))

    # data：GET 不要求；POST 要求为 dict
    sc_name = (getattr(inst, "session_collection_method", {}).get("name") or "").upper()
    scd = getattr(inst, "session_collection_data", None)
    if sc_name == "POST":
        if not isinstance(scd, dict):
            problems.append(_err_value("session_collection_data", "must be dict when method is POST"))

    # session_list
    sl = getattr(inst, "session_list")
    if not isinstance(sl, list):
        problems.append(_err_value("session_list", "must be list[dict]"))
    else:
        for i, it in enumerate(sl):
            p = f"session_list[{i}]"
            if not isinstance(it, dict):
                problems.append(_err_value(p, "must be dict"))
                continue

            # 允许的键：id/name/key；其他一律当作“未知字段”（含 session_location）
            allowed = {"session_id", "session_name", "session_key"}
            _report_unknown_keys(it, allowed, p, problems)

            if "session_id" not in it:
                problems.append(_err_missing(f"{p}.session_id"))
            elif not isinstance(it.get("session_id"), int):
                problems.append(_err_value(f"{p}.session_id", "must be int"))

            if "session_name" not in it:
                problems.append(_err_missing(f"{p}.session_name"))
            elif not _is_str(it.get("session_name")):
                problems.append(_err_value(f"{p}.session_name", "must be string (empty allowed)"))

            if "session_key" not in it:
                problems.append(_err_missing(f"{p}.session_key"))
            elif not _str_nonempty(it.get("session_key")):
                problems.append(_err_value(f"{p}.session_key", "must be non-empty string"))

    # ---------------- session_state_check（HTTP） ----------------
    ssc = getattr(inst, "session_state_check")
    if not isinstance(ssc, dict):
        problems.append(_err_value("session_state_check", "must be dict"))
    else:
        allowed_ssc = {
            "session_check_method_name",
            "session_check_method_type",
            "session_check_url",
            "session_check_headers",
            "session_check_cookies",   # 新增
            "session_check_body",
            "session_check_benchmark",
            "session_check_resign",
        }
        _report_unknown_keys(ssc, allowed_ssc, "session_state_check", problems)

        # 必须存在的字段（cookies 也要求存在，但可以为空字典）
        must_exist = [
            "session_check_method_name",
            "session_check_url",
            "session_check_headers",
            "session_check_benchmark",
            "session_check_resign",
        ]
        for f in must_exist:
            if f not in ssc:
                problems.append(_err_missing(f"session_state_check.{f}"))

        mname = (ssc.get("session_check_method_name") or "").upper()
        if mname not in {"GET", "POST"}:
            problems.append(_err_value("session_state_check.session_check_method_name", "must be 'GET' or 'POST'"))

        # URL：非空且必须有 scheme
        if "session_check_url" in ssc:
            url_val = ssc.get("session_check_url", "")
            if not _str_nonempty(url_val):
                problems.append(_err_value("session_state_check.session_check_url", "must be non-empty string"))
            elif not _has_scheme(url_val.strip()):
                problems.append(_err_value("session_state_check.session_check_url", "missing scheme (http/https)"))

        # headers/cookies 类型
        if "session_check_headers" in ssc and not _is_dict_str_str(ssc.get("session_check_headers")):
            problems.append(_err_value("session_state_check.session_check_headers", "must be dict[str,str]"))
        if "session_check_cookies" in ssc and not _is_dict_str_str(ssc.get("session_check_cookies")):
            problems.append(_err_value("session_state_check.session_check_cookies", "must be dict[str,str]"))

        # body & method_type 组合约束
        mtype = ssc.get("session_check_method_type")
        body  = ssc.get("session_check_body", None)

        if mname == "GET":
            # GET：不应有 body；method_type 必须为 None
            if mtype not in (None, "", "None"):
                problems.append(_err_value("session_state_check.session_check_method_type", "must be None for GET"))
            if body not in (None, {}):
                problems.append(_err_value("session_state_check.session_check_body", "must be None/{} for GET"))
        else:  # POST
            if mtype not in {"json", "form"}:
                problems.append(_err_value("session_state_check.session_check_method_type", "must be 'json' or 'form' for POST"))
            if body is not None and not isinstance(body, dict):
                problems.append(_err_value("session_state_check.session_check_body", "must be dict for POST (or None)"))

        # benchmark：仍要求非空字符串
        if "session_check_benchmark" in ssc and not _str_nonempty(ssc.get("session_check_benchmark", "")):
            problems.append(_err_value("session_state_check.session_check_benchmark", "must be non-empty string"))
        # resign 允许 None 或 str（无需额外校验）

    return len(problems) == 0, problems

# ------------------- SIMULATE 严格校验 -------------------
def validate_simulate_strict(inst: Any) -> Tuple[bool, List[Dict[str, str]]]:
    problems: List[Dict[str, str]] = []

    required = [
        "application_name",
        "login_page", "login_check_page",
        "login_check_url", "login_check_benchmark",
        "session_page_items",
    ]
    for f in required:
        if not hasattr(inst, f):
            problems.append(_err_missing(f))
    if problems:
        return False, problems

    if not _str_nonempty(getattr(inst, "application_name")):
        problems.append(_err_value("application_name", "must be non-empty string"))

    for f in ["login_page", "login_check_page", "login_check_url"]:
        if not _str_nonempty(getattr(inst, f)):
            problems.append(_err_value(f, "must be non-empty string"))

    if not _str_nonempty(getattr(inst, "login_check_benchmark")):
        problems.append(_err_value("login_check_benchmark", "must be non-empty string"))

    spi = getattr(inst, "session_page_items")
    if not isinstance(spi, list):
        problems.append(_err_value("session_page_items", "must be list[dict]"))
    else:
        for i, it in enumerate(spi):
            p = f"session_page_items[{i}]"
            if not isinstance(it, dict):
                problems.append(_err_value(p, "must be dict"))
                continue

            # 此层允许的键
            allowed_item = {
                "session_page_name",
                "session_page_url",
                "session_collection_url",
                "session_list",
                "session_state_check",
            }
            _report_unknown_keys(it, allowed_item, p, problems)

            # 三个字段存在即可，其中 page_name/page_url 可为空字符串
            if "session_page_name" not in it:
                problems.append(_err_missing(f"{p}.session_page_name"))
            elif not _is_str(it.get("session_page_name")):
                problems.append(_err_value(f"{p}.session_page_name", "must be string (empty allowed)"))

            if "session_page_url" not in it:
                problems.append(_err_missing(f"{p}.session_page_url"))
            elif not _is_str(it.get("session_page_url")):
                problems.append(_err_value(f"{p}.session_page_url", "must be string (empty allowed)"))

            if "session_collection_url" not in it:
                problems.append(_err_missing(f"{p}.session_collection_url"))
            elif not _str_nonempty(it.get("session_collection_url", "")):
                problems.append(_err_value(f"{p}.session_collection_url", "must be non-empty string"))

            # session_list（未知字段统一拦截）
            sl = it.get("session_list")
            if not isinstance(sl, list):
                problems.append(_err_value(f"{p}.session_list", "must be list[dict]"))
            else:
                for j, si in enumerate(sl):
                    pp = f"{p}.session_list[{j}]"
                    if not isinstance(si, dict):
                        problems.append(_err_value(pp, "must be dict"))
                        continue

                    allowed_si = {"session_id", "session_name", "session_key"}
                    _report_unknown_keys(si, allowed_si, pp, problems)

                    if "session_id" not in si:
                        problems.append(_err_missing(f"{pp}.session_id"))
                    elif not isinstance(si.get("session_id"), int):
                        problems.append(_err_value(f"{pp}.session_id", "must be int"))

                    if "session_name" not in si:
                        problems.append(_err_missing(f"{pp}.session_name"))
                    elif not _is_str(si.get("session_name")):
                        problems.append(_err_value(f"{pp}.session_name", "must be string (empty allowed)"))

                    if "session_key" not in si:
                        problems.append(_err_missing(f"{pp}.session_key"))
                    elif not _str_nonempty(si.get("session_key", "")):
                        problems.append(_err_value(f"{pp}.session_key", "must be non-empty string"))

            # session_state_check（simulate：仍只允许 benchmark + resign）
            ssc = it.get("session_state_check")
            if not isinstance(ssc, dict):
                problems.append(_err_value(f"{p}.session_state_check", "must be dict"))
            else:
                allowed_ssc = {"session_check_benchmark", "session_check_resign"}
                _report_unknown_keys(ssc, allowed_ssc, f"{p}.session_state_check", problems)

                if "session_check_benchmark" not in ssc:
                    problems.append(_err_missing(f"{p}.session_state_check.session_check_benchmark"))
                elif not _str_nonempty(ssc.get("session_check_benchmark", "")):
                    problems.append(_err_value(f"{p}.session_state_check.session_check_benchmark", "must be non-empty string"))

                # resign 必须存在，但值可以为 None 或 str
                if "session_check_resign" not in ssc:
                    problems.append(_err_missing(f"{p}.session_state_check.session_check_resign"))

    return len(problems) == 0, problems