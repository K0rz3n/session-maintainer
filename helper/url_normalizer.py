from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# ====== 配置加载 ======
try:
    from environment.environ import environ
    def _load_url_norm_cfg() -> Dict[str, Any]:
        # 期望格式：
        # URL_NORMALIZER = {
        #   "rules": [
        #     {"host": "example.com", "path": "/login", "keep_keys": ["token", "ts"]},
        #     {"host": "example.com", "path_prefix": "/api/", "keep_keys": ["session_id"]},
        #     {"host": "another.com", "path_regex": "^/v1/resource/[0-9]+$", "keep_keys": ["uid", "sig"]},
        #   ]
        # }
        return environ.get_config("URL_NORMALIZER", default={}) or {}
except Exception:
    def _load_url_norm_cfg() -> Dict[str, Any]:
        return {}

# ====== 规则编译缓存 ======
_COMPILED_RULES: Optional[List[Dict[str, Any]]] = None


def _compile_rules() -> List[Dict[str, Any]]:
    """
    从配置加载并编译 path_regex；保持原有规则顺序，不做任何排序。
    字段：
      - host: str（可选，若提供则必须相等；大小写不敏感；仅比对主机名，忽略端口）
      - path: str（可选，精确匹配；与 path_prefix/path_regex 三选一即可）
      - path_prefix: str（可选，前缀匹配）
      - path_regex: str（可选，正则匹配）
      - keep_keys: List[str]（必选；命中后仅保留这些 query keys；输出顺序严格按 keep_keys）
    """
    cfg = _load_url_norm_cfg()
    raw_rules = cfg.get("rules") or []

    compiled: List[Dict[str, Any]] = []
    for r in raw_rules:
        if not isinstance(r, dict):
            continue

        # keep_keys 必须是非空字符串列表
        keep_keys = [k for k in (r.get("keep_keys") or []) if isinstance(k, str) and k]
        if not keep_keys:
            continue

        rule: Dict[str, Any] = {
            # host 统一小写；如果配置了端口也没关系，比较时仅会用主机名
            "host": (str(r.get("host")).strip().lower() or None) if r.get("host") else None,
            "keep_keys": keep_keys,
        }

        # 统一 path/prefix 去除尾部斜杠，避免“/a/”与“/a”不一致
        if r.get("path"):
            rule["path"] = str(r["path"]).strip().rstrip("/") or "/"
        if r.get("path_prefix"):
            # 前缀也做相同处理；空字符串等价于 "/"
            rule["path_prefix"] = str(r["path_prefix"]).strip().rstrip("/") or "/"

        if r.get("path_regex"):
            try:
                rule["path_regex"] = str(r["path_regex"])
                rule["_path_re"] = re.compile(rule["path_regex"])
            except re.error:
                # 非法正则忽略该条
                continue

        compiled.append(rule)
    return compiled


def _get_rules() -> List[Dict[str, Any]]:
    global _COMPILED_RULES
    # 若想缓存一次，可把下一行改成“如果已有则直接返回”
    _COMPILED_RULES = _compile_rules()
    return _COMPILED_RULES


def _only_hostname(netloc: str) -> str:
    """从 netloc 中提取纯主机名（忽略端口与用户名等）。"""
    # 处理诸如 "user:pass@host:port" 的极端情况：
    host_port = netloc.rsplit("@", 1)[-1]  # 去掉 userinfo
    host = host_port.split(":", 1)[0]
    return host.lower()


def _host_path_match(host: str, path: str, rule: Dict[str, Any]) -> bool:
    """仅判断 host/path 条件是否命中（不检查 keep_keys 存在性）。"""
    r_host = rule.get("host")
    if r_host and r_host.lower() != host.lower():
        return False

    has_any_path_cond = bool(rule.get("path") or rule.get("path_prefix") or rule.get("path_regex"))
    if not has_any_path_cond:
        return True  # 仅 host 条件

    if rule.get("path") and path == rule["path"]:
        return True
    if rule.get("path_prefix") and path.startswith(rule["path_prefix"]):
        return True
    if rule.get("path_regex") and rule.get("_path_re") and rule["_path_re"].match(path):
        return True
    return False


def _all_keep_keys_present(pairs: List[Tuple[str, str]], keep_keys: List[str]) -> bool:
    """检查 URL 中是否包含 keep_keys 的所有键（允许空值）。"""
    keys_in_url = {k for k, _ in pairs}
    return all(k in keys_in_url for k in keep_keys)


def _filter_pairs_in_keep_order(
    pairs: List[Tuple[str, str]],
    keep_keys: List[str],
) -> List[Tuple[str, str]]:
    """
    按 keep_keys 的顺序输出；对每个 key，保留其在原 URL 中出现的所有项（维持该键的出现顺序）。
    """
    out: List[Tuple[str, str]] = []
    for k in keep_keys:
        for kk, vv in pairs:
            if kk == k:
                out.append((kk, vv))
    return out


from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from typing import Optional

def norm_url(u: Optional[str]) -> str:
    """
    规范化 URL：
      1) 提取 scheme/host/path 与 query，忽略 fragment
      2) 对 scheme/host/path：去首尾空白；path 去末尾斜杠（空 path 视作 "/"）
      3) 若无 query：直接返回规范化后的 scheme://host/path（不做规则匹配）
      4) 若有 query：解析参数并按规则顺序匹配（需 host+path 命中且包含全部 keep_keys）：
         - 命中：仅保留 keep_keys（顺序=keep_keys），拼接回规范化后的 URL 并返回
         - 未命中：忽略全部 query，只返回规范化后的 scheme://host/path
    """
    if not u:
        return ""

    raw = u.strip()
    sp = urlsplit(raw)

    # 非完整 URL：保持之前的兼容行为，仅做轻量规范化返回
    if not sp.scheme or not sp.netloc:
        return raw.rstrip("/")

    # 规范化 path
    path_norm = (sp.path or "").rstrip("/") or "/"

    # 无 query：直接返回（不匹配规则），一律清空 fragment
    if not sp.query:
        return urlunsplit((sp.scheme, sp.netloc, path_norm, "", ""))

    # 有 query：解析并尝试规则
    pairs = parse_qsl(sp.query or "", keep_blank_values=True, strict_parsing=False)
    host_for_match = sp.hostname or sp.netloc.split(":", 1)[0]  # 用纯主机名参与规则匹配

    new_query = ""
    for rule in _get_rules():
        if not _host_path_match(host_for_match, path_norm, rule):
            continue
        keep_keys = rule["keep_keys"]
        if not _all_keep_keys_present(pairs, keep_keys):
            # 该条规则要求的 key 不全，继续看下一条
            continue

        # 命中：按 keep_keys 的顺序保留参数（包含重复项，保持原来出现顺序）
        filtered = _filter_pairs_in_keep_order(pairs, keep_keys)
        new_query = urlencode(filtered, doseq=True)
        break  # 第一条满足即停止

    # 命中→带精简后的 query；未命中→忽略 query
    return urlunsplit((sp.scheme, sp.netloc, path_norm, new_query, ""))