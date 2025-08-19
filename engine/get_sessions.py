import importlib
from typing import Any, Dict, List, Optional, Iterable, Set

from engine.get_sessions_http import GetCookieItmesHttp
from engine.get_sessions_simulate import GetCookieItmesSimulate
from helper.tools import get_login_callable

class RefreshCookies:
    """
    接收类路径字符串，如 'modules.vulnapp:PersonLogin'，
    动态导入并实例化，然后根据字段选择 simulate(Playwright)/HTTP 两种刷新方式。
    返回值：List[Dict[str, Any]]（富集后的页面结果列表），由调用方负责写库。
    """

    def __init__(self, class_ref: str):
        if ":" not in class_ref:
            raise ValueError(f"Invalid class_ref: {class_ref}. Expect 'module.path:ClassName'")
        mod_name, class_name = class_ref.split(":", 1)

        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            raise ImportError(f"Cannot import module '{mod_name}': {e}") from e

        try:
            cls = getattr(mod, class_name)
        except AttributeError:
            raise ImportError(f"Module '{mod_name}' has no class '{class_name}'")

        try:
            self.target = cls()  # 要求可无参构造
        except Exception as e:
            raise RuntimeError(f"Instantiate '{class_ref}' failed: {e}")

        self.name = f"{mod_name}.{class_name}"

    def refresh(self, session_hashes: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        """
        - 优先走模拟登录（Playwright）：目标类实现 login(page) 且具备 simulate 所需字段
        - 否则走 HTTP：目标类具备 HTTP 所需字段
        - session_hashes: 可选，若提供则只更新这些 hash 对应的配置；不提供则全量
        返回：enriched_pages（List[Dict[str, Any]]）
        """
        # 允许传入任何可迭代，内部转 set 以便 engine 快速判断
        hash_set: Optional[Set[str]] = set(session_hashes) if session_hashes is not None else None

        # -------- Simulate 分支所需字段 --------
        simulate_fields = (
            "application_name",
            "login_page",
            "login_check_page",
            "login_check_url",
            "login_check_benchmark",
            "session_page_items",
        )
        login_fn = get_login_callable(self.target)

        if login_fn:
            missing = [f for f in simulate_fields if not hasattr(self.target, f)]
            if not missing:
                try:
                    enriched_pages = GetCookieItmesSimulate.get_new_cookies(
                        login_fn,
                        self.target.login_page,
                        self.target.login_check_page,
                        self.target.login_check_url,
                        self.target.login_check_benchmark,
                        self.target.session_page_items,
                        application_name=self.target.application_name,  # 必填
                        snippet_filename_hint=getattr(self.target, "snippet_filename_hint", None),
                        headless=bool(getattr(self.target, "headless", False)),
                        session_hashes=hash_set,
                    )
                    return enriched_pages
                except Exception as e:
                    raise RuntimeError(f"<{self.name}> simulate flow failed: {e}") from e
            # 有 login，但字段不全就继续看 HTTP 分支

        # -------- HTTP 分支所需字段（与 simulate 对齐的入参风格）--------
        http_fields = (
            "application_name",
            "session_page_name",
            "session_page_url",
            "session_collection_url",
            "session_collection_method",
            "session_collection_headers",
            "session_collection_cookies",
            "session_collection_data",
            "session_list",
            "session_state_check",
        )
        missing_http = [f for f in http_fields if not hasattr(self.target, f)]
        if not missing_http:
            try:
                enriched_pages = GetCookieItmesHttp.get_new_cookies(
                    application_name=self.target.application_name,
                    session_page_name=self.target.session_page_name,
                    session_page_url=self.target.session_page_url,
                    session_collection_url=self.target.session_collection_url,
                    session_collection_method=self.target.session_collection_method,
                    session_collection_headers=self.target.session_collection_headers,
                    session_collection_cookies=self.target.session_collection_cookies,
                    session_collection_data=self.target.session_collection_data,
                    session_list=self.target.session_list,
                    session_state_check=self.target.session_state_check,
                    session_hashes=hash_set,
                )
                return enriched_pages
            except Exception as e:
                raise RuntimeError(f"<{self.name}> http flow failed: {e}") from e

        # 两个分支都不满足：把缺失项说清楚
        need_sim = ", ".join(simulate_fields)
        need_http = ", ".join(http_fields)
        more = []
        if login_fn and 'missing' in locals() and missing:
            more.append(f"simulate missing: {missing}")
        if missing_http:
            more.append(f"http missing: {missing_http}")
        extra = f" Details: {'; '.join(more)}" if more else ""
        raise ValueError(
            f"<{self.name}> missing required fields. "
            f"Simulate needs: ({need_sim}); HTTP needs: ({need_http}).{extra}"
        )