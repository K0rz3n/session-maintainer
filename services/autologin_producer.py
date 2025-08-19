# 仅包含生产者（扫描配置类并派发任务）

# -*- coding: utf-8 -*-
import importlib
import logging
from typing import Type, List, Optional, Set, Tuple
from engine.get_applications import collect_classes
from helper.tools import get_login_callable, compute_session_hash, iter_urls_for_instance
from services.task_actors import update_simulate, update_http, on_success, on_failure

# 新增导入严格校验器
from helper.config_validator import (
    validate_http_strict, validate_simulate_strict, summarize_problems
)


logger = logging.getLogger(__name__)

_SIM_FIELDS = (
    "application_name", "login_page", "login_check_page", "login_check_url",
    "login_check_benchmark", "session_page_items",
)
_HTTP_FIELDS = (
    "application_name", "session_page_name", "session_page_url",
    "session_collection_url", "session_collection_method",
    "session_collection_headers", "session_collection_cookies",
    "session_collection_data", "session_list",
)

def _detect_queue_for_class(mod_name: str, class_name: str) -> Tuple[str | None, str]:
    try:
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, class_name)
        inst = cls()
    except Exception as e:
        return None, f"import/instantiate failed: {e!r}"

    login_fn = get_login_callable(inst)

    if login_fn:
        # 只验证 simulate
        ok, probs = validate_simulate_strict(inst)
        if ok:
            return "simulate", "simulate branch"
        return None, "simulate invalid:\n" + summarize_problems("  - ", probs)

    # 否则只验证 http
    ok, probs = validate_http_strict(inst)
    if ok:
        return "http", "http branch"
    return None, "http invalid:\n" + summarize_problems("  - ", probs)

def _hashes_for_class(inst) -> Set[str]:
    out: Set[str] = set()
    app = getattr(inst, "application_name", None)
    if not isinstance(app, str) or not app:
        return out
    for _mode, url in iter_urls_for_instance(inst):
        try:
            out.add(compute_session_hash(app, url))
        except Exception:
            continue
    return out




def start(
    session_hashes: Optional[Set[str]] = None,
    *,
    classes: Optional[List[Type]] = None,
) -> None:
    # 如果外部没传，就自己收集；外部传了就直接用
    classes = classes or collect_classes()
    logger.info(f"collected {len(classes)} classes from modules")

    sent = skipped = 0
    filter_on = isinstance(session_hashes, set) and len(session_hashes) > 0

    for cls in classes:
        mod_name, class_name = cls.__module__, cls.__name__
        class_ref = f"{mod_name}:{class_name}"
        queue, reason = _detect_queue_for_class(mod_name, class_name)

        if queue is None:
            skipped += 1
            logger.error(f"Skip {class_ref}: {reason}")
            continue

        hashes_to_send: Optional[List[str]] = None
        if filter_on:
            try:
                inst = cls()
                inter = _hashes_for_class(inst) & session_hashes
            except Exception as e:
                skipped += 1
                logger.error(f"Skip {class_ref}: instantiate/hash failed: {e!r}")
                continue

            if not inter:
                skipped += 1  # ← 关键：被 session_hash 过滤掉的也计入 skipped
                logger.warning(f"Skip {class_ref}: no intersecting session_hashes")
                continue

            hashes_to_send = sorted(inter)

        try:
            if queue == "simulate":
                if hashes_to_send is None:
                    update_simulate.send_with_options(
                        args=(class_ref,),
                        on_success=on_success,
                        on_failure=on_failure,
                    )
                else:
                    update_simulate.send_with_options(
                        args=(class_ref, hashes_to_send),
                        on_success=on_success,
                        on_failure=on_failure,
                    )
            else:
                if hashes_to_send is None:
                    update_http.send_with_options(
                        args=(class_ref,),
                        on_success=on_success,
                        on_failure=on_failure,
                    )
                else:
                    update_http.send_with_options(
                        args=(class_ref, hashes_to_send),
                        on_success=on_success,
                        on_failure=on_failure,
                    )
            sent += 1
            extra = f" with {len(hashes_to_send)} hashes" if hashes_to_send is not None else ""
            logger.info(f"Enqueued {class_ref} → {queue} ({reason}){extra}")
        except Exception as e:
            skipped += 1
            logger.error(f"Enqueue failed: {class_ref}: {e}")

    logger.warning(f"Tasks sent done. sent={sent}, skipped={skipped}, total={len(classes)}")