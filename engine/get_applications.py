import importlib
import inspect
import logging
import os
from typing import List, Set, Tuple

from environment.environ import environ
from helper.tools import *

logger = logging.getLogger(__name__)


def _require_list(config_key: str, item_key: str) -> List[str]:
    """
    从配置取出列表，并校验必须项：
    - 配置对象必须存在
    - item_key 必须存在
    - 值必须是 list
    否则 raise KeyError / TypeError
    """
    cfg = environ.get_config(config_key)
    if cfg is None:
        raise KeyError(f"Missing config: {config_key}")
    if item_key not in cfg:
        raise KeyError(f"Missing key '{item_key}' in config: {config_key}")
    value = cfg[item_key]
    if not isinstance(value, list):
        raise TypeError(f"Expected list at {config_key}.{item_key}, got {type(value).__name__}")
    return value


class ClassCollector:
    """
    从 modules 目录收集类，支持黑白名单。
    目录结构约定：
        <project>/modules/<module_name>/<file>.py
    """

    def __init__(self, modules_root: str):
        self.modules_root = modules_root

        # ---- 加载并校验配置（缺项即抛异常） ----
        self.module_black: Set[str] = set(_require_list("MODULE_BLACK_LIST", "module_black_list"))
        self.file_black: Set[str] = set(_require_list("FILE_BLACK_LIST", "file_black_list"))
        self.class_black: Set[str] = set(_require_list("CLASS_BLACK_LIST", "class_black_list"))

        self.module_white: Set[str] = set(_require_list("MODULE_WHITE_LIST", "module_white_list"))
        self.file_white: Set[str] = set(_require_list("FILE_WHITE_LIST", "file_white_list"))
        self.class_white: Set[str] = set(_require_list("CLASS_WHITE_LIST", "class_white_list"))

    # ----------------- 主入口 -----------------
    def collect(self) -> List[type]:
        """
        返回筛选后的类对象列表。
        规则：
        1) 先黑后白；黑名单剔除后，再按白名单并集从“剩余集合”里挑选。
        2) 白名单维度互为并集（module ∪ file ∪ class）。
        3) 白名单为空（全空）则意味着“全量允许”（在黑名单剔除之后）。
        """
        all_triplets: List[Tuple[str, str, type]] = []  # (module_name, file_name, class_obj)

        # modules 黑名单剔除
        modules = self._list_modules()
        modules_after_black = [m for m in modules if m not in self.module_black]

    
        for mod in modules_after_black:
            module_dir = os.path.join(self.modules_root, mod)

            # application 黑名单剔除
            app_files = list(iter_py_files(module_dir))
            app_files_after_black = [f for f in app_files if f not in self.file_black]

            # 类黑名单剔除
            for app_name in app_files_after_black:
                dotted = f"modules.{mod}.{app_name[:-3]}"  # 去掉 .py
                try:
                    application = importlib.import_module(dotted)
                except Exception as e:
                    logger.warning("Import failed: %s (%s)", dotted, e)
                    continue

                for _, cls in inspect.getmembers(application, inspect.isclass):
                    # 仅保留定义在当前文件里的类（排除外部导入）
                    if getattr(cls, "__module__", "") != application.__name__:
                        continue
                    if cls.__name__ in self.class_black:
                        continue
                    all_triplets.append((mod, app_name, cls))

        # 4) 白名单并集过滤（如果三者全空 -> 不过滤）
        filtered = self._apply_whitelist_union(all_triplets)

        # 5) 对白名单中找不到的条目给出提示（不报错）
        self._warn_missing_whitelist(modules, all_triplets)

        # 返回类对象列表
        return [cls for _, _, cls in filtered]




    def _list_modules(self) -> List[str]:
        """
        列举 modules 根目录下的子目录名（作为 module 名称）。
        """
        if not os.path.isdir(self.modules_root):
            logger.warning("Modules root not found: %s", self.modules_root)
            return []
        names = []
        for name in os.listdir(self.modules_root):
            path = os.path.join(self.modules_root, name)
            if os.path.isdir(path) and name not in {"__pycache__", ".DS_Store"}:
                names.append(name)
        return names
    


    def _apply_whitelist_union(self, triplets: List[Tuple[str, str, type]]) -> List[Tuple[str, str, type]]:
        """
        白名单并集逻辑：
        - 若任意一个白名单非空，则至少要匹配其中一个维度：
          (module in module_white) or (file in file_white) or (class in class_white)
        - 若全部白名单为空：不再过滤（等价全量允许）。
        """

        # 无白名单设置则不处理
        has_any_white = bool(self.module_white or self.file_white or self.class_white)
        if not has_any_white:
            return triplets

        result = []
        # 任意一个满足白名单，则允许
        for mod, file_name, cls in triplets:
            if (
                (mod in self.module_white)
                or (file_name in self.file_white)
                or (cls.__name__ in self.class_white)
            ):
                result.append((mod, file_name, cls))
        return result

    def _warn_missing_whitelist(self, modules_exist: List[str], triplets: List[Tuple[str, str, type]]) -> None:
        """
        对白名单中不存在的 module/file/class 给出提示。
        不抛异常。
        """
        # 现存集合
        existing_modules = set(modules_exist)
        existing_files = {(m, f) for (m, f, _) in triplets}
        existing_class_names = {cls.__name__ for (_, _, cls) in triplets}

        # module 提示
        for m in self.module_white:
            if m not in existing_modules and m not in self.module_black:
                logger.info("Whitelist module not found after filtering: %s", m)

        # file 提示
        for f in self.file_white:
            found = any(f == ef for (_, ef) in existing_files)
            if not found and f not in self.file_black:
                logger.info("Whitelist file not found after filtering: %s", f)

        # class 提示
        for c in self.class_white:
            if c not in existing_class_names and c not in self.class_black:
                logger.info("Whitelist class not found after filtering: %s", c)


def collect_classes() -> List[type]:
    modules_root = getattr(environ, "module_path", None)
    if not modules_root:
        # 这里是运行期错误，不属于“缺少配置文件选项”，所以给出清晰异常
        raise RuntimeError("environ.module_path is not set.")
    collector = ClassCollector(modules_root)
    return collector.collect()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    classes = collect_classes()
    for c in classes:
        print(f"[OK] {c.__module__}.{c.__name__}")