# environment/pylogger.py
import logging
import os
from logging.handlers import RotatingFileHandler  # noqa: F401  (兼容旧引用)
from concurrent_log_handler import ConcurrentRotatingFileHandler

try:
    import colorlog
    HAS_COLORLOG = True
except Exception:
    HAS_COLORLOG = False

from environment.environ import environ


class Pylogger:
    _configured = False   # 进程内幂等保护

    @classmethod
    def get_logger(cls, level: str | None = None) -> logging.Logger:
        """
        统一初始化 logging。幂等：重复调用不会叠加 handler。
        level: 可传 "DEBUG"/"INFO"/"WARNING"/"ERROR"/"CRITICAL"，不传则读 env/config。
        """
        if cls._configured:
            return logging.getLogger()  # root

        # ---- 1) 计算日志等级（优先级：参数 > 环境变量 > 配置文件 > 默认INFO） ----
        try:
            cfg = environ.get_config("LOGGING", default={}) or {}
        except (KeyError, LookupError, FileNotFoundError):
            cfg = {}
        lvl_name = (level or os.getenv("LOG_LEVEL") or cfg.get("level", "INFO")).upper()
        lvl = getattr(logging, lvl_name, logging.INFO)

        # Dramatiq 专用级别（由 launcher 传入到各子进程环境变量）
        dramatiq_lvl_name = (os.getenv("DRAMATIQ_LOG_LEVEL") or "WARNING").upper()
        if dramatiq_lvl_name == "WARN":
            dramatiq_lvl_name = "WARNING"
        dramatiq_lvl = getattr(logging, dramatiq_lvl_name, logging.WARNING)

        # ---- 2) 清理已有 handler，避免重复打印 ----
        root = logging.getLogger()
        for h in list(root.handlers):
            root.removeHandler(h)

        if HAS_COLORLOG:
            log_colors_config = {
                "DEBUG":    "light_white",       # 等级名称颜色
                "INFO":     "light_green",
                "WARNING":  "light_yellow",
                "ERROR":    "light_red",
                "CRITICAL": "bold_red",
            }

            # 为 message 定义 "浅色" 对应表
            secondary_log_colors = {
                "message": {
                    "DEBUG":    "thin_white",   # 浅灰白
                    "INFO":     "green",  # 浅绿
                    "WARNING":  "yellow", # 浅黄
                    "ERROR":    "red",    # 浅红
                    "CRITICAL": "bold_red",     # 高亮红
                }
            }

            console_fmt = colorlog.ColoredFormatter(
                "%(cyan)s%(asctime)s%(reset)s "            # 时间戳 = 青色
                "%(white)s%(filename)s[line:%(lineno)d]%(reset)s - "  # 文件名+行号 = 浅灰
                "%(log_color)s%(levelname)-8s%(reset)s: " # 日志等级 = 彩色
                "%(message_log_color)s%(message)s",       # 消息 = 使用 secondary_log_colors
                log_colors=log_colors_config,
                secondary_log_colors=secondary_log_colors,
                style="%"
            )
            ch = colorlog.StreamHandler()
            ch.setFormatter(console_fmt)
        else:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter(
                "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
            ))
        ch.setLevel(lvl)

        # ---- 4) 文件 handler（滚动）----
        log_dir = environ.log_path
        os.makedirs(log_dir, exist_ok=True)
        fh = ConcurrentRotatingFileHandler(
            os.path.join(environ.log_path, "autologin.log"),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s"
        ))
        fh.setLevel(lvl)

        # ---- 5) 绑定到 root ----
        root.addHandler(ch)
        root.addHandler(fh)
        root.setLevel(lvl)

        # ---- 6) 降低第三方噪音（集中在这里）----
        # Dramatiq：我们用 --skip-logging 启动 CLI 后，完全由本处接管日志级别
        for name in (
            "dramatiq",
            "dramatiq.MainProcess",
            "dramatiq.ForkProcess",
            "dramatiq.WorkerProcess",
            "dramatiq.PIDFile",
            "dramatiq.broker",
            "dramatiq.middleware",
            "dramatiq.middleware.prometheus",
        ):
            logging.getLogger(name).setLevel(dramatiq_lvl)

        # 其它第三方库（按需微调）
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("playwright").setLevel(logging.INFO)     # 采集期偶尔需要 INFO
        logging.getLogger("pika").setLevel(logging.CRITICAL)

        cls._configured = True
        return root


# 推荐：仅暴露 root 的简便引用
pylogger = Pylogger.get_logger()