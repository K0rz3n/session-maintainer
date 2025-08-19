import atexit
import threading
import time
import asyncio
from contextlib import contextmanager
from typing import Iterator

import logging
from environment.pylogger import pylogger
from playwright.sync_api import sync_playwright, Browser, BrowserContext

logger = logging.getLogger(__name__)


def _schedule_on_browser_loop(browser, coro):
    """
    把协程 coro 投递到 browser 所属的 asyncio loop 上执行。
    失败时返回 False。注意：不要在调用处等待结果（避免 Timeout）。
    """
    impl = getattr(browser, "_impl_obj", None)
    loop = getattr(impl, "_loop", None)
    if impl is None or loop is None or not loop.is_running():
        return False
    try:
        asyncio.run_coroutine_threadsafe(coro, loop)
        return True
    except Exception as e:
        logger.warning("[BrowserHub] schedule on loop failed: %r", e)
        return False


class BrowserHub:
    _instance = None
    _lock = threading.RLock()

    def __init__(self):
        self._pw = None                    # Playwright实例
        self._browser: Browser | None = None
        self._active_contexts = 0
        self._last_release_ts = time.time()
        self._reaper_started = False
        self._owner_thread_id: int | None = None
        self._idle_timeout = 10.0          # 空闲多久自动关浏览器
        atexit.register(self._force_close)

    @classmethod
    def instance(cls) -> "BrowserHub":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    # ---------- 回收线程 ----------
    def _start_reaper_if_needed(self) -> None:
        if self._reaper_started:
            return
        self._reaper_started = True

        def _reaper_loop():
            while True:
                time.sleep(5)
                try:
                    self.maybe_close(idle_timeout=self._idle_timeout)
                except Exception as e:
                    # 避免回收线程死掉
                    logger.debug("[BrowserHub] reaper loop error: %r", e)

        t = threading.Thread(target=_reaper_loop, name="BrowserReaper", daemon=True)
        t.start()
        logger.info("[BrowserHub] reaper started (idle_timeout=%.1fs)", self._idle_timeout)
    # --------------------------------

    def _ensure_started(self) -> None:
        if self._pw is None:
            self._pw = sync_playwright().start()
            logger.info("[BrowserHub] Playwright started.")
        if self._browser is None or self._browser.is_connected() is False:
            self._browser = self._pw.chromium.launch(
                channel="chrome",
                headless=False,
                args=[
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-features=TranslateUI,AutomationControlled",
                    "--enable-features=NetworkService,NetworkServiceInProcess",
                ],
            )
            self._owner_thread_id = threading.get_ident()  # 记录创建Browser的线程
            logger.warning("[BrowserHub] Browser launched (headless=%s).", False)
        self._start_reaper_if_needed()

    def _force_close(self):
        # 进程退出时强制清理（在当前线程，可能不是 owner；尽量别在这里做复杂清理）
        try:
            if self._browser:
                logger.info("[BrowserHub] force closing browser on exit.")
                try:
                    self._browser.close()
                except Exception:
                    pass
        finally:
            self._browser = None
        try:
            if self._pw:
                logger.info("[BrowserHub] stopping Playwright on exit.")
                try:
                    self._pw.stop()
                except Exception:
                    pass
        finally:
            self._pw = None

    def shutdown_now(self) -> None:
        """手动立即关闭 Browser 与 Playwright（尽量在 owner 线程调用）。"""
        with self._lock:
            try:
                if self._browser:
                    logger.info("[BrowserHub] shutdown_now: closing browser.")
                    self._browser.close()
            except Exception as e:
                logger.warning("[BrowserHub] shutdown_now: close browser error: %r", e)
            finally:
                self._browser = None

            try:
                if self._pw:
                    logger.info("[BrowserHub] shutdown_now: stopping Playwright.")
                    self._pw.stop()
            except Exception as e:
                logger.warning("[BrowserHub] shutdown_now: stop playwright error: %r", e)
            finally:
                self._pw = None

    def maybe_close(self, idle_timeout: float = 30.0) -> None:
        """无活动 context 且空闲超过 idle_timeout 秒时关闭 Browser。
        - 若在“拥有者线程”里：同步关闭（最稳）。
        - 若非拥有者线程：尝试投递到 owner loop（fire-and-forget），然后清引用。
        """
        with self._lock:
            browser = self._browser
            if not browser:
                return

            idle_for = time.time() - self._last_release_ts
            if self._active_contexts > 0:
                logger.debug("[BrowserHub] active_contexts=%d, keep browser.", self._active_contexts)
                return
            if idle_for < idle_timeout:
                logger.debug("[BrowserHub] idle %.1fs < %.1fs, keep browser.", idle_for, idle_timeout)
                return

            logger.info("[BrowserHub] idle %.1fs >= %.1fs → closing browser.", idle_for, idle_timeout)

            try:
                owner_tid = self._owner_thread_id
                this_tid = threading.get_ident()

                # 1) 同线程：直接同步关闭（最快、最干净）
                if owner_tid and owner_tid == this_tid:
                    try:
                        browser.close()
                        logger.warning("[BrowserHub] browser closed in owner thread.")
                    except Exception as e:
                        logger.warning("[BrowserHub] close() error in owner thread: %r", e)
                else:
                    # 2) 跨线程：把真正的关闭动作投递到 browser 的事件循环（不等待结果）
                    async def _close_on_owner_loop():
                        try:
                            impl = getattr(browser, "_impl_obj", None)
                            if impl is not None:
                                await impl.close()
                            else:
                                try:
                                    browser.close()
                                except Exception:
                                    pass
                        except Exception as e:
                            logger.warning("[BrowserHub] impl.close error on loop: %r", e)

                    scheduled = _schedule_on_browser_loop(browser, _close_on_owner_loop())
                    if scheduled:
                        logger.info("[BrowserHub] scheduled close on owner loop (fire-and-forget).")
                    else:
                        logger.warning("[BrowserHub] owner loop not available; skip active close (GC will reap).")

            finally:
                # 清理本地引用；下次用会自动重建
                self._browser = None
                # 保留 _pw 以便下次更快启动；stop 留给 atexit 或显式 shutdown_now()

    @contextmanager
    def context(self, **kw) -> Iterator[BrowserContext]:
        with self._lock:
            self._ensure_started()
            self._active_contexts += 1
            logger.info("[BrowserHub] new context (+1) → active=%d", self._active_contexts)

        ctx = self._browser.new_context(
            viewport=None,
            locale=kw.get("locale", "zh-CN"),
            timezone_id=kw.get("timezone_id", "Asia/Shanghai"),
            permissions=list(kw.get("permissions", ("geolocation",))),
            java_script_enabled=kw.get("java_script_enabled", True),
            ignore_https_errors=kw.get("ignore_https_errors", True),
            bypass_csp=True,
            service_workers="allow",
        )
        try:
            yield ctx
        finally:
            try:
                ctx.close()
                logger.info("[BrowserHub] context closed.")
            except Exception as e:
                logger.warning("[BrowserHub] close context error: %r", e)

            # 先在锁里更新计数与时间戳
            must_try_close_now = False
            with self._lock:
                self._active_contexts = max(0, self._active_contexts - 1)
                logger.info("[BrowserHub] context released (-1) → active=%d", self._active_contexts)
                if self._active_contexts == 0:
                    self._last_release_ts = time.time()
                    # ★ 刚好归零：在“当前（拥有者）线程”的安全点立即回收
                    must_try_close_now = True

            # 锁外调用，避免重入死锁；idle_timeout=0 表示“马上关”
            if must_try_close_now:
                self.maybe_close(idle_timeout=0)