# helper/human.py
from __future__ import annotations

import logging
import platform
import random
import time
from typing import Optional

from playwright.sync_api import Page, Locator

logger = logging.getLogger(__name__)

# 可选 stealth：存在则应用，不存在则跳过
try:
    from playwright_stealth import stealth_sync
    _HAS_STEALTH = True
except Exception:
    _HAS_STEALTH = False


def apply_stealth(page: Page) -> None:
    """
    尝试对页面应用 stealth；若未安装 playwright-stealth，则静默跳过。
    """
    if not _HAS_STEALTH:
        logger.debug("playwright-stealth not installed; skip stealth.")
        return
    try:
        stealth_sync(page)
        logger.info("playwright-stealth enabled.")
    except Exception:
        logger.debug("apply_stealth failed; skip.")


class HumanPage:
    """
    将常用的人类化交互封装，避免业务代码直接操作 Page。
    """
    def __init__(self, page: Page):
        self.page = page
        self.is_mac = platform.system() == "Darwin"

    @staticmethod
    def _sleep_ms(a=60, b=140):
        time.sleep(random.uniform(a, b) / 1000.0)

    @staticmethod
    def _rand_point_in_box(box: dict):
        x = box["x"] + random.uniform(0.18, 0.82) * box["width"]
        y = box["y"] + random.uniform(0.30, 0.72) * box["height"]
        return x, y

    def _ensure_locator(self, target: Locator | str) -> Locator:
        return target if isinstance(target, Locator) else self.page.locator(str(target))

    def _mouse_curve_move(self, to_x: float, to_y: float, steps: Optional[int] = None):
        if steps is None:
            steps = random.randint(12, 24)
        sx = random.uniform(5, 60)
        sy = random.uniform(5, 40)
        cx = (sx + to_x) / 2 + random.uniform(-80, 80)
        cy = (sy + to_y) / 2 + random.uniform(-40, 40)
        for i in range(1, steps + 1):
            t = i / steps
            x = (1 - t)**2 * sx + 2 * (1 - t) * t * cx + t**2 * to_x
            y = (1 - t)**2 * sy + 2 * (1 - t) * t * cy + t**2 * to_y
            x += random.uniform(-0.8, 0.8)
            y += random.uniform(-0.6, 0.6)
            self.page.mouse.move(x, y)
            self._sleep_ms(5, 16)

    def pause(self, a_ms: int = 120, b_ms: int = 420):
        self.page.wait_for_timeout(random.randint(a_ms, b_ms))

    def focus_and_clear(self, target: Locator | str):
        loc = self._ensure_locator(target)
        loc.wait_for(state="visible", timeout=10000)
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        self.click(loc)
        self.page.keyboard.press("Meta+A" if self.is_mac else "Control+A")
        self._sleep_ms(40, 90)
        self.page.keyboard.press("Backspace")
        self._sleep_ms(80, 150)

    def type(self, target: Locator | str, text: str, *, per_key=(35, 85), typo_prob=0.02, secret=False):
        loc = self._ensure_locator(target)
        loc.wait_for(state="visible", timeout=10000)
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        self.focus_and_clear(loc)

        for ch in text:
            if not secret and random.random() < typo_prob and ch.isalnum():
                wrong = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                self.page.keyboard.type(wrong, delay=random.randint(*per_key))
                self._sleep_ms(40, 90)
                self.page.keyboard.press("Backspace")
                self._sleep_ms(20, 60)

            self.page.keyboard.type(ch, delay=random.randint(*per_key))
            if random.random() < 0.12:
                self._sleep_ms(120, 260)
        self._sleep_ms(120, 240)

    def click(self, target: Locator | str):
        page = self.page
        loc = self._ensure_locator(target)
        loc.wait_for(state="visible", timeout=10000)
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        box = loc.bounding_box()
        if not box:
            loc.hover()
            self._sleep_ms(60, 140)
            loc.click(delay=random.randint(30, 80))
            return
        x, y = self._rand_point_in_box(box)
        self._mouse_curve_move(x, y)
        self._sleep_ms(60, 140)
        page.mouse.down()
        self._sleep_ms(30, 70)
        page.mouse.up()
        self._sleep_ms(50, 120)

    def hover(self, target: Locator | str):
        loc = self._ensure_locator(target)
        try:
            loc.scroll_into_view_if_needed(timeout=5000)
        except Exception:
            pass
        box = loc.bounding_box()
        if box:
            x, y = self._rand_point_in_box(box)
            self._mouse_curve_move(x, y)
        else:
            loc.hover()
        self._sleep_ms(80, 180)


def attach_human(page: Page) -> None:
    """
    给 Page 动态挂载 .human，便于业务侧随取随用：
        page.human.click("button")
        page.human.type("#user", "abc")
    """
    try:
        page.human = HumanPage(page)
    except Exception:
        pass