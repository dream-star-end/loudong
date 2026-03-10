"""Playwright browser wrapper — LLM-friendly interface for page interaction."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class BrowserTool:
    """Wraps Playwright for page navigation, screenshot, DOM extraction, and HAR capture."""

    def __init__(self) -> None:
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    async def launch(self, headless: bool = True) -> None:
        from playwright.async_api import async_playwright

        pw = await async_playwright().start()
        self._browser = await pw.chromium.launch(headless=headless)
        self._context = await self._browser.new_context(
            record_har_path="/tmp/vulnhunter_trace.har"
        )
        self._page = await self._context.new_page()
        logger.info("Browser launched (headless=%s)", headless)

    async def goto(self, url: str) -> str:
        if not self._page:
            await self.launch()
        await self._page.goto(url, wait_until="networkidle")
        return await self._page.title()

    async def screenshot(self, path: str = "/tmp/screenshot.png") -> str:
        if self._page:
            await self._page.screenshot(path=path, full_page=True)
        return path

    async def get_dom(self) -> str:
        if not self._page:
            return ""
        return await self._page.content()

    async def click(self, selector: str) -> None:
        if self._page:
            await self._page.click(selector)

    async def fill(self, selector: str, value: str) -> None:
        if self._page:
            await self._page.fill(selector, value)

    async def close(self) -> None:
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        logger.info("Browser closed")
