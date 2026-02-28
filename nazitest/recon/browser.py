"""Browser controller — Zendriver CDP wrapper for browser lifecycle + event subscription."""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any, Callable, Coroutine

import zendriver as zd
from zendriver.cdp import network as cdp_network
from zendriver.cdp import page as cdp_page
from zendriver.cdp.network import Cookie as CdpCookie

from nazitest.recon.har_recorder import HARRecorder

logger = logging.getLogger(__name__)

# Type for CDP event handlers
EventHandler = Callable[..., Coroutine[Any, Any, None]]


class BrowserController:
    """Manages Chrome via CDP. Launches browser, navigates, exposes event subscription.

    DRY: All recon recorders subscribe to this controller's CDP events
    instead of each managing their own browser connection.
    """

    def __init__(
        self,
        headless: bool = True,
        proxy_url: str | None = None,
        chrome_path: str | None = None,
    ) -> None:
        self.headless = headless
        self.proxy_url = proxy_url
        self.chrome_path = chrome_path
        self._browser: zd.Browser | None = None
        self._page: zd.Tab | None = None

    async def start(self) -> None:
        """Launch the browser."""
        config = zd.Config()
        if self.headless:
            config.headless = True
        config.sandbox = False
        config.browser_connection_timeout = 2
        config.browser_connection_max_tries = 10
        if self.proxy_url:
            config.add_argument(f"--proxy-server={self.proxy_url}")

        self._browser = await zd.start(config)
        try:
            self._page = await self._browser.get("about:blank")
        except Exception:
            await self.stop()
            raise
        logger.info("Browser started")

    async def stop(self) -> None:
        """Close the browser."""
        if self._browser:
            try:
                await self._browser.stop()
            except Exception:
                pass
            self._browser = None
            self._page = None
            logger.info("Browser stopped")

    @property
    def page(self) -> zd.Tab:
        if self._page is None:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._page

    @property
    def browser(self) -> zd.Browser:
        if self._browser is None:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._browser

    async def navigate(self, url: str) -> None:
        """Navigate to a URL and wait for the page to settle."""
        await self.page.get(url)
        # Give the page time to load dynamic content
        await asyncio.sleep(2)

    async def new_tab(self, url: str = "about:blank") -> zd.Tab:
        """Open a new tab."""
        tab = await self.browser.get(url)
        return tab

    async def screenshot(self) -> bytes:
        """Take a screenshot of the current page as PNG bytes."""
        b64_data = await self.page.screenshot_b64()
        return base64.b64decode(b64_data)

    async def evaluate(self, expression: str) -> Any:
        """Execute JavaScript in the page context."""
        return await self.page.evaluate(expression)

    async def get_cookies(self) -> list[dict[str, Any]]:
        """Get ALL cookies via CDP (including HttpOnly)."""
        try:
            cdp_cookies: list[CdpCookie] = await self.page.send(
                cdp_network.get_all_cookies()
            )
            result = []
            for c in cdp_cookies:
                result.append({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "expires": c.expires if c.expires else -1,
                    "size": c.size,
                    "httpOnly": c.http_only,
                    "secure": c.secure,
                    "session": c.session,
                    "sameSite": str(c.same_site) if c.same_site else "",
                })
            logger.info("CDP get_all_cookies: %d cookies", len(result))
            return result
        except Exception as e:
            logger.warning("CDP cookie fetch failed, falling back to JS: %s", e)
            # Fallback to JS (won't get HttpOnly but better than nothing)
            return await self.page.evaluate(
                """() => {
                    return document.cookie.split(';').map(c => {
                        const [name, ...rest] = c.trim().split('=');
                        return {name: name, value: rest.join('=')};
                    }).filter(c => c.name);
                }"""
            )

    async def get_local_storage(self) -> dict[str, str]:
        """Extract localStorage contents."""
        return await self.page.get_local_storage()

    async def get_session_storage(self) -> dict[str, str]:
        """Extract sessionStorage contents."""
        return await self.page.evaluate(
            """() => {
                const items = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return items;
            }"""
        )

    async def get_page_html(self) -> str:
        """Get the rendered HTML of the current page."""
        return await self.page.get_content()

    async def get_page_url(self) -> str:
        """Get the current page URL."""
        return self.page.url or ""

    # --- CDP event-driven capture ---

    async def enable_network_capture(self, har_recorder: HARRecorder) -> None:
        """Subscribe to CDP Network events and feed them to a HARRecorder."""
        tab = self.page

        async def on_request(event: cdp_network.RequestWillBeSent) -> None:
            req = event.request
            headers = dict(req.headers) if req.headers else {}
            # Content-Type lives in the request headers, not PostDataEntry
            post_mime = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    post_mime = v
                    break
            har_recorder.record_request(
                request_id=str(event.request_id),
                request_data={
                    "method": req.method,
                    "url": req.url,
                    "headers": headers,
                    "postData": req.post_data or "",
                    "postDataMimeType": post_mime,
                },
            )

        async def on_response(event: cdp_network.ResponseReceived) -> None:
            resp = event.response
            har_recorder.record_response(
                request_id=str(event.request_id),
                response_data={
                    "status": resp.status,
                    "statusText": resp.status_text,
                    "headers": dict(resp.headers) if resp.headers else {},
                    "mimeType": resp.mime_type,
                    "remoteIPAddress": resp.remote_ip_address or "",
                },
            )

        tab.add_handler(cdp_network.RequestWillBeSent, on_request)
        tab.add_handler(cdp_network.ResponseReceived, on_response)
        logger.info("Network capture enabled")

    async def enable_page_tracking(
        self, on_load_callback: Callable[[], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Subscribe to Page.LoadEventFired, track navigated URLs."""
        self._tracked_urls: list[str] = []
        tab = self.page

        async def on_page_load(event: cdp_page.LoadEventFired) -> None:
            url = tab.url or ""
            if url and url != "about:blank":
                if url not in self._tracked_urls:
                    self._tracked_urls.append(url)
                logger.info("Page loaded: %s", url)
                if on_load_callback:
                    await on_load_callback()

        tab.add_handler(cdp_page.LoadEventFired, on_page_load)
        logger.info("Page tracking enabled")

    def get_all_tab_urls(self) -> list[str]:
        """Return all URLs the user has visited (tracked from page load events)."""
        return list(getattr(self, "_tracked_urls", []))

    async def __aenter__(self) -> BrowserController:
        await self.start()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.stop()
