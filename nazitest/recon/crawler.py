"""Multi-phase crawl orchestrator — coordinates browser, recorders, and scope."""

from __future__ import annotations

import asyncio
import logging

from nazitest.core.scope import ScopeEnforcer
from nazitest.models.recon import SiteMap
from nazitest.models.types import ArtifactType, CrawlPhase
from nazitest.recon.browser import BrowserController
from nazitest.recon.cookie_jar import CookieJarAnalyzer
from nazitest.recon.dom_snapshot import DOMSnapshotCapture
from nazitest.recon.har_recorder import HARRecorder
from nazitest.recon.sitemap import SiteMapBuilder
from nazitest.recon.ws_monitor import WSMonitor
from nazitest.storage.artifact_store import ArtifactStore

logger = logging.getLogger(__name__)


class Crawler:
    """Multi-phase crawl strategy matching PRD section 5.1.

    Phases: passive → discovery → link following → API discovery →
            auth flow → input enum → error provocation.
    """

    def __init__(
        self,
        browser: BrowserController,
        scope: ScopeEnforcer,
        store: ArtifactStore,
        max_depth: int = 5,
        max_pages: int = 200,
    ) -> None:
        self.browser = browser
        self.scope = scope
        self.store = store
        self.max_depth = max_depth
        self.max_pages = max_pages

        # Shared recorders (DRY: all use the same browser session)
        self.har_recorder = HARRecorder()
        self.dom_capture = DOMSnapshotCapture()
        self.cookie_jar = CookieJarAnalyzer()
        self.ws_monitor = WSMonitor()
        self.sitemap_builder = SiteMapBuilder()

        self._visited: set[str] = set()
        self._queue: list[str] = []
        self._current_phase = CrawlPhase.PASSIVE_OBSERVATION

    @property
    def pages_visited(self) -> int:
        return len(self._visited)

    async def crawl(self, start_url: str) -> SiteMap:
        """Execute the full multi-phase crawl."""
        self._queue = [start_url]

        # Phase 1: Passive observation — visit the start URL
        self._current_phase = CrawlPhase.PASSIVE_OBSERVATION
        await self._visit_page(start_url)

        # Phase 2: Sitemap discovery
        self._current_phase = CrawlPhase.SITEMAP_DISCOVERY
        await self._discover_sitemaps(start_url)

        # Phase 3: Link extraction — follow discovered links
        self._current_phase = CrawlPhase.LINK_EXTRACTION
        await self._follow_links()

        # Phase 4: API discovery — analyze collected HAR for API patterns
        self._current_phase = CrawlPhase.API_DISCOVERY
        # API discovery happens implicitly through HAR analysis

        # Save artifacts
        self._save_artifacts()

        return self.sitemap_builder.build()

    async def _visit_page(self, url: str) -> None:
        """Visit a single page and capture all data."""
        if url in self._visited:
            return
        if self.pages_visited >= self.max_pages:
            return
        if not self.scope.is_in_scope(url):
            logger.debug("Skipping out-of-scope URL: %s", url)
            return

        self._visited.add(url)
        logger.info("[%s] Visiting: %s", self._current_phase.value, url)

        try:
            await self.browser.navigate(url)

            # Capture DOM snapshot
            html = await self.browser.get_page_html()
            cookies = await self.browser.get_cookies()
            local_storage = await self.browser.get_local_storage()
            session_storage = await self.browser.get_session_storage()

            snapshot = self.dom_capture.capture(
                url=url,
                html=html,
                local_storage=local_storage,
                session_storage=session_storage,
                cookies=cookies,
            )

            # Save DOM snapshot
            self.store.save(ArtifactType.DOM_SNAPSHOT, snapshot, name=self._url_slug(url))

            # Save screenshot
            try:
                screenshot_data = await self.browser.screenshot()
                self.store.save(
                    ArtifactType.SCREENSHOT, screenshot_data, name=self._url_slug(url)
                )
            except Exception as e:
                logger.warning("Screenshot failed for %s: %s", url, e)

            # Add cookies to jar
            self.cookie_jar.add_from_cdp(cookies)

            # Add links to sitemap and queue
            self.sitemap_builder.add_from_dom_links(snapshot.links, url)
            for link in snapshot.links:
                if link.startswith("/"):
                    from urllib.parse import urlparse

                    parsed = urlparse(url)
                    full = f"{parsed.scheme}://{parsed.netloc}{link}"
                    if full not in self._visited and self.scope.is_in_scope(full):
                        self._queue.append(full)
                elif link.startswith("http") and link not in self._visited:
                    if self.scope.is_in_scope(link):
                        self._queue.append(link)

        except Exception as e:
            logger.error("Error visiting %s: %s", url, e)

    async def _discover_sitemaps(self, start_url: str) -> None:
        """Try to discover robots.txt and sitemap.xml."""
        from urllib.parse import urlparse

        parsed = urlparse(start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ["/robots.txt", "/sitemap.xml"]:
            url = base + path
            if self.scope.is_in_scope(url):
                try:
                    await self._visit_page(url)
                except Exception:
                    pass

    async def _follow_links(self) -> None:
        """Visit queued links up to max_pages."""
        while self._queue and self.pages_visited < self.max_pages:
            url = self._queue.pop(0)
            await self._visit_page(url)
            # Small delay to avoid hammering
            await asyncio.sleep(0.5)

    def _save_artifacts(self) -> None:
        """Save accumulated artifacts."""
        # Save HAR
        if self.har_recorder.entry_count > 0:
            har_file = self.har_recorder.to_har_file()
            self.store.save(ArtifactType.HAR, har_file, name="crawl")

        # Save cookie jar
        cookies = self.cookie_jar.get_all()
        if cookies:
            cookie_data = [c.model_dump(mode="json") for c in cookies]
            self.store.save(ArtifactType.COOKIE_JAR, {"cookies": cookie_data})

        # Save sitemap
        sitemap = self.sitemap_builder.build()
        self.store.save(ArtifactType.SITE_MAP, sitemap)

        # Save WebSocket sessions
        ws_sessions = self.ws_monitor.get_all_sessions()
        for session in ws_sessions:
            self.store.save(
                ArtifactType.WEBSOCKET_LOG,
                session,
                name=self._url_slug(session.url),
            )

    @staticmethod
    def _url_slug(url: str) -> str:
        """Create a filesystem-safe slug from a URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path.strip("/").replace("/", "_") or "index"
        return path[:80]
