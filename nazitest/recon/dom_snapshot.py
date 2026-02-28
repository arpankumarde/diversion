"""DOM snapshot — captures rendered HTML, forms, links, scripts, storage."""

from __future__ import annotations

import hashlib
import logging
import time

from bs4 import BeautifulSoup

from nazitest.models.recon import CookieInfo, DOMSnapshot, FormData, FormInput, ScriptInfo

logger = logging.getLogger(__name__)


class DOMSnapshotCapture:
    """Captures a full DOM snapshot from rendered page HTML + browser state."""

    def capture(
        self,
        url: str,
        html: str,
        local_storage: dict[str, str] | None = None,
        session_storage: dict[str, str] | None = None,
        cookies: list[dict] | None = None,
        console_logs: list[str] | None = None,
    ) -> DOMSnapshot:
        """Parse rendered HTML and extract forms, links, scripts, meta."""
        soup = BeautifulSoup(html, "lxml")

        forms = self._extract_forms(soup)
        links = self._extract_links(soup)
        scripts = self._extract_scripts(soup)
        meta = self._extract_meta(soup)

        cookie_infos = []
        for c in cookies or []:
            cookie_infos.append(
                CookieInfo(
                    name=c.get("name", ""),
                    value=c.get("value", ""),
                    domain=c.get("domain", ""),
                    path=c.get("path", "/"),
                    http_only=c.get("httpOnly", False),
                    secure=c.get("secure", False),
                    same_site=c.get("sameSite", ""),
                )
            )

        return DOMSnapshot(
            url=url,
            timestamp=time.time(),
            html=html,
            forms=forms,
            links=links,
            scripts=scripts,
            meta=meta,
            local_storage=local_storage or {},
            session_storage=session_storage or {},
            cookies=cookie_infos,
            console_logs=console_logs or [],
        )

    def _extract_forms(self, soup: BeautifulSoup) -> list[FormData]:
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append(
                    FormInput(
                        name=inp.get("name", ""),
                        input_type=inp.get("type", "text"),
                        value=inp.get("value", ""),
                        required=inp.has_attr("required"),
                        placeholder=inp.get("placeholder", ""),
                    )
                )
            forms.append(
                FormData(
                    action=form.get("action", ""),
                    method=form.get("method", "GET").upper(),
                    inputs=inputs,
                    id=form.get("id", ""),
                    name=form.get("name", ""),
                )
            )
        return forms

    def _extract_links(self, soup: BeautifulSoup) -> list[str]:
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                links.append(href)
        return list(dict.fromkeys(links))  # Deduplicate preserving order

    def _extract_scripts(self, soup: BeautifulSoup) -> list[ScriptInfo]:
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            content = script.string or ""
            content_hash = hashlib.sha256(content.encode()).hexdigest()[:16] if content else ""
            scripts.append(
                ScriptInfo(
                    src=src,
                    inline=not bool(src),
                    content_hash=content_hash,
                    sri=script.get("integrity", ""),
                    type=script.get("type", ""),
                )
            )
        return scripts

    def _extract_meta(self, soup: BeautifulSoup) -> dict[str, str]:
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("http-equiv") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                meta[name] = content
        return meta
