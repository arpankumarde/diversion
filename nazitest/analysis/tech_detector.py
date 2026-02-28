"""Technology fingerprinting from headers, scripts, and meta tags."""

from __future__ import annotations

import re

from nazitest.models.recon import TechStack

# Header-based detection patterns
HEADER_SIGNATURES: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "servers": [
        ("Nginx", re.compile(r"nginx", re.I)),
        ("Apache", re.compile(r"apache", re.I)),
        ("IIS", re.compile(r"microsoft-iis", re.I)),
        ("Cloudflare", re.compile(r"cloudflare", re.I)),
        ("Express", re.compile(r"express", re.I)),
    ],
    "frameworks": [
        ("ASP.NET", re.compile(r"x-aspnet-version|x-powered-by:.*asp\.net", re.I)),
        ("PHP", re.compile(r"x-powered-by:.*php", re.I)),
        ("Django", re.compile(r"csrftoken|django", re.I)),
        ("Rails", re.compile(r"x-powered-by:.*phusion|_rails_session", re.I)),
        ("Spring", re.compile(r"x-application-context", re.I)),
    ],
    "cdns": [
        ("Cloudflare", re.compile(r"cf-ray|cf-cache-status", re.I)),
        ("Akamai", re.compile(r"x-akamai", re.I)),
        ("CloudFront", re.compile(r"x-amz-cf", re.I)),
        ("Fastly", re.compile(r"x-served-by.*cache", re.I)),
    ],
}

# Script source pattern detection
SCRIPT_SIGNATURES: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "frameworks": [
        ("React", re.compile(r"react|__NEXT_DATA__|_next/", re.I)),
        ("Vue.js", re.compile(r"vue\.js|vue\.min\.js|__vue__", re.I)),
        ("Angular", re.compile(r"angular|ng-version", re.I)),
        ("jQuery", re.compile(r"jquery", re.I)),
        ("Next.js", re.compile(r"_next/static|__NEXT_DATA__", re.I)),
        ("Nuxt.js", re.compile(r"_nuxt/|__NUXT__", re.I)),
        ("Svelte", re.compile(r"svelte", re.I)),
    ],
    "analytics": [
        ("Google Analytics", re.compile(r"google-analytics|gtag|ga\.js|analytics\.js", re.I)),
        ("Hotjar", re.compile(r"hotjar", re.I)),
        ("Segment", re.compile(r"segment\.com|analytics\.js", re.I)),
        ("Mixpanel", re.compile(r"mixpanel", re.I)),
    ],
    "security": [
        ("reCAPTCHA", re.compile(r"recaptcha", re.I)),
        ("hCaptcha", re.compile(r"hcaptcha", re.I)),
        ("Cloudflare Turnstile", re.compile(r"turnstile", re.I)),
        ("DataDome", re.compile(r"datadome", re.I)),
    ],
}


class TechDetector:
    """Fingerprints technologies from HTTP headers, scripts, and meta tags."""

    def detect(
        self,
        response_headers: dict[str, str] | None = None,
        script_sources: list[str] | None = None,
        html_content: str = "",
        meta_tags: dict[str, str] | None = None,
    ) -> TechStack:
        stack = TechStack()

        if response_headers:
            self._detect_from_headers(stack, response_headers)
        if script_sources:
            self._detect_from_scripts(stack, script_sources)
        if html_content:
            self._detect_from_html(stack, html_content)
        if meta_tags:
            self._detect_from_meta(stack, meta_tags)

        # Deduplicate
        stack.frameworks = list(dict.fromkeys(stack.frameworks))
        stack.servers = list(dict.fromkeys(stack.servers))
        stack.cdns = list(dict.fromkeys(stack.cdns))
        stack.analytics = list(dict.fromkeys(stack.analytics))
        stack.security = list(dict.fromkeys(stack.security))

        return stack

    def _detect_from_headers(self, stack: TechStack, headers: dict[str, str]) -> None:
        # Combine all headers into a searchable string
        header_str = " ".join(f"{k}:{v}" for k, v in headers.items())

        for category, patterns in HEADER_SIGNATURES.items():
            target_list = getattr(stack, category)
            for name, pattern in patterns:
                if pattern.search(header_str):
                    target_list.append(name)

    def _detect_from_scripts(self, stack: TechStack, sources: list[str]) -> None:
        combined = " ".join(sources)
        for category, patterns in SCRIPT_SIGNATURES.items():
            target_list = getattr(stack, category)
            for name, pattern in patterns:
                if pattern.search(combined):
                    target_list.append(name)

    def _detect_from_html(self, stack: TechStack, html: str) -> None:
        # Check for framework-specific HTML patterns
        for name, pattern in SCRIPT_SIGNATURES.get("frameworks", []):
            if pattern.search(html):
                if name not in stack.frameworks:
                    stack.frameworks.append(name)

        for name, pattern in SCRIPT_SIGNATURES.get("security", []):
            if pattern.search(html):
                if name not in stack.security:
                    stack.security.append(name)

    def _detect_from_meta(self, stack: TechStack, meta: dict[str, str]) -> None:
        generator = meta.get("generator", "")
        if generator:
            if "wordpress" in generator.lower():
                stack.cms.append("WordPress")
            elif "drupal" in generator.lower():
                stack.cms.append("Drupal")
            elif "joomla" in generator.lower():
                stack.cms.append("Joomla")
            else:
                stack.other.append(f"Generator: {generator}")
