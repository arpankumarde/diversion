"""BrightData web research wrapper — provides web_search and web_scrape tools for LLM agents."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

try:
    from brightdata import BrightDataClient
except ImportError:
    BrightDataClient = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

MAX_SCRAPE_CHARS = 15_000


@dataclass
class SearchResult:
    """A single search engine result."""

    title: str
    url: str
    description: str


@dataclass
class WebResearcher:
    """BrightData-backed web research for LLM tool-use.

    Provides search and scrape with in-memory caching and content truncation.
    """

    api_key: str
    _client: BrightDataClient | None = field(default=None, repr=False)
    _cache: dict[str, str] = field(default_factory=dict)
    _search_cache: dict[str, list[SearchResult]] = field(default_factory=dict)

    async def _get_client(self) -> BrightDataClient:
        if self._client is None:
            client = BrightDataClient(token=self.api_key, validate_token=False)
            self._client = await client.__aenter__()
        return self._client

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Search via BrightData SERP API. Results are cached per query."""
        if query in self._search_cache:
            logger.debug("Search cache hit: %s", query)
            return self._search_cache[query]

        logger.info("Web search: %s", query)
        client = await self._get_client()
        try:
            result = await client.search.google(
                query=query,
                num_results=num_results,
            )
            results = []
            items = result.data if hasattr(result, "data") else result
            if isinstance(items, list):
                for item in items[:num_results]:
                    if isinstance(item, dict):
                        results.append(SearchResult(
                            title=item.get("title", ""),
                            url=item.get("url", item.get("link", "")),
                            description=item.get("description", item.get("snippet", "")),
                        ))
            self._search_cache[query] = results
            logger.info("Search returned %d results for: %s", len(results), query)
            return results
        except Exception as e:
            logger.warning("Web search failed for '%s': %s", query, e)
            return []

    async def scrape(self, url: str) -> str:
        """Scrape a URL via BrightData. Content is cached and truncated."""
        if url in self._cache:
            logger.debug("Scrape cache hit: %s", url)
            return self._cache[url]

        logger.info("Web scrape: %s", url)
        client = await self._get_client()
        try:
            result = await client.scrape_url(url=url)
            content = result.data if hasattr(result, "data") else str(result)
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            content = str(content)

            # Truncate to protect LLM context
            if len(content) > MAX_SCRAPE_CHARS:
                content = content[:MAX_SCRAPE_CHARS] + "\n\n[... truncated ...]"

            self._cache[url] = content
            logger.info("Scraped %d chars from: %s", len(content), url)
            return content
        except Exception as e:
            logger.warning("Web scrape failed for '%s': %s", url, e)
            return f"Error scraping {url}: {e}"

    async def close(self) -> None:
        """Close the underlying BrightData client."""
        if self._client is not None:
            try:
                await self._client.__aexit__(None, None, None)
            except Exception:
                pass
            self._client = None


# --- Tool schemas (OpenAI-compatible function calling format) ---

WEB_SEARCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Search the web for information about vulnerabilities, CVEs, "
            "exploit techniques, bypass methods, and security research. "
            "Returns search results with titles, URLs, and descriptions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search query. Be specific — include technology names, "
                        "CVE IDs, vulnerability types, or tool names."
                    ),
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return (default 10, max 20).",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
}

WEB_SCRAPE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_scrape",
        "description": (
            "Scrape the content of a specific web page. Use this to read "
            "vulnerability databases, payload lists (PayloadsAllTheThings, "
            "HackTricks), CVE details, or exploit documentation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to scrape.",
                },
            },
            "required": ["url"],
            "additionalProperties": False,
        },
    },
}

ALL_TOOLS: list[dict[str, Any]] = [WEB_SEARCH_TOOL, WEB_SCRAPE_TOOL]


async def execute_tool_call(
    researcher: WebResearcher,
    tool_name: str,
    arguments: dict[str, Any],
) -> str:
    """Execute a tool call and return the result as a string for the LLM."""
    if tool_name == "web_search":
        query = arguments.get("query", "")
        num_results = min(arguments.get("num_results", 10), 20)
        results = await researcher.search(query, num_results=num_results)
        if not results:
            return "No results found."
        lines = []
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r.title}\n   URL: {r.url}\n   {r.description}")
        return "\n\n".join(lines)

    elif tool_name == "web_scrape":
        url = arguments.get("url", "")
        if not url:
            return "Error: no URL provided."
        return await researcher.scrape(url)

    else:
        return f"Unknown tool: {tool_name}"
