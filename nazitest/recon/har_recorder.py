"""HAR recording — captures CDP Network events into W3C HAR 1.2 format."""

from __future__ import annotations

import logging
import time

from nazitest.models.har import (
    HARContent,
    HAREntry,
    HARFile,
    HARHeader,
    HARLog,
    HARPostData,
    HARQueryParam,
    HARRequest,
    HARResponse,
    HARTiming,
)

logger = logging.getLogger(__name__)


class HARRecorder:
    """Builds HAR entries from captured network data.

    Designed to work with raw request/response dicts from CDP Network events.
    """

    def __init__(self) -> None:
        self._entries: list[HAREntry] = []
        self._pending_requests: dict[str, dict] = {}

    def record_request(self, request_id: str, request_data: dict) -> None:
        """Record an outgoing request (from Network.requestWillBeSent)."""
        self._pending_requests[request_id] = {
            "request": request_data,
            "timestamp": time.time(),
        }

    def record_response(
        self, request_id: str, response_data: dict, body: str = ""
    ) -> None:
        """Record a response (from Network.responseReceived + getResponseBody)."""
        pending = self._pending_requests.pop(request_id, None)
        if not pending:
            return

        req_data = pending["request"]
        start_time = pending["timestamp"]

        # Build HAR request
        headers = [
            HARHeader(name=k, value=v)
            for k, v in req_data.get("headers", {}).items()
        ]

        query_string = []
        url = req_data.get("url", "")
        if "?" in url:
            qs = url.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query_string.append(HARQueryParam(name=k, value=v))

        post_data = None
        if req_data.get("postData"):
            post_data = HARPostData(
                mimeType=req_data.get("postDataMimeType", ""),
                text=req_data.get("postData", ""),
            )

        har_request = HARRequest(
            method=req_data.get("method", "GET"),
            url=url,
            headers=headers,
            queryString=query_string,
            postData=post_data,
        )

        # Build HAR response
        resp_headers = [
            HARHeader(name=k, value=v)
            for k, v in response_data.get("headers", {}).items()
        ]

        content = HARContent(
            size=len(body.encode()) if body else 0,
            mimeType=response_data.get("mimeType", ""),
            text=body,
        )

        har_response = HARResponse(
            status=response_data.get("status", 0),
            statusText=response_data.get("statusText", ""),
            headers=resp_headers,
            content=content,
        )

        elapsed = time.time() - start_time
        timing = HARTiming(wait=elapsed * 1000)

        entry = HAREntry(
            startedDateTime=time.strftime(
                "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(start_time)
            ),
            request=har_request,
            response=har_response,
            timings=timing,
            time=elapsed * 1000,
            serverIPAddress=response_data.get("remoteIPAddress", ""),
        )

        self._entries.append(entry)

    def to_har_file(self) -> HARFile:
        """Build the complete HAR file."""
        return HARFile(log=HARLog(entries=list(self._entries)))

    def clear(self) -> None:
        """Reset the recorder for a new recording session."""
        self._entries.clear()
        self._pending_requests.clear()

    @property
    def entry_count(self) -> int:
        return len(self._entries)
