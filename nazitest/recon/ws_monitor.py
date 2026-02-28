"""WebSocket frame capture — records WS sent/received frames."""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class WSFrame(BaseModel):
    """A single WebSocket frame."""

    timestamp: float
    direction: str  # "sent" or "received"
    url: str
    data: str
    opcode: int = 1  # 1=text, 2=binary


class WSSession(BaseModel):
    """All frames for a single WebSocket connection."""

    url: str
    frames: list[WSFrame] = Field(default_factory=list)
    opened_at: float = 0.0
    closed_at: float | None = None


class WSMonitor:
    """Captures WebSocket frames from CDP events."""

    def __init__(self) -> None:
        self._sessions: dict[str, WSSession] = {}

    def on_ws_created(self, request_id: str, url: str) -> None:
        """Called when a WebSocket connection is opened."""
        self._sessions[request_id] = WSSession(url=url, opened_at=time.time())

    def on_ws_frame_sent(self, request_id: str, data: str, opcode: int = 1) -> None:
        """Called when a WebSocket frame is sent."""
        session = self._sessions.get(request_id)
        if not session:
            return
        session.frames.append(
            WSFrame(
                timestamp=time.time(),
                direction="sent",
                url=session.url,
                data=data,
                opcode=opcode,
            )
        )

    def on_ws_frame_received(self, request_id: str, data: str, opcode: int = 1) -> None:
        """Called when a WebSocket frame is received."""
        session = self._sessions.get(request_id)
        if not session:
            return
        session.frames.append(
            WSFrame(
                timestamp=time.time(),
                direction="received",
                url=session.url,
                data=data,
                opcode=opcode,
            )
        )

    def on_ws_closed(self, request_id: str) -> None:
        session = self._sessions.get(request_id)
        if session:
            session.closed_at = time.time()

    def get_all_sessions(self) -> list[WSSession]:
        return list(self._sessions.values())

    def get_all_frames(self) -> list[WSFrame]:
        frames = []
        for session in self._sessions.values():
            frames.extend(session.frames)
        return sorted(frames, key=lambda f: f.timestamp)

    def clear(self) -> None:
        self._sessions.clear()
