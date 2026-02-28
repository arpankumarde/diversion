"""HAR (HTTP Archive) format models — W3C HAR 1.2 spec."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HARHeader(BaseModel):
    name: str
    value: str


class HARCookie(BaseModel):
    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    expires: str | None = None
    http_only: bool = False
    secure: bool = False
    same_site: str | None = None


class HARQueryParam(BaseModel):
    name: str
    value: str


class HARPostData(BaseModel):
    mime_type: str = Field(alias="mimeType", default="")
    text: str = ""
    params: list[HARQueryParam] = Field(default_factory=list)


class HARRequest(BaseModel):
    method: str
    url: str
    http_version: str = Field(alias="httpVersion", default="HTTP/1.1")
    headers: list[HARHeader] = Field(default_factory=list)
    cookies: list[HARCookie] = Field(default_factory=list)
    query_string: list[HARQueryParam] = Field(alias="queryString", default_factory=list)
    post_data: HARPostData | None = Field(alias="postData", default=None)
    headers_size: int = Field(alias="headersSize", default=-1)
    body_size: int = Field(alias="bodySize", default=-1)

    model_config = {"populate_by_name": True}


class HARContent(BaseModel):
    size: int = 0
    compression: int | None = None
    mime_type: str = Field(alias="mimeType", default="")
    text: str = ""

    model_config = {"populate_by_name": True}


class HARResponse(BaseModel):
    status: int
    status_text: str = Field(alias="statusText", default="")
    http_version: str = Field(alias="httpVersion", default="HTTP/1.1")
    headers: list[HARHeader] = Field(default_factory=list)
    cookies: list[HARCookie] = Field(default_factory=list)
    content: HARContent = Field(default_factory=HARContent)
    redirect_url: str = Field(alias="redirectURL", default="")
    headers_size: int = Field(alias="headersSize", default=-1)
    body_size: int = Field(alias="bodySize", default=-1)

    model_config = {"populate_by_name": True}


class HARTiming(BaseModel):
    dns: float = -1
    connect: float = -1
    ssl: float = -1
    send: float = 0
    wait: float = 0
    receive: float = 0


class HAREntry(BaseModel):
    started_date_time: str = Field(alias="startedDateTime", default="")
    request: HARRequest
    response: HARResponse
    timings: HARTiming = Field(default_factory=HARTiming)
    server_ip_address: str = Field(alias="serverIPAddress", default="")
    connection: str = ""
    time: float = 0

    model_config = {"populate_by_name": True}


class HARCreator(BaseModel):
    name: str = "nazitest"
    version: str = "0.1.0"


class HARLog(BaseModel):
    version: str = "1.2"
    creator: HARCreator = Field(default_factory=HARCreator)
    entries: list[HAREntry] = Field(default_factory=list)


class HARFile(BaseModel):
    """Top-level HAR file wrapper."""

    log: HARLog = Field(default_factory=HARLog)
