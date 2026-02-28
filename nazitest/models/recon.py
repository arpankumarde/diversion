"""Recon data models — DOM snapshots, site maps, endpoints, cookies."""

from __future__ import annotations

from pydantic import BaseModel, Field

from nazitest.models.types import AuthType, HttpMethod


class FormInput(BaseModel):
    name: str
    input_type: str = "text"
    value: str = ""
    required: bool = False
    placeholder: str = ""


class FormData(BaseModel):
    action: str = ""
    method: str = "GET"
    inputs: list[FormInput] = Field(default_factory=list)
    id: str = ""
    name: str = ""


class ScriptInfo(BaseModel):
    src: str = ""
    inline: bool = False
    content_hash: str = ""
    sri: str = ""
    type: str = ""


class CookieInfo(BaseModel):
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    expires: str = ""
    http_only: bool = False
    secure: bool = False
    same_site: str = ""
    size: int = 0


class DOMSnapshot(BaseModel):
    """Captured state of a rendered page."""

    url: str
    timestamp: float
    html: str = ""
    forms: list[FormData] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    scripts: list[ScriptInfo] = Field(default_factory=list)
    meta: dict[str, str] = Field(default_factory=dict)
    local_storage: dict[str, str] = Field(default_factory=dict)
    session_storage: dict[str, str] = Field(default_factory=dict)
    cookies: list[CookieInfo] = Field(default_factory=list)
    console_logs: list[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """A discovered URL endpoint."""

    url: str
    method: HttpMethod = HttpMethod.GET
    status_code: int | None = None
    content_type: str = ""
    params: list[str] = Field(default_factory=list)
    requires_auth: bool = False
    auth_type: AuthType = AuthType.NONE
    discovered_via: str = ""  # "har", "dom", "sitemap", etc.


class APIRoute(BaseModel):
    """An XHR/fetch API pattern."""

    url_pattern: str
    methods: list[HttpMethod] = Field(default_factory=list)
    request_content_type: str = ""
    response_content_type: str = ""
    params: list[str] = Field(default_factory=list)
    requires_auth: bool = False


class AuthFlow(BaseModel):
    """A login/register/reset authentication sequence."""

    flow_type: str  # "login", "register", "password_reset", "oauth"
    steps: list[str] = Field(default_factory=list)
    endpoint: str = ""
    auth_type: AuthType = AuthType.NONE


class StaticAsset(BaseModel):
    url: str
    asset_type: str = ""  # "js", "css", "image", "font"
    content_hash: str = ""
    size: int = 0


class TechStack(BaseModel):
    """Detected technology stack."""

    frameworks: list[str] = Field(default_factory=list)
    servers: list[str] = Field(default_factory=list)
    cdns: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    cms: list[str] = Field(default_factory=list)
    analytics: list[str] = Field(default_factory=list)
    security: list[str] = Field(default_factory=list)
    other: list[str] = Field(default_factory=list)


class SecurityHeaders(BaseModel):
    """Per-page security header analysis."""

    csp: str = ""
    x_frame_options: str = ""
    x_content_type_options: str = ""
    strict_transport_security: str = ""
    x_xss_protection: str = ""
    referrer_policy: str = ""
    permissions_policy: str = ""
    cors_allow_origin: str = ""
    cors_allow_methods: str = ""
    cors_allow_headers: str = ""


class WebSocketEndpoint(BaseModel):
    url: str
    message_patterns: list[str] = Field(default_factory=list)


class SiteMap(BaseModel):
    """Aggregated site intelligence."""

    endpoints: list[Endpoint] = Field(default_factory=list)
    api_routes: list[APIRoute] = Field(default_factory=list)
    auth_flows: list[AuthFlow] = Field(default_factory=list)
    static_assets: list[StaticAsset] = Field(default_factory=list)
    technologies: TechStack = Field(default_factory=TechStack)
    security_headers: dict[str, SecurityHeaders] = Field(default_factory=dict)
    websocket_endpoints: list[WebSocketEndpoint] = Field(default_factory=list)
