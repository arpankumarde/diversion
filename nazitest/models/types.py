"""Enums, base types, and common fields shared across all modules."""

from __future__ import annotations

from enum import Enum


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OrchestratorPhase(str, Enum):
    INIT = "init"
    AUTHORIZE = "authorize"
    CRAWL = "crawl"
    RECORD = "record"
    MODEL = "model"
    REASON = "reason"
    EXPLOIT = "exploit"
    REPORT = "report"
    DONE = "done"


class CrawlPhase(str, Enum):
    PASSIVE_OBSERVATION = "passive_observation"
    SITEMAP_DISCOVERY = "sitemap_discovery"
    LINK_EXTRACTION = "link_extraction"
    API_DISCOVERY = "api_discovery"
    AUTH_FLOW_MAPPING = "auth_flow_mapping"
    INPUT_ENUMERATION = "input_enumeration"
    ERROR_PROVOCATION = "error_provocation"


class ArtifactType(str, Enum):
    HAR = "har"
    DOM_SNAPSHOT = "dom_snapshot"
    SCREENSHOT = "screenshot"
    COOKIE_JAR = "cookie_jar"
    WEBSOCKET_LOG = "websocket_log"
    SITE_MAP = "site_map"
    TECH_STACK = "tech_stack"
    KNOWLEDGE_GRAPH = "knowledge_graph"
    HYPOTHESIS = "hypothesis"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    EXPLOIT_RESULT = "exploit_result"
    POC = "poc"
    REPORT = "report"
    CONFIG = "config"
    AUTHORIZATION = "authorization"
    LLM_SESSION = "llm_session"


class NodeType(str, Enum):
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_MECHANISM = "auth_mechanism"
    AUTH_SCOPE = "auth_scope"
    DATA_FLOW = "data_flow"
    TECHNOLOGY = "technology"
    SECURITY_CTRL = "security_ctrl"
    VULNERABILITY = "vulnerability"
    EVIDENCE = "evidence"
    CODE_HANDLER = "code_handler"
    COOKIE = "cookie"
    API_PATTERN = "api_pattern"


class EdgeType(str, Enum):
    ACCEPTS_INPUT = "accepts_input"
    AUTHENTICATED_BY = "authenticated_by"
    REQUIRES_SCOPE = "requires_scope"
    DATA_FLOWS_TO = "data_flows_to"
    PROTECTED_BY = "protected_by"
    MAY_HAVE_VULN = "may_have_vuln"
    SUPPORTED_BY = "supported_by"
    HANDLED_BY = "handled_by"
    SETS_COOKIE = "sets_cookie"
    USES_COOKIE = "uses_cookie"
    ESCALATES_TO = "escalates_to"


class AuthType(str, Enum):
    JWT = "jwt"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    BASIC = "basic"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"
    NONE = "none"


class ExploitMethod(str, Enum):
    CURL_CFFI = "curl_cffi"
    BROWSER_REPLAY = "browser_replay"
    COMBINED = "combined"


class EncodingType(str, Enum):
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENCODE = "html_encode"
    HEX_ENCODE = "hex_encode"
    MIXED_CASE = "mixed_case"
    RAW = "raw"


class DeliveryMethod(str, Enum):
    QUERY_PARAM = "query_param"
    PATH_SEGMENT = "path_segment"
    POST_BODY_JSON = "post_body_json"
    POST_BODY_FORM = "post_body_form"
    HEADER_INJECTION = "header_injection"
    COOKIE_INJECTION = "cookie_injection"
    FRAGMENT = "fragment"


class ProxyProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class RotationStrategy(str, Enum):
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    GEO_TARGETED = "geo_targeted"
