"""Tests for recon engine — HAR recorder, DOM snapshot, cookies, WS, sitemap."""

from nazitest.recon.cookie_jar import CookieJarAnalyzer
from nazitest.recon.dom_snapshot import DOMSnapshotCapture
from nazitest.recon.har_recorder import HARRecorder
from nazitest.recon.sitemap import SiteMapBuilder
from nazitest.recon.ws_monitor import WSMonitor


class TestHARRecorder:
    def test_record_request_response(self) -> None:
        rec = HARRecorder()
        rec.record_request("req1", {
            "url": "https://example.com/api/users?page=1",
            "method": "GET",
            "headers": {"Accept": "application/json"},
        })
        rec.record_response("req1", {
            "status": 200,
            "statusText": "OK",
            "headers": {"Content-Type": "application/json"},
            "mimeType": "application/json",
        }, body='[{"id": 1}]')

        assert rec.entry_count == 1
        har = rec.to_har_file()
        entry = har.log.entries[0]
        assert entry.request.method == "GET"
        assert entry.response.status == 200
        assert entry.response.content.text == '[{"id": 1}]'

    def test_query_string_parsing(self) -> None:
        rec = HARRecorder()
        rec.record_request("req1", {
            "url": "https://example.com/search?q=test&page=2",
            "method": "GET",
            "headers": {},
        })
        rec.record_response("req1", {"status": 200, "headers": {}})

        har = rec.to_har_file()
        qs = har.log.entries[0].request.query_string
        assert len(qs) == 2
        assert qs[0].name == "q"
        assert qs[0].value == "test"

    def test_orphaned_response_ignored(self) -> None:
        rec = HARRecorder()
        rec.record_response("unknown", {"status": 200, "headers": {}})
        assert rec.entry_count == 0

    def test_clear(self) -> None:
        rec = HARRecorder()
        rec.record_request("req1", {"url": "https://example.com", "method": "GET", "headers": {}})
        rec.record_response("req1", {"status": 200, "headers": {}})
        assert rec.entry_count == 1
        rec.clear()
        assert rec.entry_count == 0


SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta name="description" content="Test page">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
    <script src="/static/app.js" integrity="sha384-abc"></script>
    <script>console.log('inline');</script>
</head>
<body>
    <a href="/about">About</a>
    <a href="/login">Login</a>
    <a href="https://external.com/link">External</a>
    <a href="#section">Anchor</a>
    <a href="javascript:void(0)">JS Link</a>
    <form action="/login" method="POST" id="loginForm">
        <input name="username" type="text" required placeholder="Username">
        <input name="password" type="password" required>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""


class TestDOMSnapshot:
    def test_extract_links(self) -> None:
        capture = DOMSnapshotCapture()
        snap = capture.capture(url="https://example.com", html=SAMPLE_HTML)
        # Should include /about, /login, external; exclude #, javascript:
        assert "/about" in snap.links
        assert "/login" in snap.links
        assert "https://external.com/link" in snap.links
        assert "#section" not in snap.links

    def test_extract_forms(self) -> None:
        capture = DOMSnapshotCapture()
        snap = capture.capture(url="https://example.com", html=SAMPLE_HTML)
        assert len(snap.forms) == 1
        form = snap.forms[0]
        assert form.action == "/login"
        assert form.method == "POST"
        assert len(form.inputs) == 3
        assert form.inputs[0].name == "username"
        assert form.inputs[0].required is True

    def test_extract_scripts(self) -> None:
        capture = DOMSnapshotCapture()
        snap = capture.capture(url="https://example.com", html=SAMPLE_HTML)
        assert len(snap.scripts) == 2
        external = [s for s in snap.scripts if not s.inline][0]
        assert external.src == "/static/app.js"
        assert external.sri == "sha384-abc"
        inline = [s for s in snap.scripts if s.inline][0]
        assert inline.content_hash != ""

    def test_extract_meta(self) -> None:
        capture = DOMSnapshotCapture()
        snap = capture.capture(url="https://example.com", html=SAMPLE_HTML)
        assert snap.meta.get("description") == "Test page"
        assert "default-src" in snap.meta.get("Content-Security-Policy", "")

    def test_cookies_and_storage(self) -> None:
        capture = DOMSnapshotCapture()
        snap = capture.capture(
            url="https://example.com",
            html="<html></html>",
            local_storage={"key": "value"},
            session_storage={"session": "data"},
            cookies=[{"name": "sid", "value": "abc123", "httpOnly": True}],
        )
        assert snap.local_storage == {"key": "value"}
        assert snap.session_storage == {"session": "data"}
        assert len(snap.cookies) == 1
        assert snap.cookies[0].http_only is True


class TestCookieJar:
    def test_add_from_cdp(self) -> None:
        jar = CookieJarAnalyzer()
        jar.add_from_cdp([
            {"name": "session_id", "value": "abc", "domain": ".example.com",
             "httpOnly": True, "secure": True, "sameSite": "Lax"},
            {"name": "prefs", "value": "dark", "domain": ".example.com"},
        ])
        cookies = jar.get_all()
        assert len(cookies) == 2

    def test_add_from_headers(self) -> None:
        jar = CookieJarAnalyzer()
        jar.add_from_headers([
            "session=xyz; HttpOnly; Secure; SameSite=Strict; Path=/; Domain=.example.com",
            "theme=light; Path=/",
        ], domain="example.com")
        cookies = jar.get_all()
        assert len(cookies) == 2
        session = [c for c in cookies if c.name == "session"][0]
        assert session.http_only is True
        assert session.secure is True
        assert session.same_site == "strict"

    def test_security_issues(self) -> None:
        jar = CookieJarAnalyzer()
        jar.add_from_cdp([
            {"name": "session_token", "value": "abc", "httpOnly": False,
             "secure": False, "sameSite": ""},
        ])
        issues = jar.get_security_issues()
        # Should flag: missing HttpOnly on session cookie, missing Secure, SameSite not set
        issue_types = [i["issue"] for i in issues]
        assert any("HttpOnly" in i for i in issue_types)
        assert any("Secure" in i for i in issue_types)


class TestWSMonitor:
    def test_record_frames(self) -> None:
        mon = WSMonitor()
        mon.on_ws_created("ws1", "wss://example.com/ws")
        mon.on_ws_frame_sent("ws1", '{"type": "ping"}')
        mon.on_ws_frame_received("ws1", '{"type": "pong"}')
        mon.on_ws_closed("ws1")

        sessions = mon.get_all_sessions()
        assert len(sessions) == 1
        assert len(sessions[0].frames) == 2
        assert sessions[0].frames[0].direction == "sent"
        assert sessions[0].frames[1].direction == "received"
        assert sessions[0].closed_at is not None

    def test_multiple_sessions(self) -> None:
        mon = WSMonitor()
        mon.on_ws_created("ws1", "wss://example.com/ws1")
        mon.on_ws_created("ws2", "wss://example.com/ws2")
        mon.on_ws_frame_sent("ws1", "msg1")
        mon.on_ws_frame_sent("ws2", "msg2")

        frames = mon.get_all_frames()
        assert len(frames) == 2

    def test_orphaned_frame_ignored(self) -> None:
        mon = WSMonitor()
        mon.on_ws_frame_sent("unknown", "data")
        assert len(mon.get_all_frames()) == 0


class TestSiteMapBuilder:
    def test_add_from_har(self) -> None:
        builder = SiteMapBuilder()
        builder.add_from_har_entry(
            request={
                "url": "https://example.com/api/users?page=1",
                "method": "GET",
                "headers": {"Authorization": "Bearer eyJ.eyJ.sig"},
            },
            response={
                "status": 200,
                "mimeType": "application/json",
                "headers": {"Content-Type": "application/json"},
            },
        )
        sitemap = builder.build()
        assert len(sitemap.endpoints) == 1
        assert sitemap.endpoints[0].requires_auth is True
        assert len(sitemap.api_routes) == 1

    def test_add_from_dom_links(self) -> None:
        builder = SiteMapBuilder()
        builder.add_from_dom_links(
            ["/about", "/contact", "/api/v1/health"],
            base_url="https://example.com",
        )
        sitemap = builder.build()
        assert len(sitemap.endpoints) == 3

    def test_security_headers_extraction(self) -> None:
        builder = SiteMapBuilder()
        builder.add_from_har_entry(
            request={"url": "https://example.com/", "method": "GET", "headers": {}},
            response={
                "status": 200,
                "headers": {
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Frame-Options": "DENY",
                    "Strict-Transport-Security": "max-age=31536000",
                },
                "mimeType": "text/html",
            },
        )
        sitemap = builder.build()
        headers = sitemap.security_headers.get("https://example.com/")
        assert headers is not None
        assert headers.csp == "default-src 'self'"
        assert headers.x_frame_options == "DENY"

    def test_dedup_endpoints(self) -> None:
        builder = SiteMapBuilder()
        for _ in range(3):
            builder.add_from_har_entry(
                request={"url": "https://example.com/api/users", "method": "GET", "headers": {}},
                response={"status": 200, "headers": {}, "mimeType": "application/json"},
            )
        sitemap = builder.build()
        assert len(sitemap.endpoints) == 1

    def test_auth_detection_jwt(self) -> None:
        builder = SiteMapBuilder()
        builder.add_from_har_entry(
            request={
                "url": "https://example.com/api/me",
                "method": "GET",
                "headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"},
            },
            response={"status": 200, "headers": {}, "mimeType": "application/json"},
        )
        sitemap = builder.build()
        from nazitest.models.types import AuthType
        assert sitemap.endpoints[0].auth_type == AuthType.JWT

    def test_auth_detection_basic(self) -> None:
        builder = SiteMapBuilder()
        builder.add_from_har_entry(
            request={
                "url": "https://example.com/api/data",
                "method": "GET",
                "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
            },
            response={"status": 200, "headers": {}, "mimeType": "application/json"},
        )
        sitemap = builder.build()
        from nazitest.models.types import AuthType
        assert sitemap.endpoints[0].auth_type == AuthType.BASIC
