"""Tests for core — scope enforcement, auth gate, proxy manager."""

import tempfile
from pathlib import Path

import orjson

from nazitest.models.config import ProxyConfig, ProxyEntry, ScopeConfig
from nazitest.models.types import ProxyProtocol, RotationStrategy
from nazitest.core.auth_gate import AuthorizationGate
from nazitest.core.scope import ScopeEnforcer
from nazitest.proxy.manager import ProxyManager


class TestScopeEnforcer:
    def _enforcer(self, **kwargs: object) -> ScopeEnforcer:
        defaults = {"target_url": "https://example.com", "allowed_domains": ["example.com"]}
        defaults.update(kwargs)
        return ScopeEnforcer(ScopeConfig(**defaults))  # type: ignore[arg-type]

    def test_in_scope_exact(self) -> None:
        se = self._enforcer()
        assert se.is_in_scope("https://example.com/api/users")
        assert se.is_in_scope("https://example.com/")
        assert se.is_in_scope("http://example.com/path")

    def test_subdomain_in_scope(self) -> None:
        se = self._enforcer()
        assert se.is_in_scope("https://api.example.com/v1")
        assert se.is_in_scope("https://www.example.com/login")

    def test_subdomain_excluded_when_disabled(self) -> None:
        se = self._enforcer(include_subdomains=False)
        assert not se.is_in_scope("https://api.example.com/v1")
        assert se.is_in_scope("https://example.com/v1")

    def test_out_of_scope_domain(self) -> None:
        se = self._enforcer()
        assert not se.is_in_scope("https://evil.com/steal")
        assert not se.is_in_scope("https://notexample.com/")

    def test_out_of_scope_protocol(self) -> None:
        se = self._enforcer()
        assert not se.is_in_scope("ftp://example.com/file")
        assert not se.is_in_scope("javascript:alert(1)")

    def test_excluded_paths(self) -> None:
        se = self._enforcer(excluded_paths=["/admin", "/internal"])
        assert not se.is_in_scope("https://example.com/admin/users")
        assert not se.is_in_scope("https://example.com/internal/debug")
        assert se.is_in_scope("https://example.com/api/users")

    def test_auto_detect_domain(self) -> None:
        se = ScopeEnforcer(ScopeConfig(target_url="https://target.co.uk"))
        assert se.is_in_scope("https://target.co.uk/path")
        assert se.is_in_scope("https://api.target.co.uk/v1")
        assert not se.is_in_scope("https://other.co.uk/path")

    def test_validate_or_raise(self) -> None:
        se = self._enforcer()
        se.validate_or_raise("https://example.com/ok")
        try:
            se.validate_or_raise("https://evil.com/bad")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_invalid_url(self) -> None:
        se = self._enforcer()
        assert not se.is_in_scope("")
        assert not se.is_in_scope("not-a-url")


class TestAuthorizationGate:
    def test_not_authorized_initially(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            gate = AuthorizationGate(Path(tmpdir))
            assert not gate.is_authorized()

    def test_authorized_after_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            gate = AuthorizationGate(Path(tmpdir))
            scope = ScopeConfig(target_url="https://example.com")
            # Directly log (bypasses interactive prompt for testing)
            gate._log_authorization("https://example.com", scope)
            assert gate.is_authorized()

    def test_authorization_record_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            gate = AuthorizationGate(Path(tmpdir))
            scope = ScopeConfig(
                target_url="https://example.com",
                allowed_domains=["example.com"],
            )
            gate._log_authorization("https://example.com", scope)

            auth_path = Path(tmpdir) / "authorization.sig"
            record = orjson.loads(auth_path.read_bytes())
            assert record["target"] == "https://example.com"
            assert record["confirmed"] is True
            assert "timestamp" in record


class TestProxyManager:
    def test_no_proxies(self) -> None:
        pm = ProxyManager(ProxyConfig())
        assert not pm.has_proxies
        assert pm.get_proxy() is None
        assert pm.get_proxy_url() is None

    def test_round_robin(self) -> None:
        proxies = [
            ProxyEntry(url="http://proxy1:8080"),
            ProxyEntry(url="http://proxy2:8080"),
            ProxyEntry(url="http://proxy3:8080"),
        ]
        pm = ProxyManager(
            ProxyConfig(proxy_list=proxies, strategy=RotationStrategy.ROUND_ROBIN, enabled=True)
        )
        assert pm.has_proxies
        assert pm.available_count == 3

        # Should cycle through proxies
        seen = set()
        for _ in range(6):
            p = pm.get_proxy()
            assert p is not None
            seen.add(p.url)
        assert len(seen) == 3

    def test_random_rotation(self) -> None:
        proxies = [
            ProxyEntry(url="http://proxy1:8080"),
            ProxyEntry(url="http://proxy2:8080"),
        ]
        pm = ProxyManager(
            ProxyConfig(proxy_list=proxies, strategy=RotationStrategy.RANDOM, enabled=True)
        )
        p = pm.get_proxy()
        assert p is not None
        assert p.url in ["http://proxy1:8080", "http://proxy2:8080"]

    def test_mark_burned(self) -> None:
        proxies = [
            ProxyEntry(url="http://proxy1:8080"),
            ProxyEntry(url="http://proxy2:8080"),
        ]
        pm = ProxyManager(
            ProxyConfig(proxy_list=proxies, strategy=RotationStrategy.ROUND_ROBIN, enabled=True)
        )
        pm.mark_burned("http://proxy1:8080", "detected by WAF")
        assert pm.available_count == 1

        # Should only return proxy2
        for _ in range(5):
            p = pm.get_proxy()
            assert p is not None
            assert p.url == "http://proxy2:8080"

    def test_reset_burned(self) -> None:
        proxies = [ProxyEntry(url="http://proxy1:8080")]
        pm = ProxyManager(
            ProxyConfig(proxy_list=proxies, strategy=RotationStrategy.ROUND_ROBIN, enabled=True)
        )
        pm.mark_burned("http://proxy1:8080")
        assert pm.available_count == 0
        pm.reset_burned()
        assert pm.available_count == 1

    def test_proxy_url_with_auth(self) -> None:
        proxies = [
            ProxyEntry(
                url="http://proxy.example.com:8080",
                username="user",
                password="pass",
            )
        ]
        pm = ProxyManager(
            ProxyConfig(proxy_list=proxies, enabled=True)
        )
        url = pm.get_proxy_url()
        assert url == "http://user:pass@proxy.example.com:8080"
