"""Tests for reasoning engine — sanitizer, belief refinement, usage tracker."""

from nazitest.models.graph import Hypothesis
from nazitest.models.types import Severity
from nazitest.reasoning.belief import BeliefRefinementLoop
from nazitest.reasoning.openrouter import UsageTracker
from nazitest.reasoning.sanitizer import LLMDataSanitizer


class TestLLMDataSanitizer:
    def test_sanitize_jwt(self) -> None:
        sanitizer = LLMDataSanitizer()
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
        result = sanitizer.sanitize(text)
        assert "eyJ" not in result
        assert "<JWT_TOKEN>" in result or "<BEARER_TOKEN>" in result

    def test_sanitize_password(self) -> None:
        sanitizer = LLMDataSanitizer()
        # Password pattern matches in string context (e.g. "password=value")
        text = 'password="super_secret_123"'
        result = sanitizer.sanitize(text)
        assert "super_secret_123" not in result

    def test_sanitize_api_key(self) -> None:
        sanitizer = LLMDataSanitizer()
        text = 'api_key: "sk-1234567890abcdef1234567890"'
        result = sanitizer.sanitize(text)
        assert "sk-1234567890" not in result

    def test_sanitize_email(self) -> None:
        sanitizer = LLMDataSanitizer()
        text = "Contact admin@example.com for support"
        result = sanitizer.sanitize(text)
        assert "admin@example.com" not in result
        assert "<EMAIL>" in result

    def test_sanitize_nested_dict(self) -> None:
        sanitizer = LLMDataSanitizer()
        data = {
            "request": {
                "headers": {"Authorization": "Bearer eyJhbGci.eyJzdWIi.sig_here_long_enough"},
            },
            "status": 200,
        }
        result = sanitizer.sanitize(data)
        assert result["status"] == 200
        assert "eyJ" not in str(result)

    def test_sanitize_list(self) -> None:
        sanitizer = LLMDataSanitizer()
        data = ["password: secret123456", "normal text"]
        result = sanitizer.sanitize(data)
        assert "secret123456" not in str(result)
        assert result[1] == "normal text"

    def test_sanitize_headers(self) -> None:
        sanitizer = LLMDataSanitizer()
        headers = {
            "Authorization": "Bearer long_token_value_here_that_is_really_long_enough",
            "Content-Type": "application/json",
            "Cookie": "session=abc123def456ghi789jkl012mno345pqr678stu901",
        }
        result = sanitizer.sanitize_headers(headers)
        assert result["Content-Type"] == "application/json"
        assert "long_token" not in result["Authorization"]


class TestBeliefRefinement:
    def _make_hypothesis(self, confidence: float = 0.3) -> Hypothesis:
        return Hypothesis(
            id="h1",
            title="Test SQLi",
            description="SQL injection test",
            confidence=confidence,
            severity=Severity.HIGH,
        )

    def test_initial_confidence(self) -> None:
        h = self._make_hypothesis()
        assert h.confidence == 0.3

    def test_update_belief_high_scout(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis()
        new = loop.update_belief(h, scout_confidence=0.8, evidence_strength=0.7)
        assert new > 0.3  # Should increase
        assert new == h.confidence

    def test_update_belief_low_scout(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.5)
        new = loop.update_belief(h, scout_confidence=0.1, evidence_strength=0.1)
        assert new < 0.5  # Should decrease

    def test_reconcile_agreement(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.7)
        new = loop.reconcile(h, validator_confidence=0.72)
        assert new >= 0.7  # Agreement should boost slightly

    def test_reconcile_skeptical_validator(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.8)
        new = loop.reconcile(h, validator_confidence=0.3)
        assert new < 0.8  # Should decrease

    def test_exploitation_success(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.8)
        loop.apply_exploitation_result(h, success=True)
        assert h.confidence == 1.0
        assert h.confirmed is True
        assert h.exploitation_attempted is True

    def test_exploitation_blocked(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.8)
        loop.apply_exploitation_result(h, success=False, blocked=True)
        assert abs(h.confidence - 0.72) < 1e-9  # 0.8 * 0.9
        assert h.confirmed is False

    def test_exploitation_failed(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.8)
        loop.apply_exploitation_result(h, success=False, blocked=False)
        assert h.confidence < 0.8  # 0.8 * 0.7

    def test_thresholds(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.3)
        assert not loop.is_ready_for_cross_validation(h)
        assert not loop.is_ready_for_exploitation(h)

        h.confidence = 0.55
        assert loop.is_ready_for_cross_validation(h)
        assert loop.is_ready_for_exploitation(h)

        h.confidence = 0.8
        assert loop.is_ready_for_exploitation(h)

    def test_parse_confidence_from_llm(self) -> None:
        assert BeliefRefinementLoop.parse_confidence_from_llm("confidence: 0.75") == 0.75
        assert BeliefRefinementLoop.parse_confidence_from_llm("Rating: 0.6") == 0.6
        assert BeliefRefinementLoop.parse_confidence_from_llm("I rate this 0.85/1.0") == 0.85
        assert BeliefRefinementLoop.parse_confidence_from_llm("no number here") is None

    def test_confidence_clamped(self) -> None:
        loop = BeliefRefinementLoop()
        h = self._make_hypothesis(0.95)
        loop.update_belief(h, scout_confidence=1.0, evidence_strength=1.0)
        assert h.confidence <= 1.0

        h.confidence = 0.05
        loop.update_belief(h, scout_confidence=0.0, evidence_strength=0.0)
        assert h.confidence >= 0.0


class TestUsageTracker:
    def test_basic_tracking(self) -> None:
        tracker = UsageTracker(budget_limit=10.0)
        tracker.record("model-a", 1000, 500, 0.05)
        tracker.record("model-b", 2000, 800, 0.10)

        assert tracker.total_input_tokens == 3000
        assert tracker.total_output_tokens == 1300
        assert abs(tracker.total_cost_usd - 0.15) < 1e-9
        assert len(tracker.calls) == 2
        assert not tracker.budget_exceeded

    def test_budget_exceeded(self) -> None:
        tracker = UsageTracker(budget_limit=1.0)
        tracker.record("model", 10000, 5000, 1.01)
        assert tracker.budget_exceeded

    def test_summary(self) -> None:
        tracker = UsageTracker()
        tracker.record("model", 100, 50, 0.01)
        summary = tracker.summary()
        assert summary["total_calls"] == 1
        assert summary["total_cost_usd"] == 0.01
