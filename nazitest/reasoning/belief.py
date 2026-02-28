"""Belief refinement loop — hypothesis confidence tracking."""

from __future__ import annotations

import logging
import re

from nazitest.models.graph import Hypothesis

logger = logging.getLogger(__name__)

# Offensive thresholds — a real pentester tries everything
CROSS_VALIDATION_THRESHOLD = 0.5
EXPLOITATION_THRESHOLD = 0.5


class BeliefRefinementLoop:
    """Manages the hypothesis confidence lifecycle.

    Offensive mode: Scout investigates, then we go straight to
    exploitation. Cross-validation is optional and advisory only
    — it can never veto an exploit attempt.
    """

    def update_belief(
        self,
        hypothesis: Hypothesis,
        scout_confidence: float,
        evidence_strength: float = 0.0,
    ) -> float:
        """Update hypothesis confidence based on scout findings.

        Weighting: 60% scout, 20% prior (strategist), 20% evidence.
        Heavy scout weight because the scout actually analyzed the
        target. If scout says it's likely, we try it.
        """
        new_confidence = (
            hypothesis.confidence * 0.2
            + scout_confidence * 0.6
            + evidence_strength * 0.2
        )
        hypothesis.confidence = max(0.0, min(1.0, new_confidence))
        return hypothesis.confidence

    def reconcile(
        self,
        hypothesis: Hypothesis,
        validator_confidence: float,
    ) -> float:
        """Reconcile with cross-validator's assessment.

        Advisory only — the validator can adjust confidence but
        can NEVER drop it below 80% of the current value. This
        prevents an overly skeptical validator from killing valid
        hypotheses.
        """
        floor = hypothesis.confidence * 0.80
        diff = abs(hypothesis.confidence - validator_confidence)

        if diff < 0.15:
            adjusted = (
                (hypothesis.confidence + validator_confidence) / 2
                + 0.05
            )
        elif validator_confidence < hypothesis.confidence:
            # Validator is more skeptical — mild reduction only
            adjusted = (
                hypothesis.confidence * 0.7
                + validator_confidence * 0.3
            )
        else:
            # Validator is more confident — boost
            adjusted = (
                hypothesis.confidence * 0.5
                + validator_confidence * 0.5
            )

        adjusted = max(floor, min(1.0, adjusted))
        hypothesis.confidence = adjusted
        return hypothesis.confidence

    def apply_exploitation_result(
        self,
        hypothesis: Hypothesis,
        success: bool,
        blocked: bool = False,
    ) -> float:
        """Update confidence based on exploitation result."""
        if success:
            hypothesis.confidence = 1.0
            hypothesis.confirmed = True
        elif blocked:
            hypothesis.confidence *= 0.9
        else:
            hypothesis.confidence *= 0.7

        hypothesis.exploitation_attempted = True
        return hypothesis.confidence

    def is_ready_for_cross_validation(
        self, hypothesis: Hypothesis
    ) -> bool:
        return hypothesis.confidence > CROSS_VALIDATION_THRESHOLD

    def is_ready_for_exploitation(
        self, hypothesis: Hypothesis
    ) -> bool:
        return hypothesis.confidence > EXPLOITATION_THRESHOLD

    @staticmethod
    def parse_confidence_from_llm(text: str) -> float | None:
        """Extract a confidence value from LLM response text.

        Handles: "confidence: 0.85", "Confidence: 85%",
        "0.85/1.0", "8/10", "rating: 0.9", "85% confident"
        """
        patterns = [
            r"confidence[:\s]*\**\s*([0-9]*\.?[0-9]+)",
            r"([0-9]*\.?[0-9]+)\s*/\s*1\.0",
            r"rating[:\s]*\**\s*([0-9]*\.?[0-9]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                val = float(match.group(1))
                if 0.0 <= val <= 1.0:
                    return val

        # Try percentage: "85%" or "85 percent"
        pct_match = re.search(
            r"(\d{1,3})\s*(?:%|percent)",
            text,
            re.I,
        )
        if pct_match:
            val = int(pct_match.group(1))
            if 0 <= val <= 100:
                return val / 100.0

        # Try X/10 scale
        scale_match = re.search(
            r"(\d(?:\.\d)?)\s*/\s*10",
            text,
        )
        if scale_match:
            val = float(scale_match.group(1))
            if 0.0 <= val <= 10.0:
                return val / 10.0

        return None
