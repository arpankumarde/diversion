"""Belief refinement loop — hypothesis confidence tracking per PRD section 7."""

from __future__ import annotations

import logging
import re

from nazitest.models.graph import Hypothesis

logger = logging.getLogger(__name__)

INITIAL_CONFIDENCE = 0.3
CROSS_VALIDATION_THRESHOLD = 0.6
EXPLOITATION_THRESHOLD = 0.75


class BeliefRefinementLoop:
    """Manages the hypothesis confidence lifecycle.

    Hypotheses start at 0.3 baseline, scouts investigate,
    cross-validator challenges, confirmed >0.75 go to exploitation.
    """

    def update_belief(
        self,
        hypothesis: Hypothesis,
        scout_confidence: float,
        evidence_strength: float = 0.0,
    ) -> float:
        """Update hypothesis confidence based on scout findings.

        Args:
            hypothesis: The hypothesis to update
            scout_confidence: Scout's assessed confidence (0.0-1.0)
            evidence_strength: How strong the supporting evidence is (0.0-1.0)

        Returns:
            Updated confidence value
        """
        # Weighted average: 40% prior, 40% scout, 20% evidence
        new_confidence = (
            hypothesis.confidence * 0.4
            + scout_confidence * 0.4
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

        The cross-validator is an independent model that challenges findings.
        If it disagrees significantly, confidence is reduced.
        """
        diff = abs(hypothesis.confidence - validator_confidence)

        if diff < 0.15:
            # Agreement — slight boost
            adjusted = (hypothesis.confidence + validator_confidence) / 2 + 0.05
        elif validator_confidence < hypothesis.confidence:
            # Validator is more skeptical — reduce confidence
            adjusted = (hypothesis.confidence * 0.4 + validator_confidence * 0.6)
        else:
            # Validator is more confident — moderate boost
            adjusted = (hypothesis.confidence * 0.6 + validator_confidence * 0.4)

        hypothesis.confidence = max(0.0, min(1.0, adjusted))
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
            # Blocked doesn't mean vuln doesn't exist — slight reduction
            hypothesis.confidence *= 0.9
        else:
            # Failed exploitation — significant reduction
            hypothesis.confidence *= 0.7

        hypothesis.exploitation_attempted = True
        return hypothesis.confidence

    def is_ready_for_cross_validation(self, hypothesis: Hypothesis) -> bool:
        return hypothesis.confidence > CROSS_VALIDATION_THRESHOLD

    def is_ready_for_exploitation(self, hypothesis: Hypothesis) -> bool:
        return hypothesis.confidence > EXPLOITATION_THRESHOLD

    @staticmethod
    def parse_confidence_from_llm(text: str) -> float | None:
        """Extract a confidence value from LLM response text."""
        patterns = [
            r"confidence[:\s]+([0-9]*\.?[0-9]+)",
            r"([0-9]*\.?[0-9]+)\s*/\s*1\.0",
            r"rating[:\s]+([0-9]*\.?[0-9]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.I)
            if match:
                val = float(match.group(1))
                if 0.0 <= val <= 1.0:
                    return val
        return None
