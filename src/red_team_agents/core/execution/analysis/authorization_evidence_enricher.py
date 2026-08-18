# core/execution/analysis/authorization_evidence_enricher.py

from copy import deepcopy

from red_team_agents.core.execution.analysis.authorization_finding_classifier import (
    AuthorizationFindingClassifier,
)
from red_team_agents.core.execution.analysis.authorization_outcome import (
    AuthorizationOutcomeClassifier,
)
from red_team_agents.core.execution.analysis.vulnerability_decision_classifier import (
    VulnerabilityDecisionClassifier,
)


class AuthorizationEvidenceEnricher:
    """
    Adds authorization analysis fields to HTTP execution evidence.

    This class does not update ResourceUpdate.vulnerable.
    It only enriches the evidence with:
    - authorization_outcome
    - authorization_outcome_explanation
    - authorization_finding
    - authorization_finding_explanation
    - vulnerability_decision
    - vulnerability_decision_vulnerable
    - vulnerability_decision_confidence
    - vulnerability_decision_explanation
    """

    def __init__(
        self,
        outcome_classifier: AuthorizationOutcomeClassifier | None = None,
        finding_classifier: AuthorizationFindingClassifier | None = None,
        decision_classifier: VulnerabilityDecisionClassifier | None = None,
    ):
        self._outcome_classifier = (
            outcome_classifier
            or AuthorizationOutcomeClassifier()
        )
        self._finding_classifier = (
            finding_classifier
            or AuthorizationFindingClassifier()
        )
        self._decision_classifier = (
            decision_classifier
            or VulnerabilityDecisionClassifier()
        )

    def enrich(
        self,
        evidence: dict | None,
        expected_secure_behavior: str | None = None,
    ) -> dict:
        if evidence is None:
            evidence = {}

        enriched = deepcopy(evidence)

        status_code = enriched.get("http_status")

        outcome_result = self._outcome_classifier.classify(
            status_code
        )

        enriched["authorization_outcome"] = (
            outcome_result.outcome.value
        )
        enriched["authorization_outcome_explanation"] = (
            outcome_result.explanation
        )

        finding_result = self._finding_classifier.classify(
            evidence=enriched,
            expected_secure_behavior=expected_secure_behavior,
        )

        enriched["authorization_finding"] = (
            finding_result.finding.value
        )
        enriched["authorization_finding_explanation"] = (
            finding_result.explanation
        )

        decision_result = self._decision_classifier.classify(
            evidence=enriched,
            expected_secure_behavior=expected_secure_behavior,
        )

        enriched["vulnerability_decision"] = (
            decision_result.decision.value
        )
        enriched["vulnerability_decision_vulnerable"] = (
            decision_result.vulnerable
        )
        enriched["vulnerability_decision_confidence"] = (
            decision_result.confidence
        )
        enriched["vulnerability_decision_explanation"] = (
            decision_result.explanation
        )

        return enriched