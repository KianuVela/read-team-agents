# core/execution/analysis/authorization_finding_classifier.py

from dataclasses import dataclass
from enum import Enum


class AuthorizationFinding(str, Enum):
    """
    Preliminary authorization finding.

    This is not yet the final vulnerability decision.
    It is an audit-friendly interpretation of the observed
    authorization outcome.
    """

    POTENTIAL_AUTHORIZATION_BYPASS = "potential_authorization_bypass"
    EXPECTED_DENIAL = "expected_denial"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class AuthorizationFindingResult:
    finding: AuthorizationFinding
    explanation: str


class AuthorizationFindingClassifier:
    """
    Converts a neutral authorization outcome into a preliminary finding.

    It does not set vulnerable=True/False.
    That final decision should be made later, after comparing:
    - actor used;
    - object ownership;
    - expected secure behavior;
    - positive and negative baselines.
    """

    def classify(
        self,
        evidence: dict | None,
        expected_secure_behavior: str | None = None,
    ) -> AuthorizationFindingResult:
        evidence = evidence or {}

        outcome = evidence.get(
            "authorization_outcome"
        )

        if (
            outcome == "allowed"
            and self._expects_denial(
                expected_secure_behavior
            )
        ):
            return AuthorizationFindingResult(
                finding=(
                    AuthorizationFinding
                    .POTENTIAL_AUTHORIZATION_BYPASS
                ),
                explanation=(
                    "The request was allowed, although the expected "
                    "secure behavior indicates that access should be "
                    "denied or restricted."
                ),
            )

        if outcome == "denied":
            return AuthorizationFindingResult(
                finding=AuthorizationFinding.EXPECTED_DENIAL,
                explanation=(
                    "The request was denied by the API, which is "
                    "consistent with an authorization boundary."
                ),
            )

        return AuthorizationFindingResult(
            finding=AuthorizationFinding.INCONCLUSIVE,
            explanation=(
                "The available evidence is not sufficient to classify "
                "the authorization behavior as either expected denial "
                "or potential authorization bypass."
            ),
        )

    def _expects_denial(
        self,
        expected_secure_behavior: str | None,
    ) -> bool:
        if not expected_secure_behavior:
            return False

        value = expected_secure_behavior.lower()

        denial_terms = (
            "deny",
            "denied",
            "forbid",
            "forbidden",
            "unauthorized",
            "not allowed",
            "reject",
            "rejected",
            "prevent",
            "blocked",
            "should not",
            "must not",
        )

        return any(
            term in value
            for term in denial_terms
        )