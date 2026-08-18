# core/execution/analysis/authorization_baseline_comparator.py

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AuthorizationBaselineComparison(str, Enum):
    """
    Baseline comparison result.

    This does not execute HTTP requests.
    It only compares evidence from an authorized baseline
    with evidence from an unauthorized authorization test.
    """

    CONFIRMS_AUTHORIZATION_BYPASS = (
        "confirms_authorization_bypass"
    )
    SUPPORTS_EXPECTED_DENIAL = (
        "supports_expected_denial"
    )
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class AuthorizationBaselineComparisonResult:
    comparison: AuthorizationBaselineComparison
    confidence: str
    matched_identifiers: tuple[str, ...]
    explanation: str


class AuthorizationBaselineComparator:
    """
    Compares authorized and unauthorized HTTP evidence.

    The goal is to reduce false positives by checking whether
    a non-authorized request not only succeeded, but also appears
    to expose the same protected object or business entity observed
    in the authorized baseline.
    """

    _IDENTIFIER_KEYS = {
        "id",
        "userid",
        "user_id",
        "authorid",
        "author_id",
        "orderid",
        "order_id",
        "carid",
        "car_id",
        "vehicleid",
        "vehicle_id",
        "vin",
        "email",
        "transaction_id",

        # # Coupon identifiers
        "coupon_code",
        "couponcode",
        "coupon_id",
        "couponid",

        # Mechanic / service request identifiers
        "service_request_id",
        "servicerequestid",
        "service_requestid",
        "request_id",
        "requestid",
        "report_id",
        "reportid",
        "mechanic_id",
        "mechanicid",
        "mechanic_code",
        "mechaniccode",
    }

    def compare(
        self,
        authorized_evidence: dict | None,
        unauthorized_evidence: dict | None,
    ) -> AuthorizationBaselineComparisonResult:
        authorized_evidence = authorized_evidence or {}
        unauthorized_evidence = unauthorized_evidence or {}

        if not self._is_allowed(
            authorized_evidence
        ):
            return AuthorizationBaselineComparisonResult(
                comparison=(
                    AuthorizationBaselineComparison
                    .INCONCLUSIVE
                ),
                confidence="low",
                matched_identifiers=(),
                explanation=(
                    "The authorized baseline did not produce a "
                    "successful parseable response, so the comparison "
                    "cannot establish expected legitimate access."
                ),
            )

        if self._is_denied(
            unauthorized_evidence
        ):
            return AuthorizationBaselineComparisonResult(
                comparison=(
                    AuthorizationBaselineComparison
                    .SUPPORTS_EXPECTED_DENIAL
                ),
                confidence="high",
                matched_identifiers=(),
                explanation=(
                    "The authorized baseline succeeded, while the "
                    "unauthorized request was denied. This supports "
                    "the expected authorization boundary."
                ),
            )

        if not self._is_allowed(
            unauthorized_evidence
        ):
            return AuthorizationBaselineComparisonResult(
                comparison=(
                    AuthorizationBaselineComparison
                    .INCONCLUSIVE
                ),
                confidence="low",
                matched_identifiers=(),
                explanation=(
                    "The unauthorized request did not produce a "
                    "successful parseable response, so there is no "
                    "confirmed authorization bypass from baseline "
                    "comparison."
                ),
            )

        matched_identifiers = self._matched_identifiers(
            authorized_evidence,
            unauthorized_evidence,
        )

        if (
            matched_identifiers
            and self._has_potential_bypass_signal(
                unauthorized_evidence
            )
        ):
            return AuthorizationBaselineComparisonResult(
                comparison=(
                    AuthorizationBaselineComparison
                    .CONFIRMS_AUTHORIZATION_BYPASS
                ),
                confidence="high",
                matched_identifiers=matched_identifiers,
                explanation=(
                    "Both the authorized baseline and the unauthorized "
                    "request succeeded, and both responses contain at "
                    "least one matching protected identifier. This "
                    "strengthens the evidence for an authorization "
                    "bypass."
                ),
            )

        return AuthorizationBaselineComparisonResult(
            comparison=(
                AuthorizationBaselineComparison
                .INCONCLUSIVE
            ),
            confidence="low",
            matched_identifiers=matched_identifiers,
            explanation=(
                "The responses were not sufficient to confirm an "
                "authorization bypass through baseline comparison."
            ),
        )

    def _is_allowed(
        self,
        evidence: dict,
    ) -> bool:
        return (
            evidence.get("authorization_outcome")
            == "allowed"
            and self._is_success_status(
                evidence.get("http_status")
            )
            and evidence.get("http_parse_success") is True
        )

    def _is_denied(
        self,
        evidence: dict,
    ) -> bool:
        return (
            evidence.get("authorization_outcome")
            == "denied"
            and evidence.get("http_status") in (401, 403)
            and evidence.get("http_parse_success") is True
        )

    def _is_success_status(
        self,
        status_code: int | None,
    ) -> bool:
        return (
            status_code is not None
            and 200 <= status_code < 300
        )

    def _has_potential_bypass_signal(
        self,
        evidence: dict,
    ) -> bool:
        return (
            evidence.get("authorization_finding")
            == "potential_authorization_bypass"
            or evidence.get("vulnerability_decision")
            == "vulnerable"
            or evidence.get(
                "vulnerability_decision_vulnerable"
            )
            is True
        )

    def _matched_identifiers(
        self,
        authorized_evidence: dict,
        unauthorized_evidence: dict,
    ) -> tuple[str, ...]:
        authorized_values = set()
        unauthorized_values = set()

        for key in (
            "body_json",
            "request_json_body",
        ):
            authorized_values.update(
                self._extract_identifier_values(
                    authorized_evidence.get(
                        key
                    )
                )
            )

            unauthorized_values.update(
                self._extract_identifier_values(
                    unauthorized_evidence.get(
                        key
                    )
                )
            )

        matches = sorted(
            authorized_values.intersection(
                unauthorized_values
            )
        )

        return tuple(matches)

    def _extract_identifier_values(
        self,
        value: Any,
    ) -> set[str]:
        collected: set[str] = set()

        self._collect_identifier_values(
            value=value,
            collected=collected,
        )

        return collected

    def _collect_identifier_values(
        self,
        value: Any,
        collected: set[str],
    ) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                normalized_key = (
                    str(key)
                    .replace("-", "_")
                    .lower()
                )

                if normalized_key in self._IDENTIFIER_KEYS:
                    if isinstance(
                        child,
                        (str, int, float),
                    ):
                        identifier_value = str(
                            child
                        ).strip()

                        if identifier_value:
                            collected.add(
                                identifier_value
                            )

                self._collect_identifier_values(
                    value=child,
                    collected=collected,
                )

        elif isinstance(value, list):
            for item in value:
                self._collect_identifier_values(
                    value=item,
                    collected=collected,
                )