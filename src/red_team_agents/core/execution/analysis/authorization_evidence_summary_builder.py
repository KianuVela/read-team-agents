class AuthorizationEvidenceSummaryBuilder:
    """
    Builds an audit-ready authorization evidence summary.

    The summary is intended for analyst/reporting layers and does not
    change vulnerability decisions. It only converts low-level execution
    evidence into a compact, readable structure.
    """

    def build(
        self,
        evidence: dict | None,
    ) -> dict:
        evidence = evidence or {}

        http_status = evidence.get(
            "http_status"
        )

        authorization_outcome = evidence.get(
            "authorization_outcome",
            "unknown",
        )

        authorization_finding = evidence.get(
            "authorization_finding",
            "inconclusive",
        )

        vulnerability_decision = evidence.get(
            "vulnerability_decision",
            "inconclusive",
        )

        vulnerability_decision_vulnerable = evidence.get(
            "vulnerability_decision_vulnerable"
        )

        vulnerability_confidence = evidence.get(
            "vulnerability_decision_confidence",
            "low",
        )

        baseline_recorded = evidence.get(
            "baseline_recorded",
            False,
        )

        baseline_comparison = evidence.get(
            "baseline_comparison",
            "inconclusive",
        )

        baseline_confidence = evidence.get(
            "baseline_comparison_confidence",
            "low",
        )

        matched_identifiers = evidence.get(
            "baseline_matched_identifiers",
            [],
        ) or []

        state_changing_follow_up = evidence.get(
            "state_changing_follow_up"
        )

        state_changing_follow_up_execution = evidence.get(
            "state_changing_follow_up_execution"
        )

        title = self._build_title(
            vulnerability_decision=vulnerability_decision,
            authorization_finding=authorization_finding,
            baseline_comparison=baseline_comparison,
        )

        summary = self._build_summary(
            http_status=http_status,
            authorization_outcome=authorization_outcome,
            authorization_finding=authorization_finding,
            vulnerability_decision=vulnerability_decision,
            vulnerability_decision_vulnerable=vulnerability_decision_vulnerable,
            vulnerability_confidence=vulnerability_confidence,
            baseline_recorded=baseline_recorded,
            baseline_comparison=baseline_comparison,
            baseline_confidence=baseline_confidence,
            matched_identifiers=matched_identifiers,
        )

        result = {
            "title": title,
            "summary": summary,
            "http_status": http_status,
            "authorization_outcome": authorization_outcome,
            "authorization_finding": authorization_finding,
            "vulnerability_decision": vulnerability_decision,
            "vulnerability_decision_vulnerable": vulnerability_decision_vulnerable,
            "vulnerability_decision_confidence": vulnerability_confidence,
            "baseline_recorded": baseline_recorded,
            "baseline_comparison": baseline_comparison,
            "baseline_comparison_confidence": baseline_confidence,
            "baseline_matched_identifiers": list(
                matched_identifiers
            ),
        }

        if state_changing_follow_up is not None:
            result["state_changing_follow_up"] = state_changing_follow_up

        if state_changing_follow_up_execution is not None:
            result[
                "state_changing_follow_up_execution"
            ] = state_changing_follow_up_execution

        return result

    def _build_title(
        self,
        vulnerability_decision: str,
        authorization_finding: str,
        baseline_comparison: str,
    ) -> str:
        if (
            vulnerability_decision == "vulnerable"
            and authorization_finding == "potential_authorization_bypass"
            and baseline_comparison == "confirms_authorization_bypass"
        ):
            return (
                "Authorization bypass confirmed by baseline comparison"
            )

        if vulnerability_decision == "vulnerable":
            return (
                "Potential authorization bypass detected"
            )

        if (
            vulnerability_decision == "not_vulnerable"
            and baseline_comparison == "supports_expected_denial"
        ):
            return (
                "Expected authorization denial confirmed by baseline comparison"
            )

        if vulnerability_decision == "not_vulnerable":
            return (
                "Expected authorization denial observed"
            )

        return (
            "Authorization result inconclusive"
        )

    def _build_summary(
        self,
        http_status,
        authorization_outcome: str,
        authorization_finding: str,
        vulnerability_decision: str,
        vulnerability_decision_vulnerable,
        vulnerability_confidence: str,
        baseline_recorded: bool,
        baseline_comparison: str,
        baseline_confidence: str,
        matched_identifiers: list,
    ) -> str:
        parts = [
            f"HTTP status: {http_status}",
            f"authorization outcome: {authorization_outcome}",
            f"authorization finding: {authorization_finding}",
            f"vulnerability decision: {vulnerability_decision}",
            f"vulnerable: {vulnerability_decision_vulnerable}",
            f"decision confidence: {vulnerability_confidence}",
            f"baseline recorded: {baseline_recorded}",
            f"baseline comparison: {baseline_comparison}",
            f"baseline confidence: {baseline_confidence}",
        ]

        if matched_identifiers:
            visible_identifiers = matched_identifiers[:10]

            parts.append(
                "matched identifiers: "
                + ", ".join(
                    str(identifier)
                    for identifier in visible_identifiers
                )
            )

            remaining = (
                len(matched_identifiers)
                - len(visible_identifiers)
            )

            if remaining > 0:
                parts.append(
                    f"additional matched identifiers: {remaining}"
                )

        return "; ".join(
            parts
        ) + "."