class AuthorizationEvidenceCategoryBuilder:
    """
    Groups authorization evidence into deterministic report buckets.
    """

    def categorize(
        self,
        evidence_summary: dict,
    ) -> str | None:
        if evidence_summary.get(
            "state_changing_follow_up_execution"
        ):
            return "dynamic_follow_up_findings"

        if (
            evidence_summary.get(
                "vulnerability_decision"
            )
            == "vulnerable"
            and evidence_summary.get(
                "baseline_comparison"
            )
            == "confirms_authorization_bypass"
        ):
            return "confirmed_static_findings"

        if evidence_summary.get(
            "missing_fixture_key"
        ):
            return "inconclusive_due_to_missing_fixture"

        return None