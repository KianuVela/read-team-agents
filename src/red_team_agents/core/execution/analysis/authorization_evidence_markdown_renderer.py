class AuthorizationEvidenceMarkdownRenderer:
    """
    Renders an authorization evidence summary as Markdown.

    The JSON summary remains the canonical machine-readable format.
    Markdown is generated only for analyst-facing reports.
    """

    def render(
        self,
        summary: dict | None,
    ) -> str:
        summary = summary or {}

        title = summary.get(
            "title",
            "Authorization evidence summary",
        )

        matched_identifiers = summary.get(
            "baseline_matched_identifiers",
            [],
        ) or []

        lines = [
            f"### {title}",
            "",
            f"- HTTP status: {summary.get('http_status')}",
            f"- Authorization outcome: {summary.get('authorization_outcome')}",
            f"- Authorization finding: {summary.get('authorization_finding')}",
            f"- Vulnerability decision: {summary.get('vulnerability_decision')}",
            f"- Vulnerable: {summary.get('vulnerability_decision_vulnerable')}",
            f"- Decision confidence: {summary.get('vulnerability_decision_confidence')}",
            f"- Baseline recorded: {summary.get('baseline_recorded')}",
            f"- Baseline comparison: {summary.get('baseline_comparison')}",
            f"- Baseline confidence: {summary.get('baseline_comparison_confidence')}",
        ]

        if matched_identifiers:
            lines.append(
                "- Matched identifiers: "
                + ", ".join(
                    str(identifier)
                    for identifier in matched_identifiers
                )
            )

        summary_text = summary.get(
            "summary"
        )

        if summary_text:
            lines.extend(
                [
                    "",
                    "**Interpretation:**",
                    "",
                    summary_text,
                ]
            )

        return "\n".join(
            lines
        )