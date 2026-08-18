from copy import deepcopy

from red_team_agents.core.execution.analysis.authorization_baseline_comparator import (
    AuthorizationBaselineComparator,
)

from red_team_agents.core.execution.analysis.authorization_evidence_summary_builder import (
    AuthorizationEvidenceSummaryBuilder,
)

from red_team_agents.core.execution.analysis.authorization_evidence_markdown_renderer import (
    AuthorizationEvidenceMarkdownRenderer,
)


class AuthorizationBaselineEvidenceEnricher:
    """
    Enriches unauthorized execution evidence with baseline comparison data.

    This class does not execute HTTP requests and does not mutate
    ResourceUpdate. It only compares an authorized baseline evidence
    object with an unauthorized test evidence object.
    """

    def __init__(
        self,
        comparator: AuthorizationBaselineComparator | None = None,
        summary_builder: AuthorizationEvidenceSummaryBuilder | None = None,
        markdown_renderer: AuthorizationEvidenceMarkdownRenderer | None = None,
    ):
        self._comparator = (
            comparator
            or AuthorizationBaselineComparator()
        )

        self._summary_builder = (
            summary_builder
            or AuthorizationEvidenceSummaryBuilder()
        )   

        self._markdown_renderer = (
            markdown_renderer
            or AuthorizationEvidenceMarkdownRenderer()
        )

    def enrich(
        self,
        authorized_evidence: dict | None,
        unauthorized_evidence: dict | None,
    ) -> dict:
        if unauthorized_evidence is None:
            unauthorized_evidence = {}

        enriched = deepcopy(
            unauthorized_evidence
        )

        baseline_recorded = (
            authorized_evidence is not None
        )

        comparison_result = self._comparator.compare(
            authorized_evidence=authorized_evidence,
            unauthorized_evidence=unauthorized_evidence,
        )

        enriched["baseline_recorded"] = baseline_recorded
        enriched["baseline_comparison"] = comparison_result.comparison.value
        enriched["baseline_comparison_confidence"] = comparison_result.confidence
        enriched["baseline_matched_identifiers"] = list(
            comparison_result.matched_identifiers
        )
        enriched["baseline_comparison_explanation"] = (
            comparison_result.explanation
        )

        summary = self._summary_builder.build(
            enriched
        )

        enriched["authorization_evidence_summary"] = summary
        enriched["authorization_evidence_summary_markdown"] = (
            self._markdown_renderer.render(
                summary
            )
        )

        return enriched