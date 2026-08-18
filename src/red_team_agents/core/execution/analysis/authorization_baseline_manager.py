# core/execution/analysis/authorization_baseline_manager.py

from red_team_agents.core.execution.analysis.authorization_baseline_evidence_enricher import (
    AuthorizationBaselineEvidenceEnricher,
)
from red_team_agents.core.execution.analysis.authorization_baseline_key_builder import (
    AuthorizationBaselineKeyBuilder,
)
from red_team_agents.core.execution.analysis.authorization_baseline_store import (
    AuthorizationBaselineStore,
)


class AuthorizationBaselineManager:
    """
    Coordinates authorization baseline storage and evidence enrichment.

    This class does not execute HTTP requests and does not decide whether
    a resource is vulnerable. It only:
    - builds stable baseline keys;
    - stores authorized baseline evidence;
    - retrieves matching baseline evidence;
    - enriches unauthorized evidence when a baseline is available.
    """

    def __init__(
        self,
        key_builder: AuthorizationBaselineKeyBuilder | None = None,
        store: AuthorizationBaselineStore | None = None,
        evidence_enricher: AuthorizationBaselineEvidenceEnricher | None = None,
    ):
        self._key_builder = (
            key_builder
            or AuthorizationBaselineKeyBuilder()
        )
        self._store = (
            store
            or AuthorizationBaselineStore()
        )
        self._evidence_enricher = (
            evidence_enricher
            or AuthorizationBaselineEvidenceEnricher()
        )

    def save_authorized_baseline(
        self,
        resource,
        evidence: dict,
    ) -> str:
        key = self._key_builder.build_from_resource(
            resource
        )

        self._store.save(
            key=key,
            evidence=evidence,
        )

        return key

    def get_authorized_baseline(
        self,
        resource,
    ) -> dict | None:
        key = self._key_builder.build_from_resource(
            resource
        )

        return self._store.get(
            key
        )

    def has_authorized_baseline(
        self,
        resource,
    ) -> bool:
        key = self._key_builder.build_from_resource(
            resource
        )

        return self._store.has(
            key
        )

    def enrich_unauthorized_evidence(
        self,
        resource,
        unauthorized_evidence: dict | None,
    ) -> dict:
        key = self._key_builder.build_from_resource(
            resource
        )

        authorized_evidence = self._store.get(
            key
        )

        return self._evidence_enricher.enrich(
            authorized_evidence=authorized_evidence,
            unauthorized_evidence=unauthorized_evidence,
        )

    def baseline_keys(
        self,
    ) -> tuple[str, ...]:
        return self._store.keys()