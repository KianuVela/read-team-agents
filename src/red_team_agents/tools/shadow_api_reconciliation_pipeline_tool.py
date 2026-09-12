from pathlib import Path
from typing import Any, Dict, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from red_team_agents.deterministic_shadow_api.run_runtime_shadow_api_reconciliation import (
    run_runtime_shadow_api_reconciliation,
)
from red_team_agents.deterministic_shadow_api.run_shadow_candidate_validation import (
    run_shadow_candidate_validation,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class ShadowAPIReconciliationPipelineToolInput(BaseModel):
    """
    Input schema for deterministic Shadow API reconciliation.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    runtime_evidence_file: str = Field(
        default="reports/api_discovery/runtime_evidence_aggregated.json",
        description=(
            "Canonical runtime evidence produced by the independent "
            "API-operation discovery pipeline."
        ),
    )

    openapi_inventory_file: str = Field(
        default="outputs/discovery/openapi_inventory.json",
        description=(
            "OpenAPI inventory used only as the documentation baseline "
            "for post-discovery reconciliation."
        ),
    )

    output_dir: str = Field(
        default="reports/shadow_api",
        description=(
            "Directory in which deterministic Shadow API artefacts "
            "will be persisted."
        ),
    )


class ShadowAPIReconciliationPipelineTool(BaseTool):
    """
    CrewAI facade for deterministic Shadow API reconciliation and validation.
    """

    name: str = "shadow_api_reconciliation_pipeline"

    description: str = (
        "Reconciles independently observed runtime API operations against "
        "the OpenAPI documentation baseline and deterministically validates "
        "Shadow API endpoint candidates. It does not perform API discovery, "
        "does not use Ground Truth, and does not perform OWASP, MITRE ATT&CK, "
        "or NIS2 mapping."
    )

    args_schema: Type[BaseModel] = (
        ShadowAPIReconciliationPipelineToolInput
    )

    def _resolve_path(
        self,
        value: str,
    ) -> Path:

        path = Path(value)

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        return path.resolve()

    def _run(
        self,
        runtime_evidence_file: str = (
            "reports/api_discovery/runtime_evidence_aggregated.json"
        ),
        openapi_inventory_file: str = (
            "outputs/discovery/openapi_inventory.json"
        ),
        output_dir: str = "reports/shadow_api",
    ) -> Dict[str, Any]:

        runtime_path = self._resolve_path(
            runtime_evidence_file
        )

        openapi_path = self._resolve_path(
            openapi_inventory_file
        )

        output_path = self._resolve_path(
            output_dir
        )

        if not runtime_path.exists():
            raise FileNotFoundError(
                "Runtime evidence file was not found: "
                f"{runtime_path}"
            )

        if not openapi_path.exists():
            raise FileNotFoundError(
                "OpenAPI inventory file was not found: "
                f"{openapi_path}"
            )

        output_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        reconciliation_file = (
            output_path
            / "runtime_shadow_api_reconciliation.json"
        )

        validation_file = (
            output_path
            / "shadow_candidate_validation.json"
        )

        stage = "runtime_openapi_reconciliation"

        try:

            reconciliation = (
                run_runtime_shadow_api_reconciliation(
                    runtime_file=runtime_path,
                    openapi_file=openapi_path,
                    output_file=reconciliation_file,
                )
            )

            stage = "shadow_candidate_validation"

            validation = run_shadow_candidate_validation(
                input_file=reconciliation_file,
                output_file=validation_file,
            )

        except Exception as exc:

            raise RuntimeError(
                "Shadow API reconciliation pipeline failed during "
                f"stage '{stage}': {exc}"
            ) from exc

        reconciliation_summary = reconciliation.get(
            "summary",
            {},
        )

        return {
            "pipeline": "deterministic_shadow_api_reconciliation",
            "status": "completed",
            "methodological_boundary": {
                "runtime_discovery_performed": False,
                "openapi_used_for_reconciliation": True,
                "ground_truth_used": False,
                "owasp_mapping_performed": False,
                "mitre_attack_mapping_performed": False,
                "nis2_mapping_performed": False,
            },
            "inputs": {
                "runtime_evidence": str(runtime_path),
                "openapi_inventory": str(openapi_path),
            },
            "artifacts": {
                "runtime_shadow_api_reconciliation": str(
                    reconciliation_file
                ),
                "shadow_candidate_validation": str(
                    validation_file
                ),
            },
            "reconciliation": {
                "observed_total": reconciliation_summary.get(
                    "observed_total",
                    0,
                ),
                "documented_count": reconciliation_summary.get(
                    "documented_count",
                    0,
                ),
                "shadow_operation_count": reconciliation_summary.get(
                    "shadow_operation_count",
                    0,
                ),
                "shadow_endpoint_count": reconciliation_summary.get(
                    "shadow_endpoint_count",
                    0,
                ),
                "excluded_total": reconciliation_summary.get(
                    "excluded_total",
                    0,
                ),
            },
            "validation": {
                "candidate_count": validation.get(
                    "candidate_count",
                    0,
                ),
                "confirmed_count": validation.get(
                    "confirmed_count",
                    0,
                ),
                "rejected_count": validation.get(
                    "rejected_count",
                    0,
                ),
                "confirmed_candidates": validation.get(
                    "confirmed_candidates",
                    [],
                ),
            },
        }
