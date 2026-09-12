"""
CrewAI facade for the deterministic API-operation discovery pipeline.

The tool consumes persisted live frontend_extract evidence and orchestrates
the deterministic runtime-discovery stages.

Methodological boundary:
- no OpenAPI input;
- no Ground Truth input;
- no Shadow API classification;
- no OWASP / MITRE ATT&CK / NIS2 mapping.
"""

import json
from pathlib import Path
from typing import Any, Dict, Type
from urllib.parse import urljoin

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from red_team_agents.tools.kali_mcp_tool import KaliMCPTool

from red_team_agents.deterministic_shadow_api.frontend_candidate_adapter import (
    write_frontend_operation_candidates,
)
from red_team_agents.deterministic_shadow_api.runtime_probe_planner import (
    write_runtime_probe_plan,
)
from red_team_agents.deterministic_shadow_api.runtime_probe_executor import (
    run_runtime_probe_file,
)
from red_team_agents.deterministic_shadow_api.active_runtime_probe_planner import (
    write_active_runtime_probe_plan,
)
from red_team_agents.deterministic_shadow_api.active_runtime_probe_executor import (
    run_active_runtime_probe_file,
)
from red_team_agents.deterministic_shadow_api.runtime_evidence_aggregator import (
    generate_runtime_evidence_aggregate,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class APIOperationDiscoveryPipelineToolInput(BaseModel):
    """
    Input schema for the deterministic API-operation discovery pipeline.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    frontend_extract_result_file: str | None = Field(
        default=None,
        description=(
            "Optional persisted frontend_extract JSON result. "
            "When omitted, the pipeline performs live frontend_extract "
            "against target_url and discovered JavaScript assets."
        ),
    )

    target_url: str = Field(
        ...,
        description=(
            "Base URL of the live target as reachable from KaliMCPTool, "
            "for example http://crapi-web."
        ),
    )

    output_dir: str = Field(
        default="reports/api_discovery",
        description=(
            "Directory in which deterministic API-discovery artefacts "
            "will be persisted."
        ),
    )


class APIOperationDiscoveryPipelineTool(BaseTool):
    """
    CrewAI wrapper around the deterministic API-operation discovery layer.
    """

    name: str = "api_operation_discovery_pipeline"

    description: str = (
        "Consumes a persisted frontend_extract result and executes the "
        "deterministic API-operation discovery pipeline: frontend candidate "
        "normalization, safe read-only runtime planning and validation, "
        "controlled active-runtime planning and validation, and final "
        "runtime-evidence aggregation. This tool does not use OpenAPI or "
        "Ground Truth and does not classify Shadow APIs."
    )

    args_schema: Type[BaseModel] = (
        APIOperationDiscoveryPipelineToolInput
    )

    def _resolve_path(
        self,
        value: str,
    ) -> Path:

        path = Path(value)

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        return path.resolve()

    def _collect_live_frontend_extract(
        self,
        target_url: str,
    ) -> Dict[str, Any]:
        """
        Execute frontend_extract against the live application root and
        discovered JavaScript assets, then aggregate the resulting
        candidates deterministically.

        No OpenAPI, Ground Truth, or vulnerability metadata is used.
        """

        tool = KaliMCPTool()

        root_result = tool.execute_json(
            tool="frontend_extract",
            args=target_url,
        )

        if not root_result.get("success"):
            raise RuntimeError(
                "frontend_extract failed for application root: "
                f"{root_result.get('error')}"
            )

        extraction_results = [root_result]
        extraction_errors = []
        asset_urls = []

        for asset in root_result.get("javascript_assets", []) or []:

            if isinstance(asset, str):
                reference = asset

            elif isinstance(asset, dict):
                reference = (
                    asset.get("url")
                    or asset.get("src")
                    or asset.get("reference")
                )

            else:
                reference = None

            if not reference:
                continue

            asset_url = urljoin(
                target_url.rstrip("/") + "/",
                str(reference),
            )

            if asset_url not in asset_urls:
                asset_urls.append(asset_url)

        for asset_url in asset_urls:

            result = tool.execute_json(
                tool="frontend_extract",
                args=asset_url,
            )

            if result.get("success"):
                extraction_results.append(result)
            else:
                extraction_errors.append(
                    {
                        "source_url": asset_url,
                        "error": result.get("error"),
                    }
                )

        combined_candidates = []
        seen_candidates = set()

        for result in extraction_results:

            for candidate in result.get("api_candidates", []) or []:

                if not isinstance(candidate, dict):
                    continue

                identity = (
                    str(candidate.get("reference")),
                    str(candidate.get("method_hint")),
                    str(candidate.get("route_key")),
                    str(candidate.get("reference_type")),
                )

                if identity in seen_candidates:
                    continue

                seen_candidates.add(identity)
                combined_candidates.append(candidate)

        return {
            "success": True,
            "tool": "frontend_extract",
            "source_url": target_url,
            "javascript_assets": asset_urls,
            "api_candidates": combined_candidates,
            "frontend_sources_scanned": [
                result.get("source_url")
                for result in extraction_results
                if result.get("source_url")
            ],
            "extraction_errors": extraction_errors,
            "summary": {
                "sources_scanned": len(extraction_results),
                "javascript_assets_discovered": len(asset_urls),
                "api_candidate_count": len(combined_candidates),
                "asset_extraction_errors": len(extraction_errors),
            },
        }

    def _run(
        self,
        target_url: str,
        frontend_extract_result_file: str | None = None,
        output_dir: str = "reports/api_discovery",
    ) -> Dict[str, Any]:

        base_url = str(target_url).strip().rstrip("/")

        if not base_url:
            raise ValueError(
                "target_url must contain a valid live target URL."
            )

        output_path = self._resolve_path(
            output_dir
        )

        output_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        stage = "frontend_extract"

        if frontend_extract_result_file:

            frontend_input = self._resolve_path(
                frontend_extract_result_file
            )

            if not frontend_input.exists():
                raise FileNotFoundError(
                    "Persisted frontend_extract result was not found: "
                    f"{frontend_input}"
                )

        else:

            frontend_input = (
                output_path
                / "frontend_extract_result.json"
            )

            frontend_result = self._collect_live_frontend_extract(
                target_url=base_url,
            )

            frontend_input.write_text(
                json.dumps(
                    frontend_result,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        frontend_candidates_file = (
            output_path
            / "frontend_operation_candidates.json"
        )

        runtime_plan_file = (
            output_path
            / "runtime_probe_plan.json"
        )

        runtime_results_file = (
            output_path
            / "runtime_probe_results.json"
        )

        active_plan_file = (
            output_path
            / "active_runtime_probe_plan.json"
        )

        active_results_file = (
            output_path
            / "active_runtime_probe_results.json"
        )

        aggregated_file = (
            output_path
            / "runtime_evidence_aggregated.json"
        )

        stage = "frontend_candidate_adapter"

        try:
            frontend_candidates = (
                write_frontend_operation_candidates(
                    input_file=frontend_input,
                    output_file=frontend_candidates_file,
                )
            )

            stage = "runtime_probe_planner"

            runtime_plan = write_runtime_probe_plan(
                input_file=frontend_candidates_file,
                output_file=runtime_plan_file,
            )

            stage = "runtime_probe_executor"

            runtime_results = run_runtime_probe_file(
                input_file=runtime_plan_file,
                output_file=runtime_results_file,
                base_url=base_url,
            )

            stage = "active_runtime_probe_planner"

            active_plan = (
                write_active_runtime_probe_plan(
                    input_file=str(runtime_plan_file),
                    output_file=str(active_plan_file),
                )
            )

            stage = "active_runtime_probe_executor"

            active_results = (
                run_active_runtime_probe_file(
                    input_file=active_plan_file,
                    output_file=active_results_file,
                    base_url=base_url,
                )
            )

            stage = "runtime_evidence_aggregator"

            aggregated = (
                generate_runtime_evidence_aggregate(
                    read_only_path=runtime_results_file,
                    active_path=active_results_file,
                    output_path=aggregated_file,
                )
            )

        except Exception as exc:
            raise RuntimeError(
                "API operation discovery pipeline failed during "
                f"stage '{stage}': {exc}"
            ) from exc

        return {
            "pipeline": "deterministic_api_operation_discovery",
            "status": "completed",
            "target_url": base_url,
            "frontend_extraction_mode": (
                "persisted_input"
                if frontend_extract_result_file
                else "live"
            ),
            "methodological_boundary": {
                "openapi_used": False,
                "ground_truth_used": False,
                "shadow_api_classification_performed": False,
            },
            "artifacts": {
                "frontend_extract_input": str(
                    frontend_input
                ),
                "frontend_operation_candidates": str(
                    frontend_candidates_file
                ),
                "runtime_probe_plan": str(
                    runtime_plan_file
                ),
                "runtime_probe_results": str(
                    runtime_results_file
                ),
                "active_runtime_probe_plan": str(
                    active_plan_file
                ),
                "active_runtime_probe_results": str(
                    active_results_file
                ),
                "runtime_evidence_aggregated": str(
                    aggregated_file
                ),
            },
            "frontend": {
                "operation_candidate_count": (
                    frontend_candidates.get(
                        "operation_candidate_count"
                    )
                ),
                "summary": frontend_candidates.get(
                    "summary",
                    {},
                ),
            },
            "read_only_runtime": {
                "probe_count": runtime_results.get(
                    "probe_count",
                    0,
                ),
                "runtime_observed_count": runtime_results.get(
                    "runtime_observed_count",
                    0,
                ),
                "inconclusive_or_error_count": runtime_results.get(
                    "inconclusive_or_error_count",
                    0,
                ),
            },
            "controlled_active_runtime": {
                "runtime_evidence_total": (
                    active_results.get(
                        "runtime_evidence_total"
                    )
                ),
                "summary": active_results.get(
                    "summary",
                    {},
                ),
            },
            "aggregate": {
                "read_only_evidence_count": aggregated.get(
                    "read_only_evidence_count",
                    0,
                ),
                "active_evidence_count": aggregated.get(
                    "active_evidence_count",
                    0,
                ),
                "total_evidence_count": aggregated.get(
                    "total_evidence_count",
                    0,
                ),
            },
        }
