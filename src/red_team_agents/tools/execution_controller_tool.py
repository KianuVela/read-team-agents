from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Type

import pprint
import os

from crewai.tools import BaseTool
from pydantic import BaseModel, ConfigDict, Field

from red_team_agents.core.builders.execution_context_builder import (
    ExecutionContextBuilder,
)

from red_team_agents.core.orchestration.execution_runtime_factory import (
    ExecutionRuntimeFactory,
)

from red_team_agents.core.planning.test_plan_parser import (
    TestPlanParser,
)


class ExecutionControllerToolInput(BaseModel):
    """
    Input schema for the ExecutionControllerTool.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    authentication_context_file: str = Field(
        ...,
        description="Path to authentication_context.json",
    )

    object_context_file: str = Field(
        ...,
        description="Path to object_context.json",
    )

    test_plan_file: str = Field(
        ...,
        description="Path to test_planning_report.json",
    )


class ExecutionControllerTool(BaseTool):
    """
    CrewAI wrapper around the cognitive execution layer.
    """

    name: str = "execution_controller"

    description: str = (
        "Loads the execution artefacts from disk and executes "
        "the deterministic cognitive execution pipeline."
    )

    args_schema: Type[BaseModel] = (
        ExecutionControllerToolInput
    )

    def __init__(self) -> None:

        super().__init__()

        self._builder = ExecutionContextBuilder()

        self._parser = TestPlanParser()

        self._controller = (
            ExecutionRuntimeFactory.create()
        )

    def _run(
        self,
        authentication_context_file: str,
        object_context_file: str,
        test_plan_file: str,
    ):

        authentication_context = self._load_json(
            authentication_context_file,
        )

        print("\n========== FILE LOADED ==========")
        print(authentication_context_file)

        print("\n========== ROOT KEYS ==========")
        print(authentication_context.keys())
        print("\n========== FILE ABSOLUTE PATH ==========")
        print(Path(authentication_context_file).resolve())

        print("\n========== LOGIN_RESULTS EXISTS ==========")
        print("login_results" in authentication_context)

        print("\n========== LOGIN_RESULTS TYPE ==========")

        print(
            type(
                authentication_context.get(
                    "login_results",
                )
            )
        )

       

        print("\n========== AUTHENTICATION CONTEXT ==========")
        pprint.pp(authentication_context, width=120)

        object_context = self._load_json(
            object_context_file,
        )

        test_plan_report = self._load_markdown(
            test_plan_file,
        )

        test_plan = self._parser.parse(
            test_plan_report,
        )

        print(
            "[ExecutionControllerTool] Parsed test cases:",
            len(test_plan.test_cases),
        )

        # --------------------------------------------------
        # RESOLVE KALI EXECUTION TARGET
        # --------------------------------------------------

        execution_target_url = os.getenv(
            "EXECUTION_TARGET_URL"
        )

        if (
            not isinstance(execution_target_url, str)
            or not execution_target_url.strip()
        ):
            raise ValueError(
                "EXECUTION_TARGET_URL is not configured. "
                "The ExecutionController requires a target "
                "URL reachable from KaliMCPTool."
            )

        execution_target_url = (
            execution_target_url
            .strip()
            .rstrip("/")
        )

        print(
            "\n========== EXECUTION TARGET URL =========="
        )
        print(execution_target_url)

        execution_context, resource_models = (
            self._builder.build(
                authentication_context=authentication_context,
                object_context=object_context,
                test_plan=test_plan,
                execution_target_url=execution_target_url,
            )
        )

        print(
            "\n========== EXECUTION CONTEXT TARGET =========="
        )
        print(
            execution_context.data.get(
                "execution_target_url"
            )
        )

        results = []

        for resource in resource_models:

            result = self._controller.run(
                context=execution_context,
                resource=resource,
            )

            results.append(result)

        authorization_evidence_files = (
            self.save_authorization_evidence(
                results=results,
            )
        )

        print(
            "\n========== AUTHORIZATION EVIDENCE FILES =========="
        )
        pprint.pp(
            authorization_evidence_files,
            width=120,
        )

        return results
        
    def save_authorization_evidence(
        self,
        results: list[Any],
    ) -> dict[str, Any]:
        """
        Save authorization evidence summaries generated during execution.

        This method exports the authorization evidence already attached
        to each ExecutionResult.evidence object. It does not reclassify,
        retest, or modify execution results.
        """

        output_dir = Path(
            "outputs/execution"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_file = output_dir / "authorization_evidence_summary.json"
        markdown_file = output_dir / "authorization_evidence_summary.md"

        authorization_summaries = []

        for index, result in enumerate(
            results,
            start=1,
        ):
            evidence = getattr(
                result,
                "evidence",
                None,
            ) or {}

            summary = evidence.get(
                "authorization_evidence_summary"
            )

            if not isinstance(
                summary,
                dict,
            ):
                continue

            matched_identifiers = evidence.get(
                "baseline_matched_identifiers",
                [],
            ) or []

            matched_identifier_sample = matched_identifiers[:20]

            authorization_summaries.append(
                {
                    "index": index,
                    "success": getattr(
                        result,
                        "success",
                        None,
                    ),
                    "message": getattr(
                        result,
                        "message",
                        None,
                    ),
                    "tool": evidence.get(
                        "tool"
                    ),
                    "arguments": evidence.get(
                        "arguments"
                    ),
                    "http_status": evidence.get(
                        "http_status"
                    ),
                    "authorization_outcome": evidence.get(
                        "authorization_outcome"
                    ),
                    "authorization_finding": evidence.get(
                        "authorization_finding"
                    ),
                    "vulnerability_decision": evidence.get(
                        "vulnerability_decision"
                    ),
                    "vulnerability_decision_vulnerable": evidence.get(
                        "vulnerability_decision_vulnerable"
                    ),
                    "vulnerability_decision_confidence": evidence.get(
                        "vulnerability_decision_confidence"
                    ),
                    "baseline_recorded": evidence.get(
                        "baseline_recorded"
                    ),
                    "baseline_comparison": evidence.get(
                        "baseline_comparison"
                    ),
                    "baseline_comparison_confidence": evidence.get(
                        "baseline_comparison_confidence"
                    ),
                    "baseline_matched_identifiers": evidence.get(
                        "baseline_matched_identifiers",
                        [],
                    ),
                    "baseline_matched_identifier_count": len(
                        matched_identifiers
                    ),
                    "baseline_matched_identifier_sample": matched_identifier_sample,
                    "baseline_comparison_explanation": evidence.get(
                        "baseline_comparison_explanation"
                    ),

                    # Temporary debug fields for baseline analysis
                    "body_json_preview": str(
                        evidence.get(
                            "body_json"
                        )
                    )[:1000],
                    "request_json_body": evidence.get(
                        "request_json_body"
                    ),
                    "authorization_evidence_summary": summary,
                }
            )

        payload = {
            "metadata": {
                "artifact_type": "authorization_evidence_summary",
                "total_execution_results": len(
                    results
                ),
                "total_authorization_summaries": len(
                    authorization_summaries
                ),
            },
            "authorization_evidence_summaries": authorization_summaries,
        }

        with json_file.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                payload,
                file,
                indent=4,
                ensure_ascii=False,
            )

        markdown_content = (
            self._build_authorization_evidence_markdown(
                payload=payload,
            )
        )

        markdown_file.write_text(
            markdown_content,
            encoding="utf-8",
        )

        return {
            "authorization_evidence_json_file": str(
                json_file
            ),
            "authorization_evidence_markdown_file": str(
                markdown_file
            ),
            "total_authorization_summaries": len(
                authorization_summaries
            ),
        }

    # HELPER
    def _build_authorization_evidence_markdown(
        self,
        payload: dict[str, Any],
    ) -> str:
        """
        Build a human-readable Markdown authorization evidence report.
        """

        metadata = payload.get(
            "metadata",
            {},
        )

        summaries = payload.get(
            "authorization_evidence_summaries",
            [],
        )

        lines = [
            "# Authorization Evidence Summary",
            "",
            "## Overview",
            "",
            f"- Total execution results: {metadata.get('total_execution_results')}",
            f"- Total authorization summaries: {metadata.get('total_authorization_summaries')}",
            "",
        ]

        if not summaries:
            lines.append(
                "No authorization evidence summaries were generated."
            )

            return "\n".join(
                lines
            )

        for item in summaries:

            summary = item.get(
                "authorization_evidence_summary",
                {},
            )

            matched_identifiers = item.get(
                "baseline_matched_identifiers",
                [],
            ) or []

            lines.extend(
                [
                    f"## Result {item.get('index')}: {summary.get('title')}",
                    "",
                    f"- Success: {item.get('success')}",
                    f"- HTTP status: {item.get('http_status')}",
                    f"- Authorization outcome: {item.get('authorization_outcome')}",
                    f"- Authorization finding: {item.get('authorization_finding')}",
                    f"- Vulnerability decision: {item.get('vulnerability_decision')}",
                    f"- Vulnerable: {item.get('vulnerability_decision_vulnerable')}",
                    f"- Decision confidence: {item.get('vulnerability_decision_confidence')}",
                    f"- Baseline recorded: {item.get('baseline_recorded')}",
                    f"- Baseline comparison: {item.get('baseline_comparison')}",
                    f"- Baseline confidence: {item.get('baseline_comparison_confidence')}",
                    "",
                    "**Interpretation:**",
                    "",
                    str(
                        summary.get(
                            "summary",
                            "",
                        )
                    ),
                    "",
                ]
            )

            if matched_identifiers:

                visible_identifiers = matched_identifiers[:20]

                lines.extend(
                    [
                        "**Matched identifiers:**",
                        "",
                        ", ".join(
                            str(identifier)
                            for identifier in visible_identifiers
                        ),
                    ]
                )

                remaining = (
                    len(matched_identifiers)
                    - len(visible_identifiers)
                )

                if remaining > 0:
                    lines.append(
                        f"... plus {remaining} additional identifiers."
                    )

                lines.append(
                    ""
                )

            explanation = item.get(
                "baseline_comparison_explanation"
            )

            if explanation:
                lines.extend(
                    [
                        "**Baseline explanation:**",
                        "",
                        str(
                            explanation
                        ),
                        "",
                    ]
                )

        return "\n".join(
            lines
        )


    @staticmethod
    def _load_json(
        file_path: str,
    ) -> dict:
        """
        Load one execution artefact from disk.
        """

        path = Path(file_path)

        if not path.exists():

            raise FileNotFoundError(
                f"Execution artefact not found: {file_path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as f:

            return json.load(f)


    @staticmethod
    def _load_markdown(
        file_path: str,
    ) -> str:
        """
        Load one markdown execution artefact.
        """

        path = Path(file_path)

        if not path.exists():

            raise FileNotFoundError(
                f"Execution artefact not found: {file_path}"
            )

        return path.read_text(
            encoding="utf-8",
        )