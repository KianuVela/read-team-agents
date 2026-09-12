from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[3]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_artifact_completeness_evaluation.json"
)


ARTIFACT_SPECS = [
    {
        "name": "runtime_evidence_aggregated",
        "path": PROJECT_ROOT / "reports" / "api_discovery" / "runtime_evidence_aggregated.json",
        "required_fields": [
            "source",
            "base_url",
            "read_only_evidence_count",
            "active_evidence_count",
            "total_evidence_count",
            "results",
        ],
        "required_result_fields": [
            "method",
            "template_path",
            "probe_path",
            "classification",
            "runtime_observed",
            "status_code",
            "content_type",
            "baseline_status_code",
            "differential_evidence",
        ],
    },
    {
        "name": "shadow_candidate_validation",
        "path": PROJECT_ROOT / "reports" / "shadow_api" / "shadow_candidate_validation.json",
        "required_fields": [
            "summary",
            "confirmed_candidates",
        ],
    },
    {
        "name": "validated_analyst_findings",
        "path": PROJECT_ROOT / "outputs" / "analysis" / "validated_analyst_findings.json",
        "required_fields": [
            "status",
            "processor",
            "source",
            "provenance",
            "confirmed_static_findings",
            "confirmed_dynamic_findings",
            "confirmed_shadow_findings",
            "mapping_ready_findings",
            "threat_compliance_context_findings",
            "metadata",
            "consistency_checks",
        ],
        "required_result_fields": [
            "canonical_id",
            "finding_type",
            "endpoint",
            "http_method",
            "vulnerability_decision",
            "reason",
        ],
        "result_collection": "threat_compliance_context_findings",
    },
    {
        "name": "validated_compliance_mapping",
        "path": PROJECT_ROOT / "outputs" / "compliance" / "validated_compliance_mapping.json",
        "required_fields": [
            "status",
            "processor",
            "source",
            "source_provenance",
            "validated_mappings",
            "mapping_summary",
            "mapping_checks",
            "consistency_checks",
        ],
        "required_result_fields": [
            "canonical_id",
            "finding_type",
            "endpoint",
            "http_method",
            "owasp",
            "mitre_attack",
            "nis2",
        ],
        "result_collection": "validated_mappings",
    },
    {
        "name": "shadow_api_evaluation",
        "path": PROJECT_ROOT / "reports" / "evaluation" / "crapi_shadow_api_evaluation.json",
        "required_fields": [
            "target",
            "evaluation_scope",
            "ground_truth_source",
            "framework_predictions_source",
            "summary",
            "true_positive_operations",
            "false_positive_operations",
            "false_negative_operations",
            "methodological_note",
        ],
    },
    {
        "name": "bola_bfla_evaluation",
        "path": PROJECT_ROOT / "reports" / "evaluation" / "crapi_bola_bfla_evaluation.json",
        "required_fields": [
            "schema_version",
            "evaluation",
            "status",
            "methodological_boundary",
            "inputs",
            "summary",
            "true_positive_findings",
            "type_mismatch_findings",
            "false_positive_findings",
            "false_negative_findings",
        ],
    },
    {
        "name": "mapping_evaluation",
        "path": PROJECT_ROOT / "reports" / "evaluation" / "crapi_mapping_evaluation.json",
        "required_fields": [
            "schema_version",
            "evaluation",
            "status",
            "methodological_boundary",
            "scope_note",
            "inputs",
            "summary",
            "matched_mappings",
            "missing_ground_truth_mappings",
            "out_of_scope_framework_mappings",
        ],
    },
    {
        "name": "endpoint_coverage_evaluation",
        "path": PROJECT_ROOT / "reports" / "evaluation" / "crapi_endpoint_coverage_evaluation.json",
        "required_fields": [
            "schema_version",
            "evaluation",
            "status",
            "methodological_boundary",
            "inputs",
            "summary",
            "correctly_discovered_endpoints",
            "missed_known_endpoints",
            "unknown_discovered_endpoints",
        ],
    },
]


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _field_present(document: Dict[str, Any], field: str) -> bool:
    return field in document and document[field] is not None


def _evaluate_top_level_fields(
    document: Dict[str, Any],
    required_fields: List[str],
) -> Dict[str, Any]:

    present = [
        field
        for field in required_fields
        if _field_present(document, field)
    ]

    missing = [
        field
        for field in required_fields
        if field not in present
    ]

    return {
        "expected_required_fields": len(required_fields),
        "present_required_fields": len(present),
        "missing_required_fields": missing,
        "present_fields": present,
    }


def _evaluate_result_fields(
    document: Dict[str, Any],
    spec: Dict[str, Any],
) -> Dict[str, Any]:

    required = spec.get("required_result_fields", [])

    if not required:
        return {
            "evaluated": False,
            "expected_required_result_fields": 0,
            "present_required_result_fields": 0,
            "missing_result_fields": [],
            "evaluated_items": 0,
        }

    collection_name = spec.get("result_collection") or "results"
    collection = document.get(collection_name, [])

    if not isinstance(collection, list) or not collection:
        return {
            "evaluated": True,
            "expected_required_result_fields": len(required),
            "present_required_result_fields": 0,
            "missing_result_fields": required,
            "evaluated_items": 0,
        }

    missing_by_item = []
    total_expected = 0
    total_present = 0

    for index, item in enumerate(collection):
        if not isinstance(item, dict):
            missing_by_item.append(
                {
                    "item_index": index,
                    "missing_fields": required,
                }
            )
            total_expected += len(required)
            continue

        missing = []

        for field in required:
            total_expected += 1

            if _field_present(item, field):
                total_present += 1
            else:
                missing.append(field)

        if missing:
            missing_by_item.append(
                {
                    "item_index": index,
                    "identifier": item.get("canonical_id")
                    or item.get("frontend_constant")
                    or item.get("method"),
                    "missing_fields": missing,
                }
            )

    return {
        "evaluated": True,
        "expected_required_result_fields": total_expected,
        "present_required_result_fields": total_present,
        "missing_result_fields": missing_by_item,
        "evaluated_items": len(collection),
    }


def evaluate_crapi_artifact_completeness(
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    output_path = Path(output_path)

    artifact_results = []

    expected_required_fields_total = 0
    present_required_fields_total = 0

    for spec in ARTIFACT_SPECS:
        path = Path(spec["path"])

        if not path.exists():
            expected_count = len(spec.get("required_fields", []))
            expected_required_fields_total += expected_count

            artifact_results.append(
                {
                    "artifact": spec["name"],
                    "path": str(path),
                    "exists": False,
                    "expected_required_fields": expected_count,
                    "present_required_fields": 0,
                    "missing_required_fields": spec.get("required_fields", []),
                    "result_field_evaluation": {
                        "evaluated": False,
                        "reason": "artifact_missing",
                    },
                    "completeness_percent": 0.0,
                }
            )
            continue

        document = _load_json(path)

        top_level = _evaluate_top_level_fields(
            document=document,
            required_fields=spec.get("required_fields", []),
        )

        result_fields = _evaluate_result_fields(
            document=document,
            spec=spec,
        )

        artifact_expected = (
            top_level["expected_required_fields"]
            + result_fields.get("expected_required_result_fields", 0)
        )

        artifact_present = (
            top_level["present_required_fields"]
            + result_fields.get("present_required_result_fields", 0)
        )

        expected_required_fields_total += artifact_expected
        present_required_fields_total += artifact_present

        completeness = (
            artifact_present / artifact_expected
            if artifact_expected
            else 1.0
        )

        artifact_results.append(
            {
                "artifact": spec["name"],
                "path": str(path),
                "exists": True,
                "expected_required_fields": artifact_expected,
                "present_required_fields": artifact_present,
                "missing_required_fields": top_level["missing_required_fields"],
                "result_field_evaluation": result_fields,
                "completeness_percent": completeness * 100,
            }
        )

    overall_completeness = (
        present_required_fields_total / expected_required_fields_total
        if expected_required_fields_total
        else 0.0
    )

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_artifact_completeness",
        "status": "completed",
        "metric_definition": {
            "name": "Artefact Completeness",
            "formula": "Present Required Fields / Expected Required Fields",
        },
        "summary": {
            "evaluated_artifacts": len(ARTIFACT_SPECS),
            "expected_required_fields": expected_required_fields_total,
            "present_required_fields": present_required_fields_total,
            "missing_required_fields": (
                expected_required_fields_total - present_required_fields_total
            ),
            "artifact_completeness": overall_completeness,
            "artifact_completeness_percent": overall_completeness * 100,
        },
        "artifacts": artifact_results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_artifact_completeness()
    summary = result["summary"]

    print()
    print("crAPI ARTEFACT COMPLETENESS EVALUATION")
    print("=" * 70)

    print("Evaluated artefacts:", summary["evaluated_artifacts"])
    print("Expected required fields:", summary["expected_required_fields"])
    print("Present required fields:", summary["present_required_fields"])
    print("Missing required fields:", summary["missing_required_fields"])

    print()
    print("METRIC")
    print("-" * 70)
    print(
        f'Artifact Completeness: '
        f'{summary["artifact_completeness_percent"]:.2f}%'
    )

    print()
    print("ARTEFACT DETAILS")
    print("-" * 70)

    for artifact in result["artifacts"]:
        status = "OK" if artifact["exists"] else "MISSING"
        print(
            f'{status:<8} '
            f'{artifact["artifact"]:<35} '
            f'{artifact["completeness_percent"]:.2f}%'
        )

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
