from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUTS = {
    "endpoint_coverage": PROJECT_ROOT / "reports" / "evaluation" / "crapi_endpoint_coverage_evaluation.json",
    "shadow_api": PROJECT_ROOT / "reports" / "evaluation" / "crapi_shadow_api_evaluation.json",
    "bola_bfla": PROJECT_ROOT / "reports" / "evaluation" / "crapi_bola_bfla_evaluation.json",
    "mapping": PROJECT_ROOT / "reports" / "evaluation" / "crapi_mapping_evaluation.json",
    "artifact_completeness": PROJECT_ROOT / "reports" / "evaluation" / "crapi_artifact_completeness_evaluation.json",
    "assessment_time": PROJECT_ROOT / "reports" / "evaluation" / "crapi_assessment_time_evaluation.json",
    "false_positive_rate": PROJECT_ROOT / "reports" / "evaluation" / "crapi_false_positive_rate_evaluation.json",
}

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_evaluation_summary.json"
)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_summary(document: Dict[str, Any]) -> Dict[str, Any]:
    return document.get("summary") or document.get("mapping_summary") or {}


def generate_crapi_evaluation_summary(
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    output_path = Path(output_path)

    documents = {}

    for name, path in INPUTS.items():
        documents[name] = {
            "path": str(path),
            "exists": path.exists(),
            "document": _load_json(path) if path.exists() else {},
        }

    endpoint_summary = _safe_summary(
        documents["endpoint_coverage"]["document"]
    )
    shadow_summary = _safe_summary(
        documents["shadow_api"]["document"]
    )
    bola_bfla_summary = _safe_summary(
        documents["bola_bfla"]["document"]
    )
    mapping_summary = _safe_summary(
        documents["mapping"]["document"]
    )
    artifact_summary = _safe_summary(
        documents["artifact_completeness"]["document"]
    )
    assessment_time_summary = _safe_summary(
        documents["assessment_time"]["document"]
    )
    fpr_summary = _safe_summary(
        documents["false_positive_rate"]["document"]
    )

    metrics = [
        {
            "metric": "Endpoint Coverage",
            "formula": "Correctly Discovered Endpoints / Known Endpoints",
            "numerator": endpoint_summary.get("correctly_discovered_endpoints"),
            "denominator": endpoint_summary.get("known_endpoints"),
            "value_percent": endpoint_summary.get("endpoint_coverage_percent"),
            "status": "computed",
            "interpretation": "Measures attack-surface discovery coverage.",
        },
        {
            "metric": "Shadow API Precision",
            "formula": "TP / (TP + FP)",
            "numerator": shadow_summary.get("true_positives"),
            "denominator": (
                shadow_summary.get("true_positives", 0)
                + shadow_summary.get("false_positives", 0)
            ),
            "value_percent": shadow_summary.get("precision_percent"),
            "status": "computed",
            "interpretation": "Measures correctness of reported Shadow API candidates.",
        },
        {
            "metric": "Shadow API Recall",
            "formula": "TP / (TP + FN)",
            "numerator": shadow_summary.get("true_positives"),
            "denominator": (
                shadow_summary.get("true_positives", 0)
                + shadow_summary.get("false_negatives", 0)
            ),
            "value_percent": shadow_summary.get("recall_percent"),
            "status": "computed",
            "interpretation": "Measures proportion of known Shadow APIs detected.",
        },
        {
            "metric": "BOLA/BFLA Precision",
            "formula": "TP / (TP + FP)",
            "numerator": bola_bfla_summary.get("typed_true_positives"),
            "denominator": (
                bola_bfla_summary.get("typed_true_positives", 0)
                + bola_bfla_summary.get("false_positives", 0)
            ),
            "value_percent": bola_bfla_summary.get("precision_percent"),
            "status": "computed_challenge_scoped",
            "interpretation": (
                "Measures correctness of reported authorization vulnerabilities "
                "within the selected challenge-scoped baseline."
            ),
        },
        {
            "metric": "BOLA/BFLA Recall",
            "formula": "TP / (TP + FN)",
            "numerator": bola_bfla_summary.get("typed_true_positives"),
            "denominator": (
                bola_bfla_summary.get("typed_true_positives", 0)
                + bola_bfla_summary.get("false_negatives", 0)
                + bola_bfla_summary.get("type_mismatches", 0)
            ),
            "value_percent": bola_bfla_summary.get("recall_percent"),
            "status": "computed_challenge_scoped",
            "interpretation": (
                "Measures proportion of selected known authorization challenges "
                "detected with the expected type."
            ),
        },
        {
            "metric": "False Positive Rate",
            "formula": "FP / (FP + TN)",
            "numerator": fpr_summary.get("false_positives"),
            "denominator": fpr_summary.get("denominator"),
            "value_percent": fpr_summary.get("false_positive_rate_percent"),
            "status": "not_computable"
            if not fpr_summary.get("computable")
            else "computed",
            "interpretation": fpr_summary.get("reason")
            or "Measures incorrect vulnerability promotion relative to secure cases.",
        },
        {
            "metric": "Mapping Precision",
            "formula": "Correct Generated Mappings / Generated Mappings",
            "numerator": mapping_summary.get("fully_correct_mappings"),
            "denominator": mapping_summary.get("framework_validated_mappings"),
            "value_percent": mapping_summary.get("mapping_precision_percent"),
            "status": "computed_challenge_scoped",
            "interpretation": "Measures correctness of generated contextual mappings.",
        },
        {
            "metric": "Mapping Recall",
            "formula": "Correct Generated Mappings / Expected Relevant Mappings",
            "numerator": mapping_summary.get("fully_correct_mappings"),
            "denominator": mapping_summary.get("ground_truth_mappings"),
            "value_percent": mapping_summary.get("mapping_recall_percent"),
            "status": "computed_challenge_scoped",
            "interpretation": "Measures coverage of expected relevant contextual mappings.",
        },
        {
            "metric": "Artefact Completeness",
            "formula": "Present Required Fields / Expected Required Fields",
            "numerator": artifact_summary.get("present_required_fields"),
            "denominator": artifact_summary.get("expected_required_fields"),
            "value_percent": artifact_summary.get("artifact_completeness_percent"),
            "status": "computed",
            "interpretation": "Measures structural completeness of generated assessment artefacts.",
        },
        {
            "metric": "Assessment Time",
            "formula": "End Time - Start Time",
            "numerator": assessment_time_summary.get("duration_seconds"),
            "denominator": None,
            "value_percent": None,
            "value_seconds": assessment_time_summary.get("duration_seconds"),
            "value_minutes": assessment_time_summary.get("duration_minutes"),
            "status": "computed_audit_proxy",
            "interpretation": (
                "Provides a secondary operational-cost measure based on "
                "filesystem artefact timestamps, not a clean benchmark runtime."
            ),
        },
    ]

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_consolidated_evaluation_summary",
        "status": "completed",
        "scope": {
            "target": "OWASP crAPI",
            "endpoint_coverage_scope": "documented OpenAPI endpoints plus frozen Shadow API ground truth",
            "bola_bfla_scope": "selected official BOLA/BFLA challenge baseline",
            "mapping_scope": "selected official BOLA/BFLA challenge mapping baseline",
        },
        "methodological_boundary": {
            "ground_truth_used_for_discovery": False,
            "ground_truth_used_for_classification": False,
            "ground_truth_used_for_mapping_generation": False,
            "ground_truth_used_only_for_final_evaluation": True,
            "additional_framework_findings_outside_challenge_ground_truth_are_not_automatically_substantive_false_positives": True,
        },
        "inputs": {
            name: {
                "path": payload["path"],
                "exists": payload["exists"],
            }
            for name, payload in documents.items()
        },
        "metrics": metrics,
        "source_summaries": {
            "endpoint_coverage": endpoint_summary,
            "shadow_api": shadow_summary,
            "bola_bfla": bola_bfla_summary,
            "mapping": mapping_summary,
            "artifact_completeness": artifact_summary,
            "assessment_time": assessment_time_summary,
            "false_positive_rate": fpr_summary,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = generate_crapi_evaluation_summary()

    print()
    print("crAPI CONSOLIDATED EVALUATION SUMMARY")
    print("=" * 70)

    for metric in result["metrics"]:
        name = metric["metric"]
        status = metric["status"]

        if metric.get("value_percent") is not None:
            value = f'{metric["value_percent"]:.2f}%'
        elif metric.get("value_seconds") is not None:
            value = (
                f'{metric["value_seconds"]:.2f} seconds '
                f'({metric["value_minutes"]:.2f} minutes)'
            )
        else:
            value = "NOT COMPUTABLE"

        print(f"{name:<25} {value:<30} {status}")

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
