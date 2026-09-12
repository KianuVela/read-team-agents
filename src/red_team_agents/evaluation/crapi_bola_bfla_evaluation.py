from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]

GROUND_TRUTH_PATH = (
    PROJECT_ROOT
    / "reports"
    / "ground_truth"
    / "crapi_bola_bfla_ground_truth.json"
)

FRAMEWORK_FINDINGS_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "analysis"
    / "validated_analyst_findings.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_bola_bfla_evaluation.json"
)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalise_method(value: Any) -> str:
    return str(value or "").strip().upper()


def _normalise_path(value: Any) -> str:
    path = str(value or "").strip()

    if not path:
        return ""

    if not path.startswith("/"):
        path = "/" + path

    return path.rstrip("/") or "/"


def _framework_finding_type(finding: Dict[str, Any]) -> str:
    finding_type = str(finding.get("finding_type", "")).strip().upper()
    endpoint = _normalise_path(finding.get("endpoint")).lower()
    test_id = str(finding.get("test_id", "")).strip().upper()

    if "/management/" in endpoint:
        return "BFLA"

    if finding_type in {"BOLA", "BFLA"}:
        return finding_type

    if test_id.startswith("BOLA"):
        return "BOLA"

    if test_id.startswith("BFLA"):
        return "BFLA"

    return ""


def _framework_findings(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = document.get("mapping_ready_findings", [])

    if not isinstance(findings, list):
        return []

    result = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        finding_type = _framework_finding_type(finding)

        if finding_type not in {"BOLA", "BFLA"}:
            continue

        copied = dict(finding)
        copied["evaluated_finding_type"] = finding_type
        copied["evaluated_endpoint"] = _normalise_path(
            copied.get("endpoint")
        )
        copied["evaluated_method"] = _normalise_method(
            copied.get("http_method")
        )

        result.append(copied)

    return result


def _matches_ground_truth(
    gt: Dict[str, Any],
    finding: Dict[str, Any],
) -> bool:
    hints = gt.get("matching_hints", {})

    expected_method = _normalise_method(
        hints.get("method")
        or gt.get("expected_method")
    )

    finding_method = _normalise_method(
        finding.get("evaluated_method")
        or finding.get("http_method")
    )

    if expected_method and finding_method != expected_method:
        return False

    endpoint = _normalise_path(
        finding.get("evaluated_endpoint")
        or finding.get("endpoint")
    )

    path_equals = hints.get("path_equals")

    if path_equals:
        return endpoint == _normalise_path(path_equals)

    path_contains = hints.get("path_contains", [])

    if isinstance(path_contains, str):
        path_contains = [path_contains]

    if path_contains:
        lowered_endpoint = endpoint.lower()

        return all(
            str(fragment).lower() in lowered_endpoint
            for fragment in path_contains
        )

    pattern = gt.get("expected_endpoint_pattern")

    if pattern:
        return endpoint == _normalise_path(pattern)

    return False


def _best_match(
    gt: Dict[str, Any],
    findings: List[Dict[str, Any]],
    used_indexes: set[int],
) -> Optional[tuple[int, Dict[str, Any]]]:
    candidates = []

    for index, finding in enumerate(findings):

        if index in used_indexes:
            continue

        if _matches_ground_truth(gt, finding):
            candidates.append((index, finding))

    if not candidates:
        return None

    expected_type = str(
        gt.get("expected_finding_type", "")
    ).strip().upper()

    candidates.sort(
        key=lambda item: (
            item[1].get("evaluated_finding_type") != expected_type,
            item[1].get("canonical_id", ""),
        )
    )

    return candidates[0]


def evaluate_crapi_bola_bfla_detection(
    ground_truth_path: Path = GROUND_TRUTH_PATH,
    framework_findings_path: Path = FRAMEWORK_FINDINGS_PATH,
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    ground_truth_path = Path(ground_truth_path)
    framework_findings_path = Path(framework_findings_path)
    output_path = Path(output_path)

    ground_truth = _load_json(ground_truth_path)
    framework_document = _load_json(framework_findings_path)

    gt_findings = ground_truth.get("ground_truth_findings", [])

    framework_findings = _framework_findings(framework_document)

    used_framework_indexes: set[int] = set()

    true_positives = []
    type_mismatches = []
    false_negatives = []

    for gt in gt_findings:

        match = _best_match(
            gt=gt,
            findings=framework_findings,
            used_indexes=used_framework_indexes,
        )

        if match is None:
            false_negatives.append(gt)
            continue

        index, finding = match
        used_framework_indexes.add(index)

        expected_type = str(
            gt.get("expected_finding_type", "")
        ).strip().upper()

        actual_type = finding.get("evaluated_finding_type")

        record = {
            "ground_truth_id": gt.get("ground_truth_id"),
            "challenge_name": gt.get("challenge_name"),
            "expected_finding_type": expected_type,
            "framework_canonical_id": finding.get("canonical_id"),
            "framework_finding_type": actual_type,
            "method": finding.get("evaluated_method"),
            "endpoint": finding.get("evaluated_endpoint"),
        }

        if actual_type == expected_type:
            true_positives.append(record)
        else:
            type_mismatches.append(record)

    false_positives = []

    for index, finding in enumerate(framework_findings):

        if index in used_framework_indexes:
            continue

        false_positives.append(
            {
                "framework_canonical_id": finding.get("canonical_id"),
                "framework_finding_type": finding.get(
                    "evaluated_finding_type"
                ),
                "method": finding.get("evaluated_method"),
                "endpoint": finding.get("evaluated_endpoint"),
            }
        )

    typed_tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives) + len(type_mismatches)

    precision = (
        typed_tp / (typed_tp + fp)
        if typed_tp + fp > 0
        else 0.0
    )

    recall = (
        typed_tp / (typed_tp + fn)
        if typed_tp + fn > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall > 0
        else 0.0
    )

    endpoint_matches = typed_tp + len(type_mismatches)

    endpoint_recall = (
        endpoint_matches / len(gt_findings)
        if gt_findings
        else 0.0
    )

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_bola_bfla_detection",
        "status": "completed",
        "methodological_boundary": {
            "ground_truth_used_for_discovery": False,
            "ground_truth_used_for_classification": False,
            "ground_truth_used_only_for_evaluation": True,
        },
        "inputs": {
            "ground_truth": str(ground_truth_path),
            "framework_findings": str(framework_findings_path),
        },
        "summary": {
            "ground_truth_findings": len(gt_findings),
            "framework_confirmed_bola_bfla_findings": len(
                framework_findings
            ),
            "typed_true_positives": typed_tp,
            "false_positives": fp,
            "false_negatives": len(false_negatives),
            "type_mismatches": len(type_mismatches),
            "precision_percent": precision * 100,
            "recall_percent": recall * 100,
            "f1_percent": f1 * 100,
            "endpoint_level_matches": endpoint_matches,
            "endpoint_level_recall_percent": endpoint_recall * 100,
        },
        "true_positive_findings": true_positives,
        "type_mismatch_findings": type_mismatches,
        "false_positive_findings": false_positives,
        "false_negative_findings": false_negatives,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_bola_bfla_detection()

    summary = result["summary"]

    print()
    print("crAPI BOLA/BFLA DETECTION EVALUATION")
    print("=" * 70)

    print(
        "Ground-truth BOLA/BFLA findings:",
        summary["ground_truth_findings"],
    )

    print(
        "Framework confirmed BOLA/BFLA findings:",
        summary["framework_confirmed_bola_bfla_findings"],
    )

    print()
    print("CONFUSION COUNTS")
    print("-" * 70)

    print("Typed TP:", summary["typed_true_positives"])
    print("FP:", summary["false_positives"])
    print("FN:", summary["false_negatives"])
    print("Type mismatches:", summary["type_mismatches"])

    print()
    print("METRICS")
    print("-" * 70)

    print(f'Precision: {summary["precision_percent"]:.2f}%')
    print(f'Recall:    {summary["recall_percent"]:.2f}%')
    print(f'F1-score:  {summary["f1_percent"]:.2f}%')
    print(
        f'Endpoint-level recall: '
        f'{summary["endpoint_level_recall_percent"]:.2f}%'
    )

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
