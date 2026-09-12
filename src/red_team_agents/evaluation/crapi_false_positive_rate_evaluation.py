from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[3]

ANALYST_FINDINGS_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "analysis"
    / "validated_analyst_findings.json"
)

BOLA_BFLA_EVALUATION_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_bola_bfla_evaluation.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_false_positive_rate_evaluation.json"
)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalise_expected_denials(items: Any) -> List[Dict[str, Any]]:
    if not isinstance(items, list):
        return []

    return [
        item
        for item in items
        if isinstance(item, dict)
    ]


def evaluate_crapi_false_positive_rate(
    analyst_findings_path: Path = ANALYST_FINDINGS_PATH,
    bola_bfla_evaluation_path: Path = BOLA_BFLA_EVALUATION_PATH,
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    analyst_findings_path = Path(analyst_findings_path)
    bola_bfla_evaluation_path = Path(bola_bfla_evaluation_path)
    output_path = Path(output_path)

    analyst_findings = _load_json(analyst_findings_path)
    bola_bfla_evaluation = _load_json(bola_bfla_evaluation_path)

    expected_denials = _normalise_expected_denials(
        analyst_findings.get("expected_denials", [])
    )

    false_positive_findings = bola_bfla_evaluation.get(
        "false_positive_findings",
        [],
    )

    if not isinstance(false_positive_findings, list):
        false_positive_findings = []

    true_negatives = len(expected_denials)
    false_positives = len(false_positive_findings)

    denominator = false_positives + true_negatives

    computable = true_negatives > 0 and denominator > 0

    false_positive_rate = (
        false_positives / denominator
        if computable
        else None
    )

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_false_positive_rate",
        "status": "completed_not_computable"
        if not computable
        else "completed",
        "metric_definition": {
            "name": "False Positive Rate",
            "formula": "FP / (FP + TN)",
        },
        "methodological_boundary": {
            "true_negatives_must_come_from_observed_expected_denials": True,
            "true_negatives_invented_or_assumed": False,
            "ground_truth_used_only_for_final_evaluation": True,
        },
        "inputs": {
            "analyst_findings": str(analyst_findings_path),
            "bola_bfla_evaluation": str(bola_bfla_evaluation_path),
        },
        "summary": {
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "denominator": denominator,
            "false_positive_rate": false_positive_rate,
            "false_positive_rate_percent": (
                false_positive_rate * 100
                if false_positive_rate is not None
                else None
            ),
            "computable": computable,
            "reason": None
            if computable
            else (
                "False Positive Rate is not computable because the current "
                "validated analyst artefact contains no observed expected_denials "
                "that can be used as true negatives."
            ),
        },
        "false_positive_findings": false_positive_findings,
        "true_negative_expected_denials": expected_denials,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_false_positive_rate()
    summary = result["summary"]

    print()
    print("crAPI FALSE POSITIVE RATE EVALUATION")
    print("=" * 70)

    print("False positives:", summary["false_positives"])
    print("True negatives:", summary["true_negatives"])
    print("Denominator:", summary["denominator"])
    print("Computable:", summary["computable"])

    print()
    print("METRIC")
    print("-" * 70)

    if summary["computable"]:
        print(
            f'False Positive Rate: '
            f'{summary["false_positive_rate_percent"]:.2f}%'
        )
    else:
        print("False Positive Rate: NOT COMPUTABLE")
        print("Reason:", summary["reason"])

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
