from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


Operation = Tuple[str, str]

PARAMETER_PATTERNS = (
    re.compile(r"\{[^{}]+\}"),
    re.compile(r"<[^<>]+>"),
)


def normalize_path(path: str) -> str:
    path = path.strip()

    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r"/+", "/", path)

    for pattern in PARAMETER_PATTERNS:
        path = pattern.sub("{param}", path)

    if len(path) > 1:
        path = path.rstrip("/")

    return path


def normalize_operation(
    method: str,
    path: str,
) -> Operation:
    return (
        method.upper().strip(),
        normalize_path(path),
    )


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_ground_truth_shadows(
    data: Dict[str, Any],
) -> Set[Operation]:
    operations: Set[Operation] = set()

    for item in data.get("shadow_operations", []):
        method = item.get("method")
        path = item.get("path")

        if not method or not path:
            continue

        operations.add(
            normalize_operation(method, path)
        )

    return operations


def extract_confirmed_framework_shadows(
    data: Dict[str, Any],
) -> Set[Operation]:
    operations: Set[Operation] = set()

    for item in data.get(
        "confirmed_candidates",
        [],
    ):
        if (
            item.get("validation_status")
            != "CONFIRMED_AGAINST_OPENAPI_BASELINE"
        ):
            continue

        method = item.get("method")
        path = item.get("path")

        if not method or not path:
            continue

        operations.add(
            normalize_operation(method, path)
        )

    return operations


def _operation_to_dict(
    operation: Operation,
) -> Dict[str, str]:
    method, path = operation

    return {
        "method": method,
        "path": path,
    }


def evaluate_crapi_shadow_detection(
    ground_truth_path: Path,
    validation_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    ground_truth_data = _load_json(
        ground_truth_path
    )

    validation_data = _load_json(
        validation_path
    )

    ground_truth = extract_ground_truth_shadows(
        ground_truth_data
    )

    predicted = extract_confirmed_framework_shadows(
        validation_data
    )

    true_positives = ground_truth & predicted
    false_positives = predicted - ground_truth
    false_negatives = ground_truth - predicted

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    result: Dict[str, Any] = {
        "target": "OWASP crAPI",
        "evaluation_scope": (
            "Consolidated Shadow API operation "
            "detection across Workshop, Identity, "
            "and Community."
        ),
        "ground_truth_source": str(
            ground_truth_path
        ),
        "framework_predictions_source": str(
            validation_path
        ),
        "summary": {
            "ground_truth_shadow_operations": len(
                ground_truth
            ),
            "framework_confirmed_shadow_operations": len(
                predicted
            ),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "precision_percent": round(
                precision * 100,
                2,
            ),
            "recall_percent": round(
                recall * 100,
                2,
            ),
            "f1_percent": round(
                f1 * 100,
                2,
            ),
        },
        "true_positive_operations": [
            _operation_to_dict(operation)
            for operation in sorted(
                true_positives
            )
        ],
        "false_positive_operations": [
            _operation_to_dict(operation)
            for operation in sorted(
                false_positives
            )
        ],
        "false_negative_operations": [
            _operation_to_dict(operation)
            for operation in sorted(
                false_negatives
            )
        ],
        "methodological_note": (
            "True negatives are not defined because "
            "the evaluated universe is the set of "
            "implemented API operations rather than "
            "a closed universe of all possible HTTP "
            "method/path combinations. Therefore, "
            "accuracy and specificity are not reported."
        ),
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    return result