import re
from typing import Any, Dict, Set, Tuple


Operation = Tuple[str, str]


def canonicalize_evaluation_path(path: str) -> str:
    """
    Canonicalize parameter names before Ground Truth comparison.

    Examples:
        /orders/{orderId}
        /orders/{order_id}
        /orders/{param}
        /orders/<orderId>

    all become:
        /orders/{param}
    """

    if not path:
        return "/"

    path = path.strip()

    path = re.sub(
        r"\{[^/{}]+\}",
        "{param}",
        path,
    )

    path = re.sub(
        r"<[^/<>]+>",
        "{param}",
        path,
    )

    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r"/+", "/", path)

    if len(path) > 1:
        path = path.rstrip("/")

    return path


def operation_key(
    method: str,
    path: str,
) -> Operation:

    return (
        method.upper().strip(),
        canonicalize_evaluation_path(path),
    )


def safe_ratio(
    numerator: int,
    denominator: int,
) -> float:

    if denominator == 0:
        return 0.0

    return round(
        numerator / denominator,
        4,
    )


def evaluate_shadow_detection(
    ground_truth: Dict[str, Any],
    framework_validation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare confirmed framework Shadow detections with an independent
    Ground Truth.

    Ground Truth positives:
        implemented_but_undocumented

    Framework positives:
        confirmed_candidates
    """

    ground_truth_shadow: Set[Operation] = {
        operation_key(
            item["method"],
            item["path"],
        )
        for item
        in ground_truth.get(
            "implemented_but_undocumented",
            [],
        )
    }

    detected_shadow: Set[Operation] = {
        operation_key(
            item["method"],
            item["path"],
        )
        for item
        in framework_validation.get(
            "confirmed_candidates",
            [],
        )
    }

    true_positives = (
        ground_truth_shadow
        & detected_shadow
    )

    false_positives = (
        detected_shadow
        - ground_truth_shadow
    )

    false_negatives = (
        ground_truth_shadow
        - detected_shadow
    )

    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)

    precision = safe_ratio(
        tp,
        tp + fp,
    )

    recall = safe_ratio(
        tp,
        tp + fn,
    )

    f1 = (
        round(
            2
            * precision
            * recall
            / (precision + recall),
            4,
        )
        if precision + recall
        else 0.0
    )

    def serialize_operations(
        operations: Set[Operation],
    ):
        return [
            {
                "method": method,
                "path": path,
            }
            for method, path
            in sorted(operations)
        ]

    return {
        "scope": "crapi-workshop",

        "confusion_counts": {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
        },

        "metrics": {
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

            "f1_score_percent": round(
                f1 * 100,
                2,
            ),
        },

        "ground_truth": {
            "shadow_operations":
                len(ground_truth_shadow),
        },

        "framework": {
            "confirmed_shadow_detections":
                len(detected_shadow),
        },

        "true_positives":
            serialize_operations(
                true_positives
            ),

        "false_positives":
            serialize_operations(
                false_positives
            ),

        "false_negatives":
            serialize_operations(
                false_negatives
            ),

        "interpretation": {
            "scope":
                "workshop_service_only",

            "true_negative_count_calculated":
                False,

            "accuracy_calculated":
                False,

            "reason":
                (
                    "This evaluation focuses on detection "
                    "of implemented-but-undocumented API "
                    "operations; no independent negative "
                    "universe is defined for accuracy or "
                    "specificity."
                ),
        },
    }