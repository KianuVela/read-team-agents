from typing import Any, Dict


def safe_rate(
    numerator: int,
    denominator: int,
) -> float:
    """
    Return a percentage rounded to two decimal places.

    Zero denominator returns 0.0.
    """
    if denominator == 0:
        return 0.0

    return round(
        (numerator / denominator) * 100,
        2,
    )


def calculate_shadow_api_metrics(
    runtime_results: Dict[str, Any],
    reconciliation: Dict[str, Any],
    validation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate descriptive experimental metrics for the deterministic
    Shadow API discovery pipeline.

    These metrics describe pipeline behaviour only.

    They must not be interpreted as precision, recall, or F1 because
    those measures require an independent ground-truth dataset.
    """

    probe_count = runtime_results.get(
        "probe_count",
        0,
    )

    runtime_observed_count = runtime_results.get(
        "runtime_observed_count",
        0,
    )

    inconclusive_count = runtime_results.get(
        "inconclusive_or_error_count",
        0,
    )

    summary = reconciliation.get(
        "summary",
        {},
    )

    eligible_total = summary.get(
        "eligible_total",
        0,
    )

    documented_count = summary.get(
        "documented_count",
        0,
    )

    shadow_operation_count = summary.get(
        "shadow_operation_count",
        0,
    )

    shadow_endpoint_count = summary.get(
        "shadow_endpoint_count",
        0,
    )

    candidate_count = validation.get(
        "candidate_count",
        0,
    )

    confirmed_count = validation.get(
        "confirmed_count",
        0,
    )

    rejected_count = validation.get(
        "rejected_count",
        0,
    )

    return {
        "counts": {
            "runtime_probes": probe_count,
            "runtime_confirmed_operations":
                runtime_observed_count,
            "inconclusive_or_error_probes":
                inconclusive_count,
            "reconciliation_eligible_operations":
                eligible_total,
            "documented_operations":
                documented_count,
            "shadow_operation_candidates":
                shadow_operation_count,
            "shadow_endpoint_candidates":
                shadow_endpoint_count,
            "validation_candidates":
                candidate_count,
            "confirmed_against_openapi_baseline":
                confirmed_count,
            "rejected_candidates":
                rejected_count,
        },

        "rates_percent": {
            "runtime_confirmation_rate":
                safe_rate(
                    runtime_observed_count,
                    probe_count,
                ),

            "inconclusive_or_error_rate":
                safe_rate(
                    inconclusive_count,
                    probe_count,
                ),

            "documented_rate_among_eligible":
                safe_rate(
                    documented_count,
                    eligible_total,
                ),

            "shadow_operation_rate_among_eligible":
                safe_rate(
                    shadow_operation_count,
                    eligible_total,
                ),

            "shadow_endpoint_rate_among_eligible":
                safe_rate(
                    shadow_endpoint_count,
                    eligible_total,
                ),

            "candidate_confirmation_rate":
                safe_rate(
                    confirmed_count,
                    candidate_count,
                ),

            "confirmed_shadow_rate_among_runtime":
                safe_rate(
                    confirmed_count,
                    runtime_observed_count,
                ),
        },

        "interpretation": {
            "metric_scope":
                "descriptive_pipeline_metrics",

            "ground_truth_available":
                False,

            "precision_recall_f1_calculated":
                False,

            "reason":
                (
                    "Precision, recall, and F1 require an "
                    "independent ground-truth inventory of "
                    "documented and Shadow API operations."
                ),
        },
    }