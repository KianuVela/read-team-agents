from typing import Any, Dict, List


RUNTIME_CONFIRMATION = "RUNTIME_DIFFERENTIAL_EVIDENCE"


def validate_shadow_endpoint_candidates(
    reconciliation: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Validate Shadow API endpoint candidates produced by runtime/OpenAPI
    reconciliation.

    A candidate is confirmed against the current OpenAPI baseline only if:

    1. It was classified as shadow_endpoint.
    2. The classification rule is PATH_NOT_DOCUMENTED.
    3. It originates from the runtime probe layer.
    4. Runtime differential evidence supports the operation.
    5. No documented endpoint/path match was found.

    This confirmation is relative to the OpenAPI baseline used in the
    experiment and does not claim universal absence from all possible
    external documentation.
    """

    validated: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    results = reconciliation.get("results", [])

    for result in results:

        if result.get("classification") != "shadow_endpoint":
            continue

        observed = result.get("observed", {})
        evidence = observed.get("evidence", {})

        checks = {
            "shadow_endpoint_classification": (
                result.get("classification")
                == "shadow_endpoint"
            ),
            "path_not_documented_rule": (
                result.get("rule")
                == "PATH_NOT_DOCUMENTED"
            ),
            "runtime_probe_source": (
                observed.get("source")
                == "runtime_probe"
            ),
            "runtime_differential_evidence": (
                evidence.get("runtime_classification")
                == RUNTIME_CONFIRMATION
            ),
            "no_documented_match": (
                result.get("documented_match") is None
            ),
            "no_documented_path_matches": (
                not result.get("documented_path_matches")
            ),
        }

        confirmed = all(checks.values())

        validation_record = {
            "method": observed.get("method"),
            "path": observed.get("path"),
            "classification": result.get("classification"),
            "reconciliation_rule": result.get("rule"),
            "validation_checks": checks,
            "validation_status": (
                "CONFIRMED_AGAINST_OPENAPI_BASELINE"
                if confirmed
                else "NOT_CONFIRMED"
            ),
            "runtime_evidence": {
                "runtime_classification": evidence.get(
                    "runtime_classification"
                ),
                "status_code": evidence.get("status_code"),
                "content_type": evidence.get("content_type"),
                "baseline_status_code": evidence.get(
                    "baseline_status_code"
                ),
                "differential_evidence": evidence.get(
                    "differential_evidence"
                ),
            },
        }

        if confirmed:
            validated.append(validation_record)
        else:
            rejected.append(validation_record)

    return {
        "candidate_count": len(validated) + len(rejected),
        "confirmed_count": len(validated),
        "rejected_count": len(rejected),
        "confirmed_candidates": validated,
        "rejected_candidates": rejected,
    }