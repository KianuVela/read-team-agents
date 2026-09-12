"""
Deterministic adapter between frontend_extract output and the
runtime probe planning pipeline.

This module performs schema normalization only.
It does not infer undocumented HTTP methods and does not use
OpenAPI, Ground Truth, or source-code knowledge.
"""

import json
from pathlib import Path
from typing import Any, Dict, List


def adapt_frontend_extract_result(
    frontend_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert frontend_extract api_candidates into the canonical
    operation_candidates schema expected by runtime_probe_planner.

    Mapping:
        reference       -> path
        method_hint     -> method
        route_key       -> frontend_constant

    No HTTP method is invented when method_hint is absent.
    """

    adapted_operations: List[Dict[str, Any]] = []

    candidates = frontend_result.get(
        "api_candidates",
        [],
    )

    for candidate in candidates:

        path = candidate.get("reference")

        if not path:
            continue

        method_hint = candidate.get(
            "method_hint"
        )

        method = (
            str(method_hint).upper()
            if method_hint
            else None
        )

        adapted_operations.append(
            {
                "path": path,
                "method": method,
                "frontend_constant": candidate.get(
                    "route_key"
                ),
                "frontend_reference_type": candidate.get(
                    "reference_type"
                ),
                "frontend_observed_methods": candidate.get(
                    "observed_methods",
                    [],
                ),
                "discovery_source": "live_frontend",
            }
        )

    with_method = sum(
        1
        for operation in adapted_operations
        if operation.get("method")
    )

    without_method = (
        len(adapted_operations)
        - with_method
    )

    return {
        "source": "frontend_extract",
        "source_url": frontend_result.get(
            "source_url"
        ),
        "operation_candidate_count": len(
            adapted_operations
        ),
        "candidates_with_method": with_method,
        "candidates_without_method": without_method,
        "operation_candidates": adapted_operations,
        "summary": {
            "total_frontend_candidates": len(
                candidates
            ),
            "adapted_candidates": len(
                adapted_operations
            ),
            "with_explicit_method_evidence": with_method,
            "without_explicit_method_evidence": without_method,
        },
    }


def write_frontend_operation_candidates(
    input_file: str | Path,
    output_file: str | Path,
) -> Dict[str, Any]:
    """
    Read a persisted frontend_extract result and write the
    normalized candidate representation used by the runtime planner.
    """

    input_file = Path(input_file)
    output_file = Path(output_file)

    frontend_result = json.loads(
        input_file.read_text(
            encoding="utf-8"
        )
    )

    result = adapt_frontend_extract_result(
        frontend_result
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return result