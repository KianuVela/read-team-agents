"""
Criámos esse módulo para agregar de forma determinística e reproduzível as 14 evidências GET e as 6 POST
num único artefacto runtime, preservando método e proveniência, para depois alimentar a reconciliação Shadow API 
sem depender de comandos manuais.
"""

from __future__ import annotations

from typing import Any, Dict, List

import json 
from pathlib import Path


def aggregate_runtime_evidence(
    read_only_data: Dict[str, Any],
    active_data: Dict[str, Any],
) -> Dict[str, Any]:
    read_only_results: List[Dict[str, Any]] = []

    for result in read_only_data.get("results", []):
        normalized = dict(result)
        candidate_fingerprint = normalized.get("candidate_fingerprint") or {}
        baseline_fingerprint = normalized.get("baseline_fingerprint") or {}

        normalized["status_code"] = candidate_fingerprint.get("status_code")
        normalized["content_type"] = candidate_fingerprint.get("content_type")
        normalized["baseline_status_code"] = baseline_fingerprint.get("status_code")
        normalized["differential_evidence"] = {
            "differing_fields": normalized.get("differing_fields") or [],
            "candidate_fingerprint": candidate_fingerprint,
            "baseline_fingerprint": baseline_fingerprint,
        }

        normalized["runtime_evidence_source"] = (
            "read_only_runtime_differential"
        )
        read_only_results.append(normalized)

    active_results: List[Dict[str, Any]] = []

    for result in (
        list(active_data.get("direct_results", []))
        + list(active_data.get("dependency_results", []))
    ):
        normalized = {
            "method": result.get("method"),
            "template_path": result.get("template_path"),
            "probe_path": result.get("probe_path"),
            "baseline_path": result.get("baseline_path"),
            "frontend_constant": result.get("frontend_constant"),
            "classification": result.get("classification"),
            "runtime_observed": result.get("runtime_observed"),
            "differing_fields": result.get("differing_fields") or [],
            "candidate_fingerprint": result.get(
                "candidate_fingerprint"
            ),
            "baseline_fingerprint": result.get(
                "baseline_fingerprint"
            ),
            "business_success": result.get("business_success"),
            "active_response_outcome": result.get(
                "active_response_outcome"
            ),
            "runtime_evidence_source": (
                "controlled_active_runtime_differential"
            ),
        }

        candidate_fingerprint = normalized.get("candidate_fingerprint") or {}
        baseline_fingerprint = normalized.get("baseline_fingerprint") or {}

        normalized["status_code"] = candidate_fingerprint.get("status_code")
        normalized["content_type"] = candidate_fingerprint.get("content_type")
        normalized["baseline_status_code"] = baseline_fingerprint.get("status_code")
        normalized["differential_evidence"] = {
            "differing_fields": normalized.get("differing_fields") or [],
            "candidate_fingerprint": candidate_fingerprint,
            "baseline_fingerprint": baseline_fingerprint,
        }

        active_results.append(normalized)

    combined_results = read_only_results + active_results

    return {
        "source": "aggregated_runtime_differential_evidence",
        "base_url": (
            read_only_data.get("base_url")
            or active_data.get("base_url")
        ),
        "read_only_evidence_count": len(read_only_results),
        "active_evidence_count": len(active_results),
        "total_evidence_count": len(combined_results),
        "results": combined_results,
    }


PROJECT_ROOT = Path(__file__).resolve().parents[3]

READ_ONLY_RUNTIME_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_probe_results.json"
)

ACTIVE_RUNTIME_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "active_runtime_probe_results.json"
)

AGGREGATED_RUNTIME_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_evidence_aggregated.json"
)


def generate_runtime_evidence_aggregate(
    read_only_path: Path = READ_ONLY_RUNTIME_PATH,
    active_path: Path = ACTIVE_RUNTIME_PATH,
    output_path: Path = AGGREGATED_RUNTIME_PATH,
) -> Dict[str, Any]:

    read_only_data = json.loads(
        read_only_path.read_text(encoding="utf-8")
    )

    active_data = json.loads(
        active_path.read_text(encoding="utf-8")
    )

    result = aggregate_runtime_evidence(
        read_only_data,
        active_data,
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

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
    result = generate_runtime_evidence_aggregate()

    print("Runtime evidence aggregation complete.")
    print(f"Output: {AGGREGATED_RUNTIME_PATH}")
    print(
        f"Read-only evidence: "
        f"{result['read_only_evidence_count']}"
    )
    print(
        f"Controlled active evidence: "
        f"{result['active_evidence_count']}"
    )
    print(
        f"Total runtime evidence: "
        f"{result['total_evidence_count']}"
    )


if __name__ == "__main__":
    main()