from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[3]

OPENAPI_INVENTORY_PATH = (
    PROJECT_ROOT / "outputs" / "discovery" / "openapi_inventory.json"
)

SHADOW_GROUND_TRUTH_PATH = (
    PROJECT_ROOT / "reports" / "ground_truth" / "crapi_ground_truth.json"
)

RUNTIME_EVIDENCE_PATH = (
    PROJECT_ROOT / "reports" / "api_discovery" / "runtime_evidence_aggregated.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_endpoint_coverage_evaluation.json"
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

    path = path.rstrip("/") or "/"

    path = re.sub(r"<[^/]+?>", "{param}", path)
    path = re.sub(r"\{[^/]+?\}", "{param}", path)

    return path


def _operation_key(method: Any, path: Any) -> Tuple[str, str]:
    return (_normalise_method(method), _normalise_path(path))


def _extract_openapi_operations(openapi: Dict[str, Any]) -> List[Dict[str, Any]]:
    operations = []

    for item in openapi.get("endpoints", []):
        if not isinstance(item, dict):
            continue

        method = item.get("method") or item.get("http_method")
        path = item.get("path") or item.get("endpoint") or item.get("operation_path")

        if method and path:
            operations.append(
                {
                    "method": _normalise_method(method),
                    "path": _normalise_path(path),
                    "source": "openapi_documented",
                    "raw": item,
                }
            )

    return operations


def _extract_shadow_ground_truth_operations(
    ground_truth: Dict[str, Any],
) -> List[Dict[str, Any]]:
    operations = []

    for item in ground_truth.get("shadow_operations", []):
        if not isinstance(item, dict):
            continue

        method = item.get("method") or item.get("http_method")
        path = item.get("path") or item.get("endpoint") or item.get("operation_path")

        if method and path:
            operations.append(
                {
                    "method": _normalise_method(method),
                    "path": _normalise_path(path),
                    "source": "shadow_ground_truth",
                    "raw": item,
                }
            )

    return operations


def _extract_runtime_discovered_operations(
    runtime_evidence: Dict[str, Any],
) -> List[Dict[str, Any]]:
    operations = []

    for item in runtime_evidence.get("results", []):
        if not isinstance(item, dict):
            continue

        if item.get("runtime_observed") is not True:
            continue

        method = item.get("method") or item.get("http_method")

        path = (
            item.get("template_path")
            or item.get("endpoint")
            or item.get("path")
            or item.get("probe_path")
        )

        if method and path:
            operations.append(
                {
                    "method": _normalise_method(method),
                    "path": _normalise_path(path),
                    "runtime_evidence_source": item.get(
                        "runtime_evidence_source"
                    ),
                    "frontend_constant": item.get("frontend_constant"),
                    "raw": item,
                }
            )

    return operations


def _deduplicate_operations(
    operations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    seen = {}
    for operation in operations:
        key = _operation_key(operation["method"], operation["path"])
        if key not in seen:
            seen[key] = operation
    return list(seen.values())


def evaluate_crapi_endpoint_coverage(
    openapi_inventory_path: Path = OPENAPI_INVENTORY_PATH,
    shadow_ground_truth_path: Path = SHADOW_GROUND_TRUTH_PATH,
    runtime_evidence_path: Path = RUNTIME_EVIDENCE_PATH,
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    openapi_inventory_path = Path(openapi_inventory_path)
    shadow_ground_truth_path = Path(shadow_ground_truth_path)
    runtime_evidence_path = Path(runtime_evidence_path)
    output_path = Path(output_path)

    openapi = _load_json(openapi_inventory_path)
    shadow_gt = _load_json(shadow_ground_truth_path)
    runtime = _load_json(runtime_evidence_path)

    documented = _deduplicate_operations(_extract_openapi_operations(openapi))
    shadow = _deduplicate_operations(
        _extract_shadow_ground_truth_operations(shadow_gt)
    )

    known = _deduplicate_operations(documented + shadow)
    discovered = _deduplicate_operations(
        _extract_runtime_discovered_operations(runtime)
    )

    known_keys = {
        _operation_key(item["method"], item["path"])
        for item in known
    }

    discovered_keys = {
        _operation_key(item["method"], item["path"])
        for item in discovered
    }

    correctly_discovered_keys = known_keys & discovered_keys
    unknown_discovered_keys = discovered_keys - known_keys
    missed_known_keys = known_keys - discovered_keys

    def _records_from_keys(
        keys: set[Tuple[str, str]],
        preferred_records: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        records = []

        record_by_key = {
            _operation_key(item["method"], item["path"]): item
            for item in preferred_records
        }

        for method, path in sorted(keys):
            record = record_by_key.get((method, path), {})
            records.append(
                {
                    "method": method,
                    "path": path,
                    "source": record.get("source")
                    or record.get("runtime_evidence_source"),
                    "frontend_constant": record.get("frontend_constant"),
                }
            )

        return records

    known_total = len(known_keys)
    correctly_discovered_total = len(correctly_discovered_keys)

    endpoint_coverage = (
        correctly_discovered_total / known_total
        if known_total
        else 0.0
    )

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_endpoint_coverage",
        "status": "completed",
        "methodological_boundary": {
            "openapi_used_as_documented_endpoint_baseline": True,
            "shadow_ground_truth_used_as_undocumented_endpoint_baseline": True,
            "ground_truth_used_for_runtime_discovery": False,
            "used_only_for_final_coverage_evaluation": True,
        },
        "inputs": {
            "openapi_inventory": str(openapi_inventory_path),
            "shadow_ground_truth": str(shadow_ground_truth_path),
            "runtime_evidence": str(runtime_evidence_path),
        },
        "summary": {
            "documented_known_endpoints": len(documented),
            "shadow_known_endpoints": len(shadow),
            "known_endpoints": known_total,
            "runtime_discovered_endpoints": len(discovered_keys),
            "correctly_discovered_endpoints": correctly_discovered_total,
            "missed_known_endpoints": len(missed_known_keys),
            "unknown_discovered_endpoints": len(unknown_discovered_keys),
            "endpoint_coverage": endpoint_coverage,
            "endpoint_coverage_percent": endpoint_coverage * 100,
        },
        "correctly_discovered_endpoints": _records_from_keys(
            correctly_discovered_keys,
            known + discovered,
        ),
        "missed_known_endpoints": _records_from_keys(
            missed_known_keys,
            known,
        ),
        "unknown_discovered_endpoints": _records_from_keys(
            unknown_discovered_keys,
            discovered,
        ),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_endpoint_coverage()
    summary = result["summary"]

    print()
    print("crAPI ENDPOINT COVERAGE EVALUATION")
    print("=" * 70)
    print("Documented known endpoints:", summary["documented_known_endpoints"])
    print("Shadow known endpoints:", summary["shadow_known_endpoints"])
    print("Known endpoints:", summary["known_endpoints"])
    print("Runtime discovered endpoints:", summary["runtime_discovered_endpoints"])
    print("Correctly discovered endpoints:", summary["correctly_discovered_endpoints"])
    print("Missed known endpoints:", summary["missed_known_endpoints"])
    print("Unknown discovered endpoints:", summary["unknown_discovered_endpoints"])

    print()
    print("METRIC")
    print("-" * 70)
    print(f'Endpoint Coverage: {summary["endpoint_coverage_percent"]:.2f}%')

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
