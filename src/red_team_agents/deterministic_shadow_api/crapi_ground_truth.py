from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _extract_shadow_operations(
    service: str,
    data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    if "shadow_operations" in data:
        operations = data["shadow_operations"]

    elif "implemented_but_undocumented" in data:
        operations = data["implemented_but_undocumented"]

    else:
        operations = []

    normalized: List[Dict[str, Any]] = []

    for operation in operations:
        item = dict(operation)
        item["service"] = service
        normalized.append(item)

    return normalized


def _implemented_count(
    service: str,
    data: Dict[str, Any],
) -> int:
    summary = data.get("summary", {})

    if service == "identity":
        return int(
            summary.get(
                "in_scope_implemented_operations",
                0,
            )
        )

    return int(
        summary.get(
            "implemented_operations",
            0,
        )
    )


def _documented_count(
    service: str,
    data: Dict[str, Any],
) -> int:
    summary = data.get("summary", {})

    if service == "workshop":
        return int(
            summary.get(
                "documented_operations",
                0,
            )
        )

    return int(
        summary.get(
            "documented_implemented_operations",
            0,
        )
    )


def build_crapi_ground_truth(
    workshop_path: Path,
    identity_path: Path,
    community_path: Path,
    output_path: Path,
) -> Dict[str, Any]:
    inputs = {
        "workshop": _load_json(workshop_path),
        "identity": _load_json(identity_path),
        "community": _load_json(community_path),
    }

    services: Dict[str, Any] = {}
    global_shadow_operations: List[Dict[str, Any]] = []

    total_implemented = 0
    total_documented = 0

    for service, data in inputs.items():
        implemented = _implemented_count(
            service,
            data,
        )

        documented = _documented_count(
            service,
            data,
        )

        shadows = _extract_shadow_operations(
            service,
            data,
        )

        total_implemented += implemented
        total_documented += documented
        global_shadow_operations.extend(shadows)

        services[service] = {
            "implemented_operations": implemented,
            "documented_implemented_operations": documented,
            "shadow_operations": len(shadows),
            "source_file": {
                "workshop": str(workshop_path),
                "identity": str(identity_path),
                "community": str(community_path),
            }[service],
        }

    result: Dict[str, Any] = {
        "target": "OWASP crAPI",
        "scope": (
            "Consolidated application API ground truth "
            "across Workshop, Identity, and Community."
        ),
        "summary": {
            "services": len(services),
            "implemented_operations": total_implemented,
            "documented_implemented_operations": total_documented,
            "implemented_but_undocumented_operations": (
                len(global_shadow_operations)
            ),
        },
        "services": services,
        "shadow_operations": sorted(
            global_shadow_operations,
            key=lambda item: (
                item.get("service", ""),
                item.get("method", ""),
                item.get("path", ""),
            ),
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