from typing import Any, Dict, List
from pathlib import Path

from red_team_agents.deterministic_shadow_api.active_runtime_input_resolver import (
    resolve_active_runtime_input,
)


ACTIVE_RUNTIME_METHODS = {
    "POST",
    "PUT",
}


def build_active_runtime_probe_plan(
    runtime_plan: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build a controlled active-runtime validation plan from
    operations previously deferred by the read-only planner.

    Selection requires:
    - an explicitly observed state-changing HTTP method;
    - deterministic runtime input resolution;
    - no OpenAPI, Ground Truth, or vulnerability-test metadata.
    """

    direct_active_probes: List[Dict[str, Any]] = []
    dependency_active_probes: List[Dict[str, Any]] = []
    still_deferred: List[Dict[str, Any]] = []

    deferred_operations = runtime_plan.get(
        "deferred_operations",
        [],
    )

    for operation in deferred_operations:

        method = str(
            operation.get("method") or ""
        ).upper()

        if method not in ACTIVE_RUNTIME_METHODS:
            item = {
                **operation,
                "active_probe_decision": (
                    "DEFER_METHOD_NOT_ACTIVE_RUNTIME_ELIGIBLE"
                ),
            }
            still_deferred.append(item)
            continue

        resolved_input = resolve_active_runtime_input(
            operation
        )

        if not resolved_input.get("ready"):
            item = {
                **operation,
                "active_probe_decision": (
                    "DEFER_NO_DETERMINISTIC_ACTIVE_INPUT"
                ),
                "active_input": resolved_input,
            }
            still_deferred.append(item)
            continue

        item = {
            **operation,
            "active_input": resolved_input,
        }

        dependency = resolved_input.get(
            "dependency"
        )

        if dependency:
            item["active_probe_decision"] = (
                "ACTIVE_RUNTIME_DEPENDENCY_REQUIRED"
            )
            dependency_active_probes.append(item)

        else:
            item["active_probe_decision"] = (
                "ACTIVE_RUNTIME_DIRECT_READY"
            )
            direct_active_probes.append(item)

    return {
        "source": "runtime_probe_plan_deferred_operations",
        "active_runtime_methods": sorted(
            ACTIVE_RUNTIME_METHODS
        ),
        "direct_active_probe_count": len(
            direct_active_probes
        ),
        "dependency_active_probe_count": len(
            dependency_active_probes
        ),
        "still_deferred_count": len(
            still_deferred
        ),
        "direct_active_probes": direct_active_probes,
        "dependency_active_probes": dependency_active_probes,
        "still_deferred": still_deferred,
        "summary": {
            "input_deferred_total": len(
                deferred_operations
            ),
            "active_ready_total": (
                len(direct_active_probes)
                + len(dependency_active_probes)
            ),
            "direct_ready": len(
                direct_active_probes
            ),
            "dependency_ready": len(
                dependency_active_probes
            ),
            "still_deferred": len(
                still_deferred
            ),
        },
    }

def write_active_runtime_probe_plan(
    input_file: str,
    output_file: str,
) -> Dict[str, Any]:
    """
    Build and persist the controlled active-runtime probe plan.
    """

    import json
    from pathlib import Path

    input_path = Path(input_file)
    output_path = Path(output_file)

    runtime_plan = json.loads(
        input_path.read_text(
            encoding="utf-8"
        )
    )

    result = build_active_runtime_probe_plan(
        runtime_plan
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

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_RUNTIME_PLAN_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_probe_plan.json"
)

DEFAULT_ACTIVE_PLAN_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "active_runtime_probe_plan.json"
)


def main() -> None:
    result = write_active_runtime_probe_plan(
        str(DEFAULT_RUNTIME_PLAN_PATH),
        str(DEFAULT_ACTIVE_PLAN_PATH),
    )

    print("Active runtime probe planning complete.")
    print(f"Output: {DEFAULT_ACTIVE_PLAN_PATH}")
    print(
        f"Direct active probes: "
        f"{len(result.get('direct_active_probes', []))}"
    )
    print(
        f"Dependency active probes: "
        f"{len(result.get('dependency_active_probes', []))}"
    )


if __name__ == "__main__":
    main()

