import json
from pathlib import Path

from red_team_agents.deterministic_shadow_api.shadow_api_reconciliation import (
    runtime_probe_results_to_canonical,
    openapi_to_canonical,
    reconcile_all,
    reconciliation_to_dict,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

RUNTIME_FILE = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_evidence_aggregated.json"
    #/ "runtime_probe_results.json"
)

OPENAPI_FILE = (
    PROJECT_ROOT
    / "outputs"
    / "discovery"
    / "openapi_inventory.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "reports"
    / "shadow_api"
    / "runtime_shadow_api_reconciliation.json"
)


def run_runtime_shadow_api_reconciliation(
    runtime_file: Path = RUNTIME_FILE,
    openapi_file: Path = OPENAPI_FILE,
    output_file: Path = OUTPUT_FILE,
):

    runtime_file = Path(runtime_file)
    openapi_file = Path(openapi_file)
    output_file = Path(output_file)

    with runtime_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        runtime_data = json.load(file)

    with openapi_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        openapi_data = json.load(file)

    runtime_endpoints = runtime_probe_results_to_canonical(
        runtime_data
    )

    documented_endpoints = openapi_to_canonical(
        openapi_data
    )

    reconciliation = reconcile_all(
        runtime_endpoints,
        documented_endpoints,
    )

    serializable = reconciliation_to_dict(
        reconciliation
    )

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            serializable,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return serializable


if __name__ == "__main__":

    result = run_runtime_shadow_api_reconciliation()

    summary = result["summary"]

    print("=" * 80)
    print("RUNTIME SHADOW API RECONCILIATION")
    print("=" * 80)

    print(
        "Observed:",
        summary["observed_total"],
    )

    print(
        "Documented:",
        summary["documented_count"],
    )

    print(
        "Shadow operations:",
        summary["shadow_operation_count"],
    )

    print(
        "Shadow endpoints:",
        summary["shadow_endpoint_count"],
    )

    print(
        "Excluded:",
        summary["excluded_total"],
    )

    print()
    print(
        "Output:",
        OUTPUT_FILE,
    )