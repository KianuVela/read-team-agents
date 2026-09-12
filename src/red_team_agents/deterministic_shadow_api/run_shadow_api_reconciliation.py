import json
from pathlib import Path

from red_team_agents.deterministic_shadow_api.shadow_api_reconciliation import (
    active_to_canonical,
    openapi_to_canonical,
    reconcile_all,
    reconciliation_to_dict,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

ACTIVE_JSON = (
    PROJECT_ROOT
    / "reports"
    / "attack_surface"
    / "attack_surface_inventory.json"
)

OPENAPI_JSON = (
    PROJECT_ROOT
    / "outputs"
    / "discovery"
    / "openapi_inventory.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "shadow_api"
)

OUTPUT_JSON = (
    OUTPUT_DIR
    / "shadow_api_reconciliation.json"
)


def load_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():

    print("\n" + "=" * 80)
    print("DETERMINISTIC SHADOW API RECONCILIATION ENGINE")
    print("=" * 80)

    # ---------------------------------------------------------
    # 1. Load machine-readable artifacts
    # ---------------------------------------------------------

    active_data = load_json(ACTIVE_JSON)
    openapi_data = load_json(OPENAPI_JSON)

    # ---------------------------------------------------------
    # 2. Adapt both sources to the canonical representation
    # ---------------------------------------------------------

    observed_endpoints = active_to_canonical(
        active_data
    )

    documented_endpoints = openapi_to_canonical(
        openapi_data
    )

    print(
        f"\nActive canonical endpoints : "
        f"{len(observed_endpoints)}"
    )

    print(
        f"OpenAPI canonical endpoints: "
        f"{len(documented_endpoints)}"
    )

    # ---------------------------------------------------------
    # 3. Deterministic reconciliation
    # ---------------------------------------------------------

    reconciliation = reconcile_all(
        observed_endpoints,
        documented_endpoints,
    )

    serializable = reconciliation_to_dict(
        reconciliation
    )

    # ---------------------------------------------------------
    # 4. Persist machine-readable evidence
    # ---------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        OUTPUT_JSON,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            serializable,
            f,
            indent=2,
            ensure_ascii=False,
        )

    # ---------------------------------------------------------
    # 5. Console summary
    # ---------------------------------------------------------

    print("\nSUMMARY")
    print("-" * 80)

    for key, value in reconciliation["summary"].items():
        print(f"{key:25}: {value}")

    print("\nRESULTS")
    print("-" * 80)

    for result in reconciliation["results"]:

        print(
            f"{result.observed.method:7} "
            f"{result.observed.path:50} "
            f"-> {result.classification}"
        )

    print("\nEXCLUDED")
    print("-" * 80)

    for endpoint in reconciliation["excluded"]:

        print(
            f"{endpoint['method']:7} "
            f"{endpoint['path']:50} "
            f"-> {endpoint['eligibility_rule']}"
        )

    print(
        f"\nReconciliation artifact written to:\n"
        f"{OUTPUT_JSON}"
    )


if __name__ == "__main__":
    main()