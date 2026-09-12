import json
import re
from pathlib import Path
from typing import Any, Dict, List

# Adicionamos este import para tornar a runtime_probe_planner.py para consultar a DeterministicFixtureStore durante materialize_template_path();
from red_team_agents.core.execution.fixtures.deterministic_fixture_store import (
    DeterministicFixtureStore,
)



# Essa classe foi criada para antes de executarmos as 42 operações, 
# O próximo passo não deve ser executar as 42 operações. Primeiro vamos 
# criar um plano determinístico de runtime validation, separando operações de leitura das que podem alterar estado.

SAFE_RUNTIME_METHODS = {
    "GET",
    "HEAD",
}


PATH_PARAMETER_PATTERN = re.compile(
    r"<(?P<parameter>[^/<>]+)>"
)


DEFAULT_PARAMETER_VALUES = {
    "postId": "1",
    "videoId": "1",
    "carId": "1",
    "serviceId": "1",
    "orderId": "1",
    "vehicleVIN": "TESTVIN00000000000",
}

ACTION_LIKE_GET_TERMS = {
    "convert",
    "create",
    "update",
    "delete",
    "remove",
    "send",
    "receive",
    "resend",
    "return",
    "apply",
    "change",
    "reset",
}


def materialize_template_path(
    path: str,
) -> Dict[str, Any]:
    """
    Replace frontend template parameters with deterministic,
    non-random probe values.

    This prepares a candidate for controlled runtime validation.
    """

    parameters = []


    # Adicionamos aqui o code em funºão do import que fizemos da DtereministicFixtureStore
    fixture_store = DeterministicFixtureStore()

    fixture_key = None
    fixture_value = None

    if fixture_store.enabled:
        fixture_key, fixture_value = (
            fixture_store.resolve_fixture_for_endpoint(path)
        )
        # Termina aqui. Por baixo permance o metodo interno que já ca tinha
        # =====================================================================

    def replace_parameter(
        match: re.Match,
    ) -> str:
        parameter = match.group("parameter")

        parameters.append(parameter)

        # Vamos subsitituir esse return por isso o deixarei comentado
        #return DEFAULT_PARAMETER_VALUES.get(
           # parameter,
            #"1",
        #)
        if (
            fixture_value is not None
            and not isinstance(fixture_value, (dict, list))
        ):
            return str(fixture_value)

        return DEFAULT_PARAMETER_VALUES.get(
            parameter,
            "1",
        )

    concrete_path = PATH_PARAMETER_PATTERN.sub(
        replace_parameter,
        path,
    )

    return {
        "template_path": path,
        "probe_path": concrete_path,
        "parameters": parameters,

        "fixture_key": fixture_key,
        "fixture_value": fixture_value,
    }


def build_runtime_probe_plan(
    candidates: Dict[str, Any],
) -> Dict[str, Any]:

    safe_probes: List[Dict[str, Any]] = []
    deferred_operations: List[Dict[str, Any]] = []

    operations = candidates.get(
        "operation_candidates",
        [],
    )

    for operation in operations:

        method = str(
            operation.get("method") or ""
        ).upper()

        path = operation.get("path")

        if not path:
            continue

        materialized = materialize_template_path(
            path
        )

        item = {
            **operation,
            **materialized,
        }

        path_lower = path.lower()

        action_like_get = any(
            term in path_lower
            for term in ACTION_LIKE_GET_TERMS
        )

        if (
            method in SAFE_RUNTIME_METHODS
            and not action_like_get
        ):
            item["probe_decision"] = (
                "LOWER_RISK_GET_RUNTIME_PROBE"
            )

            safe_probes.append(
                item
            )

        else:
            item["probe_decision"] = (
                "DEFER_POTENTIALLY_STATE_CHANGING_OPERATION"
            )

            deferred_operations.append(
                item
            )

    return {
        "source": "frontend_operation_candidates",
        "safe_runtime_methods": sorted(
            SAFE_RUNTIME_METHODS
        ),
        "safe_probe_count": len(
            safe_probes
        ),
        "deferred_count": len(
            deferred_operations
        ),
        "safe_probes": safe_probes,
        "deferred_operations": deferred_operations,
        "summary": {
            "total_candidates": len(
                operations
            ),
            "safe_read_only": len(
                safe_probes
            ),
            "side_effecting_deferred": len(
                deferred_operations
            ),
        },
    }


def write_runtime_probe_plan(
    input_file: str | Path,
    output_file: str | Path,
) -> Dict[str, Any]:

    input_file = Path(
        input_file
    )

    output_file = Path(
        output_file
    )

    candidates = json.loads(
        input_file.read_text(
            encoding="utf-8"
        )
    )

    result = build_runtime_probe_plan(
        candidates
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

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_CANDIDATES_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "frontend_operation_candidates.json"
)

DEFAULT_RUNTIME_PLAN_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_probe_plan.json"
)


def main() -> None:
    result = write_runtime_probe_plan(
        DEFAULT_CANDIDATES_PATH,
        DEFAULT_RUNTIME_PLAN_PATH,
    )

    print("Runtime probe planning complete.")
    print(f"Output: {DEFAULT_RUNTIME_PLAN_PATH}")
    print(f"Safe probes: {result['safe_probe_count']}")
    print(f"Deferred operations: {result['deferred_count']}")


if __name__ == "__main__":
    main()

