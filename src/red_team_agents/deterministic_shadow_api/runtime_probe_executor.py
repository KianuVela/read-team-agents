"""
O classificador diferencial está validado. Agora podemos executar, de forma controlada, 
apenas os 15 GETs lower-risk e comparar cada um com um sibling inexistente.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from red_team_agents.tools.kali_mcp_tool import KaliMCPTool
from red_team_agents.deterministic_shadow_api.runtime_probe_validator import (
    classify_differential_response,
)


MISSING_SEGMENT = "__definitely_missing_runtime_probe__"



# confirmado: authentication.tokens.user_a contém diretamente o token como str. 🔥
# A melhor integração é não autenticar todos os probes logo de início: fazemos primeiro o teste anónimo e só repetimos com user_a quando candidato e baseline ficam bloqueados pelo mesmo 401/403.
#Primeiro, adiciona esta função ao runtime_probe_executor.py, logo abaixo de MISSING_SEGMENT:
def load_runtime_probe_token(
    object_context_file: str | Path = (
        "outputs/execution/object_context.json"
    ),
    actor: str = "user_a",
) -> str | None:
    """
    Load an existing authenticated actor token for runtime
    route validation without invoking OpenAPI-based discovery.

    The token value is never returned in runtime evidence.
    """

    context_file = Path(object_context_file)

    if not context_file.exists():
        return None

    try:
        context = json.loads(
            context_file.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return None

    token = (
        context
        .get("authentication", {})
        .get("tokens", {})
        .get(actor)
    )

    if not isinstance(token, str):
        return None

    token = token.strip()

    return token or None


#def build_baseline_path(
 #   probe_path: str,
#) -> str:
   # """
   # Preserve the path depth while replacing only the final
    #segment with a deterministic nonexistent sibling.
   # """

   # parts = [
     #   part
    #    for part in probe_path.strip("/").split("/")
     #   if part
   # ]

   # if not parts:
   #     return f"/{MISSING_SEGMENT}"

    #parts[-1] = MISSING_SEGMENT

    #return "/" + "/".join(parts)

def build_baseline_path(
    probe_path: str,
    template_path: str | None = None,
) -> str:
    """
    Build a deterministic structurally-invalid child path.

    Appending a nonexistent segment avoids replacing a literal
    segment with a value that could accidentally match a
    parameterized sibling route such as /posts/<postId>.
    """

    normalized_path = "/" + probe_path.strip("/")

    if normalized_path == "/":
        return f"/{MISSING_SEGMENT}"

    return (
        normalized_path.rstrip("/")
        + "/"
        + MISSING_SEGMENT
    )


def execute_runtime_probe_plan(
    plan: Dict[str, Any],
    base_url: str = "http://crapi-web",
) -> Dict[str, Any]:

    tool = KaliMCPTool()

    # Agora implementamos o retry autenticado apenas quando candidato e baseline ficam ambos bloqueados por 401/403; o token não entra no JSON de evidência.
    runtime_token = load_runtime_probe_token()

    results: List[Dict[str, Any]] = []
    observed_operations: List[Dict[str, Any]] = []

    safe_probes = plan.get(
        "safe_probes",
        [],
    )

    for probe in safe_probes:

        method = probe.get("method")
        probe_path = probe.get("probe_path")
        template_path = probe.get("template_path")

        if method != "GET" or not probe_path:
            continue

        baseline_path = build_baseline_path(
            probe_path,
            template_path,
        )

        candidate_url = (
            base_url.rstrip("/")
            + probe_path
        )

        baseline_url = (
            base_url.rstrip("/")
            + baseline_path
        )

        candidate_response = tool.execute_json(
            "curl",
            f"-i -sS --max-time 15 {candidate_url}",
        )

        baseline_response = tool.execute_json(
            "curl",
            f"-i -sS --max-time 15 {baseline_url}",
        )


        # AQUI ADICIONAMOS PARA FAZER FUNCIONAR O RETRY AUTHENTICADO
        authentication_retry = False

        candidate_status = candidate_response.get(
            "http_status"
        )

        baseline_status = baseline_response.get(
            "http_status"
        )

        auth_blocked = (
            candidate_status in (401, 403)
            or baseline_status in (401, 403)
        )

        if (
            auth_blocked
            and runtime_token
        ):
            authentication_retry = True

            auth_header = (
                '-H "Authorization: Bearer '
                + runtime_token
                + '" '
            )

            candidate_response = tool.execute_json(
                "curl",
                (
                    "-i -sS --max-time 15 "
                    + auth_header
                    + candidate_url
                ),
            )

            baseline_response = tool.execute_json(
                "curl",
                (
                    "-i -sS --max-time 15 "
                    + auth_header
                    + baseline_url
                ),
            )



        if (
            not candidate_response.get("success")
            or not baseline_response.get("success")
        ):
            result = {
                "method": method,
                "template_path": template_path,
                "probe_path": probe_path,
                "baseline_path": baseline_path,
                "classification": "RUNTIME_PROBE_ERROR",
                "runtime_observed": False,
                "candidate_error": candidate_response.get(
                    "error"
                ),
                "baseline_error": baseline_response.get(
                    "error"
                ),

                # ACRESCENTAMOS AQUI 
                # Não graves runtime_token em nenhum result.
                #Depois fazemos primeiro só a verificação sintática:
                #python -m py_compile .\src\red_team_agents\deterministic_shadow_api\runtime_probe_executor.py
                "authentication_retry": authentication_retry,
                "authentication_actor": (
                    "user_a"
                    if authentication_retry
                    else None
                ),
            }

            results.append(result)
            continue

        differential = classify_differential_response(
            candidate_response,
            baseline_response,
        )

        result = {
            "method": method,
            "template_path": template_path,
            "probe_path": probe_path,
            "baseline_path": baseline_path,
            "frontend_constant": probe.get(
                "frontend_constant"
            ),
            "classification": differential[
                "classification"
            ],
            "runtime_observed": differential[
                "runtime_observed"
            ],
            "authentication_retry": authentication_retry,
            "authentication_actor": (
                "user_a"
                if authentication_retry
                else None
            ),
            "differing_fields": differential[
                "differing_fields"
            ],
            "candidate_fingerprint": differential[
                "candidate_fingerprint"
            ],
            "baseline_fingerprint": differential[
                "baseline_fingerprint"
            ],
        }

        results.append(
            result
        )

        if differential["runtime_observed"]:
            observed_operations.append(
                {
                    "path": template_path,
                    "method": method,
                    "probe_path": probe_path,
                    "discovery_method": (
                        "frontend_javascript_"
                        "plus_runtime_differential"
                    ),
                    "source_tool": "curl",
                    "runtime_classification": differential[
                        "classification"
                    ],
                    "evidence": {
                        "candidate_fingerprint": differential[
                            "candidate_fingerprint"
                        ],
                        "baseline_fingerprint": differential[
                            "baseline_fingerprint"
                        ],
                        "differing_fields": differential[
                            "differing_fields"
                        ],
                    },
                }
            )

    return {
        "source": "runtime_probe_plan",
        "base_url": base_url,
        "probe_count": len(results),
        "runtime_observed_count": len(
            observed_operations
        ),
        "inconclusive_or_error_count": (
            len(results)
            - len(observed_operations)
        ),
        "results": results,
        "observed_api_operations": observed_operations,
    }


def run_runtime_probe_file(
    input_file: str | Path,
    output_file: str | Path,
    base_url: str = "http://crapi-web",
) -> Dict[str, Any]:

    input_file = Path(input_file)
    output_file = Path(output_file)

    plan = json.loads(
        input_file.read_text(
            encoding="utf-8"
        )
    )

    result = execute_runtime_probe_plan(
        plan,
        base_url=base_url,
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

DEFAULT_RUNTIME_PLAN_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_probe_plan.json"
)

DEFAULT_RUNTIME_OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "api_discovery"
    / "runtime_probe_results.json"
)


def main() -> None:
    result = run_runtime_probe_file(
        DEFAULT_RUNTIME_PLAN_PATH,
        DEFAULT_RUNTIME_OUTPUT_PATH,
        base_url="http://crapi-web",
    )

    print("Runtime probe execution complete.")
    print(f"Output: {DEFAULT_RUNTIME_OUTPUT_PATH}")
    print(f"Probe count: {result['probe_count']}")
    print(
        f"Runtime observed: "
        f"{result['runtime_observed_count']}"
    )
    print(
        f"Inconclusive or error: "
        f"{result['inconclusive_or_error_count']}"
    )


if __name__ == "__main__":
    main()

