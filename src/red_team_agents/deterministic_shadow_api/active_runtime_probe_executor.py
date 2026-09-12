from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from red_team_agents.tools.kali_mcp_tool import KaliMCPTool
from red_team_agents.deterministic_shadow_api.runtime_probe_executor import (
    load_runtime_probe_token,
)
from red_team_agents.deterministic_shadow_api.runtime_probe_validator import (
    classify_differential_response,
)
from red_team_agents.deterministic_shadow_api.active_runtime_command_builder import (
    build_active_curl_args,
)


DEFAULT_PLAN_PATH = Path("reports/api_discovery/active_runtime_probe_plan.json")
DEFAULT_OUTPUT_PATH = Path("reports/api_discovery/active_runtime_probe_results.json")
DEFAULT_BASE_URL = "http://crapi-web"


_TOKEN_RE = re.compile(r"Authorization:\s*Bearer\s+[^\"'\s]+", re.IGNORECASE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_command_arguments(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return _TOKEN_RE.sub("Authorization: Bearer <REDACTED>", value)


def _sanitize_response(response: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(response)
    if "arguments" in sanitized:
        sanitized["arguments"] = _redact_command_arguments(sanitized["arguments"])
    if "raw_output" in sanitized and isinstance(sanitized["raw_output"], str):
        sanitized["raw_output"] = _redact_command_arguments(sanitized["raw_output"])
    return sanitized


def _status_indicates_observed_operation(status: Optional[int]) -> bool:
    if status is None:
        return False
    if status in {404, 405}:
        return False
    return 200 <= int(status) < 500


def _status_indicates_business_success(status: Optional[int]) -> bool:
    if status is None:
        return False
    return 200 <= int(status) < 300


def _active_response_outcome(status: Optional[int]) -> str:
    if status is None:
        return "NO_HTTP_STATUS"

    status = int(status)

    if 200 <= status < 300:
        return "ACTIVE_BUSINESS_SUCCESS"

    if status in {404, 405}:
        return "NOT_RUNTIME_OBSERVED"

    if 400 <= status < 500:
        return "ACTIVE_OPERATION_REACHED_CLIENT_REJECTION"

    if 500 <= status < 600:
        return "ACTIVE_OPERATION_REACHED_SERVER_ERROR"

    return "ACTIVE_OPERATION_REACHED_OTHER_STATUS"


def _build_url(base_url: str, probe_path: str) -> str:
    return base_url.rstrip("/") + "/" + str(probe_path or "").lstrip("/")

def _build_active_baseline_path(probe_path: str) -> str:
    normalized_path = "/" + str(probe_path or "").strip("/")

    return (
        normalized_path.rstrip("/")
        + "/__active_missing_runtime_probe__"
        + "/__active_missing_runtime_child__"
    )


def _operation_record(
    probe: Dict[str, Any],
    result: Dict[str, Any],
    evidence_kind: str,
) -> Dict[str, Any]:
    response = result.get("response") or {}

    return {
        "method": probe.get("method"),
        "path": probe.get("probe_path"),
        "template_path": probe.get("template_path"),
        "frontend_constant": probe.get("frontend_constant"),
        "runtime_classification": result.get("classification"),
        "runtime_observed": bool(result.get("runtime_observed")),
        "business_success": bool(result.get("business_success")),
        "active_response_outcome": result.get("active_response_outcome"),
        "http_status": response.get("http_status"),
        "baseline_path": result.get("baseline_path"),
        "differing_fields": result.get("differing_fields") or [],
        "evidence_kind": evidence_kind,
        "source_tool": "curl",
        "discovery_method": (
            "frontend_javascript_plus_"
            "controlled_active_runtime_differential"
        ),
        "evidence": {
            "candidate_fingerprint": result.get("candidate_fingerprint"),
            "baseline_fingerprint": result.get("baseline_fingerprint"),
        },
        "active_input_summary": {
            "has_json_body": bool(
                (probe.get("active_input") or {}).get("json_body")
            ),
            "has_query_params": bool(
                (probe.get("active_input") or {}).get("query_params")
            ),
            "input_source": (probe.get("active_input") or {}).get("source"),
        },
    }


def _execute_probe(
    tool: KaliMCPTool,
    probe: Dict[str, Any],
    token: str,
    base_url: str,
    json_body_override: Optional[Dict[str, Any]] = None,
    query_params_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    active_input = probe.get("active_input") or {}

    json_body = (
        json_body_override
        if json_body_override is not None
        else active_input.get("json_body")
    )

    query_params = (
        query_params_override
        if query_params_override is not None
        else active_input.get("query_params")
    )

    probe_path = probe.get("probe_path")
    baseline_path = _build_active_baseline_path(probe_path)

    candidate_args = build_active_curl_args(
        probe.get("method"),
        _build_url(base_url, probe_path),
        json_body,
        token,
        query_params=query_params,
    )

    baseline_args = build_active_curl_args(
        probe.get("method"),
        _build_url(base_url, baseline_path),
        json_body,
        token,
        query_params=query_params,
    )

    candidate_response = tool.execute_json(
        "curl",
        candidate_args,
    )

    baseline_response = tool.execute_json(
        "curl",
        baseline_args,
    )

    candidate_status = candidate_response.get("http_status")

    if (
        not candidate_response.get("success")
        or not baseline_response.get("success")
    ):
        classification = "ACTIVE_RUNTIME_PROBE_ERROR"
        runtime_observed = False
        differing_fields = []
        candidate_fingerprint = None
        baseline_fingerprint = None
    else:
        differential = classify_differential_response(
            candidate_response,
            baseline_response,
        )

        classification = differential["classification"]
        runtime_observed = differential["runtime_observed"]
        differing_fields = differential["differing_fields"]
        candidate_fingerprint = differential["candidate_fingerprint"]
        baseline_fingerprint = differential["baseline_fingerprint"]

    return {
        "frontend_constant": probe.get("frontend_constant"),
        "method": probe.get("method"),
        "template_path": probe.get("template_path"),
        "probe_path": probe_path,
        "baseline_path": baseline_path,
        "executed_at": _utc_now(),
        "json_body_used": json_body,
        "query_params_used": query_params,
        "response": _sanitize_response(candidate_response),
        "baseline_response": _sanitize_response(baseline_response),
        "classification": classification,
        "runtime_observed": runtime_observed,
        "business_success": _status_indicates_business_success(
            candidate_status
        ),
        "active_response_outcome": _active_response_outcome(
            candidate_status
        ),
        "differing_fields": differing_fields,
        "candidate_fingerprint": candidate_fingerprint,
        "baseline_fingerprint": baseline_fingerprint,
    }

def _build_dependency_body(
    dependency_probe: Dict[str, Any],
    direct_results_by_constant: Dict[str, Dict[str, Any]],
    tool: KaliMCPTool,
    token: str,
    base_url: str,
) -> Optional[Dict[str, Any]]:
    constant = dependency_probe.get("frontend_constant")
    active_input = dependency_probe.get("active_input") or {}
    dependency = active_input.get("dependency") or {}

    if constant == "APPLY_COUPON":
        validate_result = direct_results_by_constant.get("VALIDATE_COUPON") or {}
        validate_response = validate_result.get("response") or {}
        validate_body = validate_response.get("body_json") or {}

        coupon_code = validate_body.get("coupon_code")
        amount = validate_body.get("amount")

        if coupon_code is None or amount is None:
            return None

        return {
            "coupon_code": coupon_code,
            "amount": float(amount),
        }

    if dependency.get("type") == "RUNTIME_COLLECTION_FIRST_VALID_ID":
        dependency_method = str(
            dependency.get("method") or "GET"
        ).upper()

        dependency_path = dependency.get("path")
        collection_key = dependency.get("collection_key")
        id_field = dependency.get("id_field")

        if not dependency_path or not collection_key or not id_field:
            return None

        dependency_url = _build_url(
            base_url,
            dependency_path,
        )

        if dependency_method == "GET":
            args = (
                '-i -sS --max-time 15 '
                '-H "Authorization: Bearer '
                + token
                + '" '
                + dependency_url
            )
        else:
            args = build_active_curl_args(
                dependency_method,
                dependency_url,
                None,
                token,
            )

        response = tool.execute_json(
            "curl",
            args,
        )

        if not response.get("success"):
            return None

        body_json = response.get("body_json")

        if not isinstance(body_json, dict):
            return None

        collection = body_json.get(
            collection_key,
            [],
        )

        if not isinstance(collection, list):
            return None

        selected = None

        for item in collection:
            if (
                isinstance(item, dict)
                and item.get(id_field) is not None
            ):
                selected = item
                break

        if selected is None:
            return None

        payload: Dict[str, Any] = dict(
            dependency.get("static_payload") or {}
        )

        payload_mapping = dependency.get(
            "payload_mapping"
        ) or {}

        for payload_field, source_field in payload_mapping.items():
            value = selected.get(source_field)

            if value is None:
                return None

            payload[payload_field] = value

        return payload

    return active_input.get("json_body")


def _build_dependency_query_params(
    dependency_probe: Dict[str, Any],
    active_results_by_constant: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    active_input = dependency_probe.get("active_input") or {}
    dependency = active_input.get("dependency") or {}

    if dependency.get("type") != "PRIOR_ACTIVE_RESPONSE_FIELD":
        return active_input.get("query_params")

    source_constant = dependency.get("frontend_constant")
    source_result = active_results_by_constant.get(source_constant) or {}
    source_response = source_result.get("response") or {}
    source_body = source_response.get("body_json") or {}

    if not isinstance(source_body, dict):
        return None

    query_mapping = dependency.get("query_mapping") or {}

    if not query_mapping:
        return None

    query_params: Dict[str, Any] = {}

    for query_field, source_field in query_mapping.items():
        value = source_body.get(source_field)

        if value is None:
            return None

        query_params[query_field] = value

    return query_params


def execute_active_runtime_probe_plan(
    plan: Dict[str, Any],
    base_url: str = DEFAULT_BASE_URL,
) -> Dict[str, Any]:
    tool = KaliMCPTool()
    token = load_runtime_probe_token()

    direct_results: List[Dict[str, Any]] = []
    dependency_results: List[Dict[str, Any]] = []
    skipped_dependency_results: List[Dict[str, Any]] = []
    observed_operations: List[Dict[str, Any]] = []

    for probe in plan.get("direct_active_probes", []):
        result = _execute_probe(
            tool=tool,
            probe=probe,
            token=token,
            base_url=base_url,
        )
        direct_results.append(result)

        if result.get("runtime_observed"):
            observed_operations.append(
                _operation_record(
                    probe,
                    result,
                    "direct_active_probe",
                )
            )

    direct_results_by_constant = {
        result.get("frontend_constant"): result
        for result in direct_results
        if result.get("frontend_constant")
    }

    active_results_by_constant = dict(
        direct_results_by_constant
    )

    for probe in plan.get("dependency_active_probes", []):
        dependency_body = _build_dependency_body(
            probe,
            active_results_by_constant,
            tool=tool,
            token=token,
            base_url=base_url,
        )

        dependency_query_params = _build_dependency_query_params(
            probe,
            active_results_by_constant,
        )

        if (
            dependency_body is None
            and dependency_query_params is None
        ):
            skipped_dependency_results.append(
                {
                    "frontend_constant": probe.get("frontend_constant"),
                    "method": probe.get("method"),
                    "template_path": probe.get("template_path"),
                    "probe_path": probe.get("probe_path"),
                    "skipped": True,
                    "reason": "DEPENDENCY_INPUT_UNRESOLVED",
                    "executed_at": _utc_now(),
                }
            )
            continue

        result = _execute_probe(
            tool=tool,
            probe=probe,
            token=token,
            base_url=base_url,
            json_body_override=dependency_body,
            query_params_override=dependency_query_params,
        )
        dependency_results.append(result)

        result_constant = result.get("frontend_constant")

        if result_constant:
            active_results_by_constant[result_constant] = result

        if result.get("runtime_observed"):
            observed_operations.append(
                _operation_record(
                    probe,
                    result,
                    "dependency_active_probe",
                )
            )

    return {
        "source": "controlled_active_runtime_probe_executor",
        "generated_at": _utc_now(),
        "base_url": base_url,
        "direct_active_probe_count": len(plan.get("direct_active_probes", [])),
        "dependency_active_probe_count": len(
            plan.get("dependency_active_probes", [])
        ),
        "executed_direct_count": len(direct_results),
        "executed_dependency_count": len(dependency_results),
        "skipped_dependency_count": len(skipped_dependency_results),
        "runtime_evidence_total": len(observed_operations),
        "direct_results": direct_results,
        "dependency_results": dependency_results,
        "skipped_dependency_results": skipped_dependency_results,
        "observed_operations": observed_operations,
        "summary": {
            "direct_observed": sum(
                1 for result in direct_results if result.get("runtime_observed")
            ),
            "dependency_observed": sum(
                1 for result in dependency_results if result.get("runtime_observed")
            ),
            "observed_frontend_constants": [
                operation.get("frontend_constant")
                for operation in observed_operations
            ],
        },
    }



def run_active_runtime_probe_file(
    input_file: str | Path,
    output_file: str | Path,
    base_url: str = DEFAULT_BASE_URL,
) -> Dict[str, Any]:
    """
    Load a persisted controlled active-runtime probe plan,
    execute it deterministically, persist the resulting runtime
    evidence, and return the structured result.
    """

    input_path = Path(input_file)
    output_path = Path(output_file)

    plan = json.loads(
        input_path.read_text(
            encoding="utf-8",
        )
    )

    result = execute_active_runtime_probe_plan(
        plan,
        base_url=base_url,
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
    plan = json.loads(DEFAULT_PLAN_PATH.read_text(encoding="utf-8"))

    result = execute_active_runtime_probe_plan(
        plan,
        base_url=DEFAULT_BASE_URL,
    )

    DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUTPUT_PATH.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Active runtime probe execution complete.")
    print(f"Output: {DEFAULT_OUTPUT_PATH}")
    print(f"Runtime evidence total: {result['runtime_evidence_total']}")
    print(f"Executed direct: {result['executed_direct_count']}")
    print(f"Executed dependency: {result['executed_dependency_count']}")
    print(f"Skipped dependency: {result['skipped_dependency_count']}")
    print(
        "Observed frontend constants:",
        result["summary"]["observed_frontend_constants"],
    )


if __name__ == "__main__":
    main()
