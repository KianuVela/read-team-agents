import json
from pathlib import Path
from typing import Any, Dict, List

from red_team_agents.tools.kali_mcp_tool import KaliMCPTool
from red_team_agents.deterministic_shadow_api.active_runtime_command_builder import (
    build_active_curl_args,
    redact_active_curl_args,
)
from red_team_agents.deterministic_shadow_api.runtime_probe_executor import load_runtime_probe_token


def execute_active_runtime_probe_plan(
    plan: Dict[str, Any],
    base_url: str = "http://crapi-web",
) -> Dict[str, Any]:

    tool = KaliMCPTool()

    active_probes = plan.get(
        "direct_active_probes",
        [],
    )

    results: List[Dict[str, Any]] = []

    for probe in active_probes:
        method = str(
            probe.get("method") or ""
        ).upper()

        probe_path = str(
            probe.get("probe_path") or ""
        )

        frontend_constant = probe.get(
            "frontend_constant"
        )

        results.append(
            {
                "frontend_constant": frontend_constant,
                "method": method,
                "probe_path": probe_path,
                "execution_status": "NOT_EXECUTED_YET",
            }
        )

    return {
        "source": "active_runtime_probe_executor",
        "active_probe_count": len(active_probes),
        "results": results,
    }
