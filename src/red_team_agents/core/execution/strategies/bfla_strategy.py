from __future__ import annotations

from red_team_agents.core.execution.execution_strategy import ExecutionStrategy

from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
    ResourceUpdate,
)
from red_team_agents.core.execution.strategies.base_execution_strategy import (
    BaseExecutionStrategy,
)

class BFLAStrategy(BaseExecutionStrategy):

    def __init__(
        self,
        kali_tool,
        curl_builder=None,
        baseline_manager=None,
    ):
        self._kali_tool = kali_tool
        self._curl_builder = curl_builder
        self._baseline_manager = baseline_manager

    

 