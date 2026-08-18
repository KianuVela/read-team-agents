from __future__ import annotations

from abc import ABC
from abc import abstractmethod

from red_team_agents.core.execution.execution_context import ExecutionContext
from red_team_agents.core.execution.execution_result import ExecutionResult
from red_team_agents.core.reasoning.resource_model import ResourceModel


class ExecutionStrategy(ABC):

    @abstractmethod
    def execute(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:
        """
        Execute one security strategy.
        """
        raise NotImplementedError