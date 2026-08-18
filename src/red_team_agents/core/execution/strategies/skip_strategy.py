from __future__ import annotations

from red_team_agents.core.execution.execution_context import (
    ExecutionContext,
)

from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
    ResourceUpdate,
)

from red_team_agents.core.execution.execution_strategy import (
    ExecutionStrategy,
)

from red_team_agents.core.reasoning.resource_model import (
    ResourceModel,
)


class SkipStrategy(ExecutionStrategy):
    """
    Strategy used when the DecisionEngine decides that
    the current resource should not be executed.
    """

    def execute(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:

        return ExecutionResult(
            success=True,
            update=ResourceUpdate(),
            evidence={
                "decision": "SKIP",
                "endpoint": resource.endpoint,
            },
            message=(
                "Resource skipped by the DecisionEngine."
            ),
        )