from __future__ import annotations

from red_team_agents.core.execution.execution_context import (
    ExecutionContext,
)
from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
)
from red_team_agents.core.execution.strategy_registry import (
    StrategyRegistry,
)
from red_team_agents.core.reasoning.decision_result import (
    DecisionResult,
)
from red_team_agents.core.reasoning.resource_model import (
    ResourceModel,
)


class ExecutionDispatcher:

    def __init__(
        self,
        strategy_registry: StrategyRegistry,
    ) -> None:

        self.strategy_registry = strategy_registry

    def dispatch(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
        decision: DecisionResult,
    ) -> ExecutionResult:

        strategy = self.strategy_registry.get(
            decision.decision,
        )

        return strategy.execute(
            context,
            resource,
        )