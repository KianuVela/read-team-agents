from __future__ import annotations

from red_team_agents.core.reasoning.decision import Decision
from red_team_agents.core.execution.execution_strategy import ExecutionStrategy


class StrategyRegistry:

    def __init__(self):

        self._strategies: dict[
            Decision,
            ExecutionStrategy,
        ] = {}

    def register(
        self,
        decision: Decision,
        strategy: ExecutionStrategy,
    ):

        self._strategies[decision] = strategy

    def get(
        self,
        decision: Decision,
    ) -> ExecutionStrategy:

        try:
            return self._strategies[decision]

        except KeyError:

            raise ValueError(
                f"No strategy registered for {decision}"
            )