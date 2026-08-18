from __future__ import annotations

from red_team_agents.core.orchestration.execution_controller import (
    ExecutionController,
)

from red_team_agents.core.execution.execution_dispatcher import (
    ExecutionDispatcher,
)

from red_team_agents.core.execution.execution_result_processor import (
    ExecutionResultProcessor,
)

from red_team_agents.core.reasoning.decision_engine import (
    DecisionEngine,
)

from red_team_agents.tools.kali_mcp_tool import (
    KaliMCPTool,
)

from red_team_agents.core.execution.strategy_registry import (
    StrategyRegistry,
)

from red_team_agents.core.execution.strategies.authentication_strategy import (
    AuthenticationStrategy,
)

from red_team_agents.core.execution.strategies.discovery_strategy import (
    DiscoveryStrategy,
)

from red_team_agents.core.execution.strategies.bola_strategy import (
    BolaStrategy,
)

from red_team_agents.core.execution.strategies.bfla_strategy import (
    BFLAStrategy,
)

from red_team_agents.core.execution.http.curl_builder import (
    CurlBuilder,
)

from red_team_agents.core.reasoning.decision import (
    Decision,
)

from red_team_agents.core.reasoning.state_classifier import (
    StateClassifier,
)

from red_team_agents.core.execution.strategies.skip_strategy import (
    SkipStrategy,
)

from red_team_agents.core.execution.analysis.authorization_baseline_manager import (
    AuthorizationBaselineManager,
)


class ExecutionRuntimeFactory:
    """
    Builds the complete execution runtime.

    This class is responsible for assembling every component
    required by the cognitive execution layer.

    The CrewAI layer should never instantiate internal execution
    components directly.
    """

    @staticmethod
    def create() -> ExecutionController:

        decision_engine = DecisionEngine()

        strategy_registry = (
            ExecutionRuntimeFactory
            ._build_strategy_registry()
        )

        dispatcher = ExecutionDispatcher(
            strategy_registry=strategy_registry,
        )

        state_classifier = StateClassifier()

        result_processor = ExecutionResultProcessor(
            state_classifier=state_classifier,
        )

        return ExecutionController(
            decision_engine=decision_engine,
            execution_dispatcher=dispatcher,
            execution_result_processor=result_processor,
        )

    @staticmethod
    def _build_shared_dependencies() -> dict:

        return {
            "kali_tool": KaliMCPTool(),
            "curl_builder": CurlBuilder(),
            "baseline_manager": AuthorizationBaselineManager(),
        }

    @staticmethod
    def _build_strategy_registry() -> StrategyRegistry:

        deps = (
            ExecutionRuntimeFactory
            ._build_shared_dependencies()
        )

        registry = StrategyRegistry()

        registry.register(
            Decision.AUTHENTICATE,
            AuthenticationStrategy(),
        )

        registry.register(
            Decision.DISCOVER_OBJECTS,
            DiscoveryStrategy(),
        )

        registry.register(
            Decision.SKIP,
            SkipStrategy(),
        )

        registry.register(
            Decision.EXECUTE_BOLA,
            BolaStrategy(**deps),
        )

        registry.register(
            Decision.EXECUTE_BFLA,
            BFLAStrategy(**deps),
        )

        return registry