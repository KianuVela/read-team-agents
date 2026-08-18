from __future__ import annotations

from red_team_agents.core.execution.execution_context import ExecutionContext
from red_team_agents.core.execution.execution_context_provider import (
    ExecutionContextProvider,
)
from red_team_agents.tools.authentication_context_tool import (
    AuthenticationContextTool,
)


class ExecutionContextToolAdapter(
    ExecutionContextProvider
):

    def __init__(
        self,
        tool: AuthenticationContextTool,
    ):
        self.tool = tool

    def build_context(
        self,
        target_url: str,
        inventory_file: str,
    ) -> ExecutionContext:

        context = self.tool._build_execution_context(
            target_url,
            inventory_file,
        )

        context = self.tool.save_auth_context(context)

        return ExecutionContext(
            data=context,
        )