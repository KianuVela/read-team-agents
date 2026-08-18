from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from red_team_agents.core.execution.execution_context import ExecutionContext
from red_team_agents.core.execution.execution_result import ExecutionResult
from red_team_agents.core.execution.execution_strategy import ExecutionStrategy
from red_team_agents.core.execution.resource_update import ResourceUpdate
from red_team_agents.core.reasoning.resource_model import ResourceModel


class AuthenticationStrategy(ExecutionStrategy):
    """
    Deterministic strategy responsible for applying an authentication
    identity already available in the ExecutionContext.

    This strategy:
    - does not authenticate through the network;
    - does not mutate ResourceModel;
    - does not change ResourceState;
    - does not expose JWT values in evidence;
    - returns only an immutable ExecutionResult.
    """

    _CONTAINER_KEYS = (
        "users",
        "accounts",
        "actors",
        "authenticated_users",
    )

    _TOKEN_KEYS = (
        "jwt_token",
        "access_token",
        "token",
        "jwt",
    )

    def __init__(self, preferred_actor: str | None = None) -> None:
        self._preferred_actor = preferred_actor

    def execute(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:
        authentication = context.authentication

        accounts = self._extract_accounts(authentication)

        if not accounts:
            return self._authentication_failure(
                message="No authentication accounts were found in the execution context.",
                reason="authentication_context_empty",
            )

        selected = self._select_account(
            accounts=accounts,
            resource=resource,
        )

        if selected is None:
            return self._authentication_failure(
                message="No account containing a usable authentication token was found.",
                reason="authentication_token_missing",
            )

        actor, account = selected
        print(
            "[AuthenticationStrategy] "
            f"test_case={resource.test_case_id} "
            f"test_type={resource.test_type} "
            f"negative_actor={resource.negative_actor!r} "
            f"selected_actor={actor}"
        )

        token = self._extract_token(account)

        if token is None:
            return self._authentication_failure(
                message=f"The selected actor '{actor}' does not contain a usable token.",
                reason="selected_actor_token_missing",
                actor=actor,
            )

        return ExecutionResult(
            success=True,
            update=ResourceUpdate(
                authenticated=True,
                actor=actor,
                jwt_token=token,
            ),
            evidence={
                "strategy": self.__class__.__name__,
                "action": "authentication_context_applied",
                "actor": actor,
                "token_present": True,
                "token_type": self._detect_token_type(account),
            },
            message=f"Authentication context applied for actor '{actor}'.",
        )

    def _extract_accounts(
        self,
        authentication: Any,
    ) -> dict[str, Mapping[str, Any]]:
        """
        Normalises supported authentication-context structures.

        Supported examples:

        {
            "user_a": {"jwt_token": "..."},
            "user_b": {"jwt_token": "..."}
        }

        or:

        {
            "users": {
                "user_a": {"jwt_token": "..."},
                "user_b": {"jwt_token": "..."}
            }
        }
        """

        if not isinstance(authentication, Mapping):
            return {}

        for container_key in self._CONTAINER_KEYS:
            nested_accounts = authentication.get(container_key)

            if isinstance(nested_accounts, Mapping):
                return self._normalise_accounts(nested_accounts)

        return self._normalise_accounts(authentication)

    @staticmethod
    def _normalise_accounts(
        raw_accounts: Mapping[Any, Any],
    ) -> dict[str, Mapping[str, Any]]:
        accounts: dict[str, Mapping[str, Any]] = {}

        for actor, account in raw_accounts.items():
            if isinstance(account, Mapping):
                accounts[str(actor)] = account

        return accounts

    def _select_account(
        self,
        accounts: Mapping[str, Mapping[str, Any]],
        resource: ResourceModel,
    ) -> tuple[str, Mapping[str, Any]] | None:
        """
        Select an authentication account deterministically.

        Priority:
        1. Negative actor defined by the TestPlan;
        2. Actor already associated with the resource;
        3. Preferred actor configured in the strategy;
        4. Safe deterministic fallback.
        """

        # --------------------------------------------------
        # 1. Actor requested by the TestPlan
        # --------------------------------------------------

        planned_actor = self._resolve_planned_actor(
            resource=resource,
            accounts=accounts,
        )

        if planned_actor is not None:

            account = accounts.get(planned_actor)

            if (
                account is not None
                and self._extract_token(account) is not None
            ):
                return planned_actor, account

        # --------------------------------------------------
        # 2. Existing resource actor
        # --------------------------------------------------

        resource_actor = getattr(
            resource,
            "actor",
            None,
        )

        if resource_actor:

            account = accounts.get(
                str(resource_actor)
            )

            if (
                account is not None
                and self._extract_token(account) is not None
            ):
                return str(resource_actor), account

        # --------------------------------------------------
        # 3. Explicit preferred actor
        # --------------------------------------------------

        if self._preferred_actor:

            account = accounts.get(
                self._preferred_actor
            )

            if (
                account is not None
                and self._extract_token(account) is not None
            ):
                return self._preferred_actor, account

        # --------------------------------------------------
        # 4. Deterministic fallback
        # --------------------------------------------------

        for fallback_actor in (
            "user_b",
            "user_a",
            "mechanic",
            "management",
            "admin",
        ):

            account = accounts.get(
                fallback_actor
            )

            if (
                account is not None
                and self._extract_token(account) is not None
            ):
                return fallback_actor, account

        return None


    def _resolve_planned_actor(
        self,
        resource: ResourceModel,
        accounts: Mapping[str, Mapping[str, Any]],
    ) -> str | None:
        """
        Resolve the execution actor requested by the TestPlan
        into one of the concrete accounts available in the
        ExecutionContext.
        """

        negative_actor = (
            getattr(resource, "negative_actor", None)
            or ""
        )

        value = str(
            negative_actor
        ).strip().lower()

        # Exact account name produced by the planner.
        for actor in accounts:

            if value == actor.lower():
                return actor

        # --------------------------------------------------
        # Semantic mappings used by the TestPlanningAgent
        # --------------------------------------------------

        if "admin" in value:
            return (
                "admin"
                if "admin" in accounts
                else None
            )

        if "management" in value:
            return (
                "management"
                if "management" in accounts
                else None
            )

        if "mechanic" in value:
            return (
                "mechanic"
                if "mechanic" in accounts
                else None
            )

        if any(
            term in value
            for term in (
                "non-owner",
                "non owner",
                "unrelated user",
                "different user",
                "standard user",
                "non-privileged user",
                "non privileged user",
            )
        ):
            return (
                "user_b"
                if "user_b" in accounts
                else (
                    "user_a"
                    if "user_a" in accounts
                    else None
                )
            )

        return None

    def _extract_token(
        self,
        account: Mapping[str, Any],
    ) -> str | None:
        for key in self._TOKEN_KEYS:
            token = account.get(key)

            if isinstance(token, str) and token.strip():
                return token.strip()

        return None

    def _detect_token_type(
        self,
        account: Mapping[str, Any],
    ) -> str:
        for key in self._TOKEN_KEYS:
            token = account.get(key)

            if isinstance(token, str) and token.strip():
                return key

        return "unknown"

    def _authentication_failure(
        self,
        *,
        message: str,
        reason: str,
        actor: str | None = None,
    ) -> ExecutionResult:
        return ExecutionResult(
            success=False,
            update=ResourceUpdate(
                authenticated=False,
                actor=actor,
                jwt_token=None,
            ),
            evidence={
                "strategy": self.__class__.__name__,
                "action": "authentication_context_rejected",
                "reason": reason,
                "actor": actor,
                "token_present": False,
            },
            message=message,
        )