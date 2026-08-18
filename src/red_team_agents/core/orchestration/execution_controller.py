from __future__ import annotations

from dataclasses import replace

from red_team_agents.core.reasoning.decision import (
    Decision,
)

from red_team_agents.core.execution.execution_context import (
    ExecutionContext,
)
from red_team_agents.core.execution.execution_dispatcher import (
    ExecutionDispatcher,
)
from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
)
from red_team_agents.core.reasoning.decision_engine import (
    DecisionEngine,
)
from red_team_agents.core.reasoning.decision_result import (
    DecisionResult,
)
from red_team_agents.core.reasoning.resource_model import (
    ResourceModel,
)


class ExecutionController:

    def __init__(
        self,
        decision_engine: DecisionEngine,
        execution_dispatcher: ExecutionDispatcher,
        execution_result_processor,
    ) -> None:
        self._decision_engine = decision_engine
        self._execution_dispatcher = execution_dispatcher
        self._execution_result_processor = execution_result_processor


    def run(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:

        return self._execution_loop(
            context=context,
            resource=resource,
        )



    def _execution_loop(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:

        current_resource = resource
        last_result = None
        max_iterations = 20
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            print(
                f"[ExecutionController] iteration={iteration}, "
                f"state={current_resource.state}"
            )

            decision = self._decision_engine.decide(
                current_resource,
            )

            print(
                f"[ExecutionController] decision="
                f"{decision.decision}"
            )

            if decision.decision == Decision.FINISH:
                break

            current_resource, last_result = (
                self._execute_iteration(
                    context=context,
                    resource=current_resource,
                    decision=decision,
                )
            )

        else:
            raise RuntimeError(
                "ExecutionController reached the maximum "
                f"iteration limit ({max_iterations}) without "
                "reaching Decision.FINISH."
            )

        return last_result

    def _execute_iteration(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
        decision: DecisionResult,
    ) -> tuple[ResourceModel, ExecutionResult]:

        dispatch_context = context

        if self._is_authorization_execution_decision(
            decision
        ):
            self._record_authorization_baseline_if_available(
                context=context,
                resource=resource,
                decision=decision,
            )

            dispatch_context = self._with_authorization_baseline_mode(
                context=context,
                mode="compare",
            )

        result = self._execution_dispatcher.dispatch(
            context=dispatch_context,
            resource=resource,
            decision=decision,
        )

        updated_resource = self._execution_result_processor.process(
            resource=resource,
            result=result,
        )

        return (
            updated_resource,
            result,
        )

    # helper para alterar o modo baseline
    def _with_authorization_baseline_mode(
        self,
        context,
        mode: str,
    ):
        return type(context)(
            data={
                **getattr(
                    context,
                    "data",
                    {},
                ),
                "authorization_baseline_mode": mode,
            }
        )


    def _is_authorization_execution_decision(
        self,
        decision,
    ) -> bool:
        return decision.decision in (
            Decision.EXECUTE_BOLA,
            Decision.EXECUTE_BFLA,
        )


    def _get_authorization_baseline_resource(
        self,
        context,
        resource=None,
    ):
        data = getattr(
            context,
            "data",
            {},
        ) or {}

        explicit_baseline_resource = data.get(
            "authorization_baseline_resource"
        )

        if explicit_baseline_resource is not None:
            return explicit_baseline_resource

        if resource is None:
            return None

        return self._build_authorization_baseline_resource(
            context=context,
            resource=resource,
        )


    def _record_authorization_baseline_if_available(
        self,
        context,
        resource,
        decision,
    ):
        if not self._is_authorization_execution_decision(
            decision
        ):
            return None

        baseline_resource = (
            self._get_authorization_baseline_resource(
                context=context,
                resource=resource,
            )
        )

        if baseline_resource is None:
            return None

        if baseline_resource is resource:
            return None

        record_context = (
            self._with_authorization_baseline_mode(
                context=context,
                mode="record",
            )
        )

        return self._execution_dispatcher.dispatch(
            context=record_context,
            resource=baseline_resource,
            decision=decision,
        )

    # helper para procurar token do actor autorizado
    def _get_actor_token(
        self,
        context,
        actor: str | None,
    ) -> str | None:
        if not actor:
            return None

        resolved_actor = self._resolve_actor_alias(
            context=context,
            actor_description=actor,
        )

        if not resolved_actor:
            return None

        data = getattr(
            context,
            "data",
            {},
        ) or {}

        actor_tokens = data.get(
            "actor_tokens",
            {},
        )

        if isinstance(
            actor_tokens,
            dict,
        ):
            token = actor_tokens.get(
                resolved_actor,
            )

            if token:
                return token

        authentication = data.get(
            "authentication",
            {},
        )

        if isinstance(
            authentication,
            dict,
        ):
            account = authentication.get(
                resolved_actor,
            )

            if isinstance(
                account,
                dict,
            ):
                token = account.get(
                    "jwt_token",
                )

                if token:
                    return token

        tokens = data.get(
            "tokens",
            {},
        )

        if isinstance(
            tokens,
            dict,
        ):
            token = tokens.get(
                resolved_actor,
            )

            if token:
                return token

        jwt_tokens = data.get(
            "jwt_tokens",
            {},
        )

        if isinstance(
            jwt_tokens,
            dict,
        ):
            token = jwt_tokens.get(
                resolved_actor,
            )

            if token:
                return token

        return None

    # helper para construir baseline resource
    def _build_authorization_baseline_resource(
        self,
        context,
        resource,
    ):
        baseline_actor = getattr(
            resource,
            "baseline_actor",
            None,
        )

        if not baseline_actor:
            return None

        resolved_baseline_actor = self._resolve_actor_alias(
            context=context,
            actor_description=baseline_actor,
        )

        if not resolved_baseline_actor:
            print(
                "[ExecutionController] baseline_actor=",
                baseline_actor,
                "resolved_as=None",
                "token_found=False",
            )
            return None

        baseline_token = self._get_actor_token(
            context=context,
            actor=resolved_baseline_actor,
        )

        if not baseline_token:
            print(
                "[ExecutionController] baseline_actor=",
                baseline_actor,
                "resolved_as=",
                resolved_baseline_actor,
                "token_found=False",
            )
            return None

        print(
            "[ExecutionController] baseline_actor=",
            baseline_actor,
            "resolved_as=",
            resolved_baseline_actor,
            "token_found=True",
        )

        return replace(
            resource,
            actor=resolved_baseline_actor,
            jwt_token=baseline_token,
            authenticated=True,
        )

    # Helper para obter actores disponíveis
    def _get_available_actor_names(
        self,
        context,
    ) -> set[str]:
        data = getattr(
            context,
            "data",
            {},
        ) or {}

        available: set[str] = set()

        authentication = data.get(
            "authentication",
            {},
        )

        if isinstance(
            authentication,
            dict,
        ):
            available.update(
                str(actor)
                for actor in authentication.keys()
            )

        actor_tokens = data.get(
            "actor_tokens",
            {},
        )

        if isinstance(
            actor_tokens,
            dict,
        ):
            available.update(
                str(actor)
                for actor in actor_tokens.keys()
            )

        tokens = data.get(
            "tokens",
            {},
        )

        if isinstance(
            tokens,
            dict,
        ):
            available.update(
                str(actor)
                for actor in tokens.keys()
            )

        jwt_tokens = data.get(
            "jwt_tokens",
            {},
        )

        if isinstance(
            jwt_tokens,
            dict,
        ):
            available.update(
                str(actor)
                for actor in jwt_tokens.keys()
            )

        return available

    # Helper para converter descrição em actor real
    def _resolve_actor_alias(
        self,
        context,
        actor_description: str | None,
    ) -> str | None:
        if not actor_description:
            return None

        actor_text = str(
            actor_description
        ).strip()

        if not actor_text:
            return None

        available_actors = self._get_available_actor_names(
            context
        )

        if actor_text in available_actors:
            return actor_text

        normalized = actor_text.lower()

        candidate_actors: list[str] = []

        if (
            "admin" in normalized
            or "management" in normalized
            or "privileged" in normalized
        ):
            candidate_actors = [
                "admin",
                "user_admin",
                "admin_user",
            ]

        elif "mechanic" in normalized:
            candidate_actors = [
                "mechanic",
                "user_mechanic",
            ]

        elif (
            "owner" in normalized
            or "rightful" in normalized
            or "allowed" in normalized
            or "intended viewer" in normalized
            or "intended onboarding" in normalized
            or "intended customer" in normalized
            or "customer account" in normalized
            or "customer" in normalized
            or "authorized role" in normalized
            or "authorized" in normalized
        ):
            candidate_actors = [
                "user_a",
                "owner",
                "account_owner",
            ]

        elif (
            "standard" in normalized
            or "non-owner" in normalized
            or "unrelated" in normalized
            or "without entitlement" in normalized
            or "not entitled" in normalized
        ):
            candidate_actors = [
                "user_b",
                "standard_user",
            ]

        for candidate in candidate_actors:
            if candidate in available_actors:
                return candidate

        return None