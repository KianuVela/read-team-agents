"""
decision_engine.py

Deterministic dispatcher responsible for translating ResourceState
values into executable decisions.

The DecisionEngine does not inspect OpenAPI specifications, perform
authentication, discover object identifiers or execute attacks.

It receives an already classified ResourceModel and determines the next
action exclusively from its current state and a small set of execution
constraints.
"""

from typing import Dict, FrozenSet

from .decision import Decision
from .decision_result import DecisionResult
from .resource_model import ResourceModel
from .resource_state import ResourceState


class DecisionEngine:
    """
    Deterministic decision dispatcher for classified API resources.

    The engine converts ResourceState values into Decision values using a
    state-to-decision dispatch table.

    A limited amount of validation is performed to prevent invalid
    execution actions, such as executing BOLA without an object
    identifier or retrying beyond the configured attempt limit.
    """

    _DECISION_TABLE: Dict[ResourceState, Decision] = {
        ResourceState.UNKNOWN: Decision.SKIP,

        ResourceState.AUTH_REQUIRED: Decision.AUTHENTICATE,
        ResourceState.AUTHENTICATED: Decision.SKIP,
        ResourceState.INVALID_TOKEN: Decision.AUTHENTICATE,
        ResourceState.FORBIDDEN: Decision.SKIP,

        ResourceState.RESOURCE_DISCOVERED: Decision.DISCOVER_OBJECTS,
        ResourceState.RESOURCE_NOT_FOUND: Decision.SKIP,
        ResourceState.EMPTY_COLLECTION: Decision.FINISH,
        ResourceState.IDENTIFIERS_DISCOVERED: Decision.SKIP,

        ResourceState.DETAIL_ENDPOINT: Decision.DISCOVER_OBJECTS,
        ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER:
            Decision.FINISH,

        ResourceState.SELF_RESOURCE: Decision.SKIP,
        ResourceState.CROSS_USER_RESOURCE: Decision.SKIP,

        ResourceState.OBSERVED: Decision.FINISH,
        ResourceState.CLASSIFIED: Decision.SKIP,

        ResourceState.READY_FOR_BOLA: Decision.EXECUTE_BOLA,
        ResourceState.READY_FOR_BFLA: Decision.EXECUTE_BFLA,

        ResourceState.EXECUTING: Decision.SKIP,

        ResourceState.VULNERABLE: Decision.FINISH,
        ResourceState.NOT_VULNERABLE: Decision.FINISH,
        ResourceState.INCONCLUSIVE: Decision.FINISH,

        ResourceState.SERVER_FAILURE: Decision.RETRY,
        ResourceState.RATE_LIMITED: Decision.RETRY,
        ResourceState.TIMEOUT: Decision.RETRY,

        ResourceState.COMPLETED: Decision.FINISH,
        ResourceState.EXHAUSTED: Decision.FINISH,
    }

    _RETRYABLE_STATES: FrozenSet[ResourceState] = frozenset(
        {
            ResourceState.SERVER_FAILURE,
            ResourceState.RATE_LIMITED,
            ResourceState.TIMEOUT,
        }
    )

    _TERMINAL_STATES: FrozenSet[ResourceState] = frozenset(
        {
            ResourceState.VULNERABLE,
            ResourceState.NOT_VULNERABLE,
            ResourceState.INCONCLUSIVE,
            ResourceState.COMPLETED,
            ResourceState.EXHAUSTED,
        }
    )

    def __init__(self, max_execution_attempts: int = 3) -> None:
        """
        Initialise the decision engine.

        Args:
            max_execution_attempts:
                Maximum number of execution attempts permitted for one
                resource before retryable failures become exhausted.

        Raises:
            ValueError:
                If max_execution_attempts is lower than one.
        """

        if max_execution_attempts < 1:
            raise ValueError(
                "max_execution_attempts must be greater than or equal to 1."
            )

        self.max_execution_attempts = max_execution_attempts

    def decide(self, resource: ResourceModel) -> DecisionResult:
        """
        Select the next action for a classified API resource.

        Args:
            resource:
                ResourceModel previously classified by StateClassifier.

        Returns:
            DecisionResult containing the selected decision, source state,
            explanation and structured metadata.

        Raises:
            TypeError:
                If resource is not a ResourceModel instance.
        """

        if not isinstance(resource, ResourceModel):
            raise TypeError(
                "DecisionEngine.decide() expects a ResourceModel instance, "
                f"received {type(resource).__name__}."
            )

        if resource.state in self._TERMINAL_STATES:
            return self._build_result(
                resource=resource,
                decision=Decision.FINISH,
                reason=self._terminal_reason(resource),
            )

        if resource.state in self._RETRYABLE_STATES:
            return self._decide_retry(resource)

        decision = self._DECISION_TABLE.get(
            resource.state,
            Decision.SKIP,
        )

        if decision == Decision.EXECUTE_BOLA:
            return self._decide_bola(resource)

        if decision == Decision.EXECUTE_BFLA:
            return self._decide_bfla(resource)

        return self._build_result(
            resource=resource,
            decision=decision,
            reason=self._reason_for_decision(
                state=resource.state,
                decision=decision,
            ),
        )

    def _decide_bola(
        self,
        resource: ResourceModel,
    ) -> DecisionResult:
        """
        Validate and return a BOLA execution decision.
        """

        if not resource.executable:
            return self._build_result(
                resource=resource,
                decision=Decision.SKIP,
                reason=(
                    "The resource is classified as READY_FOR_BOLA, but its "
                    "executable flag is false."
                ),
            )

        if not resource.authenticated:
            return self._build_result(
                resource=resource,
                decision=Decision.AUTHENTICATE,
                reason=(
                    "BOLA execution requires an authenticated actor."
                ),
            )

        if not resource.jwt_token:
            return self._build_result(
                resource=resource,
                decision=Decision.AUTHENTICATE,
                reason=(
                    "BOLA execution requires a valid authentication token."
                ),
            )

        if resource.selected_object_id is None:
            return self._build_result(
                resource=resource,
                decision=Decision.DISCOVER_OBJECTS,
                reason=(
                    "BOLA execution requires a selected object identifier."
                ),
            )

        if resource.execution_attempts >= self.max_execution_attempts:
            return self._build_result(
                resource=resource,
                decision=Decision.FINISH,
                reason=(
                    "The maximum number of BOLA execution attempts has "
                    "already been reached."
                ),
            )

        return self._build_result(
            resource=resource,
            decision=Decision.EXECUTE_BOLA,
            reason=(
                "The authenticated detail resource has a selected object "
                "identifier and is ready for BOLA execution."
            ),
        )

    def _decide_bfla(
        self,
        resource: ResourceModel,
    ) -> DecisionResult:
        """
        Validate and return a BFLA execution decision.
        """

        if not resource.executable:
            return self._build_result(
                resource=resource,
                decision=Decision.SKIP,
                reason=(
                    "The resource is classified as READY_FOR_BFLA, but its "
                    "executable flag is false."
                ),
            )

        if not resource.authenticated:
            return self._build_result(
                resource=resource,
                decision=Decision.AUTHENTICATE,
                reason=(
                    "BFLA execution requires an authenticated actor."
                ),
            )

        if not resource.jwt_token:
            return self._build_result(
                resource=resource,
                decision=Decision.AUTHENTICATE,
                reason=(
                    "BFLA execution requires a valid authentication token."
                ),
            )

        if resource.execution_attempts >= self.max_execution_attempts:
            return self._build_result(
                resource=resource,
                decision=Decision.FINISH,
                reason=(
                    "The maximum number of BFLA execution attempts has "
                    "already been reached."
                ),
            )

        return self._build_result(
            resource=resource,
            decision=Decision.EXECUTE_BFLA,
            reason=(
                "The authenticated resource is ready for BFLA execution."
            ),
        )

    def _decide_retry(
        self,
        resource: ResourceModel,
    ) -> DecisionResult:
        """
        Decide whether a failed operation should be retried.
        """

        if resource.execution_attempts >= self.max_execution_attempts:
            return self._build_result(
                resource=resource,
                decision=Decision.FINISH,
                reason=(
                    "The resource is in a retryable failure state, but the "
                    "maximum number of execution attempts has been reached."
                ),
            )

        remaining_attempts = (
            self.max_execution_attempts - resource.execution_attempts
        )

        return self._build_result(
            resource=resource,
            decision=Decision.RETRY,
            reason=(
                f"The resource is in state {resource.state.name} and may "
                f"be retried. Remaining attempts: {remaining_attempts}."
            ),
            extra_metadata={
                "remaining_attempts": remaining_attempts,
            },
        )

    def _build_result(
        self,
        resource: ResourceModel,
        decision: Decision,
        reason: str,
        extra_metadata: Dict[str, object] | None = None,
    ) -> DecisionResult:
        """
        Build a traceable DecisionResult.
        """

        metadata: Dict[str, object] = {
            "endpoint": resource.endpoint,
            "method": resource.method,
            "actor": resource.actor,
            "authenticated": resource.authenticated,
            "executable": resource.executable,
            "selected_object_id": resource.selected_object_id,
            "execution_attempts": resource.execution_attempts,
            "max_execution_attempts": self.max_execution_attempts,
        }

        if extra_metadata:
            metadata.update(extra_metadata)

        self._record_decision(
            resource=resource,
            decision=decision,
            reason=reason,
            metadata=metadata,
        )

        return DecisionResult(
            decision=decision,
            state=resource.state,
            reason=reason,
            metadata=metadata,
        )

    @staticmethod
    def _record_decision(
        resource: ResourceModel,
        decision: Decision,
        reason: str,
        metadata: Dict[str, object],
    ) -> None:
        """
        Store a structured decision record in the resource evidence.
        """

        decisions = resource.evidence.setdefault(
            "decisions",
            [],
        )

        decisions.append(
            {
                "state": resource.state.name,
                "decision": decision.name,
                "reason": reason,
                "metadata": metadata.copy(),
            }
        )

    @staticmethod
    def _terminal_reason(resource: ResourceModel) -> str:
        """
        Return a reason for a terminal-state decision.
        """

        reasons = {
            ResourceState.VULNERABLE:
                "The resource has been confirmed as vulnerable.",
            ResourceState.NOT_VULNERABLE:
                "The resource has been classified as not vulnerable.",
            ResourceState.INCONCLUSIVE:
                "The execution result is inconclusive.",
            ResourceState.COMPLETED:
                "The resource execution workflow has been completed.",
            ResourceState.EXHAUSTED:
                "All permitted execution attempts or candidates have been "
                "exhausted.",
        }

        return reasons.get(
            resource.state,
            "The resource reached a terminal state.",
        )

    @staticmethod
    def _reason_for_decision(
        state: ResourceState,
        decision: Decision,
    ) -> str:
        """
        Return a human-readable reason for a mapped decision.
        """

        reasons = {
            ResourceState.UNKNOWN:
                "The resource has not yet been sufficiently classified.",

            ResourceState.AUTH_REQUIRED:
                "Authentication is required before execution can continue.",

            ResourceState.AUTHENTICATED:
                "Authentication is available, but the resource requires "
                "additional classification.",

            ResourceState.INVALID_TOKEN:
                "The current authentication token is missing or invalid.",

            ResourceState.FORBIDDEN:
                "The API denied access to the current actor.",

            ResourceState.RESOURCE_DISCOVERED:
                "The resource was discovered, but object identifiers are "
                "still required.",

            ResourceState.RESOURCE_NOT_FOUND:
                "The resource endpoint could not be found.",

            ResourceState.EMPTY_COLLECTION:
                "The collection did not provide object identifiers.",

            ResourceState.IDENTIFIERS_DISCOVERED:
                "Object identifiers are available, but the resource must "
                "be classified again before execution.",

            ResourceState.DETAIL_ENDPOINT:
                "The detail endpoint requires object discovery or further "
                "classification.",

            ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER:
                "The detail endpoint has no usable object identifier.",

            ResourceState.SELF_RESOURCE:
                "The resource belongs to the authenticated actor and does "
                "not yet represent a cross-user test case.",

            ResourceState.CROSS_USER_RESOURCE:
                "A cross-user resource was identified but no execution "
                "strategy was assigned.",

            ResourceState.OBSERVED:
                "The resource was observed but is not currently executable.",

            ResourceState.CLASSIFIED:
                "The resource was classified but no execution action was "
                "assigned.",

            ResourceState.EXECUTING:
                "The resource is already being executed.",
        }

        return reasons.get(
            state,
            f"State {state.name} maps to decision {decision.name}.",
        )