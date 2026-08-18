from __future__ import annotations

from copy import deepcopy
from typing import Any

from red_team_agents.core.reasoning.resource_model import ResourceModel
from red_team_agents.core.reasoning.state_classifier import StateClassifier

from .execution_result import ExecutionResult
from .resource_update import UNSET, ResourceUpdate


class ExecutionResultProcessor:
    """
    Applies an ExecutionResult to a ResourceModel and delegates state
    classification exclusively to StateClassifier.

    Responsibilities:

    1. apply strongly typed resource updates;
    2. merge structured evidence;
    3. record the execution result;
    4. invoke StateClassifier;
    5. return the updated ResourceModel.

    This processor never assigns ResourceState directly.
    """

    def __init__(
        self,
        state_classifier: StateClassifier,
    ) -> None:
        if not isinstance(state_classifier, StateClassifier):
            raise TypeError(
                "ExecutionResultProcessor expects a StateClassifier "
                f"instance, received {type(state_classifier).__name__}."
            )

        self._state_classifier = state_classifier

    def process(
        self,
        resource: ResourceModel,
        result: ExecutionResult,
    ) -> ResourceModel:
        """
        Apply an execution result and reclassify the supplied resource.

        Args:
            resource: Resource receiving the execution outcome.
            result: Immutable result produced by an execution strategy.

        Returns:
            The same ResourceModel instance after updates and classification.

        Raises:
            TypeError: If the supplied arguments have invalid types.
        """

        if not isinstance(resource, ResourceModel):
            raise TypeError(
                "ExecutionResultProcessor.process() expects a ResourceModel "
                f"instance, received {type(resource).__name__}."
            )

        if not isinstance(result, ExecutionResult):
            raise TypeError(
                "ExecutionResultProcessor.process() expects an "
                f"ExecutionResult instance, received "
                f"{type(result).__name__}."
            )

        self._apply_update(
            resource=resource,
            update=result.update,
        )

        self._merge_evidence(
            resource=resource,
            result=result,
        )

        print(
            "[ResultProcessor]",
            resource.authenticated,
            resource.actor,
            resource.jwt_token is not None,
        )

        return self._state_classifier.classify(resource)

    def _apply_update(
        self,
        resource: ResourceModel,
        update: ResourceUpdate,
    ) -> None:
        """
        Apply only fields that are not marked as UNSET.
        """

        if update.authenticated is not UNSET:
            resource.authenticated = bool(update.authenticated)

        if update.actor is not UNSET:
            resource.actor = update.actor

        if update.jwt_token is not UNSET:
            resource.jwt_token = update.jwt_token

        if update.object_ids is not UNSET:
            resource.object_ids = self._normalise_object_ids(
                update.object_ids,
            )

        if update.selected_object_id is not UNSET:
            resource.selected_object_id = self._normalise_optional_string(
                update.selected_object_id,
            )

        if update.executable is not UNSET:
            resource.executable = bool(update.executable)

        if update.execution_attempts is not UNSET:
            resource.execution_attempts = self._validate_attempts(
                update.execution_attempts,
            )

        if update.status_code is not UNSET:
            resource.status_code = self._validate_status_code(
                update.status_code,
            )

        if update.response_time is not UNSET:
            resource.response_time = self._validate_response_time(
                update.response_time,
            )

        if update.vulnerable is not UNSET:
            resource.vulnerable = update.vulnerable

        self._apply_evidence_flags(
            resource=resource,
            update=update,
        )

    @staticmethod
    def _apply_evidence_flags(
        resource: ResourceModel,
        update: ResourceUpdate,
    ) -> None:
        """
        Store workflow flags in evidence because StateClassifier reads them
        from ResourceModel.evidence.
        """

        evidence_flags = {
            "completed": update.completed,
            "exhausted": update.exhausted,
            "timeout": update.timeout,
        }

        for key, value in evidence_flags.items():
            if value is UNSET:
                continue

            if value is None:
                resource.evidence.pop(key, None)
                continue

            resource.evidence[key] = bool(value)

    @staticmethod
    def _merge_evidence(
        resource: ResourceModel,
        result: ExecutionResult,
    ) -> None:
        """
        Preserve current evidence and append an auditable execution record.
        """

        if result.evidence:
            strategy_evidence = resource.evidence.setdefault(
                "strategy_evidence",
                [],
            )

            strategy_evidence.append(
                deepcopy(result.evidence)
            )

        execution_results = resource.evidence.setdefault(
            "execution_results",
            [],
        )

        execution_results.append(
            {
                "success": result.success,
                "message": result.message,
                "update": (
                    ExecutionResultProcessor._serialise_update(
                        result.update
                    )
                ),
                "evidence": deepcopy(result.evidence),
            }
        )

    @staticmethod
    def _serialise_update(
        update: ResourceUpdate,
    ) -> dict[str, Any]:
        """
        Convert only explicitly supplied update fields into evidence-safe data.
        """

        serialised: dict[str, Any] = {}

        field_names = (
            "authenticated",
            "actor",
            "jwt_token",
            "object_ids",
            "selected_object_id",
            "executable",
            "execution_attempts",
            "status_code",
            "response_time",
            "vulnerable",
            "completed",
            "exhausted",
            "timeout",
        )

        sensitive_fields = {
            "jwt_token",
        }

        for field_name in field_names:
            value = getattr(update, field_name)

            if value is UNSET:
                continue

            if field_name in sensitive_fields:
                serialised[field_name] = (
                    "***REDACTED***"
                    if value
                    else value
                )
                continue

            if isinstance(value, tuple):
                serialised[field_name] = list(value)
            else:
                serialised[field_name] = value

        return serialised

    @staticmethod
    def _normalise_object_ids(
        object_ids: list[str] | tuple[str, ...],
    ) -> list[str]:
        """
        Normalise identifiers while preserving insertion order.
        """

        normalised: list[str] = []
        observed: set[str] = set()

        for object_id in object_ids:
            if object_id is None:
                continue

            value = str(object_id).strip()

            if not value or value in observed:
                continue

            observed.add(value)
            normalised.append(value)

        return normalised

    @staticmethod
    def _normalise_optional_string(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalised = str(value).strip()

        return normalised or None

    @staticmethod
    def _validate_attempts(
        attempts: int | None,
    ) -> int:
        if attempts is None:
            return 0

        if isinstance(attempts, bool) or not isinstance(attempts, int):
            raise TypeError(
                "execution_attempts must be an integer or None."
            )

        if attempts < 0:
            raise ValueError(
                "execution_attempts cannot be negative."
            )

        return attempts

    @staticmethod
    def _validate_status_code(
        status_code: int | None,
    ) -> int | None:
        if status_code is None:
            return None

        if isinstance(status_code, bool) or not isinstance(
            status_code,
            int,
        ):
            raise TypeError(
                "status_code must be an integer or None."
            )

        if status_code < 100 or status_code > 599:
            raise ValueError(
                "status_code must be between 100 and 599."
            )

        return status_code

    @staticmethod
    def _validate_response_time(
        response_time: float | None,
    ) -> float | None:
        if response_time is None:
            return None

        if isinstance(response_time, bool) or not isinstance(
            response_time,
            (int, float),
        ):
            raise TypeError(
                "response_time must be numeric or None."
            )

        if response_time < 0:
            raise ValueError(
                "response_time cannot be negative."
            )

        return float(response_time)