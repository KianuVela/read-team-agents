from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from red_team_agents.core.execution.execution_context import (
    ExecutionContext,
)
from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
)
from red_team_agents.core.execution.execution_strategy import (
    ExecutionStrategy,
)
from red_team_agents.core.execution.resource_update import (
    ResourceUpdate,
)
from red_team_agents.core.reasoning.resource_model import (
    ResourceModel,
)


class DiscoveryStrategy(ExecutionStrategy):
    """
    Deterministic strategy responsible for selecting an object identifier
    previously discovered during the authentication/bootstrap phase.

    This strategy never:

    - performs HTTP requests;
    - invokes KaliMCPTool;
    - mutates ResourceModel;
    - changes ResourceState.
    """

    _OBJECT_KEYS = (
        "ids",
        "objects",
        "resources",
        "object_ids",
    )

    def execute(
        self,
        context: ExecutionContext,
        resource: ResourceModel,
    ) -> ExecutionResult:

        objects = self._extract_endpoint_objects(
            context.objects,
            resource.endpoint,
        )

        if not objects:

            return ExecutionResult(
                success=False,
                update=ResourceUpdate(
                    object_ids=[],
                    selected_object_id=None,
                ),
                evidence={
                    "discovery": {
                        "endpoint": resource.endpoint,
                        "objects_found": False,
                        "object_count": 0,
                    }
                },
                message="No objects are available for this endpoint.",
            )

        reusable = self._reuse_identifier(
            resource,
            objects,
        )

        if reusable is not None:

            return ExecutionResult(
                success=True,
                update=ResourceUpdate(
                    object_ids=objects,
                    selected_object_id=reusable,
                ),
                evidence={
                    "discovery": {
                        "endpoint": resource.endpoint,
                        "objects_found": True,
                        "object_count": len(objects),
                        "selected_object": reusable,
                        "selection_method": "reuse",
                        "reused": True,
                    }
                },
                message="Existing object identifier reused.",
            )

        selected = self._select_identifier(objects)

        return ExecutionResult(
            success=True,
            update=ResourceUpdate(
                object_ids=objects,
                selected_object_id=selected,
            ),
            evidence={
                "discovery": {
                    "endpoint": resource.endpoint,
                    "objects_found": True,
                    "object_count": len(objects),
                    "selected_object": selected,
                    "selection_method": "deterministic_first",
                    "reused": False,
                }
            },
            message="Object identifier selected deterministically.",
        )

    def _extract_endpoint_objects(
        self,
        all_objects: Mapping[str, Any],
        endpoint: str,
    ) -> list[str]:

        endpoint_data = all_objects.get(endpoint)

        if endpoint_data is None:
            return []

        if isinstance(endpoint_data, Sequence) and not isinstance(
            endpoint_data,
            (str, bytes),
        ):
            return self._normalise(endpoint_data)

        if isinstance(endpoint_data, Mapping):

            for key in self._OBJECT_KEYS:

                values = endpoint_data.get(key)

                if isinstance(values, Sequence) and not isinstance(
                    values,
                    (str, bytes),
                ):
                    return self._normalise(values)

        return []

    @staticmethod
    def _normalise(
        values: Sequence[Any],
    ) -> list[str]:

        result = []

        for value in values:

            text = str(value).strip()

            if text:
                result.append(text)

        return sorted(set(result))

    @staticmethod
    def _reuse_identifier(
        resource: ResourceModel,
        objects: list[str],
    ) -> str | None:

        current = resource.selected_object_id

        if current is None:
            return None

        current = str(current)

        if current in objects:
            return current

        return None

    @staticmethod
    def _select_identifier(
        objects: list[str],
    ) -> str:

        return objects[0]