from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeAlias


class _UnsetType:
    """
    Marker used to distinguish:

    - a field that must not be changed;
    - a field that must explicitly be set to None.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Final[_UnsetType] = _UnsetType()

OptionalBooleanUpdate: TypeAlias = bool | None | _UnsetType
OptionalStringUpdate: TypeAlias = str | None | _UnsetType
OptionalIntegerUpdate: TypeAlias = int | None | _UnsetType
OptionalFloatUpdate: TypeAlias = float | None | _UnsetType
ObjectIdentifiersUpdate: TypeAlias = list[str] | tuple[str, ...] | _UnsetType


# Porque usamos frozen=True?
# O objeto torna-se imutável:

@dataclass(frozen=True, slots=True)
class ResourceUpdate:
    """
    Strongly typed and immutable description of changes that must be applied
    to a ResourceModel.

    Execution strategies must not mutate ResourceModel directly. They return
    an ExecutionResult containing a ResourceUpdate.

    UNSET means that a field must remain unchanged.
    None means that a field must explicitly be cleared, when supported.
    """

    authenticated: OptionalBooleanUpdate = UNSET

    actor: OptionalStringUpdate = UNSET

    jwt_token: OptionalStringUpdate = UNSET

    object_ids: ObjectIdentifiersUpdate = UNSET

    selected_object_id: OptionalStringUpdate = UNSET

    executable: OptionalBooleanUpdate = UNSET

    execution_attempts: OptionalIntegerUpdate = UNSET

    status_code: OptionalIntegerUpdate = UNSET

    response_time: OptionalFloatUpdate = UNSET

    vulnerable: OptionalBooleanUpdate = UNSET

    completed: OptionalBooleanUpdate = UNSET

    exhausted: OptionalBooleanUpdate = UNSET

    timeout: OptionalBooleanUpdate = UNSET