from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .resource_update import ResourceUpdate


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """
    Immutable result produced by an execution strategy.

    The result contains:

    - the operational success of the strategy;
    - a strongly typed ResourceUpdate;
    - structured execution evidence;
    - a human-readable message.

    It does not mutate or depend directly on ResourceModel.
    """

    success: bool

    update: ResourceUpdate = field(
        default_factory=ResourceUpdate,
    )

    evidence: dict[str, Any] = field(
        default_factory=dict,
    )

    message: str | None = None