"""
decision_result.py

Represents the result produced by the DecisionEngine.

A DecisionResult contains the selected action and a human-readable
explanation that can be used for logging, auditing and reporting.
"""

from dataclasses import dataclass
from typing import Any, Dict

from .decision import Decision
from .resource_state import ResourceState


# A classe é frozen=True, portanto o resultado não pode ser alterado depois de criado. Isso ajuda na rastreabilidade.

@dataclass(frozen=True)
class DecisionResult:
    """
    Immutable result returned by the DecisionEngine.

    Attributes:
        decision:
            Next action selected for the resource.

        state:
            Resource state that originated the decision.

        reason:
            Human-readable explanation for the selected action.

        metadata:
            Optional structured information supporting the decision.
    """

    decision: Decision
    state: ResourceState
    reason: str
    metadata: Dict[str, Any]