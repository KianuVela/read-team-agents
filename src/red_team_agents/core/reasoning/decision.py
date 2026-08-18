"""
decision.py

Defines the deterministic actions that may be selected by the
DecisionEngine during the API security testing workflow.
"""

from enum import Enum, auto


class Decision(Enum):
    """
    Represents the next action selected for an API resource.
    """

    AUTHENTICATE = auto()
    DISCOVER_OBJECTS = auto()

    EXECUTE_BOLA = auto()
    EXECUTE_BFLA = auto()

    RETRY = auto()
    SKIP = auto()
    FINISH = auto()