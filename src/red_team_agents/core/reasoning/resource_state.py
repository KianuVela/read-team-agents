"""
resource_state.py

Defines the execution states that describe the current condition of
API resources during autonomous security validation.

These states are shared across the reasoning layer and allow the
ExecutionAgent to make deterministic decisions based on collected
evidence instead of relying only on LLM reasoning.
"""

from enum import Enum, auto


class ResourceState(Enum):
    UNKNOWN = auto()

    AUTH_REQUIRED = auto()
    AUTHENTICATED = auto()
    INVALID_TOKEN = auto()
    FORBIDDEN = auto()

    RESOURCE_DISCOVERED = auto()
    RESOURCE_NOT_FOUND = auto()
    EMPTY_COLLECTION = auto()
    IDENTIFIERS_DISCOVERED = auto()

    DETAIL_ENDPOINT = auto()
    DETAIL_ENDPOINT_WITHOUT_IDENTIFIER = auto()

    SELF_RESOURCE = auto()
    CROSS_USER_RESOURCE = auto()

    OBSERVED = auto()
    CLASSIFIED = auto()

    READY_FOR_BOLA = auto()
    READY_FOR_BFLA = auto()

    EXECUTING = auto()

    VULNERABLE = auto()
    NOT_VULNERABLE = auto()
    INCONCLUSIVE = auto()

    SERVER_FAILURE = auto()
    RATE_LIMITED = auto()
    TIMEOUT = auto()

    COMPLETED = auto()
    EXHAUSTED = auto()