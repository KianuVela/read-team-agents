"""
resource_model.py

Represents the current knowledge collected about an API resource during
the execution phase.

The ResourceModel is continuously updated as new evidence is collected
by the ExecutionAgent and serves as the shared object used by the
StateClassifier and DecisionEngine.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .resource_state import ResourceState


@dataclass
class ResourceModel:
    """
    Represents the current execution context of one API resource.

    The model stores authentication data, discovered object identifiers,
    HTTP observations, structured evidence and the history of FSM state
    transitions associated with the resource.
    """

    # ------------------------------------------------------------------
    # Resource identification
    # ------------------------------------------------------------------

    endpoint: str
    method: str

    # ------------------------------------------------------------------
    # Current reasoning state
    # ------------------------------------------------------------------

    state: ResourceState = ResourceState.UNKNOWN

    state_history: List[ResourceState] = field(
        default_factory=lambda: [ResourceState.UNKNOWN]
    )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    authenticated: bool = False
    actor: Optional[str] = None
    jwt_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Object discovery
    # ------------------------------------------------------------------

    object_ids: List[str] = field(default_factory=list)
    selected_object_id: Optional[str] = None

    # ------------------------------------------------------------------
    # HTTP information
    # ------------------------------------------------------------------

    status_code: Optional[int] = None
    response_time: Optional[float] = None

    # ------------------------------------------------------------------
    # Structured evidence
    # ------------------------------------------------------------------

    evidence: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Decision support and execution
    # ------------------------------------------------------------------

    executable: bool = False
    execution_attempts: int = 0
    vulnerable: Optional[bool] = None

    # Novos atributos que representam instancias de um Test Case
    # --------------------------------------------------
    # Test Plan Context
    # --------------------------------------------------

    test_case_id: str | None = None
    test_type: str | None = None          # BOLA | BFLA | SHADOW

    baseline_actor: str | None = None
    negative_actor: str | None = None

    required_context: str | None = None

    input_vector: str | None = None
    object_reference: str | None = None

    expected_secure_behavior: str | None = None

    # selected_object_id: str | None = None

    # execution_ready: bool = False 