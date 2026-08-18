from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class TestCase:
    """
    Structured representation of one security test case produced
    by the TestPlanningAgent.
    """

    test_case_id: str
    test_type: str
    domain: str
    endpoint: str
    method: str

    object_reference: str | None = None
    input_vector: str | None = None
    threat_hypothesis: str | None = None

    baseline_actor: str | None = None
    negative_actor: str | None = None

    required_context: str | None = None

    expected_behavior: str | None = None
    expected_secure_behavior: str | None = None
    evidence_to_capture: str | None = None

    priority: int | None = None

    
   