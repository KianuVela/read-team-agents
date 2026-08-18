from __future__ import annotations

from dataclasses import dataclass, field

from red_team_agents.core.planning.test_case import (
    TestCase,
)


@dataclass(slots=True)
class TestPlan:
    """
    Structured representation of the test campaign produced
    by the TestPlanningAgent.
    """

    test_cases: list[TestCase] = field(
        default_factory=list,
    )