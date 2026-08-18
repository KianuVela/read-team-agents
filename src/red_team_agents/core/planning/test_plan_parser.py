from __future__ import annotations

from red_team_agents.core.planning.test_case import (
    TestCase,
)
from red_team_agents.core.planning.test_plan import (
    TestPlan,
)
from red_team_agents.core.planning.parser_utils import (
    expand_http_methods,
    extract_fields,
    normalise_field_name,
    split_test_case_sections,
)


class TestPlanParser:
    """
    Deterministic parser responsible for converting the Markdown
    report produced by TestPlanningAgent into a typed TestPlan.

    The parser only accepts BOLA and BFLA test cases.
    Shadow exploratory checks are intentionally excluded from
    the execution domain at this stage.
    """

    def parse(
        self,
        markdown: str,
    ) -> TestPlan:

        print("\n========== BOLA LINES ==========\n")

        for i, line in enumerate(markdown.splitlines(), start=1):

            if "BOLA" in line.upper() or "BFLA" in line.upper():

                print(f"{i:04d}: {repr(line)}")

        if not isinstance(markdown, str):
            raise TypeError(
                "TestPlanParser.parse() expects a string."
            )

        if not markdown.strip():
            return TestPlan()

        test_cases: list[TestCase] = []

        sections = split_test_case_sections(
            markdown,
        )

        print("\n========== SECTIONS FOUND ==========")
        print(len(sections))

        for section_id, _ in sections:
            print(section_id)

        for test_case_id, section in sections:

            fields = extract_fields(
                section,
            )

            parsed_cases = self._parse_section(
                test_case_id=test_case_id,
                fields=fields,
            )

            test_cases.extend(
                parsed_cases
            )

        return TestPlan(
            test_cases=test_cases,
        )

    def _parse_section(
        self,
        test_case_id: str,
        fields: dict[str, str],
    ) -> list[TestCase]:

        normalised_fields = {
            normalise_field_name(key): value
            for key, value in fields.items()
        }

        test_type = (
            normalised_fields.get(
                "test type"
            )
            or test_case_id.split(
                "-",
                1,
            )[0]
        ).upper()

        domain = normalised_fields.get(
            "domain / service area",
            "",
        )

        raw_methods = normalised_fields.get(
            "http method",
            "",
        )

        endpoint = normalised_fields.get(
            "target endpoint path",
            "",
        )

        if not endpoint:
            return []

        methods = expand_http_methods(
            raw_methods,
        )

        if not methods:
            return []

        object_reference = (
            normalised_fields.get(
                "object reference under test"
            )
            or normalised_fields.get(
                "privileged function under test"
            )
        )

        input_vector = normalised_fields.get(
            "input vector under test"
        )

        threat_hypothesis = (
            normalised_fields.get(
                "threat hypothesis"
            )
        )

        baseline_actor = (
            normalised_fields.get(
                "baseline authorized actor"
            )
        )

        negative_actor = (
            normalised_fields.get(
                "negative test actor"
            )
        )

        expected_behavior = (
            normalised_fields.get(
                "expected secure behavior"
            )
        )

        evidence_to_capture = (
            normalised_fields.get(
                "evidence to capture"
            )
        )

        required_context = (
            normalised_fields.get(
                "required user/account context"
            )
            or normalised_fields.get(
                "required user/account/role context"
            )
        )

        expected_secure_behavior = (
            normalised_fields.get(
                "expected secure behavior"
            )
        )

        parsed_cases: list[TestCase] = []

        multiple_methods = (
            len(methods) > 1
        )

        for method in methods:

            expanded_id = (
                f"{test_case_id}-{method}"
                if multiple_methods
                else test_case_id
            )

            test_case = TestCase(
                test_case_id=expanded_id,
                test_type=test_type,
                domain=domain,
                endpoint=endpoint,
                method=method,
                object_reference=object_reference,
                input_vector=input_vector,
                threat_hypothesis=threat_hypothesis,
                baseline_actor=baseline_actor,
                negative_actor=negative_actor,
                required_context=required_context,
                expected_behavior=expected_behavior,
                expected_secure_behavior=expected_secure_behavior,
                evidence_to_capture=evidence_to_capture,

            )

            print(
                test_case.test_case_id,
                test_case.required_context,
                test_case.expected_secure_behavior,
            )

            parsed_cases.append(
                test_case
            )
        return parsed_cases