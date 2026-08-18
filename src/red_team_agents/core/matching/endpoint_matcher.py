from __future__ import annotations

import re
from typing import Any


class EndpointMatcher:
    """
    Matches TestPlan endpoints against the resources
    discovered during Object Discovery.
    """

    _PARAM_PATTERN = re.compile(
        r"\{[^}]+\}"
    )

    def find_resource(
        self,
        endpoint: str,
        resources: dict[str, Any],
    ) -> dict[str, Any] | None:

        resource = self._find_exact_match(
            endpoint,
            resources,
        )

        if resource is not None:
            return resource

        resource = self._find_normalized_match(
            endpoint,
            resources,
        )

        if resource is not None:
            return resource

        return self._find_segment_match(
            endpoint,
            resources,
        )

    def _find_exact_match(
        self,
        endpoint: str,
        resources: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Match endpoints using exact string comparison.
        """

        endpoint = (
            endpoint
            .strip()
            .strip("`")
        )

        for resource in resources.values():

            if (
                resource["path"]
                ==
                endpoint
            ):
                return resource

        return None

    
    def _find_normalized_match(
        self,
        endpoint: str,
        resources: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Match endpoints after OpenAPI parameter normalization.
        """

        target = self._normalise_endpoint(
            endpoint,
        )

        for resource in resources.values():

            candidate = self._normalise_endpoint(
                resource["path"],
            )

            if target == candidate:

                print(
                    "[EndpointMatcher] Normalized match:",
                    target,
                )

                return resource

        return None

    def _find_segment_match(
        self,
        endpoint: str,
        resources: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Match endpoints using URI segment compatibility.
        """

        target = self._normalise_endpoint(
            endpoint,
        )

        for resource in resources.values():

            candidate = self._normalise_endpoint(
                resource["path"],
            )

            if self._segments_match(
                target,
                candidate,
            ):

                print(
                    "[EndpointMatcher] Segment match:",
                    target,
                    "<->",
                    candidate,
                )

                return resource

        return None


    def _segments_match(
        self,
        endpoint_a: str,
        endpoint_b: str,
    ) -> bool:
        """
        Compare two endpoints segment-by-segment.
        """

        segments_a = endpoint_a.strip("/").split("/")
        segments_b = endpoint_b.strip("/").split("/")

        if len(segments_a) != len(segments_b):
            return False

        for left, right in zip(
            segments_a,
            segments_b,
        ):

            if left == right:
                continue

            if (
                self._is_parameter(left)
                and
                self._is_parameter(right)
            ):
                continue

            if (
                self._is_parameter(left)
                and
                not self._is_parameter(right)
            ):
                continue

            if (
                not self._is_parameter(left)
                and
                self._is_parameter(right)
            ):
                continue

            return False

        return True


    def _is_parameter(
        self,
        segment: str,
    ) -> bool:
        """
        Return True if the URI segment is an OpenAPI parameter.
        """

        return (
            segment.startswith("{")
            and
            segment.endswith("}")
        )

    def match(
        self,
        left: str,
        right: str,
    ) -> bool:
        """
        Compare two endpoints after normalisation.
        """

        return (
            self._normalise_endpoint(left)
            ==
            self._normalise_endpoint(right)
        )

    def _normalise_endpoint(
        self,
        endpoint: str,
    ) -> str:
        """
        Replace all OpenAPI parameters with a common
        placeholder.
        """

        print(
            "RAW:",
            repr(endpoint),
        )

        endpoint = (
            endpoint
            .strip()
            .strip("`")
        )

        print(
            "NORMALIZED:",
            repr(endpoint),
        )

        return self._replace_parameters(
            endpoint,
        )

    def _replace_parameters(
        self,
        endpoint: str,
    ) -> str:

        return self._PARAM_PATTERN.sub(
            "{param}",
            endpoint,
        )