from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from red_team_agents.core.execution.fixtures.deterministic_fixture_store import (
    DeterministicFixtureStore,
)


@dataclass
class ResolvedRequestInput:
    """
    Request-specific input resolved from a ResourceModel.
    """

    json_body: dict[str, Any] | None = None
    query_params: dict[str, Any] | None = None


class RequestInputResolver:
    """
    Resolve HTTP request inputs required by individual
    authorization test cases.
    """

    def resolve(
        self,
        resource,
        context=None,
    ) -> ResolvedRequestInput:
        """
        Resolve body and query parameters for the supplied resource.
        """

        endpoint = getattr(
            resource,
            "endpoint",
            "",
        ) or ""

        if "/workshop/api/mechanic/receive_report" in endpoint:
            payload = self._build_receive_report_payload(
                resource=resource,
                context=context,
            )

            return ResolvedRequestInput(
                json_body=None,
                query_params=payload,
            )

        if "/community/api/v2/coupon/new-coupon" in endpoint:
            return ResolvedRequestInput(
                json_body=self._build_new_coupon_payload(),
                query_params={},
            )

        if "/workshop/api/shop/apply_coupon" in endpoint:
            return ResolvedRequestInput(
                json_body=self._build_apply_coupon_payload(
                    resource=resource,
                ),
                query_params={},
            )

        if resource.test_case_id == "BOLA-06":
            return ResolvedRequestInput(
                json_body={
                    "comment": (
                        "Automated authorization "
                        "validation comment"
                    )
                },
                query_params={},
            )

        return ResolvedRequestInput(
            json_body=None,
            query_params={},
        )

    
    def _build_receive_report_payload(
        self,
        resource,
        context=None,
    ) -> dict[str, Any]:
        """
        Build a valid body for crAPI receive_report.

        The endpoint requires mechanic_code, problem_details, and vin.
        Values are resolved first from deterministic fixtures, then from
        the discovered execution context as fallback.
        """

        # --------------------------------------------------
        # DETERMINISTIC FIXTURE FIRST
        # --------------------------------------------------

        fixture_store = DeterministicFixtureStore()

        if fixture_store.enabled:
            vin = fixture_store.fixture(
                "user_a_vin"
            )

            mechanic_code = fixture_store.fixture(
                "mechanic_code"
            )

            if vin and mechanic_code:
                return {
                    "mechanic_code": mechanic_code,
                    "problem_details": (
                        "Automated authorization validation report."
                    ),
                    "vin": vin,
                }

        # --------------------------------------------------
        # FALLBACK: DISCOVERED EXECUTION CONTEXT
        # --------------------------------------------------

        mechanic_code = self._resolve_input_value(
            resource=resource,
            context=context,
            candidate_keys={
                "mechanic_code",
                "mechaniccode",
            },
        )

        vin = self._resolve_input_value(
            resource=resource,
            context=context,
            candidate_keys={
                "vin",
                "vehicle_vin",
                "expected_vin",
                "verified_vin",
            },
        )

        if not mechanic_code:
            raise ValueError(
                "receive_report requires mechanic_code, "
                "but no mechanic_code was found in the execution context."
            )

        if not vin:
            raise ValueError(
                "receive_report requires vin, "
                "but no vin was found in the execution context."
            )

        return {
            "mechanic_code": mechanic_code,
            "problem_details": (
                "Automated authorization validation report."
            ),
            "vin": vin,
        }


    def _build_new_coupon_payload(
        self,
    ) -> dict[str, Any]:
        """
        Build a valid body for crAPI new-coupon.

        A fresh coupon code is generated because coupon creation is a
        state-changing endpoint.
        """

        return {
            "coupon_code": self._generate_coupon_code(),
            "amount": "75",
        }


    def _generate_coupon_code(
        self,
    ) -> str:
        """
        Generate a unique coupon code for controlled authorization testing.
        """

        return (
            "TRAC"
            + uuid4().hex[:6].upper()
        )


    def _resolve_input_value(
        self,
        resource,
        context,
        candidate_keys: set[str],
    ) -> str | None:
        """
        Resolve a scalar input value from the resource or execution context.
        """

        containers = [
            getattr(
                resource,
                "input_vector",
                None,
            ),
            getattr(
                resource,
                "required_context",
                None,
            ),
            getattr(
                resource,
                "object_reference",
                None,
            ),
            getattr(
                resource,
                #"metadata",
                # troca metadata por evidence, porque o ResourceModel não tem metadata.
                "evidence",
                None,
            ),
        ]

        if context is not None:
            context_data = getattr(
                context,
                "data",
                None,
            )

            if isinstance(
                context_data,
                dict,
            ):
                containers.append(
                    context_data
                )

        normalized_keys = {
            self._normalize_key(
                key
            )
            for key in candidate_keys
        }

        for container in containers:
            value = self._find_first_scalar_value(
                value=container,
                candidate_keys=normalized_keys,
            )

            if value:
                return value

        return None


    def _find_first_scalar_value(
        self,
        value: Any,
        candidate_keys: set[str],
        depth: int = 0,
    ) -> str | None:
        """
        Recursively search for the first scalar value under matching keys.
        """

        if depth > 8:
            return None

        if isinstance(
            value,
            dict,
        ):
            for key, child in value.items():
                normalized_key = self._normalize_key(
                    key
                )

                if normalized_key in candidate_keys:
                    if isinstance(
                        child,
                        (
                            str,
                            int,
                            float,
                        ),
                    ):
                        scalar = str(
                            child
                        ).strip()

                        if scalar:
                            return scalar

                nested_value = self._find_first_scalar_value(
                    value=child,
                    candidate_keys=candidate_keys,
                    depth=depth + 1,
                )

                if nested_value:
                    return nested_value

        if isinstance(
            value,
            list,
        ):
            for item in value:
                nested_value = self._find_first_scalar_value(
                    value=item,
                    candidate_keys=candidate_keys,
                    depth=depth + 1,
                )

                if nested_value:
                    return nested_value

        return None


    def _normalize_key(
        self,
        key: Any,
    ) -> str:
        return str(
            key
        ).replace(
            "-",
            "_",
        ).lower()


    # ************************* 
    def _build_apply_coupon_payload(
        self,
        resource,
    ) -> dict[str, Any]:
        """
        Build a valid body for crAPI apply_coupon.

        The OpenAPI specification requires amount and coupon_code.
        """

        coupon_code = getattr(
            resource,
            "selected_object_id",
            None,
        )

        if coupon_code in (
            None,
            "",
            0,
        ):
            raise ValueError(
                "apply_coupon requires a discovered coupon_code, "
                "but resource.selected_object_id is empty."
            )

        return {
            "coupon_code": str(
                coupon_code
            ),
            "amount": 75,
        }