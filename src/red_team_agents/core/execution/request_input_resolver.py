from dataclasses import dataclass
from typing import Any


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

    def resolve(self, resource) -> ResolvedRequestInput:
        """
        Resolve body and query parameters for the supplied resource.
        """

        endpoint = getattr(
            resource,
            "endpoint",
            "",
        ) or ""

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