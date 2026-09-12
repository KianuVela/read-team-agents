from typing import Any, Dict


def resolve_active_runtime_input(
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Resolve deterministic request inputs for controlled active
    runtime discovery.

    Inputs are derived from live-frontend request behaviour plus
    deterministic fixtures. No OpenAPI, Ground Truth, or
    vulnerability-test identifiers are consulted here.
    """

    frontend_constant = str(
        probe.get("frontend_constant") or ""
    ).upper()

    fixture_key = probe.get("fixture_key")
    fixture_value = probe.get("fixture_value")

    if frontend_constant == "VALIDATE_COUPON":
        if fixture_key != "coupon_code" or not fixture_value:
            return {
                "ready": False,
                "reason": "MISSING_COUPON_FIXTURE",
            }

        return {
            "ready": True,
            "input_strategy": "DIRECT_FRONTEND_DERIVED_JSON",
            "json_body": {
                "coupon_code": str(fixture_value),
            },
            "dependency": None,
        }

    if frontend_constant == "ADD_COMMENT":
        if fixture_key != "user_a_post_id" or not fixture_value:
            return {
                "ready": False,
                "reason": "MISSING_POST_FIXTURE",
            }

        return {
            "ready": True,
            "input_strategy": "DIRECT_FRONTEND_DERIVED_JSON",
            "json_body": {
                "content": "Controlled runtime discovery comment",
            },
            "dependency": None,
        }

    if frontend_constant == "APPLY_COUPON":
        if fixture_key != "coupon_code" or not fixture_value:
            return {
                "ready": False,
                "reason": "MISSING_COUPON_FIXTURE",
            }

        return {
            "ready": True,
            "input_strategy": "DEPENDENCY_DERIVED_JSON",
            "json_body": None,
            "dependency": {
                "frontend_constant": "VALIDATE_COUPON",
                "required_response_fields": [
                    "coupon_code",
                    "amount",
                ],
            },
        }

    if frontend_constant == "RESEND_MAIL":
        return {
            "ready": True,
            "input_strategy": "DIRECT_FRONTEND_DERIVED_ZERO_BODY",
            "json_body": None,
            "dependency": None,
        }

    if frontend_constant == "BUY_PRODUCT":
        return {
            "ready": True,
            "input_strategy": "DEPENDENCY_DERIVED_JSON",
            "json_body": None,
            "dependency": {
                "type": "RUNTIME_COLLECTION_FIRST_VALID_ID",
                "frontend_constant": "GET_PRODUCTS",
                "method": "GET",
                "path": "/workshop/api/shop/products",
                "collection_key": "products",
                "id_field": "id",
                "payload_mapping": {
                    "product_id": "id",
                },
                "static_payload": {
                    "quantity": 1,
                },
            },
        }

    if frontend_constant == "RETURN_ORDER":
        return {
            "ready": True,
            "input_strategy": "DEPENDENCY_DERIVED_QUERY",
            "json_body": None,
            "query_params": None,
            "dependency": {
                "type": "PRIOR_ACTIVE_RESPONSE_FIELD",
                "frontend_constant": "BUY_PRODUCT",
                "required_response_fields": [
                    "id",
                ],
                "query_mapping": {
                    "order_id": "id",
                },
            },
        }

    return {
        "ready": False,
        "reason": "NO_DETERMINISTIC_ACTIVE_INPUT_PROFILE",
    }
