from __future__ import annotations

import json

from typing import Any

from red_team_agents.core.execution.execution_context import (
    ExecutionContext,
)
from red_team_agents.core.reasoning.resource_model import (
    ResourceModel,
)

from red_team_agents.core.planning.test_plan_parser import (
    TestPlan,
)

from red_team_agents.core.planning.test_case import (
    TestCase,
)

from red_team_agents.core.matching.endpoint_matcher import (
    EndpointMatcher,
)


class ExecutionContextBuilder:
    """
    Builds the domain execution model from the execution
    artefacts produced during the ExecutionAgent workflow.
    """

    def __init__(self) -> None:

        self._endpoint_matcher = (
            EndpointMatcher()
        )

    def build(
        self,
        authentication_context: dict[str, Any],
        object_context: dict[str, Any],
        test_plan: dict[str, Any],
        execution_target_url: str,
    ) -> tuple[
        ExecutionContext,
        list[ResourceModel],
    ]:
        """
        Build the complete execution domain model.
        """

        execution_context = self._build_execution_context(
            authentication_context=authentication_context,
            object_context=object_context,
            test_plan=test_plan,
            execution_target_url=execution_target_url,
        )

        resource_models = self._build_resource_models(
            authentication_context=authentication_context,
            object_context=object_context,
            test_plan=test_plan,
        )

        execution_context.data[
            "resource_models"
        ] = resource_models

        return (
            execution_context,
            resource_models,
        )

    def _build_execution_context(
        self,
        authentication_context: dict[str, Any],
        object_context: dict[str, Any],
        test_plan: dict[str, Any],
        execution_target_url: str,
    ) -> ExecutionContext:

        authentication = self._build_authentication_context(
            authentication_context,
        )

        actor_tokens = self._build_actor_tokens(
            authentication
        )

        print(
            "[ExecutionContextBuilder] actors:",
            list(authentication.keys()),
        )

        if (
            not isinstance(execution_target_url, str)
            or not execution_target_url.strip()
        ):
            raise ValueError(
                "ExecutionContextBuilder requires a valid "
                "execution_target_url."
            )

        normalized_execution_target_url = (
            execution_target_url
            .strip()
            .rstrip("/")
        )

        print(
            "[ExecutionContextBuilder] execution target:",
            normalized_execution_target_url,
        )

        return ExecutionContext(
            data={
                "execution_target_url":
                    normalized_execution_target_url,

                "authentication": authentication,

                "actor_tokens": actor_tokens,

                "inventory": object_context,

                "objects": self._build_objects_context(
                    object_context,
                ),

                "test_plan": test_plan,

                "resource_models": [],
            }
        )

    # HELPER
    def _build_actor_tokens(
        self,
        authentication: dict[str, Any],
    ) -> dict[str, str]:
        actor_tokens: dict[str, str] = {}

        for actor, account in authentication.items():

            if not isinstance(
                account,
                dict,
            ):
                continue

            token = account.get(
                "jwt_token"
            )

            if isinstance(
                token,
                str,
            ) and token.strip():

                actor_tokens[str(actor)] = token.strip()

        print(
            "[ExecutionContextBuilder] actor tokens:",
            list(actor_tokens.keys()),
        )

        return actor_tokens


    def _build_authentication_context(
        self,
        authentication_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build the authentication accounts expected by
        AuthenticationStrategy from the normalized authentication
        context produced by AuthenticationContextTool.
        """

        authentication = authentication_context.get(
            "authentication",
            {},
        )

        if not isinstance(authentication, dict):
            return {}

        raw_tokens = authentication.get(
            "tokens",
            {},
        )

        if not isinstance(raw_tokens, dict):
            return {}

        accounts: dict[str, Any] = {}

        for actor, token in raw_tokens.items():

            if isinstance(token, str) and token.strip():

                accounts[str(actor)] = {
                    "jwt_token": token.strip(),
                }

        print(
            "[ExecutionContextBuilder] normalized actors:",
            list(accounts.keys()),
        )

        return accounts
    


    def _build_objects_context(
        self,
        object_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Index discovered object identifiers by endpoint path.
        """

        objects: dict[str, Any] = {}

        resources = object_context.get(
            "resources",
            {},
        )

        if not isinstance(resources, dict):
            return objects

        for resource in resources.values():
            if not isinstance(resource, dict):
                continue

            endpoint = str(
                resource.get("path", "")
            ).strip()

            discovery = resource.get(
                "object_discovery",
                {},
            )

            object_ids = (
                discovery.get("ids", [])
                if isinstance(discovery, dict)
                else []
            )

            if endpoint:
                objects[endpoint] = {
                    "object_ids": object_ids,
                }

        return objects

    # É uma primeira versão determinística. 
    # Mais tarde podemos torná-la semântica/configurável; agora queremos provar a ponte
    def _resolve_resource_family(
        self,
        test_case: TestCase,
    ) -> str | None:

        endpoint = str(
            test_case.endpoint or ""
        ).lower()

        if "/vehicle/" in endpoint:
            return "vehicles"

        if "/orders" in endpoint:
            return "orders"

        if "/community/posts" in endpoint:
            return "posts"

        if "/videos" in endpoint:
            return "videos"

        if "coupon" in endpoint:
            return "coupons"

        if "/shop/products" in endpoint or "/products" in endpoint:
            return "products"

        if "/mechanic/" in endpoint:
            return "reports"

        if "/user/" in endpoint or "/management/users" in endpoint:
            return "users"

        return None


    def _build_resource_models(
        self,
        authentication_context: dict[str, Any],
        object_context: dict[str, Any],
        test_plan: TestPlan,
    ) -> list[ResourceModel]:

        """
        Build one ResourceModel for each TestCase
        defined in the execution TestPlan.
        """

        print(
            "\n===== TEST CASES RECEIVED BY BUILDER ====="
        )

        for test_case in test_plan.test_cases:

            print(
                test_case.test_case_id,
                "|",
                test_case.test_type,
                "|",
                test_case.endpoint,
            )

        resource_models: list[ResourceModel] = []

        for test_case in test_plan.test_cases:

            # ---------------------------------------------
            # RESOLVE RESOURCE FAMILY
            # ---------------------------------------------

            resource_family = self._resolve_resource_family(
                test_case
            )

            if not resource_family:

                print(
                    "[ExecutionContextBuilder] "
                    f"resource family not resolved: "
                    f"{test_case.endpoint}"
                )

                continue

            # ---------------------------------------------
            # GET RESOURCE CONTEXT
            # ---------------------------------------------

            resource = object_context.get(
                "resources",
                {}
            ).get(
                resource_family
            )

            if not resource:

                print(
                    "[ExecutionContextBuilder] "
                    f"resource context not found: "
                    f"{resource_family}"
                )

                continue

            # ---------------------------------------------
            # DEBUG: VERIFY DISCOVERED IDS
            # ---------------------------------------------

            print(
                "[ExecutionContextBuilder]",
                test_case.test_case_id,
                "→",
                resource_family,
                "→ ids:",
                resource.get(
                    "object_discovery",
                    {}
                ).get(
                    "ids",
                    []
                )
            )

            print(
                "[ExecutionContextBuilder] "
                f"matched {test_case.test_case_id}"
            )

            # ---------------------------------------------
            # BUILD RESOURCE MODEL
            # ---------------------------------------------

            model = self._build_resource_model(
                resource=resource,
                test_case=test_case,
                authentication_context=authentication_context,
            )

            resource_models.append(
                model
            )

        print(
            "[ExecutionContextBuilder] Built",
            len(resource_models),
            "ResourceModels",
        )

        return resource_models

    
    def _build_resource_model(
        self,
        resource: dict[str, Any],
        test_case: TestCase,
        authentication_context: dict[str, Any],
    ) -> ResourceModel:
        """
        Build a single ResourceModel for one TestCase.

        The endpoint and HTTP method come from the TestCase,
        while discovered object identifiers come from the
        resolved resource-family context.
        """

        authentication = self._extract_authentication(
            authentication_context,
        )

        # --------------------------------------------------
        # OBJECT CONTEXT COMES FROM RESOURCE FAMILY
        # --------------------------------------------------

        object_ids = self._extract_object_ids(
            resource,
        )

        # --------------------------------------------------
        # EXECUTION TARGET COMES FROM TEST CASE
        # --------------------------------------------------

        endpoint_path = str(
            test_case.endpoint
            or ""
        ).strip()
        # Remove Markdown backticks surrounding endpoint paths.
        endpoint_path = endpoint_path.strip("`").strip()

        http_method = str(
            test_case.method
            or "GET"
        ).strip().upper()

        evidence = self._extract_evidence(
            resource,
        )

        print(
            "[ExecutionContextBuilder]",
            test_case.test_case_id,
            test_case.test_type,
            "baseline_actor=",
            test_case.baseline_actor,
            "negative_actor=",
            test_case.negative_actor,
            "endpoint=",
            endpoint_path,
            "method=",
            http_method,
            "object_ids=",
            object_ids,
        )

        return ResourceModel(
            endpoint=endpoint_path,
            method=http_method,

            authenticated=authentication[
                "authenticated"
            ],
            actor=authentication[
                "actor"
            ],
            jwt_token=authentication[
                "jwt_token"
            ],

            object_ids=object_ids,
            evidence=evidence,

            test_case_id=test_case.test_case_id,
            test_type=test_case.test_type,
            baseline_actor=test_case.baseline_actor,
            negative_actor=test_case.negative_actor,
            required_context=test_case.required_context,
            object_reference=test_case.object_reference,
            input_vector=test_case.input_vector,
            expected_secure_behavior=(
                test_case.expected_secure_behavior
            ),
        )

    def _extract_authentication(
        self,
        authentication_context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        ResourceModels start unauthenticated.

        AuthenticationStrategy is responsible for selecting
        the actor and applying the JWT during execution.
        """

        return {
            "authenticated": False,
            "actor": None,
            "jwt_token": None,
        }
    def _extract_object_ids(
        self,
        resource: dict[str, Any],
    ) -> list[str]:
        """
        Extract object identifiers discovered for one resource.
        """

        discovery = resource.get(
            "object_discovery",
            {},
        )

        object_ids = discovery.get(
            "ids",
            [],
        )

        if not isinstance(
            object_ids,
            list,
        ):
            object_ids = [object_ids]

        return [
            str(obj)
            for obj in object_ids
            if obj is not None
        ]

    def _extract_endpoint(
        self,
        resource: dict[str, Any],
    ) -> str:

        return str(
            resource.get(
                "path",
                "",
            )
        )

    def _extract_http_method(
        self,
        resource: dict[str, Any],
    ) -> str:

        return str(
            resource.get(
                "method",
                "GET",
            )
        ).upper()

    def _extract_evidence(
        self,
        resource: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Extract the execution evidence associated with
        a discovered endpoint.
        """

        return {
            "source": "ObjectDiscoveryTool",
             "resource_context": resource,
        }


        