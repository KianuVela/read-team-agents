import json
import os
import tempfile
import requests
import html
import quopri
import re
import requests
import secrets
import string

from pathlib import Path
from typing import Any, Dict, List, Optional, ClassVar
from crewai.tools import BaseTool

from red_team_agents.tools.collection_descriptor import (
    CollectionDescriptor,
)

from red_team_agents.core.execution.fixtures.deterministic_fixture_store import (
    DeterministicFixtureStore,
)


class ObjectDiscoveryTool(BaseTool):

    SHOP_PRODUCTS: ClassVar[CollectionDescriptor] = (
        CollectionDescriptor(
            endpoint="/workshop/api/shop/products",
            collection_key="products",
        )
    )

    # Passo 3 — adicionar configuração de segurança
    # -----------------------------------

    ACTIVE_DISCOVERY_ENABLED: bool = (
        os.getenv("ACTIVE_DISCOVERY_ENABLED", "true").lower() == "true"
    )

    ACTIVE_DISCOVERY_RESOURCES: set[str] = {
        "videos",
        "posts",
        "orders",
        "vehicles",
        "reports",
        #"coupons",
    }

    ACTIVE_ONLY_RESOURCES: set[str] = {
        "coupons",
    }

    ACTIVE_DISCOVERY_TIMEOUT: int = int(
        os.getenv("ACTIVE_DISCOVERY_TIMEOUT", "15")
    )


    VEHICLE_MAILBOX_ENABLED: bool = (
        os.getenv(
            "VEHICLE_MAILBOX_ENABLED",
            "true",
        ).lower() == "true"
    )

    VEHICLE_MAILBOX_URL: str = os.getenv(
        "VEHICLE_MAILBOX_URL",
        "http://127.0.0.1:8025",
    )

    RESOURCE_SELECTION_WEIGHTS: ClassVar[Dict[str, int]] = {
        # ----------------------------
        # HTTP STATUS
        # ----------------------------
        "http_200": 100,
        "http_403": 40,
        "http_401": 20,
        "http_404": 10,
        "http_500": -100,
        # ----------------------------
        # RESPONSE TYPE
        # ----------------------------
        "collection": 50,
        "object": 20,
        "unknown": 0
    }

    name: str = "Object Discovery Tool"
    
    description: str = (
        "Discovers accessible resources and object identifiers "
        "using authenticated requests."
    )


    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._enrichment_handlers = {
            "videos": self._enrich_empty_video_context,
            "posts": self._enrich_empty_post_context,
            "orders": self._enrich_empty_order_context,
            "vehicles": self._enrich_empty_vehicle_context,
            "reports": self._enrich_empty_report_context,
            "coupons": self._enrich_empty_coupon_context,

            #"service_requests": self._enrich_empty_service_request_context,
            #"management": self._enrich_empty_management_context,
        }
        

    def _run(
        self,
        auth_context_file: str
    ) -> str:

        with open(
            auth_context_file,
            "r",
            encoding="utf-8"
        ) as file:

            authentication_context = json.load(
                file
            )

        resources = self.discover_resources(
            authentication_context
        )

        resources = self.probe_resources(
            authentication_context,
            resources
        )

        resources = self.select_best_account(
            resources
        )

        resources = self.discover_objects(
            authentication_context,
            resources
        )

        auth_data = authentication_context.get(
            "authentication",
            {}
        )

        compact_authentication_context = {
            "tokens": auth_data.get(
                "tokens",
                {}
            ),
            "object_endpoints": auth_data.get(
                "object_endpoints",
                {}
            )
        }

        object_context = {
            "status": "success",
            "target": authentication_context.get(
                "target"
            ),
            "authentication": compact_authentication_context,
            "resources": resources,
            "metadata": {
                "discovered_resources": len(
                    resources
                ),
                "notes": []
            }
        }

        object_context = self._persist_deterministic_fixtures(
            object_context
        )

        object_context = self.cleanup_object_context(
            object_context
        )

        object_context = self.save_object_context(
            object_context
        )

        return json.dumps(
            {
                "status": object_context.get(
                    "status"
                ),
                "target": object_context.get(
                    "target"
                ),
                "object_context_file": object_context.get(
                    "metadata",
                    {}
                ).get(
                    "object_context_file"
                ),
                "resources_available": list(
                    object_context.get(
                        "resources",
                        {}
                    ).keys()
                ),
                "selected_identities": {
                    resource_name: resource_data.get(
                        "selected_identity"
                    )
                    for resource_name, resource_data
                    in object_context.get(
                        "resources",
                        {}
                    ).items()
                    if resource_data.get(
                        "selected_identity"
                    )
                },
                "objects_discovered": {
                    resource_name: resource_data.get(
                        "object_discovery",
                        {}
                    ).get(
                        "count",
                        0
                    )
                    for resource_name, resource_data
                    in object_context.get(
                        "resources",
                        {}
                    ).items()
                }
            },
            indent=4
        )


    # --------------------------------------------------
    # DISCOVER RESOURCES
    # --------------------------------------------------

    def discover_resources(
        self,
        authentication_context: Dict[str, Any]
    ) -> Dict[str, Any]:

        resources = {}

        endpoints = authentication_context.get(
            "authentication",
            {}
        ).get(
            "object_endpoints",
            {}
        )

        for resource_name, endpoint in endpoints.items():

            resources[resource_name] = {

                "path": endpoint.get("path"),

                "method": endpoint.get("method"),

                "status": "discovered",

                "accessible": None,

                "passive_discovery_eligible": (
                    resource_name
                    not in self.ACTIVE_ONLY_RESOURCES
                ),

                "response_type": endpoint.get(
                    "response_type",
                    "unknown"
                ),

                "collection_field": endpoint.get(
                    "collection_field"
                ),

                "id_field": endpoint.get(
                    "id_field",
                    "id"
                ),

                #"best_account": None,

                "selected_identity": None,

                "best_score": None,

                #"best_reason": [],

                "accounts": {}

            }

            resources = self._add_active_only_resources(
                resources
            )

        return resources


    
    # --------------------------------------------------
    # PROBE RESOURCES
    # --------------------------------------------------


    def probe_resources(
        self,
        authentication_context: Dict[str, Any],
        resources: Dict[str, Any]
    ) -> Dict[str, Any]:

        base_url = authentication_context.get(
            "target",
            ""
        ).rstrip("/")

        tokens = authentication_context.get(
            "authentication",
            {}
        ).get(
            "tokens",
            {}
        )

        for resource_name, resource in resources.items():

            path = resource.get(
                "path",
                ""
            )

            url = base_url + path

            best_response_type = "unknown"

            accessible = False

            for account_name, token in tokens.items():

                try:

                    response = requests.get(

                        url,

                        headers={

                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json"

                        },

                        timeout=15

                    )

                    account_result = {

                        "status_code": response.status_code,

                        "content_type": response.headers.get(
                            "Content-Type",
                            ""
                        ),

                        "accessible": response.status_code == 200

                    }

                    if response.status_code == 200:

                        accessible = True

                    try:

                        body = response.json()

                    except Exception:

                        body = None

                    if isinstance(body, list):

                        account_result["response_type"] = "collection"

                        account_result["collection_size"] = len(body)

                        best_response_type = "collection"

                    elif isinstance(body, dict):

                        account_result["response_type"] = "object"

                        if best_response_type != "collection":

                            best_response_type = "object"

                    else:

                        account_result["response_type"] = "unknown"

                    resource["accounts"][account_name] = account_result

                except requests.exceptions.RequestException as exc:

                    resource["accounts"][account_name] = {

                        "accessible": False,

                        "error": str(exc)

                    }

            # --------------------------------------------------
            # UPDATE RESOURCE STATUS
            # --------------------------------------------------

            resource["status"] = "probed"

            resource["accessible"] = accessible

            resource["response_type"] = best_response_type

        return resources



    # --------------------------------------------------
    # CALCULATE ACCOUNT SCORE
    # --------------------------------------------------

    def calculate_account_score(
        self,
        account_data: Dict[str, Any]
    ) -> Dict[str, Any]:

        weights = self.RESOURCE_SELECTION_WEIGHTS

        score = 0

        reasons = []

        status = account_data.get(
            "status_code",
            0
        )

        response_type = account_data.get(
            "response_type",
            "unknown"
        )

        # ----------------------------------------
        # HTTP STATUS
        # ----------------------------------------

        if status == 200:

            score += weights["http_200"]

            reasons.append(
                f"+{weights['http_200']} HTTP 200"
            )

        elif status == 403:

            score += weights["http_403"]

            reasons.append(
                f"+{weights['http_403']} HTTP 403"
            )

        elif status == 401:

            score += weights["http_401"]

            reasons.append(
                f"+{weights['http_401']} HTTP 401"
            )

        elif status == 404:

            score += weights["http_404"]

            reasons.append(
                f"+{weights['http_404']} HTTP 404"
            )

        elif status >= 500:

            score += weights["http_500"]

            reasons.append(
                f"{weights['http_500']} HTTP 5xx"
            )

        # ----------------------------------------
        # RESPONSE TYPE
        # ----------------------------------------

        if response_type == "collection":

            score += weights["collection"]

            reasons.append(
                f"+{weights['collection']} Collection Response"
            )

        elif response_type == "object":

            score += weights["object"]

            reasons.append(
                f"+{weights['object']} Object Response"
            )

        else:

            score += weights["unknown"]

        return {

            "score": score,

            "reason": reasons,

            # Reservado para futuras versões

            "confidence": None,

            "risk_level": None,

            "preferred_attack_strategy": None

        }

    # --------------------------------------------------
    # SELECT BEST ACCOUNT
    # --------------------------------------------------

    def select_best_account(
        self,
        resources: Dict[str, Any]
    ) -> Dict[str, Any]:

        for resource_name, resource in resources.items():

            accounts = resource.get(
                "accounts",
                {}
            )

            #best_account = None
            selected_identity = None

            best_score = -99999

            best_result = None

            for account_name, account_data in accounts.items():

                result = self.calculate_account_score(
                    account_data
                )

                score = result["score"]

                if score > best_score:

                    best_score = score

                    selected_identity = account_name

                    best_result = result

            #resource["best_account"] = best_account

            resource["selected_identity"] = selected_identity

            resource["best_score"] = best_score

            resource["selection_reason"] = (
                best_result.get("reason", [])
                if best_result
                else []
            )

            resource["selection_metadata"] = {

                "confidence": (
                    best_result.get("confidence")
                    if best_result
                    else None
                ),

                "risk_level": (
                    best_result.get("risk_level")
                    if best_result
                    else None
                ),

                "preferred_attack_strategy": (
                    best_result.get(
                        "preferred_attack_strategy"
                    )
                    if best_result
                    else None
                )

            }

        return resources

    # --------------------------------------------------
    # DISCOVER OBJECTS
    # --------------------------------------------------

    def discover_objects(
        self,
        authentication_context: Dict[str, Any],
        resources: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Discover object identifiers using passive discovery.

        When passive discovery returns no identifiers, or when the
        selected endpoint is not suitable for generic passive discovery,
        the method may invoke an approved context-enrichment handler.
        """

        base_url = authentication_context.get(
            "target",
            ""
        ).rstrip("/")

        tokens = authentication_context.get(
            "authentication",
            {}
        ).get(
            "tokens",
            {}
        )

        # --------------------------------------------------
        # PROCESS EACH RESOURCE
        # --------------------------------------------------

        for resource_name, resource in resources.items():

            identity = resource.get(
                "selected_identity"
            )

            if not identity:

                resource["object_discovery"] = {
                    "success": False,
                    "mode": "passive",
                    "status_code": None,
                    "ids": [],
                    "count": 0,
                    "error": (
                        "No identity was selected "
                        "for this resource"
                    ),
                }

                resource["status"] = (
                    "identity_not_selected"
                )

                continue

            token = tokens.get(
                identity
            )

            if not token:

                resource["object_discovery"] = {
                    "success": False,
                    "mode": "passive",
                    "status_code": None,
                    "ids": [],
                    "count": 0,
                    "error": (
                        f"No authentication token was available "
                        f"for identity '{identity}'"
                    ),
                }

                resource["status"] = (
                    "authentication_context_unavailable"
                )

                continue

            resource_path = resource.get(
                "path"
            )

            if not resource_path:

                resource["object_discovery"] = {
                    "success": False,
                    "mode": "passive",
                    "status_code": None,
                    "ids": [],
                    "count": 0,
                    "error": (
                        "No discovery endpoint was available"
                    ),
                }

                resource["status"] = (
                    "discovery_endpoint_unavailable"
                )

                continue

            # --------------------------------------------------
            # PASSIVE DISCOVERY POLICY
            # --------------------------------------------------

            passive_discovery_eligible = resource.get(
                "passive_discovery_eligible",
                True,
            )

            discovery_mode = "passive"

            ids = []

            passive_error_status = None

            resource["object_discovery"] = {
                "success": False,
                "mode": discovery_mode,
                "status_code": None,
                "endpoint": resource_path,
                "identity": identity,
                "passive_discovery_eligible": (
                    passive_discovery_eligible
                ),
                "passive_skipped": False,
                "ids": [],
                "count": 0,
                "error": None,
            }

            # --------------------------------------------------
            # PASSIVE DISCOVERY
            # --------------------------------------------------
            #
            # Only call endpoints that the OpenAPI analysis
            # identified as safe for generic passive discovery.
            #
            # Detail endpoints requiring object identifiers and
            # action-like GET endpoints are retained as metadata
            # but are not invoked here.
            # --------------------------------------------------

            if passive_discovery_eligible:

                url = (
                    f"{base_url}/"
                    f"{resource_path.lstrip('/')}"
                )

                try:

                    response = requests.get(
                        url,
                        headers={
                            "Authorization": (
                                f"Bearer {token}"
                            ),
                            "Accept": "application/json",
                        },
                        timeout=(
                            self.ACTIVE_DISCOVERY_TIMEOUT
                        ),
                    )

                    resource["object_discovery"][
                        "status_code"
                    ] = response.status_code

                    # ------------------------------------------
                    # SUCCESSFUL PASSIVE RESPONSE
                    # ------------------------------------------

                    if response.status_code == 200:

                        try:

                            body = response.json()

                        except ValueError:

                            resource[
                                "object_discovery"
                            ]["success"] = False

                            resource[
                                "object_discovery"
                            ]["error"] = (
                                "Passive discovery response "
                                "was not valid JSON"
                            )

                            passive_error_status = (
                                "invalid_discovery_response"
                            )

                        else:

                            if resource_name == "users":
                                print("\n" + "=" * 80)
                                print("USERS DISCOVERY DEBUG")
                                print("=" * 80)
                                print("endpoint         :", resource_path)
                                print("status_code      :", response.status_code)
                                print("id_field         :", resource.get("id_field"))
                                print("collection_field :", resource.get("collection_field"))
                                print("body_type        :", type(body).__name__)
                                print("body             :", body)
                                print("=" * 80)

                            ids = self.extract_object_ids(
                                body,
                                resource,
                            )

                            resource[
                                "object_discovery"
                            ]["success"] = True

                    # ------------------------------------------
                    # NON-200 PASSIVE RESPONSE
                    # ------------------------------------------

                    else:

                        resource[
                            "object_discovery"
                        ]["success"] = False

                        resource[
                            "object_discovery"
                        ]["error"] = (
                            f"Passive discovery returned HTTP "
                            f"{response.status_code}"
                        )

                        passive_error_status = (
                            "object_discovery_failed"
                        )

                except requests.exceptions.RequestException as exc:

                    resource[
                        "object_discovery"
                    ]["success"] = False

                    resource[
                        "object_discovery"
                    ]["error"] = str(
                        exc
                    )

                    passive_error_status = (
                        "object_discovery_failed"
                    )

            else:

                # --------------------------------------------------
                # PASSIVE DISCOVERY INTENTIONALLY SKIPPED
                # --------------------------------------------------

                resource[
                    "object_discovery"
                ]["passive_skipped"] = True

                resource[
                    "object_discovery"
                ]["success"] = True

                resource[
                    "object_discovery"
                ]["error"] = None

            # --------------------------------------------------
            # NORMALISE PASSIVELY DISCOVERED IDS
            # --------------------------------------------------

            ids = list(
                dict.fromkeys(
                    object_id
                    for object_id in ids
                    if object_id not in (
                        None,
                        "",
                        0,
                    )
                )
            )

            # --------------------------------------------------
            # ACTIVE CONTEXT ENRICHMENT
            # --------------------------------------------------
            #
            # Active enrichment runs when:
            #
            # 1. No usable IDs were discovered;
            # 2. Active discovery is enabled;
            # 3. An approved handler exists.
            #
            # This also covers endpoints deliberately skipped
            # because they require object-specific context.
            # --------------------------------------------------

            enrichment_handler = (
                self._enrichment_handlers.get(
                    resource_name
                )
            )

            enrichment_attempted = False

            if (
                not ids
                and self.ACTIVE_DISCOVERY_ENABLED
                and enrichment_handler is not None
            ):

                enrichment_attempted = True

                try:

                    enrichment = enrichment_handler(
                        target_url=base_url,
                        auth_context=authentication_context,
                        identity=identity,
                    )

                    print(
                        "[ContextEnrichment]",
                        enrichment,
                    )

                except Exception as exc:

                    enrichment = {
                        "enabled": True,
                        "attempted": True,
                        "mode": "active",
                        "resource": resource_name,
                        "identity": identity,
                        "success": False,
                        "verified_ids": [],
                        "error": (
                            f"Context enrichment failed: {exc}"
                        ),
                    }

                resource[
                    "context_enrichment"
                ] = enrichment

                # output passa a mostrar: coupons 
                #  mode   : active
                if enrichment_attempted:
                    discovery_mode = "active"

                enriched_ids = enrichment.get(
                    "verified_ids",
                    [],
                )

                enriched_ids = list(
                    dict.fromkeys(
                        object_id
                        for object_id in enriched_ids
                        if object_id not in (
                            None,
                            "",
                            0,
                        )
                    )
                )

                if enriched_ids:

                    ids = enriched_ids

                    discovery_mode = "active"

            # --------------------------------------------------
            # FINAL DISCOVERY RESULT
            # --------------------------------------------------

            resource[
                "object_discovery"
            ]["mode"] = discovery_mode

            resource[
                "object_discovery"
            ]["ids"] = ids

            resource[
                "object_discovery"
            ]["count"] = len(
                ids
            )

            # --------------------------------------------------
            # OBJECTS DISCOVERED
            # --------------------------------------------------

            if ids:

                resource[
                    "object_discovery"
                ]["success"] = True

                resource[
                    "object_discovery"
                ]["error"] = None

                resource["status"] = (
                    "objects_discovered"
                )

                if discovery_mode == "active":

                    context_enrichment = resource.get(
                        "context_enrichment",
                        {},
                    )

                    resource[
                        "object_discovery"
                    ]["objects_created"] = (
                        context_enrichment.get(
                            "objects_created",
                            0,
                        )
                    )

                    resource[
                        "object_discovery"
                    ]["created_ids"] = (
                        context_enrichment.get(
                            "created_ids",
                            [],
                        )
                    )

            # --------------------------------------------------
            # NO OBJECTS DISCOVERED
            # --------------------------------------------------

            else:

                enrichment_error = None

                if enrichment_attempted:

                    enrichment_error = resource.get(
                        "context_enrichment",
                        {},
                    ).get(
                        "error"
                    )

                # ----------------------------------------------
                # ACTIVE ENRICHMENT WAS AVAILABLE
                # ----------------------------------------------

                if enrichment_attempted:

                    resource["status"] = (
                        "no_objects_discovered"
                    )

                    resource[
                        "object_discovery"
                    ]["success"] = True

                    if enrichment_error:

                        resource[
                            "object_discovery"
                        ]["error"] = (
                            enrichment_error
                        )

                # ----------------------------------------------
                # PASSIVE ENDPOINT WAS INTENTIONALLY SKIPPED
                # ----------------------------------------------

                elif not passive_discovery_eligible:

                    resource["status"] = (
                        "no_objects_discovered"
                    )

                    resource[
                        "object_discovery"
                    ]["success"] = True

                    resource[
                        "object_discovery"
                    ]["error"] = None

                # ----------------------------------------------
                # REAL PASSIVE DISCOVERY FAILURE
                # ----------------------------------------------

                elif passive_error_status:

                    resource["status"] = (
                        passive_error_status
                    )

                    resource[
                        "object_discovery"
                    ]["success"] = False

                # ----------------------------------------------
                # VALID EMPTY COLLECTION
                # ----------------------------------------------

                else:

                    resource["status"] = (
                        "no_objects_discovered"
                    )

                    resource[
                        "object_discovery"
                    ]["success"] = True

                    resource[
                        "object_discovery"
                    ]["error"] = None

        return resources

    # --------------------------------------------------
    # EXTRACT OBJECT IDS
    # --------------------------------------------------

    def extract_object_ids(
        self,
        body: Any,
        resource: Dict[str, Any]
    ) -> list:

        id_field = resource.get(

            "id_field",

            "id"

        )

        collection_field = resource.get(

            "collection_field"

        )

        ids = []

        if isinstance(body, list):

            collection = body

        elif (

            isinstance(body, dict)

            and collection_field

            and collection_field in body

        ):

            collection = body.get(

                collection_field,

                []

            )

        else:

            collection = [body]

        for item in collection:

            if not isinstance(item, dict):

                continue

            value = item.get(

                id_field

            )

            if value is not None:

                ids.append(value)

        return ids


    def _persist_deterministic_fixtures(
        self,
        object_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Persist stable object identifiers discovered during Object Discovery.

        The object_context structure used by this tool stores resources under:
            object_context["resources"][resource_name]
        """

        fixture_store = DeterministicFixtureStore()

        if not fixture_store.enabled:
            return object_context

        resources = object_context.get(
            "resources",
            {},
        )

        if not isinstance(
            resources,
            dict,
        ):
            return object_context

        persisted: Dict[str, Any] = {}

        # --------------------------------------------------
        # VEHICLE FIXTURE
        # --------------------------------------------------

        vehicles = resources.get(
            "vehicles",
            {},
        )

        vehicle_id = self._first_discovered_id(
            vehicles
        )

        if vehicle_id is not None:
            fixture_store.set_fixture(
                "user_a_vehicle_id",
                vehicle_id,
            )

            persisted[
                "user_a_vehicle_id"
            ] = vehicle_id

        vehicle_vin = self._find_first_scalar_value(
            value=vehicles,
            candidate_keys={
                "vin",
                "expected_vin",
                "verified_vin",
            },
        )

        if vehicle_vin is not None:
            fixture_store.set_fixture(
                "user_a_vin",
                vehicle_vin,
            )

            persisted[
                "user_a_vin"
            ] = vehicle_vin

        # --------------------------------------------------
        # ORDER FIXTURE
        # --------------------------------------------------

        orders = resources.get(
            "orders",
            {},
        )

        order_id = self._first_discovered_id(
            orders
        )

        if order_id is not None:
            fixture_store.set_fixture(
                "user_a_order_id",
                order_id,
            )

            persisted[
                "user_a_order_id"
            ] = order_id

        # --------------------------------------------------
        # POST FIXTURE
        # --------------------------------------------------

        posts = resources.get(
            "posts",
            {},
        )

        post_id = self._first_discovered_id(
            posts
        )

        if post_id is not None:
            fixture_store.set_fixture(
                "user_a_post_id",
                post_id,
            )

            persisted[
                "user_a_post_id"
            ] = post_id

        # --------------------------------------------------
        # VIDEO FIXTURE
        # --------------------------------------------------

        videos = resources.get(
            "videos",
            {},
        )

        video_id = self._first_discovered_id(
            videos
        )

        if video_id is not None:
            fixture_store.set_fixture(
                "user_a_video_id",
                video_id,
            )

            persisted[
                "user_a_video_id"
            ] = video_id

        # --------------------------------------------------
        # REPORT FIXTURE
        # --------------------------------------------------

        reports = resources.get(
            "reports",
            {},
        )

        report_id = self._first_discovered_id(
            reports
        )

        if report_id is not None:
            fixture_store.set_fixture(
                "user_a_report_id",
                report_id,
            )

            persisted[
                "user_a_report_id"
            ] = report_id

        report_vin = self._find_first_scalar_value(
            value=reports,
            candidate_keys={
                "vin",
                "expected_vin",
                "verified_vin",
            },
        )

        if report_vin is not None:
            fixture_store.set_fixture(
                "user_a_vin",
                report_vin,
            )

            persisted[
                "user_a_vin"
            ] = report_vin

        mechanic_code = self._find_first_scalar_value(
            value=reports,
            candidate_keys={
                "mechanic_code",
                "mechaniccode",
            },
        )

        if mechanic_code is not None:
            fixture_store.set_fixture(
                "mechanic_code",
                mechanic_code,
            )

            persisted[
                "mechanic_code"
            ] = mechanic_code

        # --------------------------------------------------
        # COUPON FIXTURE
        # --------------------------------------------------

        coupons = resources.get(
            "coupons",
            {},
        )

        coupon_code = self._first_discovered_id(
            coupons
        )

        if coupon_code is not None:
            fixture_store.set_fixture(
                "coupon_code",
                coupon_code,
            )

            persisted[
                "coupon_code"
            ] = coupon_code

        object_context.setdefault(
            "metadata",
            {},
        )

        object_context[
            "metadata"
        ][
            "deterministic_fixtures_persisted"
        ] = persisted

        return object_context

    # VAMOS ADICIONAR AGORA ESTES 2 HELPERS ABAIXO

    def _first_discovered_id(
        self,
        resource: Dict[str, Any],
    ) -> Any | None:
        """
        Return the first stable object identifier discovered for a resource.
        """

        if not isinstance(
            resource,
            dict,
        ):
            return None

        discovery = resource.get(
            "object_discovery",
            {},
        )

        ids = []

        if isinstance(
            discovery,
            dict,
        ):
            ids = discovery.get(
                "ids",
                [],
            )

        if not isinstance(
            ids,
            list,
        ):
            ids = [
                ids
            ]

        for object_id in ids:
            if object_id not in (
                None,
                "",
                0,
            ):
                return object_id

        context_enrichment = resource.get(
            "context_enrichment",
            {},
        )

        if isinstance(
            context_enrichment,
            dict,
        ):
            for key in (
                "verified_ids",
                "created_ids",
            ):
                values = context_enrichment.get(
                    key,
                    [],
                )

                if not isinstance(
                    values,
                    list,
                ):
                    values = [
                        values
                    ]

                for object_id in values:
                    if object_id not in (
                        None,
                        "",
                        0,
                    ):
                        return object_id

        return None


    def _find_first_scalar_value(
        self,
        value: Any,
        candidate_keys: set[str],
        depth: int = 0,
    ) -> str | None:
        """
        Recursively find the first scalar value under one of the candidate keys.
        """

        if depth > 10:
            return None

        normalized_keys = {
            self._normalize_fixture_key(
                key
            )
            for key in candidate_keys
        }

        if isinstance(
            value,
            dict,
        ):
            for key, child in value.items():
                normalized_key = self._normalize_fixture_key(
                    key
                )

                if normalized_key in normalized_keys:
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
                    candidate_keys=normalized_keys,
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
                    candidate_keys=normalized_keys,
                    depth=depth + 1,
                )

                if nested_value:
                    return nested_value

        return None


    def _normalize_fixture_key(
        self,
        key: Any,
    ) -> str:
        return str(
            key
        ).replace(
            "-",
            "_",
        ).lower()

    # *******************************#


    # --------------------------------------------------
    # CLEANUP OBJECT CONTEXT
    # --------------------------------------------------

    def cleanup_object_context(
        self,
        object_context: Dict[str, Any]
    ) -> Dict[str, Any]:

        auth_root = object_context.get(
            "authentication",
            {}
        )

        authentication = auth_root.get(
            "authentication",
            {}
        )

        authentication.pop(
            "profile",
            None
        )

        authentication.pop(
            "registration_profile",
            None
        )

        authentication.pop(
            "login_results",
            None
        )

        authentication.pop(
            "registration_results",
            None
        )

        authentication.pop(
            "bootstrap",
            None
        )

        authentication.pop(
            "object_collection_results",
            None
        )

        resources = object_context.get(
            "resources",
            {}
        )

        for resource in resources.values():

            resource.pop(
                "accounts",
                None
            )

        return object_context

    # --------------------------------------------------
    # SAVE OBJECT CONTEXT
    # --------------------------------------------------

    def save_object_context(
        self,
        object_context: Dict[str, Any]
    ) -> Dict[str, Any]:

        output_dir = Path(
            "outputs/execution"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        output_file = output_dir / "object_context.json"

        object_context.setdefault(
            "metadata",
            {}
        )

        object_context["metadata"][
            "object_context_file"
        ] = str(output_file)

        with output_file.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                object_context,
                file,
                indent=4,
                ensure_ascii=False
            )

        return object_context


    # -------------------------------------------------
    # Passo 4 — criar o método para obter um token
    # -------------------------------------------------

    def _get_identity_token(
        self,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Optional[str]:
        """Return the JWT associated with an identity."""

        authentication = auth_context.get("authentication", {})
        tokens = authentication.get("tokens", {})

        token = tokens.get(identity)

        if not isinstance(token, str) or not token.strip():
            return None

        return token.strip()


    def _resolve_vehicle_credentials(
        self,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Resolve trusted pre-provisioned vehicle credentials
        associated with an authenticated identity.

        Resolution order:

            1. authentication.vehicle_context
            2. local laboratory mailbox

        Vehicle credentials are never generated here.
        They must originate from a trusted provisioning source.
        """

        authentication = auth_context.get(
            "authentication",
            {}
        )

        # --------------------------------------------------
        # 1. TRY EXISTING VEHICLE CONTEXT
        # --------------------------------------------------

        vehicle_context = authentication.get(
            "vehicle_context",
            {}
        )

        identity_vehicle = vehicle_context.get(
            identity
        )

        if isinstance(identity_vehicle, dict):

            vin = identity_vehicle.get(
                "vin"
            )

            pincode = identity_vehicle.get(
                "pincode"
            )

            if (
                isinstance(vin, str)
                and vin.strip()
                and isinstance(pincode, str)
                and pincode.strip()
            ):

                return {
                    "vin": vin.strip(),
                    "pincode": pincode.strip(),
                    "source": identity_vehicle.get(
                        "source",
                        "authentication_context"
                    ),
                }

        # --------------------------------------------------
        # 2. TRY LOCAL LABORATORY MAILBOX
        # --------------------------------------------------

        mailbox_credentials = (
            self._read_vehicle_credentials_from_mailbox(
                auth_context=auth_context,
                identity=identity,
            )
        )

        if not isinstance(
            mailbox_credentials,
            dict,
        ):
            return None

        if not mailbox_credentials.get(
            "success"
        ):
            return None

        # --------------------------------------------------
        # 3. VALIDATE MAILBOX CREDENTIALS
        # --------------------------------------------------

        vin = mailbox_credentials.get(
            "vin"
        )

        pincode = mailbox_credentials.get(
            "pincode"
        )

        if (
            not isinstance(vin, str)
            or not vin.strip()
        ):
            return None

        if (
            not isinstance(pincode, str)
            or not pincode.strip()
        ):
            return None

        # --------------------------------------------------
        # 4. RETURN TRUSTED CREDENTIALS
        # --------------------------------------------------

        return {
            "vin": vin.strip(),
            "pincode": pincode.strip(),
            "source": mailbox_credentials.get(
                "source",
                "mailhog"
            ),
        }

    # ------------------------------------------------
    # Passo 5 — criar um ficheiro temporário controlado
    # -----------------------------------------------

    def _create_temporary_video_file(self) -> Path:
        """
        Create a small temporary file for controlled context enrichment.

        The file is used only inside the local crAPI laboratory.
        """

        temp_directory = Path(tempfile.gettempdir()) / "crapi_context_enrichment"
        temp_directory.mkdir(parents=True, exist_ok=True)

        file_path = temp_directory / "context_enrichment_sample.mp4"

        if not file_path.exists():
            file_path.write_bytes(
                b"CRAPI_CONTEXT_ENRICHMENT_TEST_FILE"
            )

        return file_path


    # ---------------------------------------------
    # Passo 6 — adicionar o método de criação do vídeo
    # -----------------------------------------------

    def _create_video_context(
        self,
        target_url: str,
        token: str,
        identity: str,
         enrichment: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a temporary profile-video object for context enrichment."""

        endpoint = "/identity/api/v2/user/videos"
        url = f"{target_url.rstrip('/')}{endpoint}"

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "videos",
            "identity": identity,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "created_ids": [],
            "error": None,
        }

        temporary_file = self._create_temporary_video_file()

        headers = {
            "Authorization": f"Bearer {token}",
        }

        try:
            with temporary_file.open("rb") as file_handle:
                response = requests.post(
                    url,
                    headers=headers,
                    files={
                        "file": (
                            temporary_file.name,
                            file_handle,
                            "video/mp4",
                        )
                    },
                    timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
                )

            result["status_code"] = response.status_code

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = response_data
            result["response_body_preview"] = response.text[:500]

            if response.status_code not in {200, 201}:
                result["error"] = (
                    f"Resource creation returned HTTP "
                    f"{response.status_code}"
                )
                return result

            created_ids = self._extract_possible_ids(
                response_data,
                preferred_fields=["video_id", "id"],
            )

            result["created_ids"] = created_ids
            result["success"] = True
            return result

        except requests.RequestException as exc:
            result["error"] = str(exc)
            return result


    def _create_post_context(
        self,
        target_url: str,
        token: str,
        identity: str,
        enrichment: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a temporary community post for context enrichment."""

        endpoint = "/community/api/v2/community/posts"
        url = f"{target_url.rstrip('/')}{endpoint}"

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "posts",
            "identity": identity,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "created_ids": [],
            "error": None,
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        payload = {
            "title": "Red Team Context Post",
            "content": (
                "Temporary post created automatically for "
                "Object Discovery context enrichment."
            ),
        }

        try:

            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = response.status_code

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = response_data
            result["response_body_preview"] = response.text[:500]

            if response.status_code not in {200, 201}:
                result["error"] = (
                    f"Resource creation returned HTTP "
                    f"{response.status_code}"
                )
                return result

            created_ids = self._extract_possible_ids(
                response_data,
                preferred_fields=["id"],
            )

            result["created_ids"] = created_ids
            result["success"] = True

            return result

        except requests.RequestException as exc:
            result["error"] = str(exc)
            return result

    def _create_order_context(
        self,
        target_url: str,
        token: str,
        identity: str,
        enrichment: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Create one workshop order using a valid discovered product.
        """

        endpoint = "/workshop/api/shop/orders"

        url = (
            f"{target_url.rstrip('/')}{endpoint}"
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "orders",
            "identity": identity,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "created_ids": [],
            "error": None,
        }

        product = self._resolve_product(
            target_url=target_url,
            token=token,
        )

        if product is None:
            result["error"] = (
                "No valid product could be resolved "
                "for order creation."
            )
            return result

        product_id = product.get(
            "id"
        )

        if product_id is None:
            result["error"] = (
                "The selected product does not contain "
                "a valid identifier."
            )
            return result

        payload = {
            "product_id": product_id,
            "quantity": 1,
        }

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # O ponto bonito aqui é este bloco:
        # Ele deixa uma evidência auditável de que o order não foi criado arbitrariamente: 
        # o framework primeiro resolveu uma dependência válida (product_id) e só depois criou a encomenda.
        result["dependency"] = {
            "resource": "products",
            "selected_product_id": product_id,
        }

        try:

            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = (
                response_data
            )

            result["response_body_preview"] = (
                response.text[:500]
            )

            if response.status_code not in {
                200,
                201,
            }:
                result["error"] = (
                    f"Resource creation returned HTTP "
                    f"{response.status_code}"
                )
                return result

            created_ids = self._extract_possible_ids(
                response_data,
                preferred_fields=[
                    "id",
                ],
            )

            if not created_ids:
                result["error"] = (
                    "Order creation succeeded but no "
                    "order identifier was returned."
                )
                return result

            result["created_ids"] = (
                created_ids
            )

            result["success"] = True

            return result

        except requests.RequestException as exc:

            result["error"] = str(exc)

            return result


    def _associate_vehicle_context(
        self,
        target_url: str,
        token: str,
        identity: str,
        vin: str,
        pincode: str,
    ) -> Dict[str, Any]:
        """
        Associate an already provisioned vehicle with the
        authenticated user.

        This method does NOT create or fabricate vehicle
        credentials. The VIN and pincode must originate from
        a trusted, pre-provisioned context.
        """

        endpoint = "/identity/api/v2/vehicle/add_vehicle"

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "vehicles",
            "identity": identity,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "vin": None,
            "created_ids": [],
            "error": None,
        }

        # --------------------------------------------------
        # 1. VALIDATE CREDENTIALS
        # --------------------------------------------------

        if (
            not isinstance(vin, str)
            or not vin.strip()
        ):

            result["error"] = (
                "Vehicle association requires a valid VIN"
            )

            return result

        if (
            not isinstance(pincode, str)
            or not pincode.strip()
        ):

            result["error"] = (
                "Vehicle association requires a valid pincode"
            )

            return result

        vin = vin.strip()
        pincode = pincode.strip()

        result["vin"] = vin

        # --------------------------------------------------
        # 2. BUILD ASSOCIATION PAYLOAD
        # --------------------------------------------------

        payload = {
            "vin": vin,
            "pincode": pincode,
        }

        # --------------------------------------------------
        # 3. ASSOCIATE VEHICLE
        # --------------------------------------------------

        try:

            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            # --------------------------------------------------
            # 4. PARSE RESPONSE WHEN POSSIBLE
            # --------------------------------------------------

            try:

                response_data = response.json()

            except ValueError:

                response_data = None

            result["response_json"] = (
                response_data
            )

            result["response_body_preview"] = (
                response.text[:500]
            )

            # --------------------------------------------------
            # 5. VALIDATE ASSOCIATION RESPONSE
            # --------------------------------------------------

            if response.status_code not in {
                200,
                201,
            }:

                message = None

                if isinstance(
                    response_data,
                    dict,
                ):

                    message = response_data.get(
                        "message"
                    )

                result["error"] = (
                    f"Vehicle association returned HTTP "
                    f"{response.status_code}"
                    + (
                        f": {message}"
                        if message
                        else ""
                    )
                )

                return result

            # --------------------------------------------------
            # 6. ASSOCIATION SUCCEEDED
            # --------------------------------------------------
            #
            # The documented association endpoint does not
            # guarantee that a vehicle identifier is returned.
            #
            # The resulting vehicle object is therefore recovered
            # later by _read_vehicle_id().
            #

            result["success"] = True

            return result

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result
     
    # -----------------------------------------------------
    # Passo 7 — adicionar o extrator genérico de IDs
    # ------------------------------------------------

    def _extract_possible_ids(
        self,
        data: Any,
        preferred_fields: Optional[List[str]] = None,
    ) -> List[Any]:
        """Extract candidate object identifiers from JSON data."""

        fields = preferred_fields or ["id", "uuid"]

        discovered: List[Any] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for field in fields:
                    candidate = value.get(field)

                    if candidate not in (None, "", 0):
                        if candidate not in discovered:
                            discovered.append(candidate)

                for nested_value in value.values():
                    if isinstance(nested_value, (dict, list)):
                        visit(nested_value)

            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(data)
        return discovered

    # -------------------------
    # Passo 8 — adicionar a releitura do dashboard
    # Às vezes o POST pode criar o vídeo, mas não devolver claramente o ID. 
    # ------------------------------------------------

    def _read_dashboard_video_id(
        self,
        target_url: str,
        token: str,
        creation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Read the dashboard and extract the resulting video identifier."""

        endpoint = "/identity/api/v2/user/dashboard"
        url = f"{target_url.rstrip('/')}{endpoint}"

        result: Dict[str, Any] = {
            "success": False,
            "status_code": None,
            "video_id": None,
            "error": None,
        }

        try:
            response = requests.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = response.status_code

            if response.status_code != 200:
                result["error"] = (
                    f"Dashboard returned HTTP {response.status_code}"
                )
                return result

            try:
                response_data = response.json()
            except ValueError:
                result["error"] = "Dashboard response was not valid JSON"
                return result

            video_id = response_data.get("video_id")

            if video_id not in (None, "", 0):
                result["success"] = True
                result["video_id"] = video_id

            return result

        except requests.RequestException as exc:
            result["error"] = str(exc)
            return result

    
    def _read_post_id(
        self,
        target_url: str,
        token: str,
        creation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verify the created community post and recover its identifier.
        """

        created_ids = creation_result.get(
            "created_ids",
            [],
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "verified_ids": [],
            "status_code": None,
            "error": None,
        }

        if not created_ids:
            result["error"] = (
                "No created post identifier is available."
            )
            return result

        post_id = created_ids[0]

        endpoint = (
            f"/community/api/v2/community/posts/{post_id}"
        )

        url = (
            f"{target_url.rstrip('/')}{endpoint}"
        )

        headers = {
            "Authorization": f"Bearer {token}",
        }

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = response.status_code

            if response.status_code != 200:
                result["error"] = (
                    f"Verification returned HTTP "
                    f"{response.status_code}"
                )
                return result

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = response_data

            verified_ids = self._extract_possible_ids(
                response_data,
                preferred_fields=[
                    "id",
                ],
            )

            if verified_ids:

                result["verified_ids"] = verified_ids
                result["success"] = True

                return result

            result["error"] = (
                "The verification response does not "
                "contain a post identifier."
            )

            return result

        except requests.RequestException as exc:

            result["error"] = str(exc)

            return result

    def _read_order_id(
        self,
        target_url: str,
        token: str,
        creation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verify the created order and recover its identifier.
        """

        result: Dict[str, Any] = {
            "success": False,
            "status_code": None,
            "order_id": None,
            "verified_ids": [],
            "endpoint": None,
            "error": None,
        }

        # --------------------------------------------------
        # 1. RECOVER CANDIDATE ORDER ID
        # --------------------------------------------------

        created_ids = creation_result.get(
            "created_ids",
            []
        )

        if not isinstance(created_ids, list):
            created_ids = [created_ids]

        created_ids = [
            order_id
            for order_id in created_ids
            if order_id not in (
                None,
                "",
                0,
            )
        ]

        if not created_ids:
            result["error"] = (
                "Order creation succeeded but no candidate "
                "order identifier was returned."
            )

            return result

        candidate_order_id = created_ids[0]

        # --------------------------------------------------
        # 2. BUILD VERIFICATION ENDPOINT
        # --------------------------------------------------

        endpoint = (
            f"/workshop/api/shop/orders/"
            f"{candidate_order_id}"
        )

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result["endpoint"] = endpoint

        # --------------------------------------------------
        # 3. VERIFY CREATED ORDER
        # --------------------------------------------------

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            # --------------------------------------------------
            # 4. REQUIRE SUCCESSFUL RESPONSE
            # --------------------------------------------------

            if response.status_code != 200:

                result["error"] = (
                    "Order verification returned HTTP "
                    f"{response.status_code}"
                )

                result["response_body_preview"] = (
                    response.text[:500]
                )

                return result

            # --------------------------------------------------
            # 5. PARSE RESPONSE
            # --------------------------------------------------

            try:

                response_data = response.json()

            except ValueError:

                result["error"] = (
                    "Order verification response was "
                    "not valid JSON."
                )

                result["response_body_preview"] = (
                    response.text[:500]
                )

                return result

            result["response_json"] = response_data

            # --------------------------------------------------
            # 6. EXTRACT ORDER ID FROM VERIFIED OBJECT
            # --------------------------------------------------

            verified_ids = (
                self._extract_possible_ids(
                    response_data,
                    preferred_fields=[
                        "order_id",
                        "id",
                    ],
                )
            )

            # --------------------------------------------------
            # 7. CONFIRM THE CREATED ID
            # --------------------------------------------------

            verified_ids = [
                order_id
                for order_id in verified_ids
                if str(order_id)
                == str(candidate_order_id)
            ]

            if not verified_ids:

                result["error"] = (
                    "Order verification succeeded, but "
                    "the created order identifier was not "
                    "confirmed in the response."
                )

                return result

            # --------------------------------------------------
            # 8. VERIFIED
            # --------------------------------------------------

            result["success"] = True

            result["order_id"] = (
                candidate_order_id
            )

            result["verified_ids"] = (
                verified_ids
            )

            return result

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result


    def _read_vehicle_credentials_from_mailbox(
        self,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Read the laboratory MailHog mailbox and recover the
        pre-provisioned vehicle VIN and pincode associated with
        the selected authenticated identity.

        The crAPI registration workflow sends these vehicle
        credentials by email. This method only reads the local
        laboratory mailbox and extracts them.
        """

        result: Dict[str, Any] = {
            "success": False,
            "source": "mailhog",
            "identity": identity,
            "email": None,
            "mailbox_url": None,
            "message_id": None,
            "subject": None,
            "vin": None,
            "pincode": None,
            "error": None,
        }

        # --------------------------------------------------
        # 1. RECOVER THE EMAIL ADDRESS OF THE IDENTITY
        # --------------------------------------------------

        authentication = auth_context.get(
            "authentication",
            {},
        )

        registration_results = authentication.get(
            "registration_results",
            {},
        )

        identity_registration = registration_results.get(
            identity,
            {},
        )

        registration_payload = identity_registration.get(
            "payload",
            {},
        )

        email_address = registration_payload.get(
            "email"
        )

        # Small fallback in case the authentication context
        # stores account information separately.
        if not email_address:

            accounts = authentication.get(
                "accounts",
                {},
            )

            account_data = accounts.get(
                identity,
                {},
            )

            email_address = account_data.get(
                "email"
            )

        if (
            not isinstance(email_address, str)
            or not email_address.strip()
        ):

            result["error"] = (
                f"No email address could be resolved "
                f"for identity '{identity}'"
            )

            return result

        email_address = email_address.strip()

        result["email"] = email_address

        # --------------------------------------------------
        # 2. VEHICLE MAILBOX POLICY AND API URL
        # --------------------------------------------------

        if not self.VEHICLE_MAILBOX_ENABLED:

            result["error"] = (
                "Vehicle mailbox credential recovery is disabled"
            )

            return result


        mailbox_base_url = (
            self.VEHICLE_MAILBOX_URL.rstrip("/")
        )

        if mailbox_base_url.endswith(
            "/api/v2/messages"
        ):

            mailbox_url = mailbox_base_url

        else:

            mailbox_url = (
                f"{mailbox_base_url}/api/v2/messages"
            )

        result["mailbox_url"] = mailbox_url

        # --------------------------------------------------
        # 3. READ MAILBOX
        # --------------------------------------------------

        try:

            response = requests.get(
                mailbox_url,
                params={
                    "limit": 100,
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

        except requests.RequestException as exc:

            result["error"] = (
                f"MailHog request failed: {exc}"
            )

            return result

        if response.status_code != 200:

            result["error"] = (
                f"MailHog returned HTTP "
                f"{response.status_code}"
            )

            return result

        # --------------------------------------------------
        # 4. PARSE MAILHOG RESPONSE
        # --------------------------------------------------

        try:

            response_data = response.json()

        except ValueError:

            result["error"] = (
                "MailHog response was not valid JSON"
            )

            return result

        messages = response_data.get(
            "items",
            [],
        )

        if not isinstance(messages, list):

            result["error"] = (
                "MailHog response does not contain "
                "a valid message collection"
            )

            return result

        if not messages:

            result["error"] = (
                "MailHog mailbox contains no messages"
            )

            return result

        # MailHog normally returns newest messages first.
        # Sorting by the ISO timestamp makes the behaviour explicit.
        messages = sorted(
            messages,
            key=lambda message: str(
                message.get("Created", "")
            ),
            reverse=True,
        )

        target_email = email_address.lower()

        # --------------------------------------------------
        # 5. SEARCH ONLY MESSAGES SENT TO THIS IDENTITY
        # --------------------------------------------------

        for message in messages:

            recipients = message.get(
                "To",
                [],
            )

            recipient_match = False

            if isinstance(recipients, list):

                for recipient in recipients:

                    if not isinstance(recipient, dict):
                        continue

                    mailbox = str(
                        recipient.get(
                            "Mailbox",
                            "",
                        )
                    ).strip()

                    domain = str(
                        recipient.get(
                            "Domain",
                            "",
                        )
                    ).strip()

                    if mailbox and domain:

                        candidate_email = (
                            f"{mailbox}@{domain}"
                        ).lower()

                        if candidate_email == target_email:

                            recipient_match = True
                            break

            if not recipient_match:
                continue

            # --------------------------------------------------
            # 6. GET MESSAGE CONTENT
            # --------------------------------------------------

            content = message.get(
                "Content",
                {},
            )

            if not isinstance(content, dict):
                continue

            headers = content.get(
                "Headers",
                {},
            )

            if not isinstance(headers, dict):
                headers = {}

            raw_body = content.get(
                "Body",
                "",
            )

            if not isinstance(raw_body, str):
                continue

            # --------------------------------------------------
            # 7. DECODE QUOTED-PRINTABLE
            # --------------------------------------------------

            transfer_encoding = headers.get(
                "Content-Transfer-Encoding",
                [],
            )

            if isinstance(
                transfer_encoding,
                str,
            ):
                transfer_encoding = [
                    transfer_encoding
                ]

            is_quoted_printable = any(
                "quoted-printable" in str(value).lower()
                for value in transfer_encoding
            )

            if is_quoted_printable:

                try:

                    decoded_body = (
                        quopri.decodestring(
                            raw_body.encode(
                                "utf-8",
                                errors="ignore",
                            )
                        ).decode(
                            "utf-8",
                            errors="replace",
                        )
                    )

                except Exception:

                    decoded_body = raw_body

            else:

                decoded_body = raw_body

            # --------------------------------------------------
            # 8. CONVERT HTML BODY TO SEARCHABLE TEXT
            # --------------------------------------------------

            text_body = re.sub(
                r"(?is)<script.*?>.*?</script>",
                " ",
                decoded_body,
            )

            text_body = re.sub(
                r"(?is)<style.*?>.*?</style>",
                " ",
                text_body,
            )

            text_body = re.sub(
                r"(?s)<[^>]+>",
                " ",
                text_body,
            )

            text_body = html.unescape(
                text_body
            )

            text_body = re.sub(
                r"\s+",
                " ",
                text_body,
            ).strip()

            # --------------------------------------------------
            # 9. EXTRACT VIN
            # --------------------------------------------------

            vin_match = re.search(
                r"\bVIN\s*:\s*([A-Za-z0-9]{17})\b",
                text_body,
                flags=re.IGNORECASE,
            )

            # --------------------------------------------------
            # 10. EXTRACT PINCODE
            # --------------------------------------------------

            pincode_match = re.search(
                r"\b(?:Pincode|PIN\s*code)\s*:\s*(\d{4})\b",
                text_body,
                flags=re.IGNORECASE,
            )

            if (
                vin_match is None
                or pincode_match is None
            ):
                continue

            vin = vin_match.group(1)

            pincode = pincode_match.group(1)

            # --------------------------------------------------
            # 11. MESSAGE METADATA
            # --------------------------------------------------

            subject_values = headers.get(
                "Subject",
                [],
            )

            if isinstance(
                subject_values,
                str,
            ):
                subject = subject_values

            elif (
                isinstance(subject_values, list)
                and subject_values
            ):
                subject = str(
                    subject_values[0]
                )

            else:
                subject = None

            result["message_id"] = message.get(
                "ID"
            )

            result["subject"] = subject

            result["vin"] = vin

            result["pincode"] = pincode

            result["success"] = True

            return result

        # --------------------------------------------------
        # 12. NO MATCHING VEHICLE CREDENTIALS
        # --------------------------------------------------

        result["error"] = (
            "No MailHog message containing valid "
            f"vehicle credentials was found for "
            f"'{email_address}'"
        )

        return result

    # --------------------------------------------------
    # READ VEHICLE ID
    # --------------------------------------------------

    def _read_vehicle_id(
        self,
        target_url: str,
        token: str,
        expected_vin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read the authenticated user's vehicles and extract
        a usable vehicle identifier.

        When expected_vin is provided, prefer the vehicle whose
        VIN matches the expected pre-provisioned vehicle.

        UUID is preferred because the vehicle-location endpoint
        expects a UUID-like vehicleId.
        """

        endpoint = "/identity/api/v2/vehicle/vehicles"

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result: Dict[str, Any] = {
            "success": False,
            "status_code": None,
            "vehicle_id": None,
            "vehicle_uuid": None,
            "vehicle_db_id": None,
            "vin": None,
            "expected_vin": expected_vin,
            "matched_by_vin": False,
            "error": None,
        }

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            # --------------------------------------------------
            # 1. REQUIRE SUCCESSFUL RESPONSE
            # --------------------------------------------------

            if response.status_code != 200:

                result["error"] = (
                    f"Vehicle endpoint returned HTTP "
                    f"{response.status_code}"
                )

                return result

            # --------------------------------------------------
            # 2. PARSE RESPONSE
            # --------------------------------------------------

            try:

                response_data = response.json()

            except ValueError:

                result["error"] = (
                    "Vehicle endpoint response was not valid JSON"
                )

                return result

            # --------------------------------------------------
            # 3. REQUIRE COLLECTION
            # --------------------------------------------------

            if not isinstance(
                response_data,
                list,
            ):

                result["error"] = (
                    "Vehicle endpoint did not return a collection"
                )

                return result

            if not response_data:

                result["error"] = (
                    "Authenticated user has no vehicle objects"
                )

                return result

            # --------------------------------------------------
            # 4. SELECT VEHICLE
            # --------------------------------------------------

            vehicle = None

            if (
                isinstance(expected_vin, str)
                and expected_vin.strip()
            ):

                normalized_expected_vin = (
                    expected_vin.strip().upper()
                )

                for candidate in response_data:

                    if not isinstance(
                        candidate,
                        dict,
                    ):
                        continue

                    candidate_vin = candidate.get(
                        "vin"
                    )

                    if (
                        isinstance(candidate_vin, str)
                        and candidate_vin.strip().upper()
                        == normalized_expected_vin
                    ):

                        vehicle = candidate

                        result["matched_by_vin"] = True

                        break

                if vehicle is None:

                    result["error"] = (
                        "Vehicle collection was returned, but "
                        "no vehicle matched the expected VIN"
                    )

                    return result

            else:

                # No specific VIN was requested.
                # Select the first valid vehicle object.
                for candidate in response_data:

                    if isinstance(
                        candidate,
                        dict,
                    ):

                        vehicle = candidate
                        break

            # --------------------------------------------------
            # 5. VALIDATE SELECTED VEHICLE
            # --------------------------------------------------

            if not isinstance(
                vehicle,
                dict,
            ):

                result["error"] = (
                    "Vehicle collection contained no valid object"
                )

                return result

            # --------------------------------------------------
            # 6. EXTRACT IDENTIFIERS
            # --------------------------------------------------

            vehicle_uuid = vehicle.get(
                "uuid"
            )

            vehicle_db_id = vehicle.get(
                "id"
            )

            vin = vehicle.get(
                "vin"
            )

            # Prefer UUID for:
            #
            # /vehicle/{vehicleId}/location
            #
            vehicle_id = (
                vehicle_uuid
                or vehicle_db_id
            )

            if vehicle_id in (
                None,
                "",
                0,
            ):

                result["error"] = (
                    "Vehicle object did not contain "
                    "a usable identifier"
                )

                return result

            # --------------------------------------------------
            # 7. SUCCESS
            # --------------------------------------------------

            result["success"] = True

            result["vehicle_id"] = (
                vehicle_id
            )

            result["vehicle_uuid"] = (
                vehicle_uuid
            )

            result["vehicle_db_id"] = (
                vehicle_db_id
            )

            result["vin"] = vin

            return result

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result



    # método genérico de criação e verificação de objetos.
    def _create_and_verify_resource(
        self,
        *,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
        resource_name: str,
        create_callback,
        verify_callback,
    ) -> Dict[str, Any]:
        """
        Generic workflow used by active context enrichment.

        The workflow is:

            1. obtain an authentication token;
            2. create one resource;
            3. verify the created resource;
            4. return a standard enrichment structure.

        Resource-specific behaviour is delegated to the supplied callbacks.
        """

        enrichment: Dict[str, Any] = {
            "enabled": self.ACTIVE_DISCOVERY_ENABLED,
            "attempted": False,
            "mode": "active",
            "resource": resource_name,
            "identity": identity,
            "creation_method": None,
            "creation_endpoint": None,
            "objects_created": 0,
            "created_ids": [],
            "verified_ids": [],
            "success": False,
            "error": None,
        }

        if not self.ACTIVE_DISCOVERY_ENABLED:
            enrichment["error"] = (
                "Active discovery is disabled"
            )
            return enrichment

        if (
            resource_name
            not in self.ACTIVE_DISCOVERY_RESOURCES
            and resource_name
            not in self.ACTIVE_ONLY_RESOURCES
        ):
            enrichment["error"] = (
                "Resource is not permitted for active discovery"
            )
            return enrichment

        token = self._get_identity_token(
            auth_context,
            identity,
        )

        if token is None:
            enrichment["error"] = (
                f"No authentication token available "
                f"for {identity}"
            )
            return enrichment

        enrichment["attempted"] = True

        creation_result = create_callback(
            target_url=target_url,
            token=token,
            identity=identity,
            enrichment=enrichment,
        )

        enrichment["creation_result"] = creation_result

        if not creation_result.get("success"):
            enrichment["error"] = creation_result.get(
                "error",
                "Resource creation failed",
            )
            return enrichment

        created_ids = creation_result.get(
            "created_ids",
            [],
        )

        enrichment["created_ids"] = created_ids
        enrichment["objects_created"] = len(created_ids)

        verification = verify_callback(
            target_url=target_url,
            token=token,
            creation_result=creation_result,
        )

        enrichment["verification"] = verification

        verified_ids = verification.get(
            "verified_ids",
            [],
        )

        if not verified_ids:

            verified_id = verification.get(
                "id",
            )

            if verified_id not in (
                None,
                "",
                0,
            ):
                verified_ids = [
                    verified_id,
                ]

        if verified_ids:

            enrichment["verified_ids"] = verified_ids
            enrichment["success"] = True
            return enrichment

        if created_ids:

            enrichment["verified_ids"] = created_ids
            enrichment["success"] = True
            return enrichment

        enrichment["error"] = (
            "Creation succeeded but no object "
            "identifier was verified"
        )

        return enrichment

    # ------------------------------------
    # Passo 9 — criar o controlador de Context Enrichment
    # ----------------------------------------

    def _enrich_empty_video_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Attempt controlled enrichment when no video object exists.
        """

        enrichment = self._create_and_verify_resource(
            target_url=target_url,
            auth_context=auth_context,
            identity=identity,
            resource_name="videos",
            create_callback=self._create_video_context,
            verify_callback=self._read_dashboard_video_id,
        )

        enrichment["creation_method"] = "POST"
        enrichment["creation_endpoint"] = (
            "/identity/api/v2/user/videos"
        )

        return enrichment


    def _enrich_empty_post_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:

        enrichment = self._create_and_verify_resource(
            target_url=target_url,
            auth_context=auth_context,
            identity=identity,
            resource_name="posts",
            create_callback=self._create_post_context,
            verify_callback=self._read_post_id,
        )

        enrichment["creation_method"] = "POST"
        enrichment["creation_endpoint"] = (
            "/community/api/v2/community/posts"
        )

        return enrichment


    def _enrich_empty_order_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Attempt controlled enrichment when no order object exists.
        """

        enrichment = self._create_and_verify_resource(
            target_url=target_url,
            auth_context=auth_context,
            identity=identity,
            resource_name="orders",
            create_callback=self._create_order_context,
            verify_callback=self._read_order_id,
        )

        enrichment["creation_method"] = "POST"
        enrichment["creation_endpoint"] = (
            "/workshop/api/shop/orders"
        )

        return enrichment

    # --------------------------------------------------
    # ENRICH EMPTY VEHICLE CONTEXT
    # --------------------------------------------------

    def _enrich_empty_vehicle_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Attempt controlled vehicle-context enrichment.

        Vehicle enrichment differs from other resource types
        because the documented API exposes vehicle association,
        but not vehicle provisioning.

        Therefore, a vehicle may only be associated when trusted
        pre-provisioned VIN/pincode credentials are available.
        """

        enrichment: Dict[str, Any] = {
            "enabled": self.ACTIVE_DISCOVERY_ENABLED,
            "attempted": False,
            "mode": "active",
            "resource": "vehicles",
            "identity": identity,

            "dependency": {
                "type": "pre_provisioned_vehicle",
                "required": True,
                "available": False,
                "credentials_source": None,
            },

            "association_method": None,
            "association_endpoint": None,

            "verification_method": "GET",
            "verification_endpoint": (
                "/identity/api/v2/vehicle/vehicles"
            ),

            "objects_created": 0,
            "objects_associated": 0,

            "created_ids": [],
            "verified_ids": [],

            "success": False,
            "error": None,
        }

        # --------------------------------------------------
        # 1. ACTIVE DISCOVERY POLICY
        # --------------------------------------------------

        if not self.ACTIVE_DISCOVERY_ENABLED:

            enrichment["error"] = (
                "Active discovery is disabled"
            )

            return enrichment

        if (
            "vehicles"
            not in self.ACTIVE_DISCOVERY_RESOURCES
        ):

            enrichment["error"] = (
                "Resource is not permitted for active discovery"
            )

            return enrichment

        # --------------------------------------------------
        # 2. AUTHENTICATION TOKEN
        # --------------------------------------------------

        token = self._get_identity_token(
            auth_context,
            identity,
        )

        if token is None:

            enrichment["error"] = (
                f"No authentication token available "
                f"for {identity}"
            )

            return enrichment

        # --------------------------------------------------
        # TEMPORARY DIAGNOSTIC
        # VEHICLE DETAILS EMAIL WORKFLOW
        # --------------------------------------------------
        #
        # Keep this temporarily while the MailHog-based
        # credential recovery workflow is being validated.
        #

        self._debug_vehicle_resend_email(
            target_url=target_url,
            token=token,
        )

        # --------------------------------------------------
        # 3. RE-CHECK EXISTING VEHICLES
        # --------------------------------------------------

        initial_read = self._read_vehicle_id(
            target_url=target_url,
            token=token,
        )

        enrichment["initial_read"] = (
            initial_read
        )

        # --------------------------------------------------
        # 3.1 VEHICLE ALREADY EXISTS?
        # --------------------------------------------------

        if initial_read.get("success"):

            vehicle_id = initial_read.get(
                "vehicle_id"
            )

            if vehicle_id not in (
                None,
                "",
                0,
            ):

                enrichment["verified_ids"] = [
                    vehicle_id
                ]

                enrichment["success"] = True

                return enrichment

        # --------------------------------------------------
        # 4. RESOLVE PRE-PROVISIONED VEHICLE CREDENTIALS
        # --------------------------------------------------
        #
        # IMPORTANT:
        #
        # Credential-source logic belongs inside
        # _resolve_vehicle_credentials().
        #
        # That method may later obtain credentials from:
        #
        #     - authentication context;
        #     - registration metadata;
        #     - the laboratory mailbox;
        #     - another explicitly trusted laboratory source.
        #
        # This orchestration method should not know how
        # credentials are obtained.
        #

        credentials = self._resolve_vehicle_credentials(
            auth_context=auth_context,
            identity=identity,
        )

        if credentials is None:

            enrichment["error"] = (
                "Vehicle enrichment requires a "
                "pre-provisioned vehicle VIN and pincode; "
                "no trusted vehicle credentials are "
                "available for this identity."
            )

            return enrichment

        # --------------------------------------------------
        # 4.1 VALIDATE RESOLVED CREDENTIALS
        # --------------------------------------------------

        vin = credentials.get(
            "vin"
        )

        pincode = credentials.get(
            "pincode"
        )

        if (
            not isinstance(vin, str)
            or not vin.strip()
        ):

            enrichment["error"] = (
                "Resolved vehicle credentials do not "
                "contain a valid VIN."
            )

            return enrichment

        if (
            not isinstance(pincode, str)
            or not pincode.strip()
        ):

            enrichment["error"] = (
                "Resolved vehicle credentials do not "
                "contain a valid pincode."
            )

            return enrichment

        vin = vin.strip()

        pincode = pincode.strip()

        enrichment["dependency"][
            "available"
        ] = True

        enrichment["dependency"][
            "credentials_source"
        ] = credentials.get(
            "source"
        )

        enrichment["attempted"] = True

        # --------------------------------------------------
        # 5. ASSOCIATE VEHICLE
        # --------------------------------------------------

        enrichment["association_method"] = (
            "POST"
        )

        enrichment["association_endpoint"] = (
            "/identity/api/v2/vehicle/add_vehicle"
        )

        association_result = (
            self._associate_vehicle_context(
                target_url=target_url,
                token=token,
                identity=identity,
                vin=vin,
                pincode=pincode,
            )
        )

        enrichment["association_result"] = (
            association_result
        )

        if not association_result.get(
            "success"
        ):

            enrichment["error"] = (
                association_result.get(
                    "error",
                    "Vehicle association failed",
                )
            )

            return enrichment

        enrichment["objects_associated"] = 1

        # --------------------------------------------------
        # 6. VERIFY VEHICLE COLLECTION
        # --------------------------------------------------

        verification = (
            self._read_vehicle_id(
                target_url=target_url,
                token=token,
                expected_vin=vin,
            )
        )

        enrichment["verification"] = (
            verification
        )

        if not verification.get(
            "success"
        ):

            enrichment["error"] = (
                verification.get(
                    "error"
                )
                or
                "Vehicle association succeeded but "
                "the resulting vehicle could not "
                "be verified"
            )

            return enrichment

        vehicle_id = verification.get(
            "vehicle_id"
        )

        if vehicle_id in (
            None,
            "",
            0,
        ):

            enrichment["error"] = (
                "Vehicle association succeeded but "
                "no usable vehicle identifier was "
                "returned during verification"
            )

            return enrichment

        # --------------------------------------------------
        # 7. PROVENANCE CHECK
        # --------------------------------------------------
        #
        # Confirm that the object discovered after association
        # is the same pre-provisioned vehicle that was supplied
        # by the trusted credential source.
        #

        expected_vin = vin

        verified_vin = verification.get(
            "vin"
        )

        provenance_match = (
            expected_vin is not None
            and verified_vin is not None
            and str(expected_vin).strip().upper()
            == str(verified_vin).strip().upper()
        )

        enrichment["provenance"] = {
            "expected_vin": expected_vin,
            "verified_vin": verified_vin,
            "matched": provenance_match,
        }

        if not provenance_match:

            enrichment["error"] = (
                "Vehicle association succeeded, but "
                "the verified vehicle VIN does not "
                "match the pre-provisioned VIN."
            )

            return enrichment

        # --------------------------------------------------
        # 8. VERIFIED OBJECT
        # --------------------------------------------------

        enrichment["verified_ids"] = [
            vehicle_id
        ]

        enrichment["success"] = True

        return enrichment

    def _debug_vehicle_resend_email(
        self,
        target_url: str,
        token: str,
    ) -> None:
        """
        Diagnostic test for the documented vehicle-details
        email workflow.

        This method does not create or associate a vehicle.
        """

        endpoint = "/identity/api/v2/vehicle/resend_email"
        url = f"{target_url.rstrip('/')}{endpoint}"

        print("\n" + "=" * 80)
        print("VEHICLE RESEND EMAIL DEBUG")
        print("=" * 80)

        try:
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            try:
                response_json = response.json()
            except ValueError:
                response_json = None

            print("endpoint      :", endpoint)
            print("status_code   :", response.status_code)
            print("response_json :", response_json)
            print("response_text :", response.text[:1000])

        except requests.RequestException as exc:
            print(
                "request_error  :",
                f"{type(exc).__name__}: {exc}",
            )


    def _enrich_empty_report_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Attempt controlled report-context enrichment.

        A report is created only when the authenticated identity
        has a verified vehicle and a valid mechanic can be
        resolved from the documented laboratory API.

        The resulting report identifier is accepted only after
        successful verification through the documented report
        retrieval endpoint.
        """

        enrichment: Dict[str, Any] = {
            "enabled": self.ACTIVE_DISCOVERY_ENABLED,
            "attempted": False,
            "mode": "active",
            "resource": "reports",
            "identity": identity,

            "dependency": {
                "vehicle": {
                    "required": True,
                    "available": False,
                    "vin": None,
                },
                "mechanic": {
                    "required": True,
                    "available": False,
                    "mechanic_code": None,
                },
            },

            "creation_method": "GET",
            "creation_endpoint": (
                "/workshop/api/mechanic/receive_report"
            ),

            "verification_method": "GET",
            "verification_endpoint": (
                "/workshop/api/mechanic/mechanic_report"
            ),

            "objects_created": 0,
            "created_ids": [],
            "verified_ids": [],

            "success": False,
            "error": None,
        }

        # --------------------------------------------------
        # 1. ACTIVE DISCOVERY POLICY
        # --------------------------------------------------

        if not self.ACTIVE_DISCOVERY_ENABLED:

            enrichment["error"] = (
                "Active discovery is disabled"
            )

            return enrichment

        if "reports" not in self.ACTIVE_DISCOVERY_RESOURCES:

            enrichment["error"] = (
                "Resource is not permitted for active discovery"
            )

            return enrichment

        # --------------------------------------------------
        # 2. AUTHENTICATION TOKEN
        # --------------------------------------------------

        token = self._get_identity_token(
            auth_context,
            identity,
        )

        if token is None:

            enrichment["error"] = (
                f"No authentication token available "
                f"for {identity}"
            )

            return enrichment

        # --------------------------------------------------
        # 3. RESOLVE VERIFIED VEHICLE
        # --------------------------------------------------

        vehicle_result = self._read_vehicle_id(
            target_url=target_url,
            token=token,
        )

        enrichment["vehicle_result"] = (
            vehicle_result
        )

        if not vehicle_result.get(
            "success"
        ):

            enrichment["error"] = (
                vehicle_result.get("error")
                or
                "Report enrichment requires "
                "an associated vehicle"
            )

            return enrichment

        vin = vehicle_result.get(
            "vin"
        )

        if (
            not isinstance(vin, str)
            or not vin.strip()
        ):

            enrichment["error"] = (
                "Associated vehicle does not "
                "contain a usable VIN"
            )

            return enrichment

        vin = vin.strip()

        enrichment["dependency"][
            "vehicle"
        ]["available"] = True

        enrichment["dependency"][
            "vehicle"
        ]["vin"] = vin

        # --------------------------------------------------
        # 4. RESOLVE MECHANIC
        # --------------------------------------------------

        mechanic_result = (
            self._resolve_report_mechanic(
                target_url=target_url,
                token=token,
            )
        )

        enrichment["mechanic_result"] = (
            mechanic_result
        )

        if not mechanic_result.get(
            "success"
        ):

            enrichment["error"] = (
                mechanic_result.get("error")
                or
                "No usable mechanic was available"
            )

            return enrichment

        mechanic_code = (
            mechanic_result.get(
                "mechanic_code"
            )
        )

        if (
            not isinstance(mechanic_code, str)
            or not mechanic_code.strip()
        ):

            enrichment["error"] = (
                "Resolved mechanic does not contain "
                "a usable mechanic code"
            )

            return enrichment

        mechanic_code = (
            mechanic_code.strip()
        )

        enrichment["dependency"][
            "mechanic"
        ]["available"] = True

        enrichment["dependency"][
            "mechanic"
        ]["mechanic_code"] = (
            mechanic_code
        )

        # --------------------------------------------------
        # 5. CREATE / ASSIGN REPORT
        # --------------------------------------------------

        enrichment["attempted"] = True

        creation_result = (
            self._create_report_context(
                target_url=target_url,
                token=token,
                identity=identity,
                vin=vin,
                mechanic_code=mechanic_code,
            )
        )

        enrichment["creation_result"] = (
            creation_result
        )

        if not creation_result.get(
            "success"
        ):

            enrichment["error"] = (
                creation_result.get("error")
                or
                "Report creation failed"
            )

            return enrichment

        report_id = creation_result.get(
            "report_id"
        )

        if report_id in (
            None,
            "",
            0,
        ):

            enrichment["error"] = (
                "Report creation succeeded but "
                "returned no usable report identifier"
            )

            return enrichment

        created_ids = creation_result.get(
            "created_ids",
            [],
        )

        if not isinstance(created_ids, list):
            created_ids = [created_ids]

        created_ids = [
            candidate_id
            for candidate_id in created_ids
            if candidate_id not in (
                None,
                "",
                0,
            )
        ]

        # Defensive consistency:
        # _create_report_context currently returns both
        # report_id and created_ids. If created_ids is
        # unexpectedly empty, preserve the validated
        # report_id as the candidate identifier.
        if not created_ids:
            created_ids = [
                report_id
            ]

        enrichment["objects_created"] = len(
            created_ids
        )

        enrichment["created_ids"] = (
            created_ids
        )

        # --------------------------------------------------
        # 6. VERIFY REPORT
        # --------------------------------------------------
        #
        # IMPORTANT:
        #
        # _verify_report_context() receives the complete
        # creation_result. It extracts the candidate report
        # identifier from creation_result["created_ids"].
        # --------------------------------------------------

        verification = (
            self._verify_report_context(
                target_url=target_url,
                token=token,
                creation_result=creation_result,
            )
        )

        enrichment["verification"] = (
            verification
        )

        if not verification.get(
            "success"
        ):

            enrichment["error"] = (
                verification.get("error")
                or
                "Created report could not "
                "be verified"
            )

            return enrichment

        verified_report_id = (
            verification.get(
                "report_id"
            )
        )

        if verified_report_id in (
            None,
            "",
            0,
        ):

            enrichment["error"] = (
                "Report verification returned "
                "no usable identifier"
            )

            return enrichment

        # --------------------------------------------------
        # 7. PROVENANCE CHECK
        # --------------------------------------------------

        provenance_match = (
            str(report_id)
            ==
            str(verified_report_id)
        )

        enrichment["provenance"] = {
            "created_report_id": report_id,
            "verified_report_id": (
                verified_report_id
            ),
            "matched": provenance_match,
        }

        if not provenance_match:

            enrichment["error"] = (
                "Verified report identifier does "
                "not match the created report identifier"
            )

            return enrichment

        # --------------------------------------------------
        # 8. VERIFIED OBJECT
        # --------------------------------------------------

        enrichment["verified_ids"] = [
            verified_report_id
        ]

        enrichment["success"] = True

        return enrichment


    def _get_collection_resource(
        self,
        *,
        target_url: str,
        token: str,
        descriptor: CollectionDescriptor,
    ) -> list[Dict[str, Any]]:
        """
        Retrieve a collection resource described by a CollectionDescriptor.

        Returns an empty list whenever the collection cannot be retrieved
        or the response format is invalid.
        """

        url = (
            f"{target_url.rstrip('/')}"
            f"{descriptor.endpoint}"
        )

        headers = {
            "Authorization": f"Bearer {token}",
        }

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            if response.status_code != 200:
                return []

            try:
                response_data = response.json()
            except ValueError:
                return []

            collection = response_data.get(
                descriptor.collection_key,
                [],
            )

            if not isinstance(
                collection,
                list,
            ):
                return []

            return collection

        except requests.RequestException:

            return []


    def _get_shop_products(
        self,
        target_url: str,
        token: str,
    ) -> list[Dict[str, Any]]:
        """
        Retrieve the products available in the workshop shop.
        """

        return self._get_collection_resource(
            target_url=target_url,
            token=token,
            descriptor=self.SHOP_PRODUCTS,
        )

    def _select_product(
        self,
        products: list[Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        """
        Select one valid product deterministically.
        """

        for product in products:

            if not isinstance(product, dict):
                continue

            product_id = product.get("id")

            if product_id is not None:
                return product

        return None


    # Helper Intermédio...
    def _resolve_product(
        self,
        target_url: str,
        token: str,
    ) -> Dict[str, Any] | None:
        """
        Discover and select one valid product that can be
        used for order creation.
        """

        products = self._get_shop_products(
            target_url=target_url,
            token=token,
        )

        return self._select_product(
            products,
        )

    # Genrators
    def _generate_vehicle_vin(
        self,
    ) -> str:
        """
        Generate a unique VIN-like identifier for
        controlled vehicle context enrichment.
        """

        alphabet = (
            string.ascii_uppercase
            + string.digits
        )

        return "".join(
            secrets.choice(alphabet)
            for _ in range(17)
        )


    def _generate_vehicle_pincode(
        self,
    ) -> str:
        """
        Generate a four-digit vehicle pincode.
        """

        return "".join(
            secrets.choice(
                string.digits
            )
            for _ in range(4)
        )

    def _get_identity_email(
        self,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Optional[str]:
        """
        Resolve the authenticated identity email from the
        trusted authentication context.
        """

        authentication = auth_context.get(
            "authentication",
            {}
        )

        # --------------------------------------------------
        # 1. REGISTRATION RESULTS
        # --------------------------------------------------

        registration_results = authentication.get(
            "registration_results",
            {}
        )

        registration = registration_results.get(
            identity,
            {}
        )

        payload = registration.get(
            "payload",
            {}
        )

        email = payload.get("email")

        if isinstance(email, str) and email.strip():
            return email.strip()

        # --------------------------------------------------
        # 2. OPTIONAL ACCOUNT PROFILE FALLBACK
        # --------------------------------------------------

        accounts = authentication.get(
            "accounts",
            {}
        )

        account = accounts.get(
            identity,
            {}
        )

        email = account.get("email")

        if isinstance(email, str) and email.strip():
            return email.strip()

        return None

    def _request_vehicle_credentials_email(
        self,
        target_url: str,
        token: str,
    ) -> Dict[str, Any]:
        """
        Ask crAPI to resend the pre-provisioned vehicle credentials
        to the authenticated user's email address.
        """

        endpoint = "/identity/api/v2/vehicle/resend_email"

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "error": None,
        }

        try:

            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            result["response_body_preview"] = (
                response.text[:500]
            )

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = (
                response_data
            )

            if response.status_code != 200:

                result["error"] = (
                    "Vehicle credential resend returned HTTP "
                    f"{response.status_code}"
                )

                return result

            result["success"] = True

            return result

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result


    def _debug_mailbox(
        self,
        email: str,
    ) -> None:

        mailbox_url = (
            self.VEHICLE_MAILBOX_URL.rstrip("/")
        )

        url = (
            f"{mailbox_url}/api/v2/messages"
        )

        try:

            response = requests.get(
                url,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            print()
            print("=" * 80)
            print("VEHICLE MAILBOX DEBUG")
            print("=" * 80)
            print(f"email       : {email}")
            print(f"url         : {url}")
            print(
                f"status_code : "
                f"{response.status_code}"
            )
            print(
                f"content_type: "
                f"{response.headers.get('Content-Type')}"
            )
            print(
                "response_text:"
            )
            print(
                response.text[:5000]
            )

        except requests.RequestException as exc:

            print(
                "MAILBOX ERROR:",
                repr(exc),
            )

    # Primeiro HELPER de reports
    def _resolve_report_mechanic(
        self,
        target_url: str,
        token: str,
    ) -> Dict[str, Any]:
        """
        Resolve a valid mechanic for report-context enrichment.

        The method reads the documented mechanic collection and
        selects the first valid mechanic exposing a usable
        mechanic_code.

        No mechanic is created or fabricated here.
        """

        endpoint = "/workshop/api/mechanic/"

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "method": "GET",
            "endpoint": endpoint,
            "status_code": None,
            "mechanic_id": None,
            "mechanic_code": None,
            "mechanic_email": None,
            "mechanics_available": 0,
            "error": None,
        }

        # --------------------------------------------------
        # 1. READ DOCUMENTED MECHANIC COLLECTION
        # --------------------------------------------------

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result

        # --------------------------------------------------
        # 2. REQUIRE HTTP 200
        # --------------------------------------------------

        if response.status_code != 200:

            result["error"] = (
                f"Mechanic discovery returned HTTP "
                f"{response.status_code}"
            )

            return result

        # --------------------------------------------------
        # 3. PARSE RESPONSE
        # --------------------------------------------------

        try:

            response_data = response.json()

        except ValueError:

            result["error"] = (
                "Mechanic discovery response "
                "was not valid JSON"
            )

            return result

        if not isinstance(
            response_data,
            dict,
        ):

            result["error"] = (
                "Mechanic discovery did not return "
                "the expected response object"
            )

            return result

        # --------------------------------------------------
        # 4. EXTRACT MECHANIC COLLECTION
        # --------------------------------------------------

        mechanics = response_data.get(
            "mechanics",
            [],
        )

        if not isinstance(
            mechanics,
            list,
        ):

            result["error"] = (
                "Mechanic discovery response does not "
                "contain a valid mechanics collection"
            )

            return result

        result["mechanics_available"] = len(
            mechanics
        )

        if not mechanics:

            result["error"] = (
                "No mechanics are available "
                "for report enrichment"
            )

            return result

        # --------------------------------------------------
        # 5. SELECT FIRST VALID MECHANIC
        # --------------------------------------------------

        for mechanic in mechanics:

            if not isinstance(
                mechanic,
                dict,
            ):
                continue

            mechanic_code = mechanic.get(
                "mechanic_code"
            )

            if (
                not isinstance(mechanic_code, str)
                or not mechanic_code.strip()
            ):
                continue

            mechanic_id = mechanic.get(
                "id"
            )

            mechanic_email = None

            mechanic_user = mechanic.get(
                "user",
                {},
            )

            if isinstance(
                mechanic_user,
                dict,
            ):

                candidate_email = (
                    mechanic_user.get(
                        "email"
                    )
                )

                if isinstance(
                    candidate_email,
                    str,
                ):

                    mechanic_email = (
                        candidate_email.strip()
                        or None
                    )

            # --------------------------------------------------
            # 6. RESOLVED MECHANIC
            # --------------------------------------------------

            result["mechanic_id"] = (
                mechanic_id
            )

            result["mechanic_code"] = (
                mechanic_code.strip()
            )

            result["mechanic_email"] = (
                mechanic_email
            )

            result["success"] = True

            return result

        # --------------------------------------------------
        # 7. NO USABLE MECHANIC
        # --------------------------------------------------

        result["error"] = (
            "Mechanic collection was returned, "
            "but no usable mechanic_code was found"
        )

        return result 

    # Segundo HELPER de reports
    def _create_report_context(
        self,
        target_url: str,
        token: str,
        identity: str,
        vin: str,
        mechanic_code: str,
    ) -> Dict[str, Any]:
        """
        Create and assign a controlled service report for
        active object-discovery context enrichment.

        The method uses only a verified vehicle VIN and a
        mechanic_code resolved from the documented mechanic
        collection.

        The resulting report identifier is returned for
        subsequent verification.
        """

        endpoint = (
            "/workshop/api/mechanic/receive_report"
        )

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "reports",
            "identity": identity,
            "method": "GET",
            "endpoint": endpoint,
            "status_code": None,
            "vin": None,
            "mechanic_code": None,
            "report_id": None,
            "report_link": None,
            "sent": None,
            "created_ids": [],
            "error": None,
        }

        # --------------------------------------------------
        # 1. VALIDATE DEPENDENCIES
        # --------------------------------------------------

        if (
            not isinstance(vin, str)
            or not vin.strip()
        ):

            result["error"] = (
                "Report creation requires a valid VIN"
            )

            return result

        if (
            not isinstance(mechanic_code, str)
            or not mechanic_code.strip()
        ):

            result["error"] = (
                "Report creation requires a valid "
                "mechanic_code"
            )

            return result

        vin = vin.strip()
        mechanic_code = mechanic_code.strip()

        result["vin"] = vin

        result["mechanic_code"] = (
            mechanic_code
        )

        # --------------------------------------------------
        # 2. BUILD CONTROLLED REQUEST PARAMETERS
        # --------------------------------------------------

        params = {
            "mechanic_code": mechanic_code,
            "problem_details": (
                "Automated context-enrichment "
                "service report."
            ),
            "vin": vin,
        }

        # --------------------------------------------------
        # 3. CREATE / ASSIGN REPORT
        # --------------------------------------------------
        #
        # Note:
        #
        # The crAPI OpenAPI specification exposes this
        # state-changing operation through GET.
        #
        # The framework follows the documented laboratory API
        # while recording the operation explicitly as active
        # context enrichment.
        # --------------------------------------------------

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization": (
                        f"Bearer {token}"
                    ),
                    "Accept": "application/json",
                },
                params=params,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result

        # --------------------------------------------------
        # 4. PARSE RESPONSE WHEN POSSIBLE
        # --------------------------------------------------

        try:

            response_data = response.json()

        except ValueError:

            response_data = None

        result["response_json"] = (
            response_data
        )

        result["response_body_preview"] = (
            response.text[:500]
        )

        # --------------------------------------------------
        # 5. REQUIRE SUCCESSFUL HTTP RESPONSE
        # --------------------------------------------------

        if response.status_code != 200:

            message = None

            if isinstance(
                response_data,
                dict,
            ):

                message = response_data.get(
                    "message"
                )

            result["error"] = (
                f"Report creation returned HTTP "
                f"{response.status_code}"
                + (
                    f": {message}"
                    if message
                    else ""
                )
            )

            return result

        # --------------------------------------------------
        # 6. REQUIRE EXPECTED RESPONSE OBJECT
        # --------------------------------------------------

        if not isinstance(
            response_data,
            dict,
        ):

            result["error"] = (
                "Report creation did not return "
                "the expected JSON object"
            )

            return result

        # --------------------------------------------------
        # 7. EXTRACT REPORT METADATA
        # --------------------------------------------------

        report_id = response_data.get(
            "id"
        )

        sent = response_data.get(
            "sent"
        )

        report_link = response_data.get(
            "report_link"
        )

        if report_id in (
            None,
            "",
            0,
        ):

            result["error"] = (
                "Report creation returned no usable "
                "report identifier"
            )

            return result

        # --------------------------------------------------
        # 8. SUCCESS
        # --------------------------------------------------

        result["report_id"] = (
            report_id
        )

        result["sent"] = sent

        result["report_link"] = (
            report_link
        )

        result["created_ids"] = [
            report_id
        ]

        result["success"] = True

        return result

    # ULTIMO HELPER
    def _verify_report_context(
        self,
        target_url: str,
        token: str,
        creation_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Verify a service report created during active context enrichment.

        The report identifier returned by the creation step is supplied
        to the documented mechanic_report endpoint as the required
        ``report_id`` query parameter.

        Verification succeeds only when the returned Service Request
        contains an ``id`` equal to the candidate report identifier.
        """

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "status_code": None,
            "report_id": None,
            "verified_ids": [],
            "endpoint": (
                "/workshop/api/mechanic/mechanic_report"
            ),
            "query_params": {},
            "error": None,
        }

        # --------------------------------------------------
        # 1. RECOVER CANDIDATE REPORT ID
        # --------------------------------------------------

        created_ids = creation_result.get(
            "created_ids",
            [],
        )

        if not isinstance(created_ids, list):
            created_ids = [
                created_ids
            ]

        created_ids = [
            report_id
            for report_id in created_ids
            if report_id not in (
                None,
                "",
                0,
            )
        ]

        if not created_ids:

            result["error"] = (
                "Report creation succeeded but no candidate "
                "report identifier was returned."
            )

            return result

        candidate_report_id = created_ids[0]

        # --------------------------------------------------
        # 2. BUILD VERIFICATION REQUEST
        # --------------------------------------------------

        endpoint = (
            "/workshop/api/mechanic/mechanic_report"
        )

        url = (
            f"{target_url.rstrip('/')}"
            f"{endpoint}"
        )

        query_params = {
            "report_id": candidate_report_id,
        }

        result["query_params"] = (
            query_params
        )

        # --------------------------------------------------
        # 3. REQUEST SERVICE REPORT
        # --------------------------------------------------

        try:

            response = requests.get(
                url,
                headers={
                    "Authorization": (
                        f"Bearer {token}"
                    ),
                    "Accept": "application/json",
                },
                params=query_params,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = (
                response.status_code
            )

            # --------------------------------------------------
            # 4. REQUIRE HTTP 200
            # --------------------------------------------------

            if response.status_code != 200:

                result["error"] = (
                    "Report verification returned HTTP "
                    f"{response.status_code}"
                )

                result[
                    "response_body_preview"
                ] = response.text[:500]

                return result

            # --------------------------------------------------
            # 5. PARSE RESPONSE JSON
            # --------------------------------------------------

            try:

                response_data = (
                    response.json()
                )

            except ValueError:

                result["error"] = (
                    "Report verification response "
                    "was not valid JSON."
                )

                result[
                    "response_body_preview"
                ] = response.text[:500]

                return result

            result["response_json"] = (
                response_data
            )

            # --------------------------------------------------
            # 6. REQUIRE SERVICE REQUEST OBJECT
            # --------------------------------------------------

            if not isinstance(
                response_data,
                dict,
            ):

                result["error"] = (
                    "Report verification endpoint did not "
                    "return a Service Request object."
                )

                return result

            # --------------------------------------------------
            # 7. EXTRACT VERIFIED REPORT ID
            # --------------------------------------------------
            #
            # Important:
            #
            # Do not recursively search every "id" field here.
            #
            # The Service Request also contains nested mechanic
            # and vehicle objects, each of which may have its own
            # "id".
            #
            # We want specifically the top-level Service Request ID.
            # --------------------------------------------------

            verified_report_id = (
                response_data.get(
                    "id"
                )
            )

            if verified_report_id in (
                None,
                "",
                0,
            ):

                result["error"] = (
                    "The verified Service Request does not "
                    "contain a usable report identifier."
                )

                return result

            # --------------------------------------------------
            # 8. CONFIRM CREATED REPORT ID
            # --------------------------------------------------

            report_id_matches = (
                str(verified_report_id)
                == str(candidate_report_id)
            )

            result["provenance"] = {
                "expected_report_id": (
                    candidate_report_id
                ),
                "verified_report_id": (
                    verified_report_id
                ),
                "matched": (
                    report_id_matches
                ),
            }

            if not report_id_matches:

                result["error"] = (
                    "Report verification succeeded, but "
                    "the returned Service Request identifier "
                    "does not match the created report identifier."
                )

                return result

            # --------------------------------------------------
            # 9. VERIFIED
            # --------------------------------------------------

            result["success"] = True

            result["report_id"] = (
                verified_report_id
            )

            result["verified_ids"] = [
                verified_report_id
            ]

            return result

        except requests.RequestException as exc:

            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )

            return result


    # Starting Enriching COUPONS

    def _enrich_empty_coupon_context(
        self,
        target_url: str,
        auth_context: Dict[str, Any],
        identity: str,
    ) -> Dict[str, Any]:
        """
        Attempt controlled coupon-context enrichment.

        Coupons are treated as active-only because a usable coupon code
        is normally obtained through a business-flow endpoint rather than
        through passive object discovery.
        """

        enrichment: Dict[str, Any] = {
            "enabled": self.ACTIVE_DISCOVERY_ENABLED,
            "attempted": False,
            "mode": "active",
            "resource": "coupons",
            "identity": identity,
            "creation_method": None,
            "creation_endpoint": (
                "/community/api/v2/coupon/new-coupon"
            ),
            "verification_method": None,
            "verification_endpoint": None,
            "objects_created": 0,
            "created_ids": [],
            "verified_ids": [],
            "success": False,
            "error": None,
        }

        if not self.ACTIVE_DISCOVERY_ENABLED:
            enrichment["error"] = (
                "Active discovery is disabled"
            )
            return enrichment

        if "coupons" not in self.ACTIVE_ONLY_RESOURCES:
            enrichment["error"] = (
                "Coupons are not permitted for active-only discovery"
            )
            return enrichment

        token = self._get_identity_token(
            auth_context,
            identity,
        )

        if token is None:
            enrichment["error"] = (
                f"No authentication token available for {identity}"
            )
            return enrichment

        enrichment["attempted"] = True

        creation_result = self._create_coupon_context(
            target_url=target_url,
            token=token,
            identity=identity,
        )

        enrichment["creation_result"] = creation_result
        enrichment["creation_method"] = creation_result.get(
            "method"
        )
        enrichment["creation_endpoint"] = creation_result.get(
            "endpoint"
        )

        if not creation_result.get("success"):
            enrichment["error"] = creation_result.get(
                "error",
                "Coupon creation failed",
            )
            return enrichment

        coupon_codes = creation_result.get(
            "created_ids",
            [],
        )

        enrichment["created_ids"] = coupon_codes
        enrichment["verified_ids"] = coupon_codes
        enrichment["objects_created"] = len(
            coupon_codes
        )
        enrichment["success"] = bool(
            coupon_codes
        )

        if not enrichment["success"]:
            enrichment["error"] = (
                "Coupon endpoint succeeded but no coupon code was extracted."
            )

        return enrichment

    # HELPER PARA COUPONS
    def _create_coupon_context(
        self,
        target_url: str,
        token: str,
        identity: str,
    ) -> Dict[str, Any]:
        """
        Request one coupon code from the controlled crAPI laboratory.
        """

        endpoint = "/community/api/v2/coupon/new-coupon"
        url = f"{target_url.rstrip('/')}{endpoint}"

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "resource": "coupons",
            "identity": identity,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "created_ids": [],
            "error": None,
        }

        coupon_code = self._generate_coupon_code()
        amount = "75"

        payload = {
            "coupon_code": coupon_code,
            "amount": amount,
        }

        result["coupon_code"] = coupon_code
        result["amount"] = amount
        result["request_payload"] = payload

        try:
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = response.status_code
            result["response_body_preview"] = response.text[:500]

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = response_data

            if response.status_code not in {
                200,
                201,
            }:
                result["error"] = (
                    f"Coupon creation returned HTTP "
                    f"{response.status_code}: "
                    f"{response.text[:500]}"
                )
                return result

            verification = self._validate_coupon_context(
                target_url=target_url,
                token=token,
                coupon_code=coupon_code,
            )

            result["verification"] = verification

            if not verification.get("success"):
                result["error"] = (
                    verification.get("error")
                    or "Coupon validation failed"
                )
                return result

            result["created_ids"] = [
                coupon_code
            ]
            result["success"] = True

            return result

        except requests.RequestException as exc:
            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )
            return result


    def _add_active_only_resources(
        self,
        resources: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Add resources that are intentionally handled only through
        controlled active context enrichment.

        These resources may not be selected by the generic OpenAPI
        object-endpoint ranking because they do not expose a normal
        passive collection endpoint.
        """

        if (
            "coupons" in self.ACTIVE_ONLY_RESOURCES
            and "coupons" not in resources
        ):
            resources["coupons"] = {
                "path": "/community/api/v2/coupon/new-coupon",
                "method": "POST",
                "status": "discovered",
                "accessible": None,
                "passive_discovery_eligible": False,
                "response_type": "object",
                "collection_field": None,
                "id_field": "coupon_code",
                "selected_identity": None,
                "best_score": None,
                "accounts": {},
            }

        return resources

    # extractor específico para coupon code
    def _extract_coupon_codes(
        self,
        response_data: Any,
        response_text: str,
    ) -> List[str]:
        """
        Extract coupon codes from crAPI coupon responses.

        The endpoint may return the coupon in different formats,
        so this extractor checks common JSON keys and finally falls
        back to a conservative text search.
        """

        discovered: List[str] = []

        coupon_fields = {
            "coupon_code",
            "couponCode",
            "coupon",
            "code",
            "discount_code",
            "discountCode",
        }

        def add_candidate(value: Any) -> None:
            if not isinstance(value, str):
                return

            candidate = value.strip()

            if not candidate:
                return

            if candidate not in discovered:
                discovered.append(candidate)

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if str(key) in coupon_fields:
                        add_candidate(child)

                    if isinstance(child, (dict, list)):
                        visit(child)

            elif isinstance(value, list):
                for item in value:
                    visit(item)

            elif isinstance(value, str):
                # Some versions return the coupon directly as text.
                add_candidate(value)

        visit(response_data)

        if not discovered and isinstance(response_text, str):
            matches = re.findall(
                r"[A-Z0-9]{4,}(?:-[A-Z0-9]{2,})?",
                response_text.upper(),
            )

            for match in matches:
                if match not in discovered:
                    discovered.append(match)

        return discovered


    def _generate_coupon_code(
        self,
    ) -> str:
        """
        Generate a deterministic-shape coupon code for controlled
        crAPI context enrichment.
        """

        suffix = "".join(
            secrets.choice(
                string.digits
            )
            for _ in range(3)
        )

        return f"TRAC{suffix}"

    # verificação do coupon
    def _validate_coupon_context(
        self,
        target_url: str,
        token: str,
        coupon_code: str,
    ) -> Dict[str, Any]:
        """
        Verify that a controlled coupon was created and can be
        validated through the documented coupon validation endpoint.
        """

        endpoint = "/community/api/v2/coupon/validate-coupon"
        url = f"{target_url.rstrip('/')}{endpoint}"

        result: Dict[str, Any] = {
            "attempted": True,
            "success": False,
            "method": "POST",
            "endpoint": endpoint,
            "status_code": None,
            "coupon_code": coupon_code,
            "verified_ids": [],
            "error": None,
        }

        try:
            response = requests.post(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={
                    "coupon_code": coupon_code,
                },
                timeout=self.ACTIVE_DISCOVERY_TIMEOUT,
            )

            result["status_code"] = response.status_code
            result["response_body_preview"] = response.text[:500]

            try:
                response_data = response.json()
            except ValueError:
                response_data = None

            result["response_json"] = response_data

            if response.status_code != 200:
                result["error"] = (
                    f"Coupon validation returned HTTP "
                    f"{response.status_code}: "
                    f"{response.text[:500]}"
                )
                return result

            if not isinstance(
                response_data,
                dict,
            ):
                result["error"] = (
                    "Coupon validation did not return "
                    "the expected JSON object."
                )
                return result

            verified_coupon_code = response_data.get(
                "coupon_code"
            )

            if str(verified_coupon_code) != str(coupon_code):
                result["error"] = (
                    "Coupon validation succeeded, but "
                    "the returned coupon_code does not "
                    "match the created coupon."
                )
                return result

            result["verified_ids"] = [
                coupon_code
            ]
            result["amount"] = response_data.get(
                "amount"
            )
            result["success"] = True

            return result

        except requests.RequestException as exc:
            result["error"] = (
                f"{type(exc).__name__}: "
                f"{repr(exc)}"
            )
            return result
    

    
