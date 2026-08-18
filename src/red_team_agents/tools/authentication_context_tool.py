import json
import requests
import secrets
import string
import os
import pprint
from datetime import datetime
from typing import Type, Dict, Any, List, ClassVar
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

from red_team_agents.tools.kali_mcp_tool import KaliMCPTool

from red_team_agents.core.reasoning.resource_model import ResourceModel
from red_team_agents.core.reasoning.state_classifier import StateClassifier


class AuthenticationContextToolInput(BaseModel):

    target_url: str = Field(
        ...,
        description="Base URL of the target application."
    )

    openapi_inventory_file: str = Field(
        default="outputs/discovery/openapi_inventory.json",
        description="Path to the OpenAPI inventory JSON file."
    )


class AuthenticationContextTool(BaseTool):

    # --------------------------------------------------
    # AUTHENTICATION RANKING WEIGHTS
    # --------------------------------------------------

    AUTHENTICATION_RANKING_WEIGHTS: ClassVar[Dict[str, int]] = {

        "login_path": 100,
        "login_operation": 100,
        "login_summary": 80,
        "keyword": 25,
        "negative_keyword": -100,
        "http_200": 20,
        "email_password": 200,
        "token": -150,
        "otp": -150,
        "verification_code": -150
    }


    OBJECT_ENDPOINT_RANKING_WEIGHTS: ClassVar[
        Dict[str, int]
    ] = {

        "get_method": 20,

        # Applied only when the OpenAPI response schema
        # actually represents a collection.
        "collection_endpoint": 120,

        # Detail-resource penalties.
        "detail_endpoint": -80,
        "path_parameter": -60,

        # Query parameters such as report_id that identify
        # one specific object.
        "identifier_query_parameter": -60,

        # GET endpoints whose documented semantics indicate
        # creation, assignment or another state-changing action.
        "action_endpoint": -160,

        "nested_resource": -20,
        "keyword_match": 30,
    }

    OPERATION_PROFILES: ClassVar[Dict[str, Dict[str, Any]]] = {

        "login": {

            "method": "POST",

            "positive_keywords": [

                "login",
                "signin",
                "sign-in",
                "authenticate",
                "authentication",
                "auth",
                "token"

            ],

            "negative_keywords": [

                "register",
                "signup",
                "sign-up",
                "create",
                "forgot",
                "reset",
                "verify",
                "activate"
            ],

            "required_fields": [

                "password"
            ],

            "preferred_identity_fields": [

                "email",
                "username"

            ]
        },



        "register": {

            "method": "POST",

            "positive_keywords": [

                "register",
                "signup",
                "sign-up",
                "create"

            ],

            "negative_keywords": [

                "login",
                "signin",
                "sign-in",
                "authenticate",
                "authentication"

            ],

            "required_fields": [

                "email",
                "password",
                "name"

            ],

            "preferred_identity_fields": [

                "email"
            ]
        }
}


    RESOURCE_KEYWORDS: ClassVar[Dict[str, List[str]]] = {

        "vehicles": [

            "vehicle",
            "vehicles",
            "car",
            "cars"

        ],

        "orders": [

            "order",
            "orders"

        ],

        "reports": [

            "report",
            "reports"

        ],

        "posts": [

            "post",
            "posts"

        ],

        "videos": [

            "video",
            "videos"

        ],

        "users": [

            "user",
            "users",
            "profile"

        ]

}



    ACTION_WORDS: ClassVar[set[str]] = {

        "login",
        "logout",
        "authenticate",
        "register",
        "refresh",
        "verify",
        "activate",
        "deactivate",
        "upload",
        "download",
        "convert",
        "reset",
        "change",
        "create",
        "update",
        "delete",
        "remove",
        "search",
        "filter",
        "send",
        "receive",
        "submit",
        "approve",
        "reject",
        "cancel",
        "checkout",
        "pay",
        "export",
        "import"

    }




    name: str = "Authentication Context Tool"

    description: str = (
        "Obtains authentication tokens and execution context "
        "required for BOLA and BFLA testing."
    )

    args_schema: Type[BaseModel] = AuthenticationContextToolInput

    # --------------------------------------------------
    # INITIALIZE CONTEXT
    # --------------------------------------------------

    def initialize_context(
        self,
        target_url: str,
        openapi_inventory_file: str
    ) -> Dict[str, Any]:

        return {
            "status": "initialized",
            "target": target_url.rstrip("/"),
            "inventory": {
                "file": openapi_inventory_file,
                "loaded": False,
                "summary": {}
            },
            "credentials": {},
            "valid_credentials": {},
            "authentication": {
                "profile": {
                    "found": False,
                    "base_url": None,
                    "login_url": None,
                    "endpoint": None,
                    "method": None,
                    "content_type": None,
                    "summary": None,
                    "operationId": None,
                    "request_body": {},
                    "parameter_details": [],
                    "responses": {}
                },
                "tokens": {},
                "login_results": {}
            },
            "objects": {
                "vehicle_ids": [],
                "order_ids": [],
                "post_ids": [],
                "video_ids": [],
                "report_ids": []
            },
            "metadata": {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "available_accounts": [],
                "notes": []
            }
        }


    # --------------------------------------------------
    # GENERATE RANDOM PASSWORD
    # --------------------------------------------------

    def generate_password(
        self,
        length: int = 16
    ) -> str:

        alphabet = (
            string.ascii_letters
            + string.digits
            + "!@#$%^&*"
        )

        return "".join(
            secrets.choice(alphabet)
            for _ in range(length)

        )

    # --------------------------------------------------
    # GENERATE RANDOM PHONE NUMBER
    # --------------------------------------------------

    def generate_phone_number(
        self
    ) -> str:

        return "9" + "".join(
            secrets.choice(string.digits)
            for _ in range(8)

        )
    


    # --------------------------------------------------
    # LOAD OPENAPI INVENTORY
    # --------------------------------------------------

    def load_openapi_inventory(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        openapi_inventory_file = context["inventory"]["file"]

        if not os.path.exists(openapi_inventory_file):
            context["inventory"]["loaded"] = False
            context["metadata"]["notes"].append(
                f"OpenAPI inventory file not found: {openapi_inventory_file}"
            )
            return context

        with open(
            openapi_inventory_file,
            "r",
            encoding="utf-8"
        ) as f:
            inventory = json.load(f)

        context["inventory"]["loaded"] = True
        context["inventory"]["data"] = inventory
        context["inventory"]["summary"] = inventory.get(
            "summary",
            {}
        )

        return context


    # --------------------------------------------------
    # DISCOVER AUTHENTICATION PROFILE
    # --------------------------------------------------

    def rank_authentication_endpoints(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not context["inventory"].get("loaded"):
            context["metadata"]["notes"].append(
                "Authentication endpoint ranking could not be performed because the OpenAPI inventory was not loaded."
            )
            return context

        inventory = context["inventory"].get("data", {})

        #login_keywords = [
            #"login",
            #"signin",
            #"sign-in",
            #"authenticate",
            #"authentication",
            #"auth",
            #"token"
        #]

        #negative_keywords = [
            #"register",
            #"signup",
            #"sign-up",
            #"create",
            #"forgot",
            #"reset",
            #"verify",
            #"activate"
        #]

        # Essa parte substitui a parte comentada acima, porém com o mesmo resultado]
        
        operation_profile = self.rank_operation_endpoints(
            context,
            "login"
        )

        required_fields = operation_profile.get(
            "required_fields",
            []
        )

        preferred_identity_fields = operation_profile.get(
            "preferred_identity_fields",
            []
        )

        login_keywords = operation_profile["positive_keywords"]
        negative_keywords = operation_profile["negative_keywords"]


        best_candidate = None

        best_ranking_reason = []

        best_score = -9999

        for endpoint in inventory.get(

            "endpoints",

            []

        ):

            path = endpoint.get(

                "path",

                ""

            ).lower()

            summary = endpoint.get(

                "summary",

                ""

            ).lower()

            operation_id = endpoint.get(

                "operationId",

                ""

            ).lower()

            method = endpoint.get(

                "method",

                ""

            ).upper()

            if method != "POST":

                continue

            score = 0
            ranking_reason = []

            tags = " ".join(
                endpoint.get(
                    "tags",
                    []
                )
            ).lower()

            searchable = " ".join(
                [
                    path,
                    summary,
                    operation_id,
                    tags
                ]

            )

            # --------------------------
            # Positive scoring
            # --------------------------

            if "login" in path:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["login_path"]
                ranking_reason.append(
                    "+100: 'login' found in path"
                )

            if "login" in operation_id:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["login_operation"]
                ranking_reason.append(
                    "+100: 'login' found in operationId"
                )

            if "login" in summary:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["login_summary"]
                ranking_reason.append(
                    "+80: 'login' found in summary"
                )

            for keyword in login_keywords:

                if keyword in searchable:

                    score += self.AUTHENTICATION_RANKING_WEIGHTS["keyword"]
                    ranking_reason.append(
                        f"+25: keyword '{keyword}' matched"
                    )

            # --------------------------
            # Negative scoring
            # --------------------------

            for keyword in negative_keywords:

                if keyword in searchable:

                    score += self.AUTHENTICATION_RANKING_WEIGHTS["negative_keyword"]
                    ranking_reason.append(
                        f"-100: negative keyword '{keyword}' matched"
                    )

            # --------------------------
            # Prefer JWT responses
            # --------------------------

            responses = endpoint.get(
                "responses",
                {}
            )
            if "200" in responses:
                score += self.AUTHENTICATION_RANKING_WEIGHTS["http_200"]
                ranking_reason.append(
                    "+20: endpoint defines HTTP 200 response"
                )
                
            
            # --------------------------
            # Analyse request body
            # --------------------------

            request_body = endpoint.get(
                "request_body",
                {}
            )

            content = request_body.get(
                "content",
                {}
            )

            schema = {}

            if "application/json" in content:

                schema = content[
                    "application/json"
                ].get(
                    "schema",
                    {}
                )

            properties = schema.get(
                "properties",
                {}
            )

            property_names = {

                name.lower()

                for name in properties.keys()

            }


            required_fields_present = all(

                field in property_names
                for field in required_fields
            )

            identity_field_present = any(

                field in property_names
                for field in preferred_identity_fields
            )


            # --------------------------
            # Strong preference for classic username/password
            # --------------------------

            # Antiga logica hardcode 
           # if (
               # "password" in property_names
               # and
                #(
                    #email" in property_names
                   # or
                   # "username" in property_names
               # )
            #):

            # Nova lógica bloco baseado no perfil da operação.
            if (
                required_fields_present
                and
                identity_field_present
            ):

                score += self.AUTHENTICATION_RANKING_WEIGHTS["email_password"]
                ranking_reason.append(
                    "+200: classic email/password authentication payload"
                )

            # --------------------------
            # Penalise token-based login
            # --------------------------

            if "token" in property_names:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["token"]
                ranking_reason.append(
                    "-150: token-based authentication payload"
                )

            if "otp" in property_names:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["otp"]
                ranking_reason.append(
                   "-150: OTP-based authentication payload"
                )

            if "verification_code" in property_names:

                score += self.AUTHENTICATION_RANKING_WEIGHTS["verification_code"]
                ranking_reason.append(
                    "-150: verification-code authentication payload"
                )

            # --------------------------
            # Keep best candidate
            # --------------------------

            if score > best_score:

                best_score = score

                best_candidate = endpoint

                best_ranking_reason = ranking_reason.copy()

        if not best_candidate:
            context["authentication"]["profile"] = {
                "found": False,
                "score": best_score,
                "ranking_reason": [],
                "base_url": context["target"],
                "login_url": None,
                "endpoint": None,
                "method": None,
                "content_type": None,
                "summary": None,
                "operationId": None,
                "request_body": {},
                "parameter_details": [],
                "responses": {}
            }

            context["metadata"]["notes"].append(
                "No login/authentication endpoint was discovered in the OpenAPI inventory."
            )

            return context

        request_body = best_candidate.get(
            "request_body",
            {}
        )

        content_type = self.infer_content_type(
            request_body
        )

        context["authentication"]["profile"] = {
            "found": True,
            "score": best_score,
            "ranking_reason": best_ranking_reason,
            "base_url": context["target"],
            "login_url": (
                context["target"].rstrip("/")
                + best_candidate.get("path")
            ),

            "endpoint": best_candidate.get("path"),
            "method": best_candidate.get("method"),
            "content_type": content_type,
            "summary": best_candidate.get("summary"),
            "operationId": best_candidate.get("operationId"),
            "request_body": request_body,
            "parameter_details": best_candidate.get(
                "parameter_details",
                []
            ),
            "responses": best_candidate.get(
                "responses",
                {}
            )
        }

        return context




    # --------------------------------------------------
    # DISCOVER OPERATION ENDPOINT
    # --------------------------------------------------

    def discover_operation_endpoint(
        self,
        context: Dict[str, Any],
        operation: str
    ) -> Dict[str, Any]:

        operation_profile = self.rank_operation_endpoints(
            context,
            operation
        )

        inventory = context["inventory"].get(
            "data",
            {}
        )

        return {
            "profile": operation_profile,
            "inventory": inventory
        }


    # --------------------------------------------------
    # RANK OPERATION ENDPOINTS
    # --------------------------------------------------

    def rank_operation_endpoints(
        self,
        context: Dict[str, Any],
        operation: str
    ) -> Dict[str, Any]:

        operation_profile = self.OPERATION_PROFILES.get(
            operation
        )

        if operation_profile is None:

            context["metadata"]["notes"].append(
                f"Unknown operation profile: {operation}"
            )

            return {}

        return operation_profile


    # --------------------------------------------------
    # DISCOVER REGISTRATION PROFILE
    # --------------------------------------------------

    def rank_registration_endpoints(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not context["inventory"].get("loaded"):

            context["metadata"]["notes"].append(
                "Registration endpoint ranking could not be performed because the OpenAPI inventory was not loaded."
            )

            return context

        inventory = context["inventory"].get(
            "data",
            {}
        )

        operation_profile = self.rank_operation_endpoints(
            context,
            "register"
        )

        positive_keywords = operation_profile[
            "positive_keywords"
        ]

        negative_keywords = operation_profile[
            "negative_keywords"
        ]

        best_candidate = None

        best_score = -9999

        for endpoint in inventory.get(
            "endpoints",
            []
        ):

            method = endpoint.get(
                "method",
                ""
            ).upper()

            if method != "POST":

                continue

            path = endpoint.get(
                "path",
            ""
            ).lower()

            summary = endpoint.get(
                "summary",
                ""
            ).lower()

            operation_id = endpoint.get(
                "operationId",
                ""
            ).lower()

            tags = " ".join(
                endpoint.get(
                    "tags",
                    []
                )
            ).lower()

            searchable = " ".join(

                [

                    path,

                    summary,

                    operation_id,

                    tags

                ]

            )

            score = 0

            for keyword in positive_keywords:

                if keyword in searchable:

                    score += 25

            for keyword in negative_keywords:

                if keyword in searchable:

                    score -= 100

            request_body = endpoint.get(
                "request_body",
                {}
            )

            content = request_body.get(
                "content",
                {}
            )

            schema = {}

            if "application/json" in content:

                schema = content[
                    "application/json"
                ].get(
                    "schema",
                    {}
                )

            properties = {

                p.lower()

                for p in schema.get(
                    "properties",
                    {}
                ).keys()

            }

            if (

                "email" in properties

                and

                "password" in properties

                and

                "name" in properties

            ):

                score += 200

            if score > best_score:

                best_score = score

                best_candidate = endpoint

        if not best_candidate:

            context["authentication"]["registration_profile"] = {

                "found": False,

                "score": best_score,

                "registration_url": None,

                "endpoint": None,

                "method": None,

                "request_body": {},

                "responses": {}

            }

            return context

        context["authentication"]["registration_profile"] = {

            "found": True,

            "score": best_score,

            "registration_url": (

                context["target"].rstrip("/")

                + best_candidate.get("path")

            ),

            "endpoint": best_candidate.get(
                "path"
            ),

            "method": best_candidate.get(
                "method"
            ),

            "request_body": best_candidate.get(
                "request_body",
                {}
            ),

            "responses": best_candidate.get(
                "responses",
                {}
            )

        }

        return context


    # --------------------------------------------------
    # INFER CONTENT TYPE
    # --------------------------------------------------

    def infer_content_type(
        self,
        request_body: Dict[str, Any]
    ) -> str:

        content = request_body.get(
            "content",
            {}
        )

        if "application/json" in content:
            return "application/json"

        if "application/x-www-form-urlencoded" in content:
            return "application/x-www-form-urlencoded"

        if content:
            return list(content.keys())[0]

        return "application/json"


    # --------------------------------------------------
    # DISCOVER LOGIN FIELDS
    # --------------------------------------------------

    def discover_login_fields(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        profile = context["authentication"]["profile"]

        request_body = profile.get(
            "request_body",
            {}
        )

        content_type = profile.get(
            "content_type",
            "application/json"
        )

        content = request_body.get(
            "content",
            {}
        )

        schema = (
            content
            .get(
                content_type,
                {}
            )
            .get(
                "schema",
                {}
            )
        )

        properties = schema.get(
            "properties",
            {}
        )

        required = schema.get(
            "required",
            []
        )

        username_candidates = [
            "email",
            "username",
            "user",
            "login",
            "identifier"
        ]

        password_candidates = [
            "password",
            "pass",
            "secret"
        ]

        username_field = None
        password_field = None

        for candidate in username_candidates:

            if candidate in properties:

                username_field = candidate
                break

        for candidate in password_candidates:

            if candidate in properties:

                password_field = candidate
                break

        context["authentication"]["profile"]["login_fields"] = {
            "username_field": username_field,
            "password_field": password_field,
            "required": required,
            "properties": list(
                properties.keys()
            )
        }

        if not username_field or not password_field:

            context["metadata"]["notes"].append(
                "Login fields could not be confidently discovered from the OpenAPI request body."
            )

        return context




    # --------------------------------------------------
    # DISCOVER REGISTRATION FIELDS
    # --------------------------------------------------

    def discover_registration_fields(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        profile = context["authentication"].get(
            "registration_profile",
            {}
        )

        request_body = profile.get(
            "request_body",
            {}
        )

        content_type = self.infer_content_type(
            request_body
        )

        content = request_body.get(
            "content",
            {}
        )

        schema = (
            content
            .get(
                content_type,
                {}
            )
            .get(
                "schema",
                {}
            )
        )

        properties = schema.get(
            "properties",
            {}
        )

        required = schema.get(
            "required",
            []
        )

        email_candidates = [

            "email",
            "username",
            "user",
            "login"

        ]

        password_candidates = [

            "password",
            "pass",
            "secret"

        ]

        name_candidates = [

            "name",
            "fullname",
            "full_name",
            "displayName",
            "display_name"

        ]

        email_field = None
        password_field = None
        name_field = None

        for candidate in email_candidates:

            if candidate in properties:
                email_field = candidate

                break

        for candidate in password_candidates:

            if candidate in properties:
                password_field = candidate

                break

        for candidate in name_candidates:

            if candidate in properties:
                name_field = candidate

                break

        context["authentication"]["registration_profile"][
            "registration_fields"
        ] = {

            "email_field": email_field,
            "password_field": password_field,
            "name_field": name_field,
            "required": required,
            "properties": list(
                properties.keys()
            )

        }

        if not email_field:

            context["metadata"]["notes"].append(
                "Registration email field could not be identified."
            )

        if not password_field:

            context["metadata"]["notes"].append(
                "Registration password field could not be identified."
            )

        return context

    

    # --------------------------------------------------
    # LOAD CREDENTIALS
    # --------------------------------------------------

    def load_credentials(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        context["credentials"] = {
            "user_a": {
                "email": os.getenv("USER_A_EMAIL", ""),
                "password": os.getenv("USER_A_PASSWORD", "")
            },
            "user_b": {
                "email": os.getenv("USER_B_EMAIL", ""),
                "password": os.getenv("USER_B_PASSWORD", "")
            },
            "admin": {
                "email": os.getenv("ADMIN_EMAIL", ""),
                "password": os.getenv("ADMIN_PASSWORD", "")
            },
            "mechanic": {
                "email": os.getenv("MECHANIC_EMAIL", ""),
                "password": os.getenv("MECHANIC_PASSWORD", "")
            },
            "management": {
                "email": os.getenv("MANAGEMENT_EMAIL", ""),
                "password": os.getenv("MANAGEMENT_PASSWORD", "")
            }
        }

        return context

    # --------------------------------------------------
    # VALIDATE CREDENTIALS
    # --------------------------------------------------

    def validate_credentials(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        valid_credentials = {}

        for role, values in context["credentials"].items():

            if values.get("email") and values.get("password"):
                valid_credentials[role] = values

        context["valid_credentials"] = valid_credentials

        context["metadata"]["available_accounts"] = list(
            valid_credentials.keys()
        )

        return context

    # --------------------------------------------------
    # BOOTSTRAP AUTHENTICATION CONTEXT
    # --------------------------------------------------

    def bootstrap_authentication_context(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        accounts = [
            "user_a",
            "user_b",
            "admin",
            "mechanic",
            "management"

        ]

        available_accounts = []
        missing_accounts = []

        for account in accounts:

            credentials = context["credentials"].get(
                account,
                {}
            )

            email = credentials.get("email")
            password = credentials.get("password")

            if email and password:
                available_accounts.append(
                    account
                )

            else:

                missing_accounts.append(
                    account
                )

        context["authentication"]["bootstrap"] = {
            "available_accounts": available_accounts,
            "missing_accounts": missing_accounts,
            "ready_for_authentication": (
                len(available_accounts) > 0
            )

        }

        return context    


    # --------------------------------------------------
    # BUILD LOGIN REQUEST
    # --------------------------------------------------

    def build_login_request(
        self,
        context: Dict[str, Any],
        account_name: str
    ) -> Dict[str, Any]:

        profile = context["authentication"]["profile"]

        login_fields = context["authentication"]["profile"].get(
            "login_fields",
            {}
        )

        credentials = context["credentials"].get(
            account_name,
            {}
        )

        username_field = login_fields.get(
            "username_field"
        )

        password_field = login_fields.get(
            "password_field"
        )

        username = (
            credentials.get("email")
            or
            credentials.get("username")
        )

        password = credentials.get(
            "password"
        )

        # --------------------------------------------------
        # VALIDATE DISCOVERED LOGIN FIELDS
        # --------------------------------------------------

        if not username_field:

            return {
                "success": False,
                "message":
                    "Username field could not be determined.",
                "request": {}
            }

        if not password_field:

            return {
                "success": False,
                "message":
                    "Password field could not be determined.",
                "request": {}
            }

        # --------------------------------------------------
        # VALIDATE AVAILABLE CREDENTIALS
        # --------------------------------------------------
        if not username:

            return {
                "success": False,
                "message":
                    "Username value not available.",
                "request": {}
            }

        if not password:
            return {
                "success": False,
                "message":
                    "Password value not available.",
                "request": {}
            }

        # --------------------------------------------------
        # REQUEST CAN BE BUILT
        # --------------------------------------------------
        return {
            "success": True,
            "message":
                "Authentication request can be built.",
            "request": {}
        }



    # --------------------------------------------------
    # BUILD REGISTRATION REQUEST
    # --------------------------------------------------

    def build_registration_request(
        self,
        context: Dict[str, Any],
        account_name: str
    ) -> Dict[str, Any]:

        registration_profile = context["authentication"].get(
            "registration_profile",
            {}
        )

        registration_fields = registration_profile.get(
            "registration_fields",
            {}
        )

        email_field = registration_fields.get(
            "email_field"
        )

        password_field = registration_fields.get(
            "password_field"
        )

        name_field = registration_fields.get(
            "name_field"
        )

        required_fields = registration_fields.get(
            "required",
            []
        )

        request = {}

        #
        # Build identity
        #      

        email = f"{account_name}_{secrets.token_hex(4)}@autopt.local"
        password = self.generate_password()
        display_name = account_name
        phone_number = self.generate_phone_number()

        #
        # Dynamic fields
        #

        if email_field:

            request[email_field] = email

        if password_field:

            request[password_field] = password

        if name_field:

            request[name_field] = display_name

        #
        # Fill remaining required fields
        #

        for field in required_fields:

            if field in request:

                continue

            if field.lower() == "number":

                request[field] = phone_number

                continue

            request[field] = "AUTO"

        return {

            "success": True,

            "request": request,

            "generated_credentials": {

                "email": email,

                "password": password,

                "name": display_name

            }

        }



    # --------------------------------------------------
    # BUILD AUTHENTICATION REQUEST
    # --------------------------------------------------

    def build_authentication_request(
        self,
        context: Dict[str, Any],
        account_name: str
    ) -> Dict[str, Any]:

        login_profile = context["authentication"][
            "profile"
        ]

        login_fields = login_profile.get(
            "login_fields",
            {}
        )

        credentials = context["credentials"].get(
            account_name,
            {}
        )

        username_field = login_fields.get(
            "username_field"
        )

        password_field = login_fields.get(
            "password_field"
        )

        request = {}

        if username_field:

            request[username_field] = credentials.get(
                "email"
            )

        if password_field:

            request[password_field] = credentials.get(
                "password"
            )

        return {

            "success": True,

            "request": request

        }



    
    # --------------------------------------------------
    # PROVISION AUTHENTICATION ACCOUNTS
    # --------------------------------------------------

    def provision_authentication_accounts(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        registration = context["authentication"].get(
            "registration_profile",
            {}
        )
        print("\n===== REGISTRATION PROFILE =====")
        print(
            json.dumps(
                registration,
                indent=4
            )
        )

        if not registration.get("found"):

            context["metadata"]["notes"].append(
                "Registration endpoint not available."
            )

            return context

        registration_url = registration.get(
            "registration_url"
        )

        accounts = [

            "user_a",
            "user_b",
            "admin",
            "mechanic",
            "management"
        ]

        results = {}

        for account in accounts:

            registration_request = self.build_registration_request(
                context,
                account
            )

            if not registration_request.get("success"):

                results[account] = registration_request

                continue

            payload = registration_request.get(
                "request",
                {}
            )

            try:

                print("\n" + "=" * 80)
                print(f"REGISTER ACCOUNT: {account}")
                print("REGISTRATION URL:")
                print(registration_url)

                print("\nPAYLOAD:")
                print(json.dumps(payload, indent=4))

                response = requests.post(
                    registration_url,
                    json=payload,
                    headers={
                        "Accept": "application/json"
                    },
                    timeout=20
                )

                success = response.status_code in (
                    200,
                    201
                )
                print("\nSTATUS CODE:")
                print(response.status_code)

                print("\nRESPONSE:")
                print(response.text)

                results[account] = {

                    "success": success,

                    "status_code": response.status_code,

                    "response_text": response.text,

                    "response_headers": dict(
                        response.headers
                    ),

                    "payload": payload

                }

                if success:

                    generated = registration_request.get(
                        "generated_credentials",
                        {}
                    )

                    context["credentials"][account] = {

                        "email": generated.get(
                            "email",
                            ""
                        ),

                        "password": generated.get(
                            "password",
                            ""
                        )

                    }

            except requests.exceptions.RequestException as exc:

                results[account] = {

                    "success": False,

                    "error": str(exc),

                    "payload": payload

                }

        context["authentication"][
            "registration_results"
        ] = results

        return context



    # --------------------------------------------------
    # AUTHENTICATE USERS
    # --------------------------------------------------

    def authenticate_users(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        login_url = context["authentication"][
            "profile"
        ].get(
            "login_url"
        )

        accounts = list(
            context["credentials"].keys()
        )

        tokens = {}

        login_results = {}

        for account in accounts:

            auth_request = self.build_authentication_request(
                context,
                account
            )

            payload = auth_request.get(
                "request",
                {}
            )

            try:
                print("\n" + "=" * 80)
                print(f"ACCOUNT : {account}")
                print("LOGIN URL:")
                print(login_url)

                print("\nPAYLOAD:")
                print(
                    json.dumps(
                        payload,
                        indent=4
                    )
                )
                print("=" * 80)
                response = requests.post(

                    login_url,

                    json=payload,

                    headers={
                        "Accept": "application/json"
                    },

                    timeout=20

                )

                success = response.status_code == 200

                login_results[account] = {

                    "success": success,

                    "status_code": response.status_code,

                    "response_text": response.text

                }

                if success:

                    data = response.json()

                    token = data.get(
                        "token"
                    )

                    if token:

                        tokens[account] = token

            except requests.exceptions.RequestException as exc:

                login_results[account] = {

                    "success": False,

                    "error": str(exc)

                }

        context["authentication"][
            "tokens"
        ] = tokens

        context["authentication"][
            "login_results"
        ] = login_results

        print(
            json.dumps(
                login_results,
                indent=4
            )
        )

        return context



    # --------------------------------------------------
    # AUTHENTICATED REQUEST
    # --------------------------------------------------

    def authenticated_request(
        self,
        token: str,
        method: str,
        url: str,
        json_data: Dict[str, Any] | None = None
    ):

        headers = {

            "Authorization": f"Bearer {token}",
            "Accept": "application/json"

        }

        response = requests.request(

            method=method,
            url=url,
            headers=headers,
            json=json_data,
            timeout=20
        )

        return response



    # --------------------------------------------------
    # TOKENIZE ENDPOINT TEXT
    # --------------------------------------------------

    def tokenize_endpoint_text(
        self,
        value: str
    ) -> List[str]:

        normalized = (
            value
            .replace("-", " ")
            .replace("_", " ")
            .replace("/", " ")
            .replace(".", " ")
        )

        tokens = []

        current_token = ""

        for character in normalized:

            if character.isupper() and current_token:

                tokens.append(
                    current_token.lower()
                )

                current_token = character

            elif character.isalnum():

                current_token += character

            else:

                if current_token:

                    tokens.append(
                        current_token.lower()
                    )

                    current_token = ""

        if current_token:

            tokens.append(
                current_token.lower()
            )

        return tokens



    # --------------------------------------------------
    # MATCH RESOURCE KEYWORD
    # --------------------------------------------------

    def match_resource_keyword(
        self,
        endpoint: Dict[str, Any],
        keywords: List[str]
    ) -> str | None:

        path = endpoint.get(
            "path",
            ""
        ).lower()

        summary = endpoint.get(
            "summary",
            ""
        ).lower()

        operation_id = endpoint.get(
            "operationId",
            ""
        ).lower()

        tags = [
            str(tag).lower()
            for tag in endpoint.get(
                "tags",
                []
            )
        ]

        # --------------------------------------------------
        # NORMALIZE PATH SEGMENTS
        # --------------------------------------------------

        path_segments = [
            segment.replace("-", "_")
            for segment in path.split("/")
            if segment
        ]

        # --------------------------------------------------
        # 1. EXACT PATH SEGMENT MATCH
        # Highest-confidence strategy
        # --------------------------------------------------

        for keyword in keywords:

            normalized_keyword = keyword.lower().replace(
                "-",
                "_"
            )

            if normalized_keyword in path_segments:

                return keyword

        # --------------------------------------------------
        # 2. EXACT TAG MATCH
        # --------------------------------------------------

        for keyword in keywords:

            normalized_keyword = keyword.lower().replace(
                "-",
                "_"
            )

            normalized_tags = [
                tag.replace("-", "_")
                for tag in tags
            ]

            if normalized_keyword in normalized_tags:

                return keyword

        # --------------------------------------------------
        # 3. TOKEN MATCH IN SUMMARY AND OPERATION ID
        # --------------------------------------------------

        summary_tokens = self.tokenize_endpoint_text(
            summary
        )

        operation_tokens = self.tokenize_endpoint_text(
            operation_id
        )

        for keyword in keywords:

            normalized_keyword = keyword.lower()

            if normalized_keyword in summary_tokens:

                return keyword

            if normalized_keyword in operation_tokens:

                return keyword

        return None

    
    # --------------------------------------------------
    # DISCOVER OBJECT ENDPOINTS
    # --------------------------------------------------

    def rank_object_endpoints(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        inventory = context["inventory"].get(
            "data",
            {}
        )

        endpoints = inventory.get(
            "endpoints",
            []
        )

        discovered = {}

        # --------------------------------------------------
        # SEMANTIC ACTION TERMS
        # --------------------------------------------------

        action_terms = {
            "create",
            "assign",
            "add",
            "update",
            "delete",
            "send",
            "resend",
            "contact",
            "register",
            "signup",
        }

        # --------------------------------------------------
        # LOCAL HELPER:
        # DOES THE RESPONSE EXPOSE A USABLE IDENTIFIER?
        # --------------------------------------------------
        #
        # This prevents a collection from winning passive
        # discovery merely because it is a collection.
        #
        # Example:
        #
        # /management/users/all
        #
        # returns:
        #
        # {
        #     "users": [
        #         {
        #             "user": {
        #                 "email": "...",
        #                 "number": "..."
        #             }
        #         }
        #     ]
        # }
        #
        # The collection is valid, but its items do not expose
        # an object identifier such as "id" or "uuid".
        #
        # By contrast:
        #
        # /identity/api/v2/user/dashboard
        #
        # returns a top-level "id", so it is suitable for
        # passive object discovery.
        # --------------------------------------------------

        def response_exposes_identifier(
            endpoint: Dict[str, Any],
            metadata: Dict[str, Any],
        ) -> bool:

            responses = endpoint.get(
                "responses",
                {}
            )

            if not isinstance(responses, dict):
                return False

            response_200 = responses.get(
                "200",
                {}
            )

            if not isinstance(response_200, dict):
                return False

            content = response_200.get(
                "content",
                {}
            )

            if not isinstance(content, dict):
                return False

            media_type = content.get(
                "application/json",
                {}
            )

            if not isinstance(media_type, dict):
                return False

            schema = media_type.get(
                "schema",
                {}
            )

            if not isinstance(schema, dict):
                return False

            id_field = metadata.get(
                "id_field"
            )

            if (
                not isinstance(id_field, str)
                or not id_field.strip()
            ):
                id_field = "id"

            identifier_fields = {
                id_field,
                "id",
                "uuid",
            }

            # ----------------------------------------------
            # CASE 1:
            # TOP-LEVEL OBJECT
            # ----------------------------------------------

            schema_type = schema.get(
                "type"
            )

            properties = schema.get(
                "properties",
                {}
            )

            if isinstance(properties, dict):

                if any(
                    field in properties
                    for field in identifier_fields
                ):
                    return True

            # ----------------------------------------------
            # CASE 2:
            # TOP-LEVEL ARRAY
            # ----------------------------------------------

            if schema_type == "array":

                items = schema.get(
                    "items",
                    {}
                )

                if isinstance(items, dict):

                    item_properties = items.get(
                        "properties",
                        {}
                    )

                    if isinstance(
                        item_properties,
                        dict,
                    ):

                        if any(
                            field in item_properties
                            for field in identifier_fields
                        ):
                            return True

            # ----------------------------------------------
            # CASE 3:
            # OBJECT CONTAINING A COLLECTION
            # ----------------------------------------------

            collection_field = metadata.get(
                "collection_field"
            )

            if (
                isinstance(collection_field, str)
                and collection_field
                and isinstance(properties, dict)
            ):

                collection_schema = properties.get(
                    collection_field,
                    {}
                )

                if isinstance(
                    collection_schema,
                    dict,
                ):

                    collection_items = (
                        collection_schema.get(
                            "items",
                            {}
                        )
                    )

                    if isinstance(
                        collection_items,
                        dict,
                    ):

                        item_properties = (
                            collection_items.get(
                                "properties",
                                {}
                            )
                        )

                        if isinstance(
                            item_properties,
                            dict,
                        ):

                            if any(
                                field in item_properties
                                for field in identifier_fields
                            ):
                                return True

            return False

        # --------------------------------------------------
        # RANK RESOURCES
        # --------------------------------------------------

        for resource, keywords in (
            self.RESOURCE_KEYWORDS.items()
        ):

            best_candidate = None

            # Priority is now evaluated using:
            #
            # 1. passive-discovery eligibility;
            # 2. identifier availability;
            # 3. ranking score.
            #
            # This is more robust than score alone.

            best_priority = (
                -1,
                -1,
                -9999,
            )

            for endpoint in endpoints:

                path = endpoint.get(
                    "path",
                    ""
                )

                path_lower = str(
                    path
                ).lower()

                method = str(
                    endpoint.get(
                        "method",
                        ""
                    )
                ).upper()

                # --------------------------------------------------
                # 1. ONLY CONSIDER GET ENDPOINTS
                # --------------------------------------------------

                if method != "GET":
                    continue

                if not self.is_resource_endpoint(
                    endpoint
                ):
                    continue

                # --------------------------------------------------
                # 2. RESOURCE KEYWORD MATCH
                # --------------------------------------------------

                matched_keyword = None

                for keyword in keywords:

                    if keyword in path_lower:

                        matched_keyword = keyword
                        break

                if not matched_keyword:
                    continue

                # --------------------------------------------------
                # 3. INFER OPENAPI METADATA
                # --------------------------------------------------

                metadata = (
                    self.infer_resource_metadata(
                        endpoint
                    )
                )

                # --------------------------------------------------
                # 4. DETECT ACTION-LIKE GET ENDPOINTS
                # --------------------------------------------------

                summary = str(
                    endpoint.get(
                        "summary",
                        ""
                    )
                )

                operation_id = str(
                    endpoint.get(
                        "operationId",
                        ""
                    )
                )

                resource_type = str(
                    endpoint.get(
                        "resource_type",
                        ""
                    )
                )

                semantic_text = " ".join(
                    [
                        summary,
                        operation_id,
                        resource_type,
                    ]
                ).lower()

                semantic_text = (
                    semantic_text
                    .replace("_", " ")
                    .replace("-", " ")
                    .replace("/", " ")
                )

                semantic_tokens = set(
                    semantic_text.split()
                )

                action_like = any(
                    term in semantic_tokens
                    for term in action_terms
                )

                # --------------------------------------------------
                # 5. PATH / IDENTIFIER CONTEXT
                # --------------------------------------------------

                path_parameters = endpoint.get(
                    "path_parameters",
                    []
                )

                if not isinstance(
                    path_parameters,
                    list,
                ):
                    path_parameters = []

                has_path_parameter = (
                    bool(path_parameters)
                    or (
                        "{"
                        in path_lower
                        and
                        "}"
                        in path_lower
                    )
                )

                requires_identifier_context = bool(
                    metadata.get(
                        "requires_identifier_context"
                    )
                )

                is_collection_response = bool(
                    metadata.get(
                        "is_collection_response"
                    )
                )

                # --------------------------------------------------
                # 6. VERIFY IDENTIFIER AVAILABILITY
                # --------------------------------------------------

                has_discoverable_identifier = (
                    response_exposes_identifier(
                        endpoint,
                        metadata,
                    )
                )

                # --------------------------------------------------
                # 7. PASSIVE-DISCOVERY ELIGIBILITY
                # --------------------------------------------------
                #
                # NEW RULE:
                #
                # Passive discovery requires a response from which
                # an object identifier can actually be extracted.
                # --------------------------------------------------

                passive_discovery_eligible = (
                    not has_path_parameter
                    and not requires_identifier_context
                    and not action_like
                    and has_discoverable_identifier
                )

                # --------------------------------------------------
                # 8. SCORE ENDPOINT
                # --------------------------------------------------

                score = 0
                ranking_reason = []

                weight = (
                    self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                        "get_method"
                    ]
                )

                score += weight

                ranking_reason.append(
                    f"{weight:+d} GET method"
                )

                weight = (
                    self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                        "keyword_match"
                    ]
                )

                score += weight

                ranking_reason.append(
                    f"{weight:+d} keyword matched: "
                    f"{matched_keyword}"
                )

                # --------------------------------------------------
                # TRUE COLLECTION BONUS
                # --------------------------------------------------

                if is_collection_response:

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "collection_endpoint"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} collection response "
                        f"confirmed by OpenAPI schema"
                    )

                # --------------------------------------------------
                # IDENTIFIER DISCOVERY METADATA
                # --------------------------------------------------

                if has_discoverable_identifier:

                    ranking_reason.append(
                        "identifier exposed by response schema"
                    )

                else:

                    ranking_reason.append(
                        "response schema exposes no usable "
                        "object identifier"
                    )

                # --------------------------------------------------
                # PATH-BASED DETAIL ENDPOINT
                # --------------------------------------------------

                if has_path_parameter:

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "detail_endpoint"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} detail endpoint"
                    )

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "path_parameter"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} path parameter required"
                    )

                # --------------------------------------------------
                # QUERY-BASED DETAIL ENDPOINT
                # --------------------------------------------------

                if requires_identifier_context:

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "detail_endpoint"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} detail endpoint "
                        f"requiring identifier context"
                    )

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "identifier_query_parameter"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} identifier query "
                        f"parameter required"
                    )

                # --------------------------------------------------
                # ACTION-LIKE GET ENDPOINT
                # --------------------------------------------------

                if action_like:

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "action_endpoint"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} action-like GET endpoint"
                    )

                # --------------------------------------------------
                # NESTED RESOURCE PENALTY
                # --------------------------------------------------

                if path_lower.count("/") > 5:

                    weight = (
                        self.OBJECT_ENDPOINT_RANKING_WEIGHTS[
                            "nested_resource"
                        ]
                    )

                    score += weight

                    ranking_reason.append(
                        f"{weight:+d} deeply nested resource"
                    )

                # --------------------------------------------------
                # 9. CANDIDATE PRIORITY
                # --------------------------------------------------
                #
                # CRITICAL CHANGE:
                #
                # We no longer choose candidates using only:
                #
                #     score > best_score
                #
                # Priority is:
                #
                #     passive eligible
                #         >
                #     exposes identifier
                #         >
                #     numeric score
                #
                # Therefore, a high-scoring collection that contains
                # no usable identifiers cannot displace an endpoint
                # that actually provides an identifiable object.
                # --------------------------------------------------

                candidate_priority = (
                    1
                    if passive_discovery_eligible
                    else 0,

                    1
                    if has_discoverable_identifier
                    else 0,

                    score,
                )

                if candidate_priority > best_priority:

                    best_priority = (
                        candidate_priority
                    )

                    best_candidate = {

                        "path": endpoint.get(
                            "path"
                        ),

                        "method": endpoint.get(
                            "method"
                        ),

                        "score": score,

                        "matched_keyword": (
                            matched_keyword
                        ),

                        "ranking_reason": (
                            ranking_reason
                        ),

                        "passive_discovery_eligible": (
                            passive_discovery_eligible
                        ),

                        "has_discoverable_identifier": (
                            has_discoverable_identifier
                        ),

                        "action_like": (
                            action_like
                        ),

                        **metadata,
                    }

            if best_candidate:

                discovered[
                    resource
                ] = best_candidate

        context["authentication"][
            "object_endpoints"
        ] = discovered

        return context

    # --------------------------------------------------
    # INFER RESOURCE METADATA
    # --------------------------------------------------
    
    def infer_resource_metadata(
        self,
        endpoint: Dict[str, Any]
    ) -> Dict[str, Any]:

        metadata = {

            "id_field": "id",

            "response_type": "unknown",

            "collection_field": None,

            # True only when the response schema actually
            # represents a collection.
            "is_collection_response": False,

            # Required query parameters declared by OpenAPI.
            "required_query_parameters": [],

            # Required query parameters that appear to identify
            # a specific object, e.g. report_id.
            "identifier_query_parameters": [],

            # True when the endpoint cannot be called generically
            # because an object identifier is required.
            "requires_identifier_context": False,

        }

        # --------------------------------------------------
        # 1. INSPECT PARAMETERS
        # --------------------------------------------------

        parameter_details = endpoint.get(
            "parameter_details",
            []
        )

        if not isinstance(
            parameter_details,
            list,
        ):
            parameter_details = []

        required_query_parameters = []

        identifier_query_parameters = []

        for parameter in parameter_details:

            if not isinstance(
                parameter,
                dict,
            ):
                continue

            if parameter.get("in") != "query":
                continue

            if not parameter.get("required"):
                continue

            parameter_name = parameter.get(
                "name"
            )

            if not isinstance(
                parameter_name,
                str,
            ):
                continue

            parameter_name = (
                parameter_name.strip()
            )

            if not parameter_name:
                continue

            required_query_parameters.append(
                parameter_name
            )

            normalized_name = (
                parameter_name.lower()
            )

            identifier_like = (
                normalized_name == "id"
                or normalized_name.endswith("_id")
                or normalized_name.endswith("id")
            )

            if identifier_like:

                identifier_query_parameters.append(
                    parameter_name
                )

        metadata[
            "required_query_parameters"
        ] = required_query_parameters

        metadata[
            "identifier_query_parameters"
        ] = identifier_query_parameters

        metadata[
            "requires_identifier_context"
        ] = bool(
            identifier_query_parameters
        )

        # --------------------------------------------------
        # 2. READ RESPONSE SCHEMA
        # --------------------------------------------------

        responses = endpoint.get(
            "responses",
            {}
        )

        response_200 = responses.get(
            "200",
            {}
        )

        content = response_200.get(
            "content",
            {}
        )

        json_content = content.get(
            "application/json",
            {}
        )

        schema = json_content.get(
            "schema",
            {}
        )

        if not isinstance(
            schema,
            dict,
        ):
            schema = {}

        # --------------------------------------------------
        # 3. DETERMINE RESPONSE TYPE
        # --------------------------------------------------

        schema_type = schema.get(
            "type"
        )

        if schema_type == "array":

            metadata[
                "response_type"
            ] = "collection"

            metadata[
                "is_collection_response"
            ] = True

            items = schema.get(
                "items",
                {}
            )

            if not isinstance(
                items,
                dict,
            ):
                items = {}

            properties = items.get(
                "properties",
                {}
            )

        elif schema_type == "object":

            metadata[
                "response_type"
            ] = "object"

            properties = schema.get(
                "properties",
                {}
            )

        else:

            properties = {}

        if not isinstance(
            properties,
            dict,
        ):
            properties = {}

        # --------------------------------------------------
        # 4. INFER IDENTIFIER FIELD
        # --------------------------------------------------

        preferred_id_fields = [

            "id",
            "vehicleid",
            "vehicle_id",
            "orderid",
            "order_id",
            "postid",
            "post_id",
            "videoid",
            "video_id",
            "reportid",
            "report_id",
            "userid",
            "user_id",

        ]

        for field in properties:

            field_lower = field.lower()

            if field_lower in preferred_id_fields:

                metadata[
                    "id_field"
                ] = field

                break

        else:

            for field in properties:

                if field.lower().endswith(
                    "id"
                ):

                    metadata[
                        "id_field"
                    ] = field

                    break

        # --------------------------------------------------
        # 5. IDENTIFY WRAPPED COLLECTIONS
        # --------------------------------------------------
        #
        # Example:
        #
        # {
        #     "orders": [...]
        # }
        #
        # The outer response is an object, but semantically
        # it is still a collection response.
        # --------------------------------------------------

        if metadata[
            "response_type"
        ] == "object":

            for field, definition in (
                properties.items()
            ):

                if not isinstance(
                    definition,
                    dict,
                ):
                    continue

                if definition.get(
                    "type"
                ) == "array":

                    metadata[
                        "collection_field"
                    ] = field

                    metadata[
                        "is_collection_response"
                    ] = True

                    break

        return metadata
    
    # --------------------------------------------------
    # RESOURCE ENDPOINT VALIDATION
    # --------------------------------------------------

    def is_resource_endpoint(
        self,
        endpoint: Dict[str, Any]
    ) -> bool:

        path = endpoint.get(
            "path",
            ""
        ).lower()

        segments = [

            segment

            for segment in path.split("/")

            if segment

        ]

        if not segments:

            return False

        last_segment = segments[-1].replace("-", "_")

        for action in self.ACTION_WORDS:

            if action == last_segment:

                return False

            if last_segment.startswith(
                action + "_"
            ):

                return False

            if last_segment.endswith(
                "_" + action
            ):

                return False

            if (
                action in last_segment
                and "_" in last_segment
            ):

                return False

        return True




    # --------------------------------------------------
    # COLLECT RESOURCE IDS
    # --------------------------------------------------

    def collect_resource_ids(
        self,
        token: str,
        endpoint: str,
        id_field: str
    ) -> list:

        response = self.authenticated_request(

            token=token,
            method="GET",
            url=endpoint

        )

        if response.status_code != 200:

            return []

        try:

            data = response.json()

        except Exception:

            return []

        if isinstance(data, list):

            return [

                item[id_field]

                for item in data

                if isinstance(item, dict)

                and id_field in item

            ]

        return []




    # --------------------------------------------------
    # COLLECT OBJECTS
    # --------------------------------------------------

    def collect_objects(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        tokens = context["authentication"].get(
            "tokens",
            {}
        )

        object_endpoints = context["authentication"].get(
            "object_endpoints",
            {}
        )

        base_url = context.get(
            "target",
            ""
        ).rstrip("/")

        collection_results = {}

        for resource, endpoint_info in object_endpoints.items():

            path = endpoint_info.get(
                "path"
            )

            if not path:

                continue

            if "{" in path or "}" in path:

                collection_results[resource] = {
                    "success": False,
                    "reason": "Skipped endpoint with unresolved path parameter.",
                    "path": path
                }

                continue

            url = base_url + path

            id_field = endpoint_info.get(
                "id_field",
                "id"
            )

            collection_field = endpoint_info.get(
                "collection_field"
            )

            resource_ids = []

            per_account_results = {}

            for account, token in tokens.items():

                try:

                    response = self.authenticated_request(
                        token=token,
                        method="GET",
                        url=url
                    )

                    result = {
                        "status_code": response.status_code,
                        "success": response.status_code == 200
                    }

                    if response.status_code != 200:

                        result["response_text"] = response.text

                        per_account_results[account] = result

                        continue

                    try:

                        data = response.json()

                    except Exception:

                        result["success"] = False
                        result["reason"] = "Response was not valid JSON."
                        result["response_text"] = response.text

                        per_account_results[account] = result

                        continue

                    items = []

                    if isinstance(data, list):

                        items = data

                    elif isinstance(data, dict):

                        if collection_field and isinstance(
                            data.get(collection_field),
                            list
                        ):

                            items = data.get(
                                collection_field,
                                []
                            )

                        else:

                            for value in data.values():

                                if isinstance(value, list):

                                    items = value

                                    break

                    extracted_ids = []

                    for item in items:

                        if not isinstance(item, dict):

                            continue

                        if id_field in item:

                            extracted_ids.append(
                                item[id_field]
                            )

                        else:

                            for key, value in item.items():

                                if key.lower().endswith("id"):

                                    extracted_ids.append(
                                        value
                                    )

                                    break

                    resource_ids.extend(
                        extracted_ids
                    )

                    result["extracted_ids"] = extracted_ids
                    result["count"] = len(extracted_ids)

                    per_account_results[account] = result

                except requests.exceptions.RequestException as exc:

                    per_account_results[account] = {
                        "success": False,
                        "error": str(exc)
                    }

            unique_ids = list(
                dict.fromkeys(
                    resource_ids
                )
            )

            collection_results[resource] = {
                "success": True,
                "endpoint": path,
                "url": url,
                "id_field": id_field,
                "collection_field": collection_field,
                "ids": unique_ids,
                "count": len(unique_ids),
                "accounts": per_account_results
            }

            object_key = f"{resource.rstrip('s')}_ids"

            if object_key in context["objects"]:

                context["objects"][object_key] = unique_ids

            else:

                context["objects"][f"{resource}_ids"] = unique_ids

        context["authentication"][
            "object_collection_results"
        ] = collection_results

        return context
    



    # --------------------------------------------------
    # SAVE AUTH CONTEXT
    # --------------------------------------------------

    def save_auth_context(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        output_dir = Path(
            "outputs/execution"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        output_file = output_dir / "authentication_context.json"

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                context,
                file,
                indent=4
            )

        context["metadata"]["auth_context_file"] = str(
            output_file
        )

        return context

    # --------------------------------------------------
    # GENERATE REPORT - FUTURE FEATURE
    # --------------------------------------------------

    def generate_report(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        context["metadata"]["notes"].append(
            "generate_report() not implemented yet."
        )

        return context

    def cleanup_context(
        self,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:

        inventory = context.get(
            "inventory",
            {}

        )

        inventory_data = inventory.get("data") or {}

        inventory["summary"] = {
            "total_endpoints": len(
                inventory_data.get("endpoints", [])
            ),
            "loaded": inventory.get("loaded", False)
        }

        inventory.pop(
            "data",
            None
        )

        return context





    # --------------------------------------------------
    # BUILD RESOURCE MODELS
    # --------------------------------------------------

    def build_resource_models(self, context: dict) -> list[ResourceModel]:
        """
        Build and classify one ResourceModel for each discovered API endpoint.

        The method converts the authentication and object-discovery context
        into structured ResourceModel instances. Each resource is immediately
        classified by the deterministic StateClassifier.

        Args:
            context: Authentication and object-discovery context produced by
                the AuthenticationContextTool pipeline.

        Returns:
            A list of classified ResourceModel instances.
        """

        resource_models: list[ResourceModel] = []
        classifier = StateClassifier()

        authentication_context = context.get("authentication", {})

        authenticated = bool(
            authentication_context.get("authenticated", False)
        )

        actor = authentication_context.get("actor")

        jwt_token = (
            authentication_context.get("jwt_token")
            or authentication_context.get("access_token")
            or authentication_context.get("token")
        )

        object_endpoints = authentication_context.get(
            "object_endpoints",
            [],
        )

        for endpoint_data in object_endpoints:
            if not isinstance(endpoint_data, dict):
                continue

            endpoint = (
                endpoint_data.get("endpoint")
                or endpoint_data.get("path")
                or endpoint_data.get("url")
                or ""
            )

            method = endpoint_data.get("method", "GET")

            object_ids = (
                endpoint_data.get("object_ids")
                or endpoint_data.get("identifiers")
                or endpoint_data.get("ids")
                or []
            )

            if not isinstance(object_ids, list):
                object_ids = [object_ids]

            resource = ResourceModel(
                endpoint=str(endpoint),
                method=str(method),
                authenticated=authenticated,
                actor=actor,
                jwt_token=jwt_token,
                object_ids=[
                    str(object_id)
                    for object_id in object_ids
                    if object_id is not None
                ],
                evidence={
                    "source": "AuthenticationContextTool",
                    "endpoint_context": endpoint_data,
                },
            )

            classifier.classify(resource)

            resource_models.append(resource)

        context["resource_models"] = resource_models

        return resource_models





    def _build_execution_context(
        self,
        target_url: str,
        inventory_file: str,
    ) -> dict:

        context = self.initialize_context(
            target_url,
            inventory_file,
        )

        context = self.load_openapi_inventory(context)

        context = self.rank_authentication_endpoints(context)

        context = self.rank_registration_endpoints(context)

        context = self.discover_registration_fields(context)

        context = self.discover_login_fields(context)

        context = self.load_credentials(context)

        context = self.validate_credentials(context)

        context = self.bootstrap_authentication_context(context)

        context = self.provision_authentication_accounts(context)

        context = self.authenticate_users(context)

        context = self.rank_object_endpoints(context)

        context = self.collect_objects(context)

        self.build_resource_models(context)

        return context




    # --------------------------------------------------
    # MAIN
    # --------------------------------------------------

    def _run(
        self,
        target_url: str,
        openapi_inventory_file: str = "outputs/discovery/openapi_inventory.json"
    ) -> str:

        load_dotenv()

        target_url = os.getenv(
            "CRAPI_BASE_URL",
            target_url
        )

        context = self.initialize_context(
            target_url=target_url,
            openapi_inventory_file=openapi_inventory_file
        )

        context = self.load_openapi_inventory(
            context
        )

        context = self.rank_authentication_endpoints(
            context
        )

        context = self.rank_registration_endpoints(
            context
        )

        context = self.discover_registration_fields(
            context
        )

        context = self.discover_login_fields(
            context
        )

        context = self.load_credentials(
            context
        )

        context = self.validate_credentials(
            context
        )

        context = self.bootstrap_authentication_context(
            context
        )

        context = self.provision_authentication_accounts(
            context
        )

        context = self.authenticate_users(
            context
        )

        print("\n===== TOKENS AFTER authenticate_users =====")
        print(
            context["authentication"]["tokens"]
        )

        context = self.rank_object_endpoints(
            context
        )

        print("\n===== TOKENS AFTER rank_object_endpoints =====")
        print(
            context["authentication"]["tokens"]
        )

        context = self.collect_objects(
            context
        )

        resource_models = self.build_resource_models(
            context
        )

        print("\n===== TOKENS AFTER collect_objects =====")
        print(
            context["authentication"]["tokens"]
        )

        print("\n===== TOKENS BEFORE SAVE =====")
        print(
            context["authentication"]["tokens"]
        )

        print("\n===== AUTHENTICATION STRUCTURE =====")
        
        pprint.pp(context["authentication"])

        context = self.save_auth_context(
            context
        )

        context = self.generate_report(
            context
        )

    # estava a executar toda a pipeline outra vez...
        #context = self._build_execution_context(
           # target_url,
            #openapi_inventory_file,
        #)
        
        context = self.cleanup_context(
        context
        )

        context["status"] = "success"

        return json.dumps(
            {
                "status": context.get(
                    "status"
                ),

                "target": context.get(
                    "target"
                ),

                "auth_context_file": context.get(
                    "metadata",
                    {}
                ).get(
                    "auth_context_file"
                ),

                "tokens_available": list(
                    context.get(
                        "authentication",
                        {}
                    ).get(
                        "tokens",
                        {}
                    ).keys()
                ),

                "object_endpoints_available": list(
                    context.get(
                        "authentication",
                        {}
                    ).get(
                        "object_endpoints",
                        {}
                    ).keys()
                )
            },
            indent=4
        )