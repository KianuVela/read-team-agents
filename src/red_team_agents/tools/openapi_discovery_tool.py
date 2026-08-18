import json
import os
import tempfile
import requests

from prance import ResolvingParser
from crewai.tools import BaseTool


class OpenAPIDiscoveryTool(BaseTool):

    name: str = "OPENAPI DISCOVERY TOOL"

    description: str = (
        "Parses OpenAPI specifications and generates "
        "a structured API inventory."
    )

    # --------------------------------------------------
    # DOWNLOAD REMOTE SPEC
    # --------------------------------------------------

    def download_spec(self, url: str) -> str:

        response = requests.get(
            url,
            timeout=30
        )

        response.raise_for_status()

        suffix = ".yaml"

        if url.endswith(".json"):
            suffix = ".json"

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        )

        temp_file.write(
            response.content
        )

        temp_file.close()

        return temp_file.name

    # --------------------------------------------------
    # LOAD SPEC
    # --------------------------------------------------

    def load_openapi_spec(
        self,
        spec_source: str
    ):

        temp_file = None

        try:

            if spec_source.startswith(
                "http"
            ):

                temp_file = self.download_spec(
                    spec_source
                )

                parser = ResolvingParser(
                    temp_file
                )

            else:

                parser = ResolvingParser(
                    spec_source
                )

            return parser.specification

        finally:

            if (
                temp_file
                and os.path.exists(
                    temp_file
                )
            ):

                os.remove(
                    temp_file
                )

    # --------------------------------------------------
    # MAIN
    # --------------------------------------------------

    def _run(
        self,
        spec_url: str
    ) -> str:

        try:

            spec = self.load_openapi_spec(
                spec_url
            )
            print(
                f"TOTAL PATHS: "
                f"{len(spec.get('paths', {}))}"
            )
            print(
                spec.get(
                    "info",
                    {}
                )
            )

            inventory = {

                "title":

                    spec.get(
                        "info",
                        {}
                    ).get(
                        "title"
                    ),

                "version":

                    spec.get(
                        "info",
                        {}
                    ).get(
                        "version"
                    ),

                "servers": [],

                "auth_schemes": [],

                "endpoints": []
            }

            # ------------------------------------------
            # SERVERS
            # ------------------------------------------

            for server in spec.get(
                "servers",
                []
            ):

                inventory[
                    "servers"
                ].append(

                    server.get(
                        "url"
                    )
                )

            # ------------------------------------------
            # AUTH SCHEMES
            # ------------------------------------------

            security_schemes = (

                spec.get(
                    "components",
                    {}
                )

                .get(
                    "securitySchemes",
                    {}
                )
            )

            for (
                name,
                scheme
            ) in security_schemes.items():

                inventory[
                    "auth_schemes"
                ].append({

                    "name":

                        name,

                    "type":

                        scheme.get(
                            "type"
                        ),

                    "scheme":

                        scheme.get(
                            "scheme",
                            ""
                        ),

                    "description":

                        scheme.get(
                            "description",
                            ""
                        )
                })

            # ------------------------------------------
            # ENDPOINTS
            # ------------------------------------------

            paths = spec.get(
                "paths",
                {}
            )

            for (
                path,
                methods
            ) in paths.items():

            # ------------------------------------------
            # PATH LEVEL PARAMETERS
            # ------------------------------------------

                path_level_parameters = methods.get(
                    "parameters",
                    []
                )

                for (
                    method,
                    details
                ) in methods.items():

                    if method.lower() not in [

                        "get",
                        "post",
                        "put",
                        "patch",
                        "delete",
                        "head",
                        "options"

                    ]:
                        continue

                    # ------------------------------------------
                    # MERGE PARAMETERS
                    # ------------------------------------------

                    all_parameters = []

                    all_parameters.extend(
                        path_level_parameters
                    )

                    all_parameters.extend(
                        details.get(
                            "parameters",
                            []
                        )
                    )

                    # ------------------------------------------
                    # PATH PARAMETERS
                    # ------------------------------------------

                    path_parameters = []

                    #for param in details.get(
                        #"parameters",
                       # []
                    #):
                    for param in all_parameters:

                        if param.get("in") == "path":

                            path_parameters.append(
                                param.get("name")
                            )


                    # ------------------------------------------
                    # RESOURCE TYPE
                    # ------------------------------------------

                    resource_type = None

                    parts = path.strip(
                        "/"
                    ).split(
                        "/"
                    )

                    for part in reversed(
                        parts
                    ):

                        if not part.startswith(
                            "{"
                        ):

                            resource_type = part

                            break

                    inventory[
                        "endpoints"
                    ].append({

                        "path":

                            path,

                        "resource_type":

                            resource_type,

                        "path_parameters":

                            path_parameters,

                        "method":

                            method.upper(),

                        "summary":

                            details.get(
                                "summary",
                                ""
                            ),

                        "operationId":

                            details.get(
                                "operationId",
                                ""
                            ),

                        "tags":

                            details.get(
                                "tags",
                                []
                            ),

                        "parameters_count":

                            len(
                                #details.get(
                                    #"parameters",
                                    #[]
                                all_parameters
                               #)
                            ),

                        "parameter_details":

                            #details.get(
                                #"parameters",
                                #[]
                            #),
                            all_parameters,

                        "has_request_body":

                            "requestBody" in details,

                        "request_body":

                            details.get(
                                "requestBody",
                                {}
                            ),

                        "response_codes":

                            list(
                                details.get(
                                    "responses",
                                    {}
                                ).keys()
                            ),

                        "responses":

                            details.get(
                                "responses",
                                {}
                            ),

                        "security":

                            details.get(
                                "security",
                                []
                            )
                    })

            # ------------------------------------------
            # SUMMARY
            # ------------------------------------------

            inventory["summary"] = {

                "total_paths":
                    len(
                         spec.get(
                            "paths",
                            {}
                        )
                    ),

                "total_operations":
                    len(
                        inventory[
                            "endpoints"
                        ]
                    ),

                "total_auth_schemes":
                    len(
                        inventory[
                            "auth_schemes"
                        ]
                    )
            }

            # ------------------------------------------
            # SAVE JSON INVENTORY
            # ------------------------------------------

            os.makedirs(
                "outputs/discovery",
                exist_ok=True
            )

            with open(
                "outputs/discovery/openapi_inventory.json",
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    inventory,
                    f,
                    indent=4
                )


            # ------------------------------------------
            # RETURN JSON
            # ------------------------------------------

            return json.dumps(
                inventory,
                indent=2
            )

        except Exception as e:

            return (
                f"ERROR PARSING OPENAPI SPEC: "
                f"{str(e)}"
            )