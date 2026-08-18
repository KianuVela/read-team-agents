from __future__ import annotations

import json
import re

from urllib.parse import (
    quote,
    urlsplit,
)

from red_team_agents.core.execution.execution_strategy import (
    ExecutionStrategy,
)

from red_team_agents.core.execution.execution_result import (
    ExecutionResult,
    ResourceUpdate,
)

from red_team_agents.core.execution.request_input_resolver import (
    RequestInputResolver,
)

from red_team_agents.core.execution.analysis.authorization_evidence_enricher import (
    AuthorizationEvidenceEnricher,
)

from red_team_agents.core.execution.analysis.vulnerability_promotion_update_builder import (
    VulnerabilityPromotionUpdateBuilder,
)


class BaseExecutionStrategy(
    ExecutionStrategy
):
    """
    Base HTTP execution strategy.

    Responsibilities:

    1. validate the execution context;
    2. resolve endpoint path parameters;
    3. construct an absolute execution URL;
    4. create a fresh CurlBuilder;
    5. build curl arguments only;
    6. execute curl through KaliMCPTool;
    7. validate whether a real HTTP response was obtained;
    8. return structured execution evidence.

    The strategy does not classify BOLA/BFLA vulnerability.
    It only determines whether the HTTP execution itself
    completed successfully.
    """

    _PATH_PARAMETER_PATTERN = re.compile(
        r"\{([^{}]+)\}"
    )

    # --------------------------------------------------
    # EXECUTE
    # --------------------------------------------------

    def execute(
        self,
        context,
        resource,
    ) -> ExecutionResult:
        """
        Execute one HTTP request.

        A strategy execution is marked completed only when the
        Kali curl tool produces a parseable HTTP response.
        """

        try:

            self._validate(
                context=context,
                resource=resource,
            )

            self._last_request_json_body = None

            curl_args = self._build_request(
                context=context,
                resource=resource,
            )

            request_json_body = getattr(
                self,
                "_last_request_json_body",
                None,
            )

        except (
            ValueError,
            RuntimeError,
        ) as exc:

            return self._build_failure_result(
                resource=resource,
                stage="request_build",
                error=exc,
            )

        try:

            response = self._execute(
                curl_args
            )

        except Exception as exc:
            """
            External-tool boundary.

            Tool execution failures must become structured
            execution evidence instead of being mistaken for
            completed HTTP requests.
            """

            return self._build_failure_result(
                resource=resource,
                stage="tool_execution",
                error=exc,
            )

        return self._build_execution_result(
            context=context,
            resource=resource,
            response=response,
            request_json_body=request_json_body,
        )

    # --------------------------------------------------
    # VALIDATE EXECUTION INPUT
    # --------------------------------------------------

    def _validate(
        self,
        context,
        resource,
    ) -> None:
        """
        Validate the minimum execution prerequisites.
        """

        if context is None:

            raise ValueError(
                "ExecutionContext is required."
            )

        if resource is None:

            raise ValueError(
                "ResourceModel is required."
            )

        endpoint = str(
            getattr(
                resource,
                "endpoint",
                "",
            )
            or ""
        ).strip()

        if not endpoint:

            raise ValueError(
                "Resource endpoint is unavailable."
            )

        method = str(
            getattr(
                resource,
                "method",
                "",
            )
            or ""
        ).strip()

        if not method:

            raise ValueError(
                "HTTP method is unavailable."
            )

        token = str(
            getattr(
                resource,
                "jwt_token",
                "",
            )
            or ""
        ).strip()

        if not token:

            raise ValueError(
                "Authenticated execution requires "
                "a usable JWT token."
            )

        if getattr(
            self,
            "_kali_tool",
            None,
        ) is None:

            raise RuntimeError(
                "Kali execution tool is not configured."
            )

        if getattr(
            self,
            "_curl_builder",
            None,
        ) is None:

            raise RuntimeError(
                "CurlBuilder is not configured."
            )

        placeholders = (
            self._PATH_PARAMETER_PATTERN.findall(
                endpoint
            )
        )

        if placeholders:

            selected_object_id = getattr(
                resource,
                "selected_object_id",
                None,
            )

            if selected_object_id in (
                None,
                "",
            ):

                raise ValueError(
                    "Endpoint requires an object "
                    "identifier but "
                    "selected_object_id is unavailable."
                )

    # --------------------------------------------------
    # BUILD REQUEST
    # --------------------------------------------------

    def _build_request(
        self,
        context,
        resource,
    ) -> str:
        """
        Build curl arguments for one HTTP request.

        IMPORTANT:
        The returned value contains curl arguments only.
        The executable name ``curl`` is supplied separately
        to KaliMCPTool.
        """

        endpoint = (
            self._resolve_endpoint_template(
                resource=resource,
            )
        )

        execution_target = (
            self._resolve_execution_target(
                context=context,
                resource=resource,
            )
        )

        absolute_url = (
            self._construct_absolute_url(
                execution_target=(
                    execution_target
                ),
                endpoint=endpoint,
            )
        )

        builder = (
            self._new_curl_builder()
        )

        builder.with_method(
            resource.method
        )

        builder.with_url(
            absolute_url
        )

        builder.bearer(
            resource.jwt_token
        )

        if hasattr(
            builder,
            "accept_json",
        ):

            builder.accept_json()

        # --------------------------------------------------
        # RESOLVE TEST-CASE REQUEST INPUT
        # --------------------------------------------------

        request_input = (
            RequestInputResolver().resolve(
                resource
            )
        )

        json_body = (
            request_input.json_body
        )

        if json_body is not None:

            if hasattr(
                builder,
                "content_json",
            ):
                builder.content_json()

            if not hasattr(
                builder,
                "with_body",
            ):
                raise RuntimeError(
                    "CurlBuilder does not support "
                    "request bodies."
                )

            builder.with_body(
                json.dumps(
                    json_body
                )
            )

        curl_args = builder.build()

        # --------------------------------------------------
        # DEFENSIVE CONTRACT CHECK
        # --------------------------------------------------

        normalized_args = str(
            curl_args or ""
        ).strip()

        if not normalized_args:

            raise RuntimeError(
                "CurlBuilder returned empty arguments."
            )

        if normalized_args.lower().startswith(
            "curl "
        ):

            raise RuntimeError(
                "CurlBuilder returned an invalid command: "
                "KaliMCPTool requires curl arguments only, "
                "without the leading 'curl' executable."
            )

        self._last_request_json_body = json_body

        return normalized_args

    # --------------------------------------------------
    # RESOLVE ENDPOINT TEMPLATE
    # --------------------------------------------------

    def _resolve_endpoint_template(
        self,
        resource,
    ) -> str:
        """
        Replace an endpoint path parameter using the verified
        selected_object_id already available in ResourceModel.

        No object identifier is fabricated.
        """

        endpoint = str(
            getattr(
                resource,
                "endpoint",
                "",
            )
            or ""
        ).strip()

        placeholders = (
            self._PATH_PARAMETER_PATTERN.findall(
                endpoint
            )
        )

        if not placeholders:

            return endpoint

        unique_placeholders = set(
            placeholders
        )

        if len(
            unique_placeholders
        ) > 1:

            raise ValueError(
                "Endpoint contains multiple different "
                "path parameters. Automatic substitution "
                "would be ambiguous."
            )

        selected_object_id = getattr(
            resource,
            "selected_object_id",
            None,
        )

        if selected_object_id in (
            None,
            "",
        ):

            raise ValueError(
                "Endpoint contains a path parameter "
                "but no selected_object_id is available."
            )

        encoded_identifier = quote(
            str(
                selected_object_id
            ),
            safe="",
        )

        resolved_endpoint = (
            self._PATH_PARAMETER_PATTERN.sub(
                encoded_identifier,
                endpoint,
            )
        )

        return resolved_endpoint

    # --------------------------------------------------
    # RESOLVE EXECUTION TARGET
    # --------------------------------------------------

    def _resolve_execution_target(
        self,
        context,
        resource,
    ) -> str:
        """
        Resolve the network-visible execution target.

        The canonical source is ``execution_target_url``.

        A ResourceModel ``base_url`` attribute is accepted only
        as an explicit execution alias.

        The method intentionally DOES NOT fall back to:

            authentication_context["target"]
            object_context["target"]

        because those values may represent the host-side URL
        rather than the URL reachable from the Kali execution
        environment.
        """

        execution_target = getattr(
            resource,
            "execution_target_url",
            None,
        )

        if not execution_target:

            execution_target = getattr(
                resource,
                "base_url",
                None,
            )

        context_data = getattr(
            context,
            "data",
            {},
        )

        if (
            not execution_target
            and isinstance(
                context_data,
                dict,
            )
        ):

            execution_target = (
                context_data.get(
                    "execution_target_url"
                )
            )

        execution_target = str(
            execution_target or ""
        ).strip()

        if not execution_target:

            raise ValueError(
                "No execution_target_url is available "
                "for Kali HTTP execution."
            )

        parsed = urlsplit(
            execution_target
        )

        if parsed.scheme not in {
            "http",
            "https",
        }:

            raise ValueError(
                "execution_target_url must use "
                "http:// or https://."
            )

        if not parsed.netloc:

            raise ValueError(
                "execution_target_url must contain "
                "a network host."
            )

        return execution_target.rstrip(
            "/"
        )

    # --------------------------------------------------
    # CONSTRUCT ABSOLUTE URL
    # --------------------------------------------------

    def _construct_absolute_url(
        self,
        execution_target: str,
        endpoint: str,
    ) -> str:
        """
        Combine the execution target with an endpoint path.

        If an absolute URL accidentally reaches this method,
        its original host is discarded and only its path/query
        are retained. This preserves execution-target provenance.
        """

        normalized_endpoint = str(
            endpoint or ""
        ).strip()

        if not normalized_endpoint:

            raise ValueError(
                "Resolved endpoint is empty."
            )

        parsed_endpoint = urlsplit(
            normalized_endpoint
        )

        if (
            parsed_endpoint.scheme
            and parsed_endpoint.netloc
        ):

            normalized_endpoint = (
                parsed_endpoint.path
                or "/"
            )

            if parsed_endpoint.query:

                normalized_endpoint += (
                    "?"
                    + parsed_endpoint.query
                )

        absolute_url = (
            f"{execution_target.rstrip('/')}/"
            f"{normalized_endpoint.lstrip('/')}"
        )

        parsed_url = urlsplit(
            absolute_url
        )

        if (
            parsed_url.scheme
            not in {
                "http",
                "https",
            }
            or not parsed_url.netloc
        ):

            raise ValueError(
                "The generated execution URL "
                "is not absolute."
            )

        return absolute_url

    # --------------------------------------------------
    # CREATE NEW CURL BUILDER
    # --------------------------------------------------

    def _new_curl_builder(
        self,
    ):
        """
        Return a clean CurlBuilder for one request.

        Reusing the same mutable builder between requests caused
        Authorization headers to accumulate. Every request must
        therefore start from fresh state.
        """

        configured_builder = getattr(
            self,
            "_curl_builder",
            None,
        )

        if configured_builder is None:

            raise RuntimeError(
                "CurlBuilder is not configured."
            )

        # Preferred production path.
        if hasattr(
            configured_builder,
            "fresh",
        ):

            fresh_builder = (
                configured_builder.fresh()
            )

            if fresh_builder is None:

                raise RuntimeError(
                    "CurlBuilder.fresh() returned None."
                )

            return fresh_builder

        # Compatibility path for injected test builders.
        try:

            return type(
                configured_builder
            )()

        except TypeError:

            if hasattr(
                configured_builder,
                "reset",
            ):

                configured_builder.reset()

                return configured_builder

            raise RuntimeError(
                "Unable to create a clean "
                "CurlBuilder instance."
            )

    # --------------------------------------------------
    # EXECUTE THROUGH KALI MCP
    # --------------------------------------------------

    def _execute(
        self,
        curl_args: str,
    ):
        """
        Execute curl through KaliMCPTool.

        ``tool`` and ``args`` are intentionally separate.
        """

        return self._kali_tool.execute_json(
            tool="curl",
            args=curl_args,
        )

    # --------------------------------------------------
    # EXTRACT HTTP STATUS
    # --------------------------------------------------

    def _extract_http_status(
        self,
        response,
    ) -> int | None:
        """
        Recover an HTTP status code from structured Kali evidence.
        """

        if not isinstance(
            response,
            dict,
        ):

            return None

        candidate = response.get(
            "http_status"
        )

        if candidate is None:

            candidate = response.get(
                "status_code"
            )

        if isinstance(
            candidate,
            bool,
        ):

            return None

        try:

            status_code = int(
                candidate
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        if not (
            100
            <= status_code
            <= 599
        ):

            return None

        return status_code

    # --------------------------------------------------
    # VALIDATE HTTP RESPONSE
    # --------------------------------------------------

    def _is_valid_http_response(
        self,
        response,
    ) -> bool:
        """
        Return True only when actual HTTP evidence exists.

        Tool invocation success alone is insufficient.

        For example:

            curl process executed
            but DNS failed

        is NOT a completed HTTP request.
        """

        if not isinstance(
            response,
            dict,
        ):

            return False

        if response.get(
            "error"
        ):

            return False

        if response.get(
            "http_parse_success"
        ) is False:

            return False

        status_code = (
            self._extract_http_status(
                response
            )
        )

        if status_code is None:

            return False

        return True


    def _resolve_baseline_mode(
        self,
        context,
    ) -> str:
        """
        Resolve optional baseline handling mode.

        Supported modes:
        - compare: enrich unauthorized evidence with baseline comparison;
        - record: store the current authorized evidence as baseline;
        - off: disable baseline handling for this execution.
        """

        context_data = getattr(
            context,
            "data",
            {},
        )

        if not isinstance(
            context_data,
            dict,
        ):
            return "compare"

        mode = str(
            context_data.get(
                "authorization_baseline_mode",
                "compare",
            )
            or "compare"
        ).strip().lower()

        if mode not in {
            "compare",
            "record",
            "off",
        }:
            return "compare"

        return mode

    # --------------------------------------------------
    # BUILD EXECUTION RESULT
    # --------------------------------------------------

    def _build_execution_result(
        self,
        context,
        resource,
        response,
        request_json_body=None
    ) -> ExecutionResult:
        """
        Convert Kali execution evidence into an ExecutionResult.

        A resource is completed only when a real HTTP response
        was obtained and parsed.
        """

        valid_http_response = (
            self._is_valid_http_response(
                response
            )
        )

        status_code = (
            self._extract_http_status(
                response
            )
        )

        update_values = {
            "completed": (
                valid_http_response
            ),
            "execution_attempts": (
                resource.execution_attempts
                + 1
            ),
        }

        if status_code is not None:

            update_values[
                "status_code"
            ] = status_code

        if valid_http_response:

            message = (
                "HTTP execution completed "
                f"with status {status_code}."
            )

        else:

            message = (
                "HTTP execution did not produce "
                "a valid parseable HTTP response."
            )

        if isinstance(response, dict):
            response = dict(response)

            if request_json_body is not None:
                response["request_json_body"] = request_json_body

        enriched_evidence = AuthorizationEvidenceEnricher().enrich(
            evidence=response,
            expected_secure_behavior=(
                resource.expected_secure_behavior
            ),
        )

        baseline_manager = getattr(
            self,
            "_baseline_manager",
            None,
        )

        baseline_mode = self._resolve_baseline_mode(
            context=context,
        )

        if (
            baseline_manager is not None
            and baseline_mode == "record"
        ):
            enriched_evidence = dict(
                enriched_evidence
            )

            if valid_http_response:
                baseline_key = (
                    baseline_manager
                    .save_authorized_baseline(
                        resource=resource,
                        evidence=enriched_evidence,
                    )
                )

                enriched_evidence["baseline_recorded"] = True
                enriched_evidence["baseline_key"] = baseline_key

            else:
                enriched_evidence["baseline_recorded"] = False
                enriched_evidence["baseline_record_error"] = (
                    "Baseline was not recorded because the execution "
                    "did not produce a valid parseable HTTP response."
                )

        elif (
            baseline_manager is not None
            and baseline_mode == "compare"
        ):
            enriched_evidence = (
                baseline_manager
                .enrich_unauthorized_evidence(
                    resource=resource,
                    unauthorized_evidence=enriched_evidence,
                )
            )

        if baseline_mode != "record":
            promotion_update_values = (
                VulnerabilityPromotionUpdateBuilder()
                .build_update_values(
                    enriched_evidence
                )
            )

            update_values.update(
                promotion_update_values
            )

        return ExecutionResult(
            success=valid_http_response,
            update=ResourceUpdate(
                **update_values
            ),
            evidence=enriched_evidence,
            message=message,
        )

    # --------------------------------------------------
    # BUILD FAILURE RESULT
    # --------------------------------------------------

    def _build_failure_result(
        self,
        resource,
        stage: str,
        error: Exception,
    ) -> ExecutionResult:
        """
        Return a structured non-completed result for request
        construction or external tool failures.
        """

        evidence = {
            "success": False,
            "stage": stage,
            "http_status": None,
            "http_parse_success": False,
            "error": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }

        return ExecutionResult(
            success=False,
            update=ResourceUpdate(
                completed=False,
                execution_attempts=(
                    resource.execution_attempts
                    + 1
                ),
            ),
            evidence=evidence,
            message=(
                "Execution failed before a valid "
                "HTTP response was obtained."
            ),
        )