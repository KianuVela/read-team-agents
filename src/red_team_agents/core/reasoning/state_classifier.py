"""
state_classifier.py

Deterministic finite-state classifier responsible for updating the
execution state of a ResourceModel according to the evidence collected
during the execution phase.

The classifier does not execute attacks, send HTTP requests or invoke
external tools. Its responsibility is limited to interpreting the
current resource context and assigning an appropriate ResourceState.

All state changes are performed through the _transition() method to
ensure traceability and prevent uncontrolled state mutations.
"""

from typing import FrozenSet

from .resource_model import ResourceModel
from .resource_state import ResourceState


class StateClassifier:
    """
    Deterministic finite-state classifier for API resources.

    The classifier evaluates:

    - execution outcomes;
    - HTTP outcomes;
    - authentication context;
    - endpoint availability;
    - object identifier availability;
    - endpoint type;
    - HTTP method;
    - readiness for BOLA or BFLA testing.

    It mutates and returns the supplied ResourceModel.
    """

    _BFLA_METHODS: FrozenSet[str] = frozenset(
        {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }
    )

    _TERMINAL_STATES: FrozenSet[ResourceState] = frozenset(
        {
            ResourceState.VULNERABLE,
            ResourceState.NOT_VULNERABLE,
            ResourceState.COMPLETED,
            ResourceState.EXHAUSTED,
        }
    )

    def classify(self, resource: ResourceModel) -> ResourceModel:
        """
        Classify the current state of an API resource.

        Classification is deterministic: identical ResourceModel values
        produce the same resulting state.

        Args:
            resource: Resource model containing the currently available
                execution context and evidence.

        Returns:
            The same ResourceModel instance after its state and execution
            flags have been updated.

        Raises:
            TypeError: If resource is not a ResourceModel instance.
        """

        if not isinstance(resource, ResourceModel):
            raise TypeError(
                "StateClassifier.classify() expects a ResourceModel "
                f"instance, received {type(resource).__name__}."
            )

        # Resources in final states must not be automatically reclassified.
        if resource.state in self._TERMINAL_STATES:
            resource.executable = False
            return resource

        # Every new classification cycle recalculates executability.
        resource.executable = False

        # Normalise the basic resource information.
        resource.endpoint = self._normalise_endpoint(resource.endpoint)
        resource.method = self._normalise_method(resource.method)

        # --------------------------------------------------------------
        # Phase 1: execution evidence and final outcomes
        # --------------------------------------------------------------

        if self._classify_execution_outcome(resource):
            return resource

        # --------------------------------------------------------------
        # Phase 2: transport and HTTP failure conditions
        # --------------------------------------------------------------

        if self._classify_transport_or_http_failure(resource):
            return resource

        # --------------------------------------------------------------
        # Phase 3: endpoint validation
        # --------------------------------------------------------------

        if not resource.endpoint:
            self._transition(
                resource,
                ResourceState.RESOURCE_NOT_FOUND,
                reason="The API endpoint is empty or unavailable.",
            )
            return resource

        # --------------------------------------------------------------
        # Phase 4: authentication validation
        # --------------------------------------------------------------

        if not resource.authenticated:
            self._transition(
                resource,
                ResourceState.AUTH_REQUIRED,
                reason="The resource does not have an authenticated actor.",
            )
            return resource

        if not resource.jwt_token or not resource.jwt_token.strip():
            self._transition(
                resource,
                ResourceState.INVALID_TOKEN,
                reason=(
                    "The actor is marked as authenticated, but no valid "
                    "JWT token is available."
                ),
            )
            return resource

        self._transition(
            resource,
            ResourceState.AUTHENTICATED,
            reason="An authenticated actor and JWT token are available.",
        )

        # --------------------------------------------------------------
        # Phase 5: endpoint characterisation
        # --------------------------------------------------------------

        is_detail_endpoint = self._is_detail_endpoint(resource.endpoint)

        if is_detail_endpoint:
            self._transition(
                resource,
                ResourceState.DETAIL_ENDPOINT,
                reason=(
                    "The endpoint contains a path parameter that represents "
                    "an individual API resource."
                ),
            )
        else:
            self._transition(
                resource,
                ResourceState.RESOURCE_DISCOVERED,
                reason="The API resource endpoint is available.",
            )

        # --------------------------------------------------------------
        # Phase 6: HTTP method-specific reasoning
        # --------------------------------------------------------------

        if resource.test_type == "BOLA":

            return self._classify_bola(
                resource=resource,
                is_detail_endpoint=is_detail_endpoint,
            )

        if resource.test_type == "BFLA":

            return self._classify_bfla(
                resource=resource,
                is_detail_endpoint=is_detail_endpoint,
            )

        # Fallback (compatibilidade)
        if resource.method == "GET":

            return self._classify_get_resource(
                resource=resource,
                is_detail_endpoint=is_detail_endpoint,
            )

        if resource.method in self._BFLA_METHODS:

            return self._classify_mutating_resource(
                resource=resource,
                is_detail_endpoint=is_detail_endpoint,
            )

        # --------------------------------------------------------------
        # Phase 7: unsupported or observational method
        # --------------------------------------------------------------

        self._transition(
            resource,
            ResourceState.OBSERVED,
            reason=(
                f"HTTP method '{resource.method or 'UNKNOWN'}' is not "
                "currently mapped to a BOLA or BFLA execution strategy."
            ),
        )

        return resource


    def _classify_bola(
        self,
        resource: ResourceModel,
        is_detail_endpoint: bool,
    ) -> ResourceModel:

        if resource.test_type == "BOLA":
            is_detail_endpoint = True

        return self._classify_get_resource(
            resource=resource,
            is_detail_endpoint=is_detail_endpoint,
        )
        

    def _classify_bfla(
        self,
        resource: ResourceModel,
        is_detail_endpoint: bool,
    ) -> ResourceModel:

        return self._classify_mutating_resource(
            resource,
            is_detail_endpoint,
        )


    

    def _classify_get_resource(
        self,
        resource: ResourceModel,
        is_detail_endpoint: bool,
    ) -> ResourceModel:
        """
        Classify a GET resource.

        A detail endpoint with an available object identifier can be
        prepared for BOLA testing. A collection endpoint is treated as an
        object-discovery source rather than immediately as a BOLA target.
        """

        self._normalise_object_ids(resource)

        if not resource.object_ids:
            if is_detail_endpoint:
                self._transition(
                    resource,
                    ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER,
                    reason=(
                        "The detail endpoint requires an object identifier, "
                        "but no identifier has been discovered."
                    ),
                )
            else:
                self._transition(
                    resource,
                    ResourceState.EMPTY_COLLECTION,
                    reason=(
                        "No object identifiers were discovered from the "
                        "collection endpoint."
                    ),
                )

            return resource

        self._transition(
            resource,
            ResourceState.IDENTIFIERS_DISCOVERED,
            reason=(
                f"{len(resource.object_ids)} unique object identifier(s) "
                "are available."
            ),
        )

        self._select_object_identifier(resource)

        if not is_detail_endpoint:
            self._transition(
                resource,
                ResourceState.OBSERVED,
                reason=(
                    "The GET endpoint is a collection endpoint. It can be "
                    "used for object discovery but is not directly marked "
                    "as a detail-level BOLA target."
                ),
            )
            return resource

        if resource.selected_object_id is None:
            self._transition(
                resource,
                ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER,
                reason=(
                    "The endpoint is a detail endpoint, but no object "
                    "identifier could be selected."
                ),
            )
            return resource

        resource.executable = True

        self._transition(
            resource,
            ResourceState.READY_FOR_BOLA,
            reason=(
                "The authenticated GET detail endpoint has a selected "
                "object identifier and is ready for BOLA testing."
            ),
        )

        return resource

    def _classify_mutating_resource(
        self,
        resource: ResourceModel,
        is_detail_endpoint: bool,
    ) -> ResourceModel:
        """
        Classify POST, PUT, PATCH and DELETE resources for BFLA testing.

        POST collection endpoints normally do not require an existing
        object identifier. Detail-level PUT, PATCH or DELETE endpoints
        generally require one.
        """

        self._normalise_object_ids(resource)

        requires_identifier = (
            is_detail_endpoint
            and resource.method in {"PUT", "PATCH", "DELETE"}
        )

        if requires_identifier and not resource.object_ids:
            self._transition(
                resource,
                ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER,
                reason=(
                    f"The {resource.method} detail endpoint requires an "
                    "object identifier, but none has been discovered."
                ),
            )
            return resource

        if resource.object_ids:
            self._transition(
                resource,
                ResourceState.IDENTIFIERS_DISCOVERED,
                reason=(
                    f"{len(resource.object_ids)} unique object identifier(s) "
                    "are available."
                ),
            )
            self._select_object_identifier(resource)

        if requires_identifier and resource.selected_object_id is None:
            self._transition(
                resource,
                ResourceState.DETAIL_ENDPOINT_WITHOUT_IDENTIFIER,
                reason=(
                    "No object identifier could be selected for the "
                    "detail-level operation."
                ),
            )
            return resource

        resource.executable = True

        self._transition(
            resource,
            ResourceState.READY_FOR_BFLA,
            reason=(
                f"The authenticated {resource.method} endpoint is ready "
                "for BFLA testing."
            ),
        )

        return resource

    def _classify_execution_outcome(
        self,
        resource: ResourceModel,
    ) -> bool:
        """
        Classify explicit execution results.

        Returns:
            True when the resource reached an outcome that should stop the
            current classification cycle; otherwise False.
        """

        if resource.vulnerable is True:
            resource.executable = False

            self._transition(
                resource,
                ResourceState.VULNERABLE,
                reason=(
                    "Execution evidence indicates that the tested resource "
                    "is vulnerable."
                ),
            )
            return True

        if resource.vulnerable is False:
            resource.executable = False

            self._transition(
                resource,
                ResourceState.NOT_VULNERABLE,
                reason=(
                    "Execution evidence indicates that the tested resource "
                    "is not vulnerable."
                ),
            )
            return True

        if self._evidence_flag(resource, "completed"):
            resource.executable = False

            self._transition(
                resource,
                ResourceState.COMPLETED,
                reason="The resource execution workflow is complete.",
            )
            return True

        if self._evidence_flag(resource, "exhausted"):
            resource.executable = False

            self._transition(
                resource,
                ResourceState.EXHAUSTED,
                reason=(
                    "The configured execution attempts or candidate "
                    "identifiers have been exhausted."
                ),
            )
            return True

        if self._evidence_flag(resource, "executing"):
            resource.executable = False

            self._transition(
                resource,
                ResourceState.EXECUTING,
                reason="A security test is currently being executed.",
            )
            return True

        return False

    def _classify_transport_or_http_failure(
        self,
        resource: ResourceModel,
    ) -> bool:
        """
        Classify timeout, rate-limit and relevant HTTP response conditions.

        Returns:
            True when a failure state was assigned; otherwise False.
        """

        if self._evidence_flag(resource, "timeout"):
            self._transition(
                resource,
                ResourceState.TIMEOUT,
                reason="The HTTP request exceeded the configured timeout.",
            )
            return True

        status_code = resource.status_code

        if status_code is None:
            return False

        if status_code == 401:
            self._transition(
                resource,
                ResourceState.INVALID_TOKEN,
                reason="The API returned HTTP 401 Unauthorized.",
            )
            return True

        if status_code == 403:
            self._transition(
                resource,
                ResourceState.FORBIDDEN,
                reason="The API returned HTTP 403 Forbidden.",
            )
            return True

        if status_code == 404:
            self._transition(
                resource,
                ResourceState.RESOURCE_NOT_FOUND,
                reason="The API returned HTTP 404 Not Found.",
            )
            return True

        if status_code == 429:
            self._transition(
                resource,
                ResourceState.RATE_LIMITED,
                reason="The API returned HTTP 429 Too Many Requests.",
            )
            return True

        if 500 <= status_code <= 599:
            self._transition(
                resource,
                ResourceState.SERVER_FAILURE,
                reason=f"The API returned server error HTTP {status_code}.",
            )
            return True

        return False

    def _transition(
        self,
        resource: ResourceModel,
        new_state: ResourceState,
        reason: str,
    ) -> None:
        """
        Apply and record a state transition.

        Every state mutation performed by the classifier passes through
        this method. Repeated transitions to the same state are not added
        twice to state_history.

        A structured transition record is also stored under:

            resource.evidence["state_transitions"]

        Args:
            resource: Resource being updated.
            new_state: State to assign.
            reason: Human-readable explanation for the transition.
        """

        previous_state = resource.state

        if previous_state == new_state:
            return

        resource.state = new_state

        if not resource.state_history:
            resource.state_history.append(previous_state)

        if resource.state_history[-1] != new_state:
            resource.state_history.append(new_state)

        transitions = resource.evidence.setdefault(
            "state_transitions",
            [],
        )

        transitions.append(
            {
                "from": previous_state.name,
                "to": new_state.name,
                "reason": reason,
            }
        )

    @staticmethod
    def _normalise_endpoint(endpoint: str) -> str:
        """
        Return a trimmed endpoint string.
        """

        if not isinstance(endpoint, str):
            return ""

        return endpoint.strip()

    @staticmethod
    def _normalise_method(method: str) -> str:
        """
        Return an uppercase and trimmed HTTP method.
        """

        if not isinstance(method, str):
            return ""

        return method.strip().upper()

    @staticmethod
    def _is_detail_endpoint(endpoint: str) -> bool:
        """
        Determine whether an endpoint contains a path parameter.

        Examples:

            /identity/api/v2/vehicle/{vehicleId}
            /users/{id}
        """

        return "{" in endpoint and "}" in endpoint

    @staticmethod
    def _evidence_flag(
        resource: ResourceModel,
        key: str,
    ) -> bool:
        """
        Read a Boolean execution flag from structured evidence.
        """

        return resource.evidence.get(key) is True

    @staticmethod
    def _normalise_object_ids(resource: ResourceModel) -> None:
        """
        Remove empty and duplicate object identifiers while preserving order.
        """

        normalised_ids = []
        observed_ids = set()

        for object_id in resource.object_ids:
            if object_id is None:
                continue

            value = str(object_id).strip()

            if not value or value in observed_ids:
                continue

            observed_ids.add(value)
            normalised_ids.append(value)

        resource.object_ids = normalised_ids

        if (
            resource.selected_object_id is not None
            and str(resource.selected_object_id).strip()
            not in observed_ids
        ):
            resource.selected_object_id = None

    @staticmethod
    def _select_object_identifier(resource: ResourceModel) -> None:
        """
        Select the first available object identifier when none is selected.
        """

        if resource.selected_object_id is not None:
            resource.selected_object_id = str(
                resource.selected_object_id
            ).strip()
            return

        if resource.object_ids:
            resource.selected_object_id = resource.object_ids[0]