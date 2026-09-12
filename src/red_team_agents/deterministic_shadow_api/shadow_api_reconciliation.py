import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# PRECISAMOS SERIALIZAR O RESULTADO PARA JSON
# DEPOIS DESSA IMPORTAÇÃO, VEM O MÉTODO reconciliation_to_dict
from dataclasses import asdict


@dataclass
class CanonicalEndpoint:
    """
    Canonical representation of an API endpoint.

    Both active discovery findings and OpenAPI findings
    must eventually be converted into this representation
    before deterministic reconciliation.
    """

    source: str
    host: Optional[str]
    base_path: Optional[str]
    version: Optional[str]

    path: str
    method: str

    auth_required: Optional[bool] = None

    parameters: List[str] = field(default_factory=list)

    discovered_as: Optional[str] = None

    evidence: Dict[str, Any] = field(default_factory=dict)

    metadata: Dict[str, Any] = field(default_factory=dict)


VERSION_PATTERN = re.compile(
    r"^v\d+(?:\.\d+)*$",
    re.IGNORECASE,
)


ANGLE_PARAMETER_PATTERN = re.compile(r"<([^/<>]+)>")


# ======================================================
# CRIAMOS ESSE MÉTODO DEPOIS DE ADICIONAR O REGEX ANGLE_PARAMETER...
# ====================================================================
def normalize_template_placeholders(path: str) -> str:
    """
    Normalize runtime template placeholders to OpenAPI-style placeholders.

    Example:
        /orders/<orderId>
        ->
        /orders/{orderId}
    """
    if not path:
        return path

    return ANGLE_PARAMETER_PATTERN.sub(
        lambda match: "{" + match.group(1) + "}",
        path,
    )


# ======================================================================
# ADAPTERS
# ======================================================================
def active_to_canonical(data: Dict[str, Any]) -> List[CanonicalEndpoint]:
        """
        Convert the structured output produced by
        agent_attack_surface_discovery into CanonicalEndpoint objects.

        This function does NOT normalize paths and does NOT perform
        Shadow API detection. It only adapts the raw discovery artifact
        into the canonical internal representation.
        """

        canonical_endpoints: List[CanonicalEndpoint] = []

        target = data.get("target", {})

        # Prefer the resolved host because this represents
        # the actual host reached during active discovery.
        host = (
            target.get("resolved_host")
            or target.get("host")
        )

        discovered_endpoints = data.get("discovered_endpoints", [])

        for endpoint in discovered_endpoints:

            path = endpoint.get("path")
            method = endpoint.get("method")

            # A canonical endpoint needs at least a path and HTTP method.
            if not path or not method:
                continue

            canonical = CanonicalEndpoint(
                source="active_discovery",

                host=host,

                # At this stage api_root is preserved exactly as reported.
                base_path=endpoint.get("api_root"),

                version=endpoint.get("version"),

                # IMPORTANT:
                # Preserve the raw observed path.
                # Normalization will happen later.
                path=path,

                method=method.upper(),

                auth_required=endpoint.get("auth_observed"),

                parameters=[],

                discovered_as=path,

                evidence={
                    "status_code": endpoint.get("status_code"),
                    "source_tool": endpoint.get("source_tool"),
                    "content_type": endpoint.get("content_type"),
                    "redirect_location": endpoint.get("redirect_location"),
                    "raw_evidence": endpoint.get("evidence", {}),
                },

                metadata={
                    "discovery_type": endpoint.get("discovery_type"),
                    "api_related": endpoint.get("api_related"),
                },
            )

            canonical_endpoints.append(canonical)

        return canonical_endpoints


def openapi_to_canonical(data: Dict[str, Any]) -> List[CanonicalEndpoint]:
    """
    Convert the structured OpenAPI inventory produced by
    OpenAPIDiscoveryTool into CanonicalEndpoint objects.

    This function does NOT perform path normalization,
    version extraction, host reconciliation, or Shadow API detection.
    """

    canonical_endpoints: List[CanonicalEndpoint] = []

    endpoints = data.get("endpoints", [])
    servers = data.get("servers", [])

    for endpoint in endpoints:

        path = endpoint.get("path")
        method = endpoint.get("method")

        if not path or not method:
            continue

        security = endpoint.get("security")

        # OpenAPI security=[] means that this operation does not
        # declare an authentication requirement.
        if security is None:
            # Security requirement not explicitly available.
            auth_required = None

        elif security == []:
            # Explicitly no authentication required.
            auth_required = False

        elif any(requirement == {} for requirement in security):
            # An empty security requirement allows anonymous access.
            auth_required = False

        else:
            # One or more concrete security schemes are required.
            auth_required = True

        canonical = CanonicalEndpoint(
            source="openapi",

            # Host binding will be handled later by the deterministic
            # target reconciliation layer.
            host=None,

            # Do not derive these yet.
            # The Normalizer will extract them deterministically.
            base_path=None,
            version=None,

            # Preserve the OpenAPI path exactly as documented.
            path=path,

            method=method.upper(),

            auth_required=auth_required,

            parameters=endpoint.get("path_parameters", []),

            discovered_as=path,

            evidence={
                "operation_id": endpoint.get("operationId"),
                "summary": endpoint.get("summary"),
                "response_codes": endpoint.get("response_codes", []),
                "security": security,
            },

            metadata={
                "resource_type": endpoint.get("resource_type"),
                "tags": endpoint.get("tags", []),
                "parameter_details": endpoint.get(
                    "parameter_details", []
                ),
                "has_request_body": endpoint.get(
                    "has_request_body"
                ),
                "servers": servers,
                "spec_title": data.get("title"),
                "spec_version": data.get("version"),
            },
        )

        canonical_endpoints.append(canonical)

    return canonical_endpoints



# =====================================================
# DETERMINISTIC NORMALIZER
# =====================================================

def normalize_path(path: str) -> str:
    """
    Apply safe syntactic normalization to an API path.

    This function does NOT replace concrete IDs with placeholders yet.
    """

    if not path:
        return "/"

    path = path.strip()

    # Ensure leading slash.
    if not path.startswith("/"):
        path = "/" + path

    # Collapse repeated slashes.
    path = re.sub(r"/+", "/", path)

    # Remove trailing slash except for root.
    if len(path) > 1:
        path = path.rstrip("/")

    return path


def extract_api_version(path: str) -> Optional[str]:
    """
    Extract an explicit API version segment such as:
    v2
    v3
    v2.7
    v4.0

    Returns None if no explicit version segment exists.
    """

    normalized = normalize_path(path)

    segments = [
        segment
        for segment in normalized.split("/")
        if segment
    ]

    for segment in segments:
        if VERSION_PATTERN.match(segment):
            return segment.lower()

    return None


# ================================================================
# todos os testes passaram, então podemos considerar normalize_path() 
# e extract_api_version() validados e avançar para normalizar um 
# CanonicalEndpoint inteiro.
#=======================================

def normalize_endpoint(endpoint: CanonicalEndpoint) -> CanonicalEndpoint:
    """
    Normalize a CanonicalEndpoint deterministically while preserving
    the original observed/documented path in discovered_as.
    """

    normalized_path = normalize_path(endpoint.path)
    detected_version = extract_api_version(normalized_path)

    return CanonicalEndpoint(
        source=endpoint.source,
        host=endpoint.host,
        base_path=endpoint.base_path,
        version=detected_version,
        path=normalized_path,
        method=endpoint.method.upper().strip(),
        auth_required=endpoint.auth_required,
        parameters=list(endpoint.parameters),
        discovered_as=endpoint.discovered_as,
        evidence=dict(endpoint.evidence),
        metadata=dict(endpoint.metadata),
    )


def normalize_endpoints(
    endpoints: List[CanonicalEndpoint],
) -> List[CanonicalEndpoint]:
    """
    Normalize a collection of canonical endpoints.
    """

    return [
        normalize_endpoint(endpoint)
        for endpoint in endpoints
    ]

# FECHAMOS A NORMALIZAÇÃO SEGURA...

# ===========================================
# AGORA AVANÇAMOS PARA A PARTE CRITICA: ETERMINISTIC PATH-TEMPLATE MATCHING
# ======================================================
PATH_PARAMETER_PATTERN = re.compile(r"\{[^/{}]+\}")


def path_template_to_regex(template: str) -> re.Pattern:
    """
    Convert an OpenAPI path template into a deterministic regex.

    Example:
    /workshop/api/shop/orders/{order_id}

    becomes a pattern capable of matching:
    /workshop/api/shop/orders/25
    """

    normalized_template = normalize_path(template)

    parts = PATH_PARAMETER_PATTERN.split(normalized_template)
    parameters = PATH_PARAMETER_PATTERN.findall(normalized_template)

    regex_parts = []

    for index, part in enumerate(parts):
        regex_parts.append(re.escape(part))

        if index < len(parameters):
            # A path parameter must occupy exactly one path segment.
            regex_parts.append(r"[^/]+")

    regex = "^" + "".join(regex_parts) + "$"

    return re.compile(regex)


def path_matches_template(
    observed_path: str,
    documented_template: str,
) -> bool:
    """
    Determine whether an observed concrete path matches
    an OpenAPI path template.
    """

    observed = normalize_path(observed_path)
    template_regex = path_template_to_regex(documented_template)

    return bool(template_regex.fullmatch(observed))

# =======================================================
# AGORA VAMOS CRIAR O PRIMEIRO COMPONENTE REAL DE MATCHING DA RECONCIALIAÇÃO
# =========================================================
def match_documented_endpoint(
    observed: CanonicalEndpoint,
    documented_endpoints: List[CanonicalEndpoint],
) -> Optional[CanonicalEndpoint]:
    """
    Find the best documented OpenAPI endpoint corresponding
    to an observed endpoint.

    Matching priority:
    1. Exact normalized path + HTTP method
    2. Template path + HTTP method
    3. No match

    HTTP method is intentionally part of the match.
    Shadow operations will be handled separately later.
    """

    observed_path = normalize_path(observed.path)
    observed_method = observed.method.upper().strip()

    # ---------------------------------------------------------
    # 1. EXACT PATH + METHOD
    # ---------------------------------------------------------
    for documented in documented_endpoints:

        documented_path = normalize_path(documented.path)
        documented_method = documented.method.upper().strip()

        if (
            observed_path == documented_path
            and observed_method == documented_method
        ):
            return documented

    # ---------------------------------------------------------
    # 2. TEMPLATE PATH + METHOD
    # ---------------------------------------------------------
    for documented in documented_endpoints:

        documented_method = documented.method.upper().strip()

        if observed_method != documented_method:
            continue

        if path_matches_template(
            observed_path,
            documented.path,
        ):
            return documented

    # ---------------------------------------------------------
    # 3. NO MATCH
    # ---------------------------------------------------------
    return None


# ========================================================
# O MATCHING DOCUMENTADO ESTÁ VALIDADO E JÁ TEMOS A PRIORIDADE CERTA ENTRE EXACT MATCH,
# TEMPLATE MATCH E AUSÊNCIA DE CORRESPÔNDÊNCIAA; AGORA VAMOS FINALMENTE DISTINGUIR 
# SHADOW ENDPOINT DE SHADOW OPERATION.
# =============================================================
def find_documented_path_matches(
    observed: CanonicalEndpoint,
    documented_endpoints: List[CanonicalEndpoint],
) -> List[CanonicalEndpoint]:
    """
    Find documented endpoints whose path corresponds to the observed path,
    regardless of HTTP method.

    Matching priority:
    1. Exact normalized path
    2. Template path
    """

    observed_path = normalize_path(observed.path)

    exact_matches: List[CanonicalEndpoint] = []
    template_matches: List[CanonicalEndpoint] = []

    # ---------------------------------------------------------
    # 1. EXACT PATH MATCHES
    # ---------------------------------------------------------
    for documented in documented_endpoints:
        documented_path = normalize_path(documented.path)

        if observed_path == documented_path:
            exact_matches.append(documented)

    if exact_matches:
        return exact_matches

    # ---------------------------------------------------------
    # 2. TEMPLATE PATH MATCHES
    # ---------------------------------------------------------
    for documented in documented_endpoints:

        if path_matches_template(
            observed_path,
            documented.path,
        ):
            template_matches.append(documented)

    return template_matches

# ==========================================================
# VAMOS ACRESCENTAR AGORA A PRIMEIRA FUNÇÃO DE CLASSIFICAÇÃO
# ========================================================
def classify_observed_endpoint(
    observed: CanonicalEndpoint,
    documented_endpoints: List[CanonicalEndpoint],
) -> str:
    """
    Deterministically classify an observed API operation.

    Returns:
    - documented
    - shadow_operation
    - shadow_endpoint
    """

    # ---------------------------------------------------------
    # 1. PATH + METHOD DOCUMENTED
    # ---------------------------------------------------------
    documented_match = match_documented_endpoint(
        observed,
        documented_endpoints,
    )

    if documented_match is not None:
        return "documented"

    # ---------------------------------------------------------
    # 2. PATH EXISTS, BUT METHOD DOES NOT
    # ---------------------------------------------------------
    path_matches = find_documented_path_matches(
        observed,
        documented_endpoints,
    )

    if path_matches:
        return "shadow_operation"

    # ---------------------------------------------------------
    # 3. PATH ITSELF IS NOT DOCUMENTED
    # ---------------------------------------------------------
    return "shadow_endpoint"

#=========================================================================
# o núcleo classificatório está validado: documented, shadow_operation e shadow_endpoint 
# já estão a ser distinguidos deterministicamente como queríamos.
#
# Agora fazemos o passo seguinte: em vez de devolver apenas uma string, vamos criar um resultado estruturado e auditável.
#============================================================================
@dataclass
class ReconciliationResult:
    observed: CanonicalEndpoint
    classification: str
    rule: str

    documented_match: Optional[CanonicalEndpoint] = None
    documented_path_matches: List[CanonicalEndpoint] = field(
        default_factory=list
    )

    evidence: Dict[str, Any] = field(default_factory=dict)


def reconcile_observed_endpoint(
    observed: CanonicalEndpoint,
    documented_endpoints: List[CanonicalEndpoint],
) -> ReconciliationResult:
    """
    Reconcile one observed endpoint against the documented OpenAPI inventory.
    """

    documented_match = match_documented_endpoint(
        observed,
        documented_endpoints,
    )

    # ---------------------------------------------------------
    # DOCUMENTED
    # ---------------------------------------------------------
    if documented_match is not None:
        return ReconciliationResult(
            observed=observed,
            classification="documented",
            rule="PATH_AND_METHOD_DOCUMENTED",
            documented_match=documented_match,
            evidence={
                "observed_path": observed.path,
                "observed_method": observed.method,
                "documented_path": documented_match.path,
                "documented_method": documented_match.method,
            },
        )

    path_matches = find_documented_path_matches(
        observed,
        documented_endpoints,
    )

    # ---------------------------------------------------------
    # SHADOW OPERATION
    # ---------------------------------------------------------
    if path_matches:
        return ReconciliationResult(
            observed=observed,
            classification="shadow_operation",
            rule="PATH_DOCUMENTED_METHOD_UNDOCUMENTED",
            documented_path_matches=path_matches,
            evidence={
                "observed_path": observed.path,
                "observed_method": observed.method,
                "documented_methods": [
                    endpoint.method
                    for endpoint in path_matches
                ],
            },
        )

    # ---------------------------------------------------------
    # SHADOW ENDPOINT
    # ---------------------------------------------------------
    return ReconciliationResult(
        observed=observed,
        classification="shadow_endpoint",
        rule="PATH_NOT_DOCUMENTED",
        evidence={
            "observed_path": observed.path,
            "observed_method": observed.method,
        },
    )


# antes do reconcile_all() vamos corrigir uma questão arquitetural essencial: um recurso descoberto 
# não é automaticamente uma operação API candidata a Shadow API
# Se reconciliássemos agora os 10 findings reais, isto aconteceria:

# GET /identity/     → shadow_endpoint ❌
# GET /community/    → shadow_endpoint ❌
# GET /health        → shadow_endpoint ❌
# GET /robots.txt    → shadow_endpoint ❌

# O motor estaria correto matematicamente, mas semanticamente errado, porque esses recursos não representam
#  necessariamente operações REST. Portanto, vamos criar uma Deterministic Eligibility Gate.

# VAMOS ADICIONAR:

def extract_documented_api_prefixes(
    documented_endpoints: List[CanonicalEndpoint],
) -> List[str]:
    """
    Extract deterministic API namespace prefixes from documented paths.

    Examples:
    /identity/api/v2/user/dashboard -> /identity/api
    /community/api/v2/...           -> /community/api
    /workshop/api/shop/...          -> /workshop/api
    """

    prefixes = set()

    for endpoint in documented_endpoints:

        normalized_path = normalize_path(endpoint.path)

        segments = [
            segment
            for segment in normalized_path.split("/")
            if segment
        ]

        for index, segment in enumerate(segments):

            if segment.lower() == "api":

                prefix = "/" + "/".join(
                    segments[: index + 1]
                )

                prefixes.add(prefix)
                break

    return sorted(prefixes)


def is_reconciliation_candidate(
    observed: CanonicalEndpoint,
    documented_endpoints: List[CanonicalEndpoint],
) -> tuple[bool, str]:
    """
    Determine whether an observed resource is eligible for
    Shadow API reconciliation.

    Returns:
        (eligible, eligibility_rule)
    """

    # ---------------------------------------------------------
    # 1. Already corresponds to a documented operation
    # ---------------------------------------------------------
    if match_documented_endpoint(
        observed,
        documented_endpoints,
    ):
        return True, "DOCUMENTED_OPERATION_MATCH"

    # ---------------------------------------------------------
    # 2. Path exists in documentation regardless of method
    # ---------------------------------------------------------
    if find_documented_path_matches(
        observed,
        documented_endpoints,
    ):
        return True, "DOCUMENTED_PATH_MATCH"

    # ---------------------------------------------------------
    # 3. Observed resource is inside a documented API namespace
    # ---------------------------------------------------------
    prefixes = extract_documented_api_prefixes(
        documented_endpoints
    )

    observed_path = normalize_path(observed.path)

    for prefix in prefixes:

        if (
            observed_path == prefix
            or observed_path.startswith(prefix + "/")
        ):
            return True, "DOCUMENTED_API_NAMESPACE"

    # ---------------------------------------------------------
    # 4. Response provides deterministic JSON evidence
    # ---------------------------------------------------------
    content_type = str(
        observed.evidence.get("content_type") or ""
    ).lower()

    if "json" in content_type:
        return True, "JSON_RESPONSE"

    # ---------------------------------------------------------
    # 5. Not sufficiently supported as an API operation
    # ---------------------------------------------------------
    return False, "NOT_API_OPERATION_CANDIDATE"


# =================================================================
# a Eligibility Gate está validada, então agora podemos finalmente montar o reconcile_all() 
# sem transformar roots, health checks ou recursos estáticos em falsos Shadow APIs.
def reconcile_all(
    observed_endpoints: List[CanonicalEndpoint],
    documented_endpoints: List[CanonicalEndpoint],
) -> Dict[str, Any]:
    """
    Reconcile all observed endpoints against the documented OpenAPI inventory.

    Only endpoints that pass the deterministic eligibility gate are
    submitted to Shadow API classification.
    """

    normalized_observed = normalize_endpoints(observed_endpoints)
    normalized_documented = normalize_endpoints(documented_endpoints)

    results: List[ReconciliationResult] = []
    excluded: List[Dict[str, Any]] = []

    for observed in normalized_observed:

        eligible, eligibility_rule = is_reconciliation_candidate(
            observed,
            normalized_documented,
        )

        if not eligible:
            excluded.append(
                {
                    "path": observed.path,
                    "method": observed.method,
                    "source": observed.source,
                    "eligibility_rule": eligibility_rule,
                    "evidence": observed.evidence,
                }
            )
            continue

        result = reconcile_observed_endpoint(
            observed,
            normalized_documented,
        )

        result.evidence["eligibility_rule"] = eligibility_rule

        results.append(result)

    summary = {
        "observed_total": len(normalized_observed),
        "documented_total": len(normalized_documented),
        "eligible_total": len(results),
        "excluded_total": len(excluded),
        "documented_count": sum(
            1 for result in results
            if result.classification == "documented"
        ),
        "shadow_operation_count": sum(
            1 for result in results
            if result.classification == "shadow_operation"
        ),
        "shadow_endpoint_count": sum(
            1 for result in results
            if result.classification == "shadow_endpoint"
        ),
    }

    return {
        "summary": summary,
        "results": results,
        "excluded": excluded,
    }


# =====================================================
# DEPOIS DA IMPORTAÇÃO DO asdict
def reconciliation_to_dict(
    reconciliation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Convert reconciliation results into a JSON-serializable dictionary.
    """

    return {
        "summary": reconciliation["summary"],
        "results": [
            asdict(result)
            for result in reconciliation["results"]
        ],
        "excluded": reconciliation["excluded"],
    }


# ===================================================
# CRIAÇAÕ DE UM ADAPTER DETERMINISTICO PARA observed_api_operations.json
#   COM UMA REGRA RIGIDA: namespace/root não é operação concreta
# ===========================================================
def api_operations_to_canonical(
    data: Dict[str, Any]
) -> List[CanonicalEndpoint]:
    """
    Convert independently observed API operations into CanonicalEndpoint objects.

    Only concrete API operations are admitted.
    Namespace/root probes are excluded deterministically.
    """

    canonical_endpoints: List[CanonicalEndpoint] = []

    target = data.get("target", {})

    host = (
        target.get("resolved_host")
        or target.get("host")
    )

    observed_operations = data.get(
        "observed_api_operations",
        []
    )

    for operation in observed_operations:

        path = operation.get("path")
        method = operation.get("method")
        namespace = operation.get("api_namespace")

        if not path or not method:
            continue

        normalized_path = normalize_path(path)

        normalized_namespace = (
            normalize_path(namespace)
            if namespace
            else None
        )

        # Deterministic admission rule:
        # a namespace/root probe is NOT a concrete API operation.
        if (
            normalized_namespace
            and normalized_path == normalized_namespace
        ):
            continue

        canonical = CanonicalEndpoint(
            source="active_api_discovery",
            host=host,
            base_path=namespace,
            version=operation.get("version"),
            path=path,
            method=method.upper(),
            auth_required=(
                True
                if operation.get("auth_observed")
                else None
            ),
            parameters=[],
            discovered_as=path,
            evidence={
                "status_code": operation.get(
                    "status_code"
                ),
                "content_type": operation.get(
                    "content_type"
                ),
                "source_tool": operation.get(
                    "source_tool"
                ),
                "discovery_method": operation.get(
                    "discovery_method"
                ),
                "redirect_location": operation.get(
                    "redirect_location"
                ),
                "auth_observed": operation.get(
                    "auth_observed"
                ),
                "raw_evidence": operation.get(
                    "evidence",
                    {}
                ),
            },
            metadata={
                "api_namespace": namespace,
            },
        )

        canonical_endpoints.append(
            canonical
        )

    return canonical_endpoints



def runtime_probe_results_to_canonical(
    data: Dict[str, Any]
) -> List[CanonicalEndpoint]:
    """
    Convert runtime-confirmed API operations into CanonicalEndpoint objects.

    Only operations supported by deterministic runtime differential
    evidence are admitted for Shadow API reconciliation.

    Inconclusive middleware responses and execution errors are excluded.
    """

    canonical_endpoints: List[CanonicalEndpoint] = []

    results = data.get("results", [])

    target = data.get("target", {})
    host = (
        target.get("resolved_host")
        or target.get("host")
        or data.get("target_host")
        or data.get("base_url")
    )

    for result in results:

        # Only runtime-confirmed operations enter reconciliation.
        if (
            result.get("classification")
            != "RUNTIME_DIFFERENTIAL_EVIDENCE"
        ):
            continue

        method = result.get("method")

        # Prefer the actual probed path when available.
        path = (
            result.get("observed_path")
            or result.get("request_path")
            or result.get("template_path")
        )

        if not path or not method:
            continue

        normalized_path = normalize_path(
            normalize_template_placeholders(path)
        )

        canonical = CanonicalEndpoint(
            source="runtime_probe",
            host=host,
            base_path=None,
            version=extract_api_version(normalized_path),
            path=normalized_path,
            method=method.upper().strip(),
            auth_required=None,
            parameters=[],
            discovered_as=result.get("template_path"),
            evidence={
                "runtime_classification": result.get(
                    "classification"
                ),
                "status_code": result.get("status_code"),
                "content_type": result.get("content_type"),
                "baseline_status_code": result.get(
                    "baseline_status_code"
                ),
                "differential_evidence": result.get(
                    "differential_evidence"
                ),
                "probe_evidence": result.get("evidence", {}),
            },
            metadata={
                "probe_source": (
                    result.get("runtime_evidence_source")
                    or "runtime_probe_executor"
                ),
                "runtime_evidence_source": result.get(
                    "runtime_evidence_source"
                ),
                "template_path": result.get("template_path"),
            },
        )

        canonical_endpoints.append(canonical)

    return canonical_endpoints




