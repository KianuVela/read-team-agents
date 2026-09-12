import hashlib
import json
from typing import Any, Dict

# ===============================================================
# CRIAMOS ESTA CLASSE POR CAUSA DISTO...
# CANDIDATE
# 401
# application/json
# {"message":"JWT Token required!"}

# BASELINE
# 404
# text/html
# Not Found

# Portanto, para /workshop/api/shop/products, temos evidência runtime diferencial clara. O 401 não deve ser interpretado como falha; neste caso ele mostra que a requisição atingiu uma operação protegida, enquanto o sibling inexistente cai no 404 genérico.

# Agora vamos transformar essa decisão em código determinístico antes de executar os 15 GETs.
# ====================================================================================================================

def normalize_content_type(
    content_type: str | None,
) -> str | None:
    """
    Normalize Content-Type while ignoring charset and
    other optional parameters.
    """

    if not content_type:
        return None

    return content_type.split(
        ";",
        1,
    )[0].strip().lower()


def body_signature(
    body: Any,
) -> str | None:
    """
    Produce a deterministic SHA-256 signature for a
    response body without storing the whole body in the
    comparison result.
    """

    if body is None:
        return None

    if not isinstance(body, str):
        try:
            body = json.dumps(
                body,
                sort_keys=True,
                ensure_ascii=False,
            )
        except Exception:
            body = str(body)

    normalized = body.strip()

    return hashlib.sha256(
        normalized.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def response_fingerprint(
    response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Create the deterministic response fingerprint used
    for candidate-vs-baseline comparison.
    """

    headers = response.get(
        "headers",
        {},
    ) or {}

    return {
        "status_code": response.get(
            "http_status"
        ),
        "content_type": normalize_content_type(
            headers.get("Content-Type")
        ),
        "body_signature": body_signature(
            response.get("body")
        ),
    }


def classify_differential_response(
    candidate_response: Dict[str, Any],
    baseline_response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare a frontend-derived API candidate against an
    intentionally nonexistent sibling path.

    A difference provides runtime differential evidence.

    Equality is considered inconclusive rather than proof
    that the candidate does not exist.
    """

    candidate = response_fingerprint(
        candidate_response
    )

    baseline = response_fingerprint(
        baseline_response
    )

    differences = []

    for field in (
        "status_code",
        "content_type",
        "body_signature",
    ):
        if candidate.get(field) != baseline.get(field):
            differences.append(field)

    if differences:
        classification = (
            "RUNTIME_DIFFERENTIAL_EVIDENCE"
        )
        runtime_observed = True

    else:
        classification = (
            "INCONCLUSIVE_MIDDLEWARE_RESPONSE"
        )
        runtime_observed = False

    return {
        "classification": classification,
        "runtime_observed": runtime_observed,
        "differing_fields": differences,
        "candidate_fingerprint": candidate,
        "baseline_fingerprint": baseline,
    }