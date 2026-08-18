# src/core/execution/analysis/authorization_outcome.py

from dataclasses import dataclass
from enum import Enum


class AuthorizationOutcome(str, Enum):
    """
    Neutral interpretation of an HTTP response from an authorization test.

    This class does not decide whether a vulnerability exists.
    It only describes how the target API responded.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    NOT_FOUND = "not_found"
    BAD_REQUEST = "bad_request"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AuthorizationOutcomeResult:
    outcome: AuthorizationOutcome
    status_code: int | None
    explanation: str


class AuthorizationOutcomeClassifier:
    """
    Classifies HTTP execution results without making vulnerability claims.

    Vulnerability confirmation must be done later by comparing:
    - actor used;
    - expected authorization boundary;
    - object owner;
    - endpoint intention;
    - baseline positive/negative behaviour.
    """

    def classify(self, status_code: int | None) -> AuthorizationOutcomeResult:
        if status_code is None:
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.UNKNOWN,
                status_code=status_code,
                explanation="No HTTP status code was available.",
            )

        if 200 <= status_code < 300:
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.ALLOWED,
                status_code=status_code,
                explanation="The request was accepted by the API.",
            )

        if status_code in (401, 403):
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.DENIED,
                status_code=status_code,
                explanation="The request was rejected by the API due to authentication or authorization.",
            )

        if status_code == 404:
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.NOT_FOUND,
                status_code=status_code,
                explanation="The requested resource or route was not found.",
            )

        if status_code == 400:
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.BAD_REQUEST,
                status_code=status_code,
                explanation="The API rejected the request as malformed or incomplete.",
            )

        if 500 <= status_code < 600:
            return AuthorizationOutcomeResult(
                outcome=AuthorizationOutcome.SERVER_ERROR,
                status_code=status_code,
                explanation="The API returned a server-side error.",
            )

        return AuthorizationOutcomeResult(
            outcome=AuthorizationOutcome.UNKNOWN,
            status_code=status_code,
            explanation="The HTTP response does not map to a known authorization outcome.",
        )