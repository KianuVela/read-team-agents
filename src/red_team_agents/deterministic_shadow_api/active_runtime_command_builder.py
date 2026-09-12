import json
import shlex
from typing import Any, Dict
from urllib.parse import urlencode


def build_active_curl_args(
    method: str,
    url: str,
    json_body: Dict[str, Any] | None = None,
    bearer_token: str | None = None,
    query_params: Dict[str, Any] | None = None,
) -> str:
    """
    Build deterministic curl arguments for the Kali MCP server.

    The returned string is compatible with the server-side
    shlex.split(args) parsing. This function performs no HTTP
    execution.
    """

    normalized_method = str(method or "").upper()

    if normalized_method not in {"POST", "PUT"}:
        raise ValueError(
            f"Unsupported active runtime method: {normalized_method}"
        )

    argv = [
        "-i",
        "-sS",
        "--max-time",
        "15",
        "-X",
        normalized_method,
        "-H",
        "Content-Type: application/json",
    ]

    if bearer_token:
        argv.extend(
            [
                "-H",
                f"Authorization: Bearer {bearer_token}",
            ]
        )

    if json_body is not None:
        payload = json.dumps(
            json_body,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

        argv.extend(
            [
                "--data-binary",
                payload,
            ]
        )

    if query_params:
        encoded_query = urlencode(
            query_params,
            doseq=True,
        )
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{encoded_query}"

    argv.append(url)

    return shlex.join(argv)


def redact_active_curl_args(
    args: str,
    bearer_token: str | None,
) -> str:
    """
    Produce a printable dry-run representation without
    exposing the bearer token.
    """

    if bearer_token:
        return args.replace(
            bearer_token,
            "<REDACTED_TOKEN>",
        )

    return args
