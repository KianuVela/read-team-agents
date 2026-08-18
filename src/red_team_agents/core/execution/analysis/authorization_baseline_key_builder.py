# core/execution/analysis/authorization_baseline_key_builder.py

from urllib.parse import quote, urlsplit


class AuthorizationBaselineKeyBuilder:
    """
    Builds stable keys for storing and retrieving authorization baseline evidence.

    The key is intentionally independent from:
    - execution host;
    - JWT token;
    - actor identity;
    - response content.

    It is based only on:
    - HTTP method;
    - normalized endpoint;
    - selected object identifier, when available.
    """

    def build(
        self,
        method: str,
        endpoint: str,
        selected_object_id: str | int | None = None,
    ) -> str:
        normalized_method = self._normalize_method(
            method
        )
        normalized_endpoint = self._normalize_endpoint(
            endpoint
        )
        normalized_object_id = self._normalize_object_id(
            selected_object_id
        )

        return (
            f"{normalized_method}:"
            f"{normalized_endpoint}:"
            f"{normalized_object_id}"
        )

    def build_from_resource(
        self,
        resource,
    ) -> str:
        return self.build(
            method=resource.method,
            endpoint=resource.endpoint,
            selected_object_id=resource.selected_object_id,
        )

    def _normalize_method(
        self,
        method: str,
    ) -> str:
        if not method:
            raise ValueError(
                "HTTP method is required to build a baseline key."
            )

        return method.strip().upper()

    def _normalize_endpoint(
        self,
        endpoint: str,
    ) -> str:
        if not endpoint:
            raise ValueError(
                "Endpoint is required to build a baseline key."
            )

        value = (
            endpoint
            .strip()
            .strip("`")
            .strip()
        )

        parsed = urlsplit(value)

        if parsed.scheme and parsed.netloc:
            value = parsed.path or "/"

            if parsed.query:
                value = f"{value}?{parsed.query}"

        if not value.startswith("/"):
            value = f"/{value}"

        while "//" in value:
            value = value.replace(
                "//",
                "/",
            )

        return value

    def _normalize_object_id(
        self,
        selected_object_id: str | int | None,
    ) -> str:
        if selected_object_id is None:
            return "no-object"

        value = str(
            selected_object_id
        ).strip()

        if not value:
            return "no-object"

        return quote(
            value,
            safe="",
        )