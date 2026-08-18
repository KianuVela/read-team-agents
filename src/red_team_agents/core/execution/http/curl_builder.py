from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CurlBuilder:
    """
    Build curl argument strings for KaliMCPTool.

    IMPORTANT:
    This builder returns curl ARGUMENTS ONLY.

    The executable name ``curl`` must not be included because
    KaliMCPTool receives the executable separately:

        tool="curl"
        args="<arguments only>"
    """

    method: str = "GET"
    url: str = ""
    headers: list[str] = field(
        default_factory=list
    )
    body: str | None = None

    # --------------------------------------------------
    # CREATE FRESH BUILDER
    # --------------------------------------------------

    def fresh(self) -> "CurlBuilder":
        """
        Return a completely new builder instance.

        This prevents headers, body data, URL values, or HTTP
        methods from leaking from one execution to another.
        """

        return type(self)()

    # --------------------------------------------------
    # RESET
    # --------------------------------------------------

    def reset(self) -> "CurlBuilder":
        """
        Reset this builder instance.

        Normally ``fresh()`` should be preferred for execution
        strategies, but reset() is retained for deterministic
        reuse where explicitly required.
        """

        self.method = "GET"
        self.url = ""
        self.headers.clear()
        self.body = None

        return self

    # --------------------------------------------------
    # HTTP METHOD
    # --------------------------------------------------

    def with_method(
        self,
        method: str,
    ) -> "CurlBuilder":

        normalized_method = str(
            method or ""
        ).strip().upper()

        if not normalized_method:

            raise ValueError(
                "HTTP method is required."
            )

        self.method = normalized_method

        return self

    # --------------------------------------------------
    # REQUEST URL
    # --------------------------------------------------

    def with_url(
        self,
        url: str,
    ) -> "CurlBuilder":

        normalized_url = str(
            url or ""
        ).strip()

        if not normalized_url:

            raise ValueError(
                "Request URL is required."
            )

        self.url = normalized_url

        return self

    # --------------------------------------------------
    # INTERNAL HEADER HANDLER
    # --------------------------------------------------

    def _set_header(
        self,
        name: str,
        value: str,
    ) -> "CurlBuilder":
        """
        Set a header while ensuring that only one header with
        the same name exists.

        This is particularly important for Authorization.
        """

        normalized_name = str(
            name or ""
        ).strip()

        normalized_value = str(
            value or ""
        ).strip()

        if not normalized_name:

            raise ValueError(
                "Header name is required."
            )

        if not normalized_value:

            raise ValueError(
                f"Header value is required for "
                f"'{normalized_name}'."
            )

        prefix = (
            f"{normalized_name.lower()}:"
        )

        self.headers = [
            header
            for header in self.headers
            if not str(
                header
            ).lower().startswith(
                prefix
            )
        ]

        self.headers.append(
            f"{normalized_name}: "
            f"{normalized_value}"
        )

        return self

    # --------------------------------------------------
    # BEARER TOKEN
    # --------------------------------------------------

    def bearer(
        self,
        token: str,
    ) -> "CurlBuilder":

        normalized_token = str(
            token or ""
        ).strip()

        if not normalized_token:

            raise ValueError(
                "Bearer token is required."
            )

        return self._set_header(
            "Authorization",
            f"Bearer {normalized_token}",
        )

    # --------------------------------------------------
    # ACCEPT JSON
    # --------------------------------------------------

    def accept_json(
        self,
    ) -> "CurlBuilder":

        return self._set_header(
            "Accept",
            "application/json",
        )

    # --------------------------------------------------
    # CONTENT TYPE JSON
    # --------------------------------------------------

    def content_json(
        self,
    ) -> "CurlBuilder":

        return self._set_header(
            "Content-Type",
            "application/json",
        )

    # --------------------------------------------------
    # GENERIC HEADER
    # --------------------------------------------------

    def with_header(
        self,
        header: str,
    ) -> "CurlBuilder":

        normalized_header = str(
            header or ""
        ).strip()

        if not normalized_header:

            return self

        if ":" not in normalized_header:

            raise ValueError(
                "Header must use the format "
                "'Name: value'."
            )

        name, value = (
            normalized_header.split(
                ":",
                1,
            )
        )

        return self._set_header(
            name.strip(),
            value.strip(),
        )

    # --------------------------------------------------
    # REQUEST BODY
    # --------------------------------------------------

    def with_body(
        self,
        body: str | None,
    ) -> "CurlBuilder":

        self.body = body

        return self

    # --------------------------------------------------
    # BUILD CURL ARGUMENTS
    # --------------------------------------------------

    def build(
        self,
    ) -> str:
        """
        Build curl arguments for KaliMCPTool.

        Example output:

            -i -s -X GET "http://target/api/resource" \
            -H "Authorization: Bearer token" \
            -H "Accept: application/json"

        Notice that the returned string DOES NOT begin with
        ``curl``.
        """

        if not self.url:

            raise ValueError(
                "Request URL is required "
                "before build()."
            )

        command: list[str] = [
            "-i",
            "-s",
            "-X",
            self.method,
            f'"{self.url}"',
        ]

        for header in self.headers:

            command.extend(
                [
                    "-H",
                    f'"{header}"',
                ]
            )

        if self.body is not None:

            command.extend(
                [
                    "--data",
                    f"'{self.body}'",
                ]
            )

        return " ".join(
            command
        )