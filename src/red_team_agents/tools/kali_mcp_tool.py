from dotenv import load_dotenv


import asyncio
import json
import os
import re

from typing import Any, Dict, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from fastmcp import Client


from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

# Para o frontend_extract
from urllib.parse import urljoin, urlparse



MAX_RAW_OUTPUT_CHARS = 12000
MAX_RAW_OUTPUT_LINES = 150

MAX_HTTP_BODY_CHARS = 4000
MAX_HTTP_BODY_LINES = 80

MAX_JSON_OUTPUT_CHARS = 8000

# Para o frontend_extract
MAX_FRONTEND_CANDIDATES = 200
MAX_FRONTEND_SNIPPET_CHARS = 240

class KaliMCPToolInput(BaseModel):

    tool: str = Field(
    ...,
    description="Tool to execute via MCP."
    )


    args: str = Field(
        default="",
        description=(
            "Tool to execute via MCP. "
            "Use frontend_extract for deterministic HTML/JavaScript "
            "route extraction from a live URL."
        )
    )


class KaliMCPTool(BaseTool):
    name: str = "Kali MCP Tool"

    description: str = """
    Execute Kali Linux security tools through the Kali MCP Server.

    Special helper:
    - frontend_extract: fetch a live HTML or JavaScript URL using MCP curl
    and deterministically extract JavaScript assets, API route candidates,
    and conservative HTTP method hints.

    For frontend_extract, pass exactly one live HTTP/HTTPS URL in args.

    Do NOT pass shell pipelines such as:
    | grep
    | head
    &&
    ;
    to curl.
    """

    args_schema: Type[BaseModel] = KaliMCPToolInput


    def redact_sensitive_data(
        self,
        value: str
    ) -> str:
        """
        Removes bearer tokens from commands before they are
        returned to the agent or stored as execution evidence.
        """

        if not value:
            return value

        return re.sub(
            r"Authorization:\s*Bearer\s+[A-Za-z0-9._\-]+",
            "Authorization: Bearer [REDACTED]",
            value,
            flags=re.IGNORECASE
        )



    def normalize_result_data(
        self,
        data: Any
    ) -> Any:
        """
        Converts the MCP result into a JSON-serializable value.
        """

        if data is None:
            return None

        if isinstance(
            data,
            (
                str,
                int,
                float,
                bool,
                list,
                dict
            )
        ):
            return data

        if hasattr(data, "model_dump"):

            try:
                return data.model_dump()

            except Exception:
                pass

        return str(data)


    # ===================================================
    # DUAS FUNÇÔES para reduzir o tamnho do chars para o LLM
    # PRIMEIRA FUNÇÂO
    # ===================================================
    def compact_output_for_llm(
        self,
        value: Any,
        max_chars: int,
        max_lines: int | None = None,
    ) -> Dict[str, Any]:
        """
        Produce a bounded representation suitable for the LLM context.

        The original value is NOT modified here.
        """

        if value is None:
            return {
                "preview": None,
                "truncated": False,
                "original_chars": 0,
                "original_lines": 0,
            }

        # Preserve small structured objects when possible.
        if not isinstance(value, str):
            try:
                serialized = json.dumps(
                    value,
                    ensure_ascii=False,
                )
            except Exception:
                serialized = str(value)

            serialized = self.redact_sensitive_data(
                serialized
            )

            original_chars = len(serialized)
            original_lines = serialized.count("\n") + 1

            if original_chars <= max_chars:
                return {
                    "preview": value,
                    "truncated": False,
                    "original_chars": original_chars,
                    "original_lines": original_lines,
                }

            return {
                "preview": (
                    serialized[:max_chars]
                    + "\n...[OUTPUT TRUNCATED]..."
                ),
                "truncated": True,
                "original_chars": original_chars,
                "original_lines": original_lines,
            }

        text = self.redact_sensitive_data(value)

        original_chars = len(text)
        original_lines = text.count("\n") + 1

        truncated = False

        if (
            max_lines is not None
            and original_lines > max_lines
        ):
            text = "\n".join(
                text.splitlines()[:max_lines]
            )
            truncated = True

        if len(text) > max_chars:
            text = text[:max_chars]
            truncated = True

        if truncated:
            text += (
                "\n...[OUTPUT TRUNCATED "
                f"original_chars={original_chars} "
                f"original_lines={original_lines}]..."
            )

        return {
            "preview": text,
            "truncated": truncated,
            "original_chars": original_chars,
            "original_lines": original_lines,
        }

    # =======================================
    # SEGUNDA FUNÇÂO
    # =======================================
    def persist_raw_output(
        self,
        tool: str,
        value: Any,
    ) -> str | None:
        """
        Preserve full tool output outside the LLM context.

        Sensitive bearer tokens are redacted before persistence.
        """

        if value is None:
            return None

        if isinstance(value, str):
            raw_text = value
        else:
            try:
                raw_text = json.dumps(
                    value,
                    indent=2,
                    ensure_ascii=False,
                )
            except Exception:
                raw_text = str(value)

        raw_text = self.redact_sensitive_data(
            raw_text
        )

        project_root = (
            Path(__file__).resolve().parents[3]
        )

        output_dir = (
            project_root
            / "reports"
            / "raw_tools"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        safe_tool = re.sub(
            r"[^A-Za-z0-9_.-]",
            "_",
            tool.lower(),
        )

        timestamp = datetime.now(
            timezone.utc
        ).strftime("%Y%m%dT%H%M%SZ")

        filename = (
            f"{timestamp}_"
            f"{safe_tool}_"
            f"{uuid4().hex[:8]}.txt"
        )

        output_path = output_dir / filename

        output_path.write_text(
            raw_text,
            encoding="utf-8",
        )

        return str(output_path)



    def parse_http_response(
        self,
        raw_output: Any
    ) -> Dict[str, Any]:
        """
        Parses curl output produced with the -i option.

        Returns the HTTP status, reason phrase, headers,
        response body and, when possible, the decoded
        JSON body.
        """

        parsed_response: Dict[str, Any] = {
            "http_status": None,
            "reason_phrase": None,
            "headers": {},
            "body": None,
            "body_json": None,
            "parse_success": False
        }

        if not isinstance(raw_output, str):

            parsed_response["parse_error"] = (
                "The curl output is not a string."
            )

            return parsed_response

        if not raw_output.strip():

            parsed_response["parse_error"] = (
                "The curl output is empty."
            )

            return parsed_response

        normalized_output = raw_output.replace(
            "\r\n",
            "\n"
        )

        # Find every HTTP response status line.
        # The final response is used because curl may return
        # intermediate responses during redirects or negotiation.
        status_matches = list(
            re.finditer(
                r"(?m)^HTTP/\S+[ \t]+(\d{3})(?:[ \t]+([^\r\n]*))?[ \t]*$",
                normalized_output
            )
        )

        if not status_matches:

            parsed_response["body"] = (
                self.redact_sensitive_data(
                    normalized_output
                )
            )

            parsed_response["parse_error"] = (
                "No HTTP status line was found."
            )

            return parsed_response

        final_status_match = status_matches[-1]

        response_output = normalized_output[
            final_status_match.start():
        ]

        status_code = int(
            final_status_match.group(1)
        )

        reason_phrase = (
            final_status_match.group(2) or ""
        ).strip() or None

        header_separator = response_output.find(
            "\n\n"
        )

        if header_separator == -1:

            header_block = response_output
            response_body = ""

        else:

            header_block = response_output[
                :header_separator
            ]

            response_body = response_output[
                header_separator + 2:
            ]

        header_lines = header_block.split(
            "\n"
        )

        headers: Dict[str, Any] = {}

        # Skip the first line because it is the HTTP status line.
        for header_line in header_lines[1:]:

            if ":" not in header_line:
                continue

            header_name, header_value = header_line.split(
                ":",
                1
            )

            header_name = header_name.strip()
            header_value = header_value.strip()

            if not header_name:
                continue

            # Preserve repeated headers, such as Set-Cookie.
            if header_name in headers:

                existing_value = headers[
                    header_name
                ]

                if isinstance(
                    existing_value,
                    list
                ):

                    existing_value.append(
                        header_value
                    )

                else:

                    headers[header_name] = [
                        existing_value,
                        header_value
                    ]

            else:

                headers[header_name] = (
                    header_value
                )

        response_body = self.redact_sensitive_data(
            response_body.strip()
        )

        body_json = None

        if response_body:

            try:

                body_json = json.loads(
                    response_body
                )

            except json.JSONDecodeError:

                body_json = None

        parsed_response.update(
            {
                "http_status": status_code,
                "reason_phrase": reason_phrase,
                "headers": headers,
                "body": response_body,
                "body_json": body_json,
                "parse_success": True
            }
        )

        return parsed_response


    # ===============================================
    # AQUI ADICIONAMOS OS MÉTODOS NECESSÁRIOS PARA CRIAR O frontend_extrct
    # ====================================================
    def get_header_value(
        self,
        headers: Dict[str, Any],
        name: str,
    ) -> Any:

        target = name.lower()

        for key, value in headers.items():
            if str(key).lower() == target:
                return value

        return None


    def parse_frontend_extract_url(
        self,
        args: str,
    ) -> str | None:
        """
        frontend_extract accepts exactly one HTTP/HTTPS URL.
        """

        if not args or not args.strip():
            return None

        raw = args.strip()
        url = raw

        # Also permit:
        # {"url": "http://crapi-web/file.js"}
        if raw.startswith("{"):

            try:
                parsed_args = json.loads(raw)

            except json.JSONDecodeError:
                return None

            if not isinstance(parsed_args, dict):
                return None

            url = parsed_args.get("url")

            if not isinstance(url, str):
                return None

            url = url.strip()

        # frontend_extract never needs shell syntax.
        if (
            re.search(r"\s", url)
            or "|" in url
            or "&&" in url
            or ";" in url
            or "\n" in url
            or "\r" in url
        ):
            return None

        parsed_url = urlparse(url)

        if parsed_url.scheme not in {"http", "https"}:
            return None

        if not parsed_url.netloc:
            return None

        return url


    def infer_frontend_method_hint(
        self,
        text: str,
        match_start: int,
        match_end: int,
    ) -> str | None:
        """
        Infer method only when nearby JavaScript provides evidence.
        """

        before = text[
            max(0, match_start - 180):
            match_start
        ]

        after = text[
            match_end:
            min(len(text), match_end + 180)
        ]

        window = (
            before
            + text[match_start:match_end]
            + after
        )

        # Example:
        # method: "POST"
        explicit_method = re.search(
            r"""(?i)\bmethod\s*:\s*["']"""
            r"""(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)"""
            r"""["']""",
            window,
        )

        if explicit_method:
            return explicit_method.group(1).upper()

        # Examples:
        # axios.post("...")
        # client.get("...")
        method_call = re.search(
            r"""(?i)\."""
            r"""(get|post|put|patch|delete|options|head)"""
            r"""\s*\([^()]{0,180}$""",
            before,
        )

        if method_call:
            return method_call.group(1).upper()

        # fetch("/path") defaults to GET when no explicit
        # method evidence was found.
        fetch_call = re.search(
            r"""(?i)\bfetch\s*\(\s*$""",
            before,
        )

        if fetch_call:
            return "GET"

        return None


    def extract_frontend_evidence(
        self,
        source_url: str,
        body: str,
        content_type: Any = None,
    ) -> Dict[str, Any]:
        """
        Extract route evidence from live HTML/JavaScript.

        IMPORTANT:
        This function does not use OpenAPI or Ground Truth.
        """

        body = body or ""

        # =====================================================
        # JAVASCRIPT ASSETS REFERENCED BY HTML
        # =====================================================

        javascript_assets = []
        seen_assets = set()

        asset_pattern = re.compile(
            r"""(?i)(?:src|href)\s*=\s*"""
            r"""["']([^"']+\.js(?:\?[^"']*)?)["']"""
        )

        for match in asset_pattern.finditer(body):

            reference = match.group(1).strip()

            if not reference:
                continue

            absolute_url = urljoin(
                source_url,
                reference,
            )

            if absolute_url in seen_assets:
                continue

            seen_assets.add(
                absolute_url
            )

            javascript_assets.append(
                {
                    "reference": reference,
                    "url": absolute_url,
                }
            )

        # =====================================================
        # API-LIKE ROUTE REFERENCES
        # =====================================================

        api_candidates = []
        seen_candidates = set()

        # Search only for application/API-like paths.
        #
        # We deliberately DO NOT collect arbitrary absolute URLs such as:
        #   http://www.w3.org/2000/svg
        #   https://reactjs.org/...
        #
        # This keeps frontend discovery focused on routes that resemble
        # the live application's namespaces, independently from OpenAPI.
        route_pattern = re.compile(
            r"""
            /
            (?:
                api
                |
                identity
                |
                community
                |
                workshop
                |
                v[0-9]+
            )
            (?:
                [/
                A-Za-z0-9
                _.\-~
                ${}
                :@
                %+
                ?=&
                ]*
            )
            """,
            re.IGNORECASE | re.VERBOSE,
        )

        api_prefix_pattern = re.compile(
            r"^/(?:api|identity|community|workshop|v[0-9]+)(?:/|$)",
            re.IGNORECASE,
        )

        for match in route_pattern.finditer(body):

            candidate_path = (
                match.group(0)
                .strip()
                .replace("\\/", "/")
            )

            # Remove punctuation that may belong to surrounding
            # minified JavaScript rather than to the route itself.
            candidate_path = candidate_path.rstrip(
                ".,;:)]}"
            )

            if not candidate_path:
                continue

            if not api_prefix_pattern.match(
                    candidate_path
            ):
                continue

            # Ignore obvious static assets.
            lowered = candidate_path.lower()

            if lowered.endswith(
                (
                    ".js",
                    ".css",
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".gif",
                    ".svg",
                    ".ico",
                    ".woff",
                    ".woff2",
                    ".ttf",
                    ".map",
                )
            ):
                continue

            method_hint = (
                self.infer_frontend_method_hint(
                    body,
                    match.start(),
                    match.end(),
                )
            )

            dedupe_key = (
                candidate_path,
                method_hint,
            )

            if dedupe_key in seen_candidates:
                continue

            seen_candidates.add(
                dedupe_key
            )

            snippet_start = max(
                0,
                match.start()
                - MAX_FRONTEND_SNIPPET_CHARS // 2,
            )

            snippet_end = min(
                len(body),
                match.end()
                + MAX_FRONTEND_SNIPPET_CHARS // 2,
            )

            snippet = (
                body[
                    snippet_start:
                    snippet_end
                ]
                .replace("\n", " ")
                .replace("\r", " ")
            )

            if (
                len(snippet)
                > MAX_FRONTEND_SNIPPET_CHARS
            ):

                snippet = (
                    snippet[
                        :MAX_FRONTEND_SNIPPET_CHARS
                    ]
                    + "...[TRUNCATED]"
                )

            api_candidates.append(
                {
                    "path": candidate_path,
                    "method_hint": method_hint,
                    "source_url": source_url,
                    "discovery_method": (
                        "frontend_reference"
                    ),
                    "evidence": {
                        "literal": candidate_path,
                        "snippet": snippet,
                    },
                }
            )

            if (
                len(api_candidates)
                >= MAX_FRONTEND_CANDIDATES
            ):
                break

        return {
            "source_url": source_url,
            "content_type": content_type,
            "javascript_assets": (
                javascript_assets
            ),
            "api_candidates": api_candidates,
            "summary": {
                "javascript_asset_count": len(
                    javascript_assets
                ),
                "api_candidate_count": len(
                    api_candidates
                ),
                "candidate_limit_reached": (
                    len(api_candidates)
                    >= MAX_FRONTEND_CANDIDATES
                ),
            },
        }


    async def execute_frontend_extract(
        self,
        client: Client,
        args: str,
    ) -> str:
        """
        Execute the deterministic frontend extractor implemented
        natively by the Kali MCP Server.

        The server performs the live retrieval and extraction.
        This wrapper only normalizes and compacts the resulting
        evidence before returning it to the agent.
        """

        source_url = self.parse_frontend_extract_url(args)

        if not source_url:
            return json.dumps(
                {
                    "success": False,
                    "tool": "frontend_extract",
                    "arguments": self.redact_sensitive_data(args),
                    "error_type": "invalid_frontend_extract_args",
                    "error": (
                        "frontend_extract expects exactly one "
                        "HTTP/HTTPS URL."
                    ),
                },
                indent=4,
                ensure_ascii=False,
            )

        # Execute the native deterministic MCP operation.
        result = await client.call_tool(
            "run_tool",
            {
                "tool": "frontend_extract",
                "args": source_url,
            },
        )

        normalized_data = self.normalize_result_data(
            result.data
        )

        # FastMCP may expose the returned JSON either as text
        # or as an already-decoded dictionary.
        if isinstance(normalized_data, str):
            try:
                extracted = json.loads(normalized_data)
            except json.JSONDecodeError:
                return json.dumps(
                    {
                        "success": False,
                        "tool": "frontend_extract",
                        "source_url": source_url,
                        "error_type": "invalid_frontend_extract_result",
                        "error": (
                            "MCP frontend_extract returned "
                            "non-JSON text."
                        ),
                    },
                    indent=4,
                    ensure_ascii=False,
                )

        elif isinstance(normalized_data, dict):
            extracted = normalized_data

        else:
            return json.dumps(
                {
                    "success": False,
                    "tool": "frontend_extract",
                    "source_url": source_url,
                    "error_type": "unexpected_frontend_extract_result",
                    "error": (
                        "MCP frontend_extract returned an "
                        "unsupported result type."
                    ),
                },
                indent=4,
                ensure_ascii=False,
            )

        if not isinstance(extracted, dict):
            return json.dumps(
                {
                    "success": False,
                    "tool": "frontend_extract",
                    "source_url": source_url,
                    "error_type": "invalid_frontend_extract_result",
                    "error": (
                        "Decoded frontend_extract result "
                        "is not an object."
                    ),
                },
                indent=4,
                ensure_ascii=False,
            )

        api_candidates = extracted.get(
            "api_candidates",
            [],
        )

        if not isinstance(api_candidates, list):
            api_candidates = []

        # Keep every candidate visible to the agent, while removing
        # verbose fields that unnecessarily consume LLM context.
        compact_candidates = []

        for candidate in api_candidates:
            if not isinstance(candidate, dict):
                continue

            compact_candidates.append(
                {
                    "reference": candidate.get(
                        "reference"
                    ),
                    "method_hint": candidate.get(
                        "method_hint"
                    ),
                    "observed_methods": candidate.get(
                        "observed_methods",
                        [],
                    ),
                    "reference_type": candidate.get(
                        "reference_type"
                    ),
                    "route_key": candidate.get(
                        "route_key"
                    ),
                }
            )

        # Preserve the complete deterministic extractor result
        # outside the LLM context when useful for auditability.
        serialized_full_result = json.dumps(
            extracted,
            indent=2,
            ensure_ascii=False,
        )

        raw_output_file = None

        if len(serialized_full_result) > MAX_RAW_OUTPUT_CHARS:
            raw_output_file = self.persist_raw_output(
                "frontend_extract",
                serialized_full_result,
            )

        evidence = {
            "success": bool(
                extracted.get("success", True)
            ),
            "tool": "frontend_extract",
            "arguments": self.redact_sensitive_data(
                args
            ),
            "source_url": extracted.get(
                "source_url",
                source_url,
            ),
            "javascript_assets": extracted.get(
                "javascript_assets",
                [],
            ),
            "api_candidates": compact_candidates,
            "summary": extracted.get(
                "summary",
                {},
            ),
            "raw_output_file": raw_output_file,
            "error": extracted.get("error"),
        }

        return json.dumps(
            evidence,
            indent=4,
            ensure_ascii=False,
        )

    # =====================================================
    


    def _run(
        self,
        tool: str,
        args: str = ""
    ) -> str:

        return asyncio.run(
            self.execute_tool(
                tool,
                args
            )
        )

    async def execute_tool(
        self,
        tool: str,
        args: str
    ) -> str:

        load_dotenv()

        mcp_server_url = os.getenv(
            "MCP_SERVER_URL"
        )

        if not mcp_server_url:

            return json.dumps(
                {
                    "success": False,
                    "tool": tool,
                    "error_type": "configuration_error",
                    "error": (
                        "MCP_SERVER_URL is not configured."
                    )
                },
                indent=4
            )

        client = Client(
            mcp_server_url
        )

        try:

           async with client:

                if tool.strip().lower() == "frontend_extract":

                    return await self.execute_frontend_extract(
                        client,
                        args,
                    )

                result = await client.call_tool(
                    "run_tool",
                    {
                        "tool": tool,
                        "args": args
                    }
                )

                normalized_data = (
                    self.normalize_result_data(
                        result.data
                    )
                )

                # =====================================================
                # COMPACTAÇÃO GLOBAL — PARA TODAS AS FERRAMENTAS
                # =====================================================

                raw_compact = self.compact_output_for_llm(
                    normalized_data,
                    max_chars=MAX_RAW_OUTPUT_CHARS,
                    max_lines=MAX_RAW_OUTPUT_LINES,
                )

                # Inicializar sempre, mesmo para nmap/gobuster/nikto
                body_compact = {
                    "preview": None,
                    "truncated": False,
                    "original_chars": 0,
                    "original_lines": 0,
                }

                body_json_compact = {
                    "preview": None,
                    "truncated": False,
                    "original_chars": 0,
                    "original_lines": 0,
                }

                raw_output_file = None


                # =====================================================
                # TRATAMENTO ESPECÍFICO PARA CURL
                # =====================================================

                http_response = None

                if (
                    tool.lower() == "curl"
                    and isinstance(
                        normalized_data,
                        str
                    )
                ):

                    http_response = (
                        self.parse_http_response(
                            normalized_data
                        )
                    )

                    body_compact = self.compact_output_for_llm(
                        http_response.get("body"),
                        max_chars=MAX_HTTP_BODY_CHARS,
                        max_lines=MAX_HTTP_BODY_LINES,
                    )

                    body_json_compact = self.compact_output_for_llm(
                        http_response.get("body_json"),
                        max_chars=MAX_JSON_OUTPUT_CHARS,
                    )


                # =====================================================
                # DECIDIR SE O RAW OUTPUT DEVE SER PRESERVADO
                # =====================================================

                should_persist_raw = (
                    raw_compact["truncated"]
                    or body_compact["truncated"]
                    or body_json_compact["truncated"]
                )

                if should_persist_raw:

                    raw_output_file = self.persist_raw_output(
                        tool,
                        normalized_data,
                    )

                # VAMOS SUBSTITUIR OS DOIS BLOCOS ACTUAIS DE EVIDENCE
                # VOU DEIXAR COMENTADO
                evidence = {
                    "success": True,

                    "tool": tool,

                    "arguments": self.redact_sensitive_data(
                        args
                    ),

                    "data_type": type(
                        result.data
                    ).__name__,

                    "http_status": (
                        http_response.get("http_status")
                        if http_response
                        else None
                    ),

                    "reason_phrase": (
                        http_response.get("reason_phrase")
                        if http_response
                        else None
                    ),

                    "headers": (
                        http_response.get("headers", {})
                        if http_response
                        else {}
                    ),

                    "body": (
                        body_compact["preview"]
                        if http_response
                        else None
                    ),

                    "body_truncated": (
                        body_compact["truncated"]
                        if http_response
                        else False
                    ),

                    "body_original_chars": (
                        body_compact["original_chars"]
                        if http_response
                        else 0
                    ),

                    "body_json": (
                        body_json_compact["preview"]
                        if http_response
                        else None
                    ),

                    "body_json_truncated": (
                        body_json_compact["truncated"]
                        if http_response
                        else False
                    ),

                    "http_parse_success": (
                        http_response.get(
                            "parse_success",
                            False
                        )
                        if http_response
                        else False
                    ),

                    "http_parse_error": (
                        http_response.get(
                            "parse_error"
                        )
                        if http_response
                        else None
                    ),

                    # Curl output is already represented by
                    # status + headers + body above.
                    # Do not duplicate it in the LLM context.
                    "raw_output": (
                        None
                        if (
                            tool.lower() == "curl"
                            and http_response
                            and http_response.get(
                                "parse_success"
                            )
                        )
                        else raw_compact["preview"]
                    ),

                    "raw_output_truncated": (
                        raw_compact["truncated"]
                    ),

                    "raw_output_original_chars": (
                        raw_compact["original_chars"]
                    ),

                    "raw_output_original_lines": (
                        raw_compact["original_lines"]
                    ),

                    "raw_output_file": raw_output_file,

                    "error": None,
                }
                

                return json.dumps(
                    evidence,
                    indent=4,
                    ensure_ascii=False
                )

        except Exception as exc:

            evidence = {
                "success": False,
                "tool": tool,
                "arguments": self.redact_sensitive_data(
                    args
                ),
                "data_type": None,
                "raw_output": None,
                "error_type": type(exc).__name__,
                "error": str(exc)
            }

            return json.dumps(
                evidence,
                indent=4,
                ensure_ascii=False
            )


    def execute_json(
        self,
        tool: str,
        args: str = "",
    ) -> dict[str, Any]:
        """
        Execute an MCP tool and return a parsed JSON response.

        This helper avoids repetitive json.loads(...)
        throughout the execution strategies.
        """

        return json.loads(
            self._run(
                tool=tool,
                args=args,
            )
        )

