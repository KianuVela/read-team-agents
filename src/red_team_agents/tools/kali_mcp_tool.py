from dotenv import load_dotenv


import asyncio
import json
import os
import re

from typing import Any, Dict, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool
from fastmcp import Client

class KaliMCPToolInput(BaseModel):

    tool: str = Field(
    ...,
    description="Tool to execute via MCP."
    )


    args: str = Field(
        default="",
        description="Arguments for the tool."
    )


class KaliMCPTool(BaseTool):
    name: str = "Kali MCP Tool"

    description: str = """
    Execute Kali Linux security tools through
    the Kali MCP Server.
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

                evidence = {
                    "success": True,
                    "tool": tool,
                    "arguments": self.redact_sensitive_data(
                        args
                    ),
                    "data_type": type(
                        result.data
                    ).__name__,
                    "raw_output": normalized_data,
                    "error": None
                }


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
                        http_response.get(
                            "http_status"
                        )
                        if http_response
                        else None
                    ),

                    "reason_phrase": (
                        http_response.get(
                            "reason_phrase"
                        )
                        if http_response
                        else None
                    ),

                    "headers": (
                        http_response.get(
                            "headers",
                            {}
                        )
                        if http_response
                        else {}
                    ),

                    "body": (
                        http_response.get(
                            "body"
                        )
                        if http_response
                        else None
                    ),

                    "body_json": (
                        http_response.get(
                            "body_json"
                        )
                        if http_response
                        else None
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

                    "raw_output": (
                        self.redact_sensitive_data(
                            normalized_data
                        )
                        if isinstance(
                            normalized_data,
                            str
                        )
                        else normalized_data
                    ),

                    "error": None
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

