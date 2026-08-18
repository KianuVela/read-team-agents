from __future__ import annotations

import re


_TEST_CASE_HEADING_RE = re.compile(
    r"^###\s+(BOLA|BFLA)-(\d+)\s*$",
    re.IGNORECASE,
)

_FIELD_RE = re.compile(
    r"^-\s+\*\*(.+?):\*\*\s*(.*)$"
)


def normalise_whitespace(
    value: str,
) -> str:
    """
    Collapse repeated whitespace and trim the supplied text.
    """

    return " ".join(
        value.strip().split()
    )


def split_test_case_sections(
    markdown: str,
) -> list[tuple[str, str]]:
    """
    Split the Markdown report into BOLA/BFLA test-case sections.

    Returns:
        List of tuples:
            (
                test_case_id,
                section_text,
            )
    """

    lines = markdown.splitlines()

    sections: list[
        tuple[str, list[str]]
    ] = []

    current_id: str | None = None
    current_lines: list[str] = []

    for line in lines:

        match = _TEST_CASE_HEADING_RE.match(
            line.strip(),
        )

        if match:

            if current_id is not None:
                sections.append(
                    (
                        current_id,
                        current_lines,
                    )
                )

            test_type = match.group(1).upper()
            number = match.group(2)

            current_id = (
                f"{test_type}-{number}"
            )

            current_lines = []

            continue

        if current_id is not None:

            # Stop collecting when another major Markdown
            # section begins.
            if line.startswith("## "):
                sections.append(
                    (
                        current_id,
                        current_lines,
                    )
                )

                current_id = None
                current_lines = []

                continue

            current_lines.append(line)

    if current_id is not None:
        sections.append(
            (
                current_id,
                current_lines,
            )
        )

    return [
        (
            test_case_id,
            "\n".join(section_lines),
        )
        for test_case_id, section_lines
        in sections
    ]


def extract_fields(
    section: str,
) -> dict[str, str]:
    """
    Extract Markdown bullet fields from one test-case section.
    """

    fields: dict[str, str] = {}

    current_key: str | None = None

    for raw_line in section.splitlines():

        line = raw_line.strip()

        match = _FIELD_RE.match(line)

        if match:

            key = normalise_whitespace(
                match.group(1)
            )

            value = normalise_whitespace(
                match.group(2)
            )

            fields[key] = value

            current_key = key

            continue

        # Support wrapped Markdown field values.
        if (
            current_key is not None
            and line
            and not line.startswith("#")
            and not line.startswith("- **")
        ):

            fields[current_key] = (
                normalise_whitespace(
                    f"{fields[current_key]} {line}"
                )
            )

    return fields


def expand_http_methods(
    raw_method: str,
) -> list[str]:
    """
    Expand method expressions such as:

        GET / PUT / DELETE

    into:

        ["GET", "PUT", "DELETE"]
    """

    if not raw_method:
        return []

    supported_methods = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    }

    candidates = re.split(
        r"[/,|]",
        raw_method.upper(),
    )

    methods = []

    for candidate in candidates:

        method = candidate.strip()

        if method in supported_methods:
            methods.append(method)

    return methods


def normalise_field_name(
    value: str,
) -> str:
    """
    Normalize small wording variations in Markdown field names.
    """

    return normalise_whitespace(
        value
    ).lower()