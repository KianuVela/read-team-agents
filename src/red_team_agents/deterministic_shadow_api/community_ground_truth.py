from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

Operation = Tuple[str, str]

HANDLE_FUNC_PATTERN = re.compile(
    r'HandleFunc\(\s*"([^"]+)"[\s\S]*?\)'
    r'\.Methods\(([^)]*)\)',
    re.MULTILINE,
)

QUOTED_VALUE_PATTERN = re.compile(r'"([^"]+)"')
PARAMETER_PATTERN = re.compile(r"\{[^{}]+\}")


class CommunityGroundTruthError(RuntimeError):
    pass


def _run_command(
    command: List[str],
    *,
    check: bool = True,
) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if check and result.returncode != 0:
        raise CommunityGroundTruthError(
            "Command failed:\n"
            f"{' '.join(command)}\n\n"
            f"stdout:\n{result.stdout}\n\n"
            f"stderr:\n{result.stderr}"
        )

    return result.stdout


def _docker_shell(
    container: str,
    script: str,
) -> str:
    return _run_command(
        [
            "docker",
            "exec",
            container,
            "sh",
            "-c",
            script,
        ]
    )


def normalize_path(path: str) -> str:
    path = path.strip()

    if not path:
        return "/"

    if not path.startswith("/"):
        path = "/" + path

    path = re.sub(r"/+", "/", path)
    path = PARAMETER_PATTERN.sub("{param}", path)

    if len(path) > 1:
        path = path.rstrip("/")

    return path


def extract_source_operations(
    routes_file: Path,
) -> Set[Operation]:
    text = routes_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    operations: Set[Operation] = set()

    for match in HANDLE_FUNC_PATTERN.finditer(text):
        path = match.group(1)
        methods_text = match.group(2)

        # Ground Truth scope is application API only.
        if not path.startswith("/community/api/"):
            continue

        methods = QUOTED_VALUE_PATTERN.findall(
            methods_text
        )

        for method in methods:
            method = method.upper()

            # OPTIONS is CORS/preflight and is not evaluated
            # as an application operation.
            if method not in HTTP_METHODS:
                continue

            operations.add(
                (
                    method,
                    normalize_path(path),
                )
            )

    return operations


def get_binary_strings(
    container: str,
    binary_path: str,
) -> str:
    return _docker_shell(
        container,
        f'strings "{binary_path}"',
    )


def verify_source_paths_in_binary(
    source_operations: Set[Operation],
    binary_strings: str,
) -> Dict[str, Any]:
    unique_paths = sorted(
        {
            path
            for _, path in source_operations
        }
    )

    confirmations: List[Dict[str, Any]] = []

    for normalized_path in unique_paths:
        # Source paths were normalized to {param}; the
        # concrete Go binary retains the original variable
        # name, e.g. {postID}. Compare structurally.
        regex_text = re.escape(normalized_path).replace(
            re.escape("{param}"),
            r"\{[^{}\/]+\}",
        )

        pattern = re.compile(regex_text)

        match = pattern.search(binary_strings)

        confirmations.append(
            {
                "normalized_path": normalized_path,
                "confirmed": match is not None,
                "binary_match": (
                    match.group(0)
                    if match
                    else None
                ),
            }
        )

    return {
        "all_confirmed": all(
            item["confirmed"]
            for item in confirmations
        ),
        "confirmed_count": sum(
            1
            for item in confirmations
            if item["confirmed"]
        ),
        "total_paths": len(confirmations),
        "paths": confirmations,
    }


def load_documented_operations(
    openapi_path: Path,
) -> Set[Operation]:
    with openapi_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        spec = json.load(file)

    documented: Set[Operation] = set()

    for path, path_item in spec.get(
        "paths",
        {},
    ).items():
        if not path.startswith("/community/api/"):
            continue

        if not isinstance(path_item, dict):
            continue

        for method in path_item:
            method_upper = method.upper()

            if method_upper not in HTTP_METHODS:
                continue

            documented.add(
                (
                    method_upper,
                    normalize_path(path),
                )
            )

    return documented


def get_container_evidence(
    container: str,
    binary_path: str,
) -> Dict[str, Any]:
    image_reference = _run_command(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.Config.Image}}",
        ]
    ).strip()

    image_id = _run_command(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.Image}}",
        ]
    ).strip()

    repo_digests_raw = _run_command(
        [
            "docker",
            "image",
            "inspect",
            image_reference,
            "--format",
            "{{json .RepoDigests}}",
        ],
        check=False,
    ).strip()

    try:
        repo_digests = json.loads(
            repo_digests_raw
        )
    except Exception:
        repo_digests = []

    binary_hash_output = _docker_shell(
        container,
        f'sha256sum "{binary_path}"',
    ).strip()

    binary_sha256 = (
        binary_hash_output.split()[0]
    )

    return {
        "docker_container": container,
        "docker_image_reference": image_reference,
        "docker_image_id": image_id,
        "docker_repo_digests": repo_digests,
        "binary_path": binary_path,
        "binary_sha256": binary_sha256,
    }


def build_community_ground_truth(
    routes_file: Path,
    openapi_path: Path,
    output_path: Path,
    *,
    container: str = "crapi-community",
    binary_path: str = "/app/main",
    source_commit: str = (
        "8f1be712998b4db72f2dd0f04b283650df75d05a"
    ),
) -> Dict[str, Any]:
    source_operations = extract_source_operations(
        routes_file
    )

    if not source_operations:
        raise CommunityGroundTruthError(
            "No /community/api operations were "
            "extracted from routes.go."
        )

    binary_strings = get_binary_strings(
        container,
        binary_path,
    )

    binary_verification = (
        verify_source_paths_in_binary(
            source_operations,
            binary_strings,
        )
    )

    if not binary_verification["all_confirmed"]:
        missing = [
            item["normalized_path"]
            for item in binary_verification["paths"]
            if not item["confirmed"]
        ]

        raise CommunityGroundTruthError(
            "Historical source paths were not all "
            "confirmed in the fixed Docker binary: "
            + ", ".join(missing)
        )

    documented = load_documented_operations(
        openapi_path
    )

    documented_implemented = (
        source_operations & documented
    )

    shadow_operations = (
        source_operations - documented
    )

    container_evidence = get_container_evidence(
        container,
        binary_path,
    )

    result: Dict[str, Any] = {
        "service": "community",
        "scope": "/community/api/...",
        "ground_truth_definition": (
            "Application API operations extracted "
            "deterministically from the historical "
            "Community gorilla/mux route table, with "
            "every route path independently confirmed "
            "in the fixed Docker binary, and compared "
            "against the historical OpenAPI baseline."
        ),
        "evidence": {
            **container_evidence,
            "source_commit": source_commit,
            "source_route_file": str(
                routes_file
            ),
            "openapi_baseline": str(
                openapi_path
            ),
            "route_parser": (
                "gorilla/mux HandleFunc + Methods"
            ),
            "binary_path_verification": (
                binary_verification
            ),
        },
        "scope_exclusions": [
            "OPTIONS methods",
            "/debug/pprof/",
            "/community/home",
        ],
        "summary": {
            "implemented_operations": len(
                source_operations
            ),
            "documented_implemented_operations": len(
                documented_implemented
            ),
            "implemented_but_undocumented": len(
                shadow_operations
            ),
            "source_paths_confirmed_in_binary": (
                binary_verification[
                    "confirmed_count"
                ]
            ),
            "source_paths_total": (
                binary_verification[
                    "total_paths"
                ]
            ),
        },
        "implemented_operations": [
            {
                "method": method,
                "path": path,
            }
            for method, path in sorted(
                source_operations
            )
        ],
        "documented_implemented_operations": [
            {
                "method": method,
                "path": path,
            }
            for method, path in sorted(
                documented_implemented
            )
        ],
        "shadow_operations": [
            {
                "method": method,
                "path": path,
            }
            for method, path in sorted(
                shadow_operations
            )
        ],
    }

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    return result