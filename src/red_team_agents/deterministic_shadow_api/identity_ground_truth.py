from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}

SPRING_MAPPING_METHODS = {
    "GetMapping": ["GET"],
    "PostMapping": ["POST"],
    "PutMapping": ["PUT"],
    "DeleteMapping": ["DELETE"],
    "PatchMapping": ["PATCH"],
}

METHOD_HEADER_PATTERN = re.compile(
    r"(?m)^\s*public\s+"
    r".*?\s+"
    r"([A-Za-z_$][A-Za-z0-9_$]*)"
    r"\([^;]*\)"
    r"(?:\s+throws\s+[^;]+)?"
    r";"
)

MAPPING_PATTERN = re.compile(
    r"org\.springframework\.web\.bind\.annotation\."
    r"(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"
    r"\s*(?:\((.*?)\))?",
    re.DOTALL,
)

PARAMETER_PATTERN = re.compile(r"\{[^{}]+\}")


Operation = Tuple[str, str]


class IdentityGroundTruthError(RuntimeError):
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
        raise IdentityGroundTruthError(
            "Command failed:\n"
            f"{' '.join(command)}\n\n"
            f"stdout:\n{result.stdout}\n\n"
            f"stderr:\n{result.stderr}"
        )

    return result.stdout.strip()


def _docker_shell(container: str, script: str) -> str:
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


def join_paths(base_path: str, method_path: str) -> str:
    base_path = base_path.strip()
    method_path = method_path.strip()

    if not base_path and not method_path:
        return "/"

    if not base_path:
        return normalize_path(method_path)

    if not method_path:
        return normalize_path(base_path)

    return normalize_path(
        "/" + base_path.strip("/") + "/" + method_path.strip("/")
    )


def _extract_paths(annotation_body: Optional[str]) -> List[str]:
    if not annotation_body:
        return [""]

    for attribute in ("value", "path"):
        array_match = re.search(
            rf"\b{attribute}\s*=\s*\[(.*?)\]",
            annotation_body,
            re.DOTALL,
        )

        if array_match:
            values = re.findall(
                r'"([^"]*)"',
                array_match.group(1),
            )
            if values:
                return values

        scalar_match = re.search(
            rf'\b{attribute}\s*=\s*"([^"]*)"',
            annotation_body,
        )

        if scalar_match:
            return [scalar_match.group(1)]

    return [""]


def _extract_request_mapping_methods(
    annotation_body: Optional[str],
) -> List[str]:
    if not annotation_body:
        return []

    methods = re.findall(
        r"RequestMethod;\.([A-Z]+)",
        annotation_body,
    )

    return [
        method
        for method in methods
        if method in HTTP_METHODS
    ]


def _extract_mapping_annotations(
    text: str,
) -> List[Tuple[str, List[str], List[str]]]:
    mappings: List[Tuple[str, List[str], List[str]]] = []

    for match in MAPPING_PATTERN.finditer(text):
        annotation_name = match.group(1)
        annotation_body = match.group(2)

        paths = _extract_paths(annotation_body)

        if annotation_name == "RequestMapping":
            methods = _extract_request_mapping_methods(
                annotation_body
            )
        else:
            methods = SPRING_MAPPING_METHODS[annotation_name]

        mappings.append(
            (
                annotation_name,
                methods,
                paths,
            )
        )

    return mappings


def _extract_class_base_paths(javap_text: str) -> List[str]:
    class_close = javap_text.rfind("\n}")

    if class_close == -1:
        class_tail = javap_text
    else:
        class_tail = javap_text[class_close + 2 :]

    mappings = _extract_mapping_annotations(class_tail)

    base_paths: List[str] = []

    for annotation_name, _, paths in mappings:
        if annotation_name != "RequestMapping":
            continue

        base_paths.extend(paths)

    if not base_paths:
        return [""]

    return base_paths


def parse_controller_javap(
    javap_text: str,
) -> Set[Operation]:
    operations: Set[Operation] = set()

    base_paths = _extract_class_base_paths(javap_text)

    method_headers = list(
        METHOD_HEADER_PATTERN.finditer(javap_text)
    )

    class_close = javap_text.rfind("\n}")

    if class_close == -1:
        class_close = len(javap_text)

    for index, method_match in enumerate(method_headers):
        start = method_match.start()

        if index + 1 < len(method_headers):
            end = method_headers[index + 1].start()
        else:
            end = class_close

        method_block = javap_text[start:end]

        mappings = _extract_mapping_annotations(method_block)

        for _, methods, method_paths in mappings:
            if not methods:
                continue

            for base_path in base_paths:
                for method_path in method_paths:
                    full_path = join_paths(
                        base_path,
                        method_path,
                    )

                    for http_method in methods:
                        operations.add(
                            (
                                http_method.upper(),
                                full_path,
                            )
                        )

    return operations


def prepare_identity_classes(
    container: str,
    jar_path: str,
    extraction_root: str,
) -> None:
    script = f"""
set -e

rm -rf {extraction_root}
mkdir -p {extraction_root}
cd {extraction_root}

JAR_BIN="$(command -v jar || true)"

if [ -z "$JAR_BIN" ]; then
    JAR_BIN="/opt/java/openjdk/bin/jar"
fi

"$JAR_BIN" xf \
    {jar_path} \
    BOOT-INF/classes/com/crapi/controller
"""

    _docker_shell(container, script)


def list_controller_classes(
    container: str,
    extraction_root: str,
) -> List[str]:
    controller_dir = (
        f"{extraction_root}/"
        "BOOT-INF/classes/com/crapi/controller"
    )

    output = _docker_shell(
        container,
        (
            f'find "{controller_dir}" '
            '-maxdepth 1 '
            '-type f '
            '-name "*.class"'
        ),
    )

    classes: List[str] = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        filename = Path(line).name

        if "$" in filename:
            continue

        if not filename.endswith(".class"):
            continue

        class_name = filename[:-6]

        classes.append(
            f"com.crapi.controller.{class_name}"
        )

    return sorted(set(classes))


def javap_controller(
    container: str,
    extraction_root: str,
    class_name: str,
) -> str:
    classpath = (
        f"{extraction_root}/BOOT-INF/classes"
    )

    script = f"""
set -e

JAVAP_BIN="$(command -v javap || true)"

if [ -z "$JAVAP_BIN" ]; then
    JAVAP_BIN="/opt/java/openjdk/bin/javap"
fi

"$JAVAP_BIN" \
    -v \
    -classpath "{classpath}" \
    "{class_name}"
"""

    return _docker_shell(container, script)


def extract_identity_operations(
    container: str = "crapi-identity",
    jar_path: str = "/app/identity-service-1.0-SNAPSHOT.jar",
    extraction_root: str = "/tmp/crapi_identity_ground_truth",
    raw_output_path: Optional[Path] = None,
) -> Set[Operation]:
    prepare_identity_classes(
        container,
        jar_path,
        extraction_root,
    )

    controller_classes = list_controller_classes(
        container,
        extraction_root,
    )

    if not controller_classes:
        raise IdentityGroundTruthError(
            "No controller classes were discovered."
        )

    operations: Set[Operation] = set()
    raw_sections: List[str] = []

    for class_name in controller_classes:
        javap_text = javap_controller(
            container,
            extraction_root,
            class_name,
        )

        raw_sections.append(
            "\n".join(
                [
                    "=" * 80,
                    class_name,
                    "=" * 80,
                    javap_text,
                    "",
                ]
            )
        )

        operations.update(
            parse_controller_javap(javap_text)
        )

    if raw_output_path is not None:
        raw_output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        raw_output_path.write_text(
            "\n".join(raw_sections),
            encoding="utf-8",
        )

    return operations


def load_documented_identity_operations(
    openapi_path: Path,
) -> Set[Operation]:
    with openapi_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        spec = json.load(file)

    operations: Set[Operation] = set()

    for path, path_item in spec.get(
        "paths",
        {},
    ).items():
        if not path.startswith("/identity/api/"):
            continue

        if not isinstance(path_item, dict):
            continue

        for method in path_item:
            method_upper = method.upper()

            if method_upper not in HTTP_METHODS:
                continue

            operations.add(
                (
                    method_upper,
                    normalize_path(path),
                )
            )

    return operations


def get_container_evidence(
    container: str,
    jar_path: str,
) -> Dict[str, Any]:
    image_reference = _run_command(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.Config.Image}}",
        ]
    )

    image_id = _run_command(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.Image}}",
        ]
    )

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
    )

    try:
        repo_digests = json.loads(
            repo_digests_raw
        )
    except Exception:
        repo_digests = []

    jar_hash_output = _docker_shell(
        container,
        f'sha256sum "{jar_path}"',
    )

    jar_sha256 = jar_hash_output.split()[0]

    return {
        "docker_container": container,
        "docker_image_reference": image_reference,
        "docker_image_id": image_id,
        "docker_repo_digests": repo_digests,
        "application_jar": jar_path,
        "application_jar_sha256": jar_sha256,
    }


def build_identity_ground_truth(
    openapi_path: Path,
    output_path: Path,
    *,
    raw_output_path: Optional[Path] = None,
    container: str = "crapi-identity",
    jar_path: str = "/app/identity-service-1.0-SNAPSHOT.jar",
) -> Dict[str, Any]:
    raw_implemented = extract_identity_operations(
        container=container,
        jar_path=jar_path,
        raw_output_path=raw_output_path,
    )

    normalized_implemented = {
        (
            method,
            normalize_path(path),
        )
        for method, path in raw_implemented
    }

    in_scope = {
        operation
        for operation in normalized_implemented
        if operation[1].startswith(
            "/identity/api/"
        )
    }

    excluded = (
        normalized_implemented - in_scope
    )

    documented = (
        load_documented_identity_operations(
            openapi_path
        )
    )

    documented_implemented = (
        in_scope & documented
    )

    shadow_operations = (
        in_scope - documented
    )

    evidence = get_container_evidence(
        container,
        jar_path,
    )

    result: Dict[str, Any] = {
        "service": "identity",
        "scope": "/identity/api/...",
        "ground_truth_definition": (
            "Implemented Spring controller operations "
            "extracted deterministically from the fixed "
            "crAPI Identity Docker container and compared "
            "against the historical OpenAPI baseline."
        ),
        "evidence": {
            **evidence,
            "route_extraction": (
                "Spring mapping annotations extracted "
                "with javap -v"
            ),
            "openapi_baseline": str(
                openapi_path
            ),
        },
        "scope_exclusions": [
            {
                "method": method,
                "path": path,
            }
            for method, path in sorted(excluded)
        ],
        "summary": {
            "raw_implemented_operations": len(
                normalized_implemented
            ),
            "in_scope_implemented_operations": len(
                in_scope
            ),
            "excluded_outside_scope": len(
                excluded
            ),
            "documented_implemented_operations": len(
                documented_implemented
            ),
            "implemented_but_undocumented": len(
                shadow_operations
            ),
        },
        "implemented_operations": [
            {
                "method": method,
                "path": path,
            }
            for method, path in sorted(in_scope)
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