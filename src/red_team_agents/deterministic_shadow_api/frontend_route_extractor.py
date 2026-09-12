import json
import re
from pathlib import Path
from typing import Any, Dict, List


FUNCTIONAL_ROOTS = (
    "identity",
    "community",
    "workshop",
)


ROUTE_PATTERN = re.compile(
    r"""(?P<quote>["'`])
        (?P<path>
            /(?:identity|community|workshop)
            /[^"'`\s\\]*
        )
        (?P=quote)
    """,
    re.VERBOSE,
)

# =========================================================
# VAMOS ADICIONAR ESSAS FUNÇÕES QUE FARÃO O EXTRACTOR RECONSTRUIR
# APENAS COMBINAÇÕES REALMENTE OBSERVADAS NO JAVASCRIPT E NÃO
# FAZER UM PRODUTO CARTESIANO ENTRE TODOS OS PREFIXOS E TODAS AS ROTAS

PREFIX_ASSIGNMENT_PATTERN = re.compile(
    r'(?P<variable>[A-Za-z_$][A-Za-z0-9_$]*)='
    r'["\'](?P<prefix>identity/|community/|workshop/)["\']'
)


API_CONSTANT_PATTERN = re.compile(
    r'(?P<key>[A-Z][A-Z0-9_]*)'
    r':["\'](?P<path>api/[^"\']+)["\']'
)


COMPOSED_ROUTE_PATTERN = re.compile(
    r'(?P<prefix_var>[A-Za-z_$][A-Za-z0-9_$]*)'
    r'\+'
    r'(?P<object_var>[A-Za-z_$][A-Za-z0-9_$]*)'
    r'\.'
    r'(?P<key>[A-Z][A-Z0-9_]*)'
)


def extract_service_prefixes(
    javascript: str,
) -> Dict[str, str]:
    """
    Extract frontend service-prefix variables such as:

        og="identity/"
        ig="workshop/"
        lg="community/"
    """

    prefixes: Dict[str, str] = {}

    for match in PREFIX_ASSIGNMENT_PATTERN.finditer(
        javascript
    ):
        variable = match.group("variable")
        prefix = match.group("prefix")

        prefixes[variable] = prefix

    return prefixes


def extract_api_constants(
    javascript: str,
) -> Dict[str, str]:
    """
    Extract API path constants such as:

        GET_USER:"api/v2/user/dashboard"
    """

    constants: Dict[str, str] = {}

    for match in API_CONSTANT_PATTERN.finditer(
        javascript
    ):
        key = match.group("key")
        path = match.group("path")

        constants[key] = path

    return constants


def extract_composed_frontend_routes(
    javascript: str,
) -> List[str]:
    """
    Reconstruct only service/API combinations that are
    actually referenced by the frontend code.

    Example:

        og="identity/"
        GET_USER:"api/v2/user/dashboard"
        og+sg.GET_USER

    becomes:

        /identity/api/v2/user/dashboard
    """

    prefixes = extract_service_prefixes(
        javascript
    )

    constants = extract_api_constants(
        javascript
    )

    routes = set()

    for match in COMPOSED_ROUTE_PATTERN.finditer(
        javascript
    ):
        prefix_var = match.group(
            "prefix_var"
        )

        key = match.group(
            "key"
        )

        prefix = prefixes.get(
            prefix_var
        )

        relative_path = constants.get(
            key
        )

        if not prefix or not relative_path:
            continue

        route = "/" + prefix + relative_path

        route = clean_route_candidate(
            route
        )

        routes.add(
            route
        )

    return sorted(routes)

# ==========================================================
def clean_route_candidate(
    value: str,
) -> str:
    """
    Conservatively clean a frontend route candidate.

    This does not convert identifiers into placeholders
    and does not infer HTTP methods.
    """

    value = value.strip()

    # Common escaped slash representation in JavaScript.
    value = value.replace("\\/", "/")

    # Remove fragment/query only for candidate comparison.
    value = value.split("#", 1)[0]
    value = value.split("?", 1)[0]

    if len(value) > 1:
        value = value.rstrip("/")

    return value


# Agora precisamos integrar isso com o extractor existente. Substitui a função atual POR ESTA:
def extract_frontend_routes(
    javascript: str,
) -> List[str]:
    """
    Extract frontend API route candidates using two
    independent deterministic strategies:

    1. literal full-path extraction;
    2. reconstruction of actually observed
       service-prefix + API-constant compositions.

    No runtime existence or HTTP method is inferred here.
    """

    candidates = set()

    # Strategy 1:
    # complete literal paths already present in the bundle.
    for match in ROUTE_PATTERN.finditer(
        javascript
    ):
        raw_path = match.group(
            "path"
        )

        cleaned = clean_route_candidate(
            raw_path
        )

        if cleaned:
            candidates.add(
                cleaned
            )

    # Strategy 2:
    # reconstructed paths such as:
    # og + sg.GET_USER
    for route in extract_composed_frontend_routes(
        javascript
    ):
        candidates.add(
            route
        )

    return sorted(
        candidates
    )


# precisamos extrair deterministicamente o método HTTP observado no próprio JavaScript, porque já vimos evidências como:

# og+sg.GET_USER        → method:"GET"
# ig+sg.GET_ORDERS      → method:"GET"
# lg+sg.ADD_NEW_POST    → method:"POST"

# Assim teremos candidatos de operação, não apenas de caminho.
# ======================================================================
def extract_frontend_operations(
    javascript: str,
) -> List[Dict[str, Any]]:
    """
    Extract frontend API operations by combining:

    - observed service-prefix variables;
    - observed API constants;
    - actual prefix + constant usage;
    - HTTP method observed in the nearby fetch() call.

    These remain frontend-derived candidates.
    Runtime existence is not established here.
    """

    prefixes = extract_service_prefixes(
        javascript
    )

    constants = extract_api_constants(
        javascript
    )

    operations = set()

    for match in COMPOSED_ROUTE_PATTERN.finditer(
        javascript
    ):
        prefix_var = match.group(
            "prefix_var"
        )

        key = match.group(
            "key"
        )

        prefix = prefixes.get(
            prefix_var
        )

        relative_path = constants.get(
            key
        )

        if not prefix or not relative_path:
            continue

        route = clean_route_candidate(
            "/" + prefix + relative_path
        )

        # Search only a bounded local window after the
        # composition expression.
        context_start = match.start()
        context_end = min(
            len(javascript),
            match.end() + 700,
        )

        context = javascript[
            context_start:context_end
        ]

        method_match = re.search(
            r'method\s*:\s*["\']'
            r'(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)'
            r'["\']',
            context,
            re.IGNORECASE,
        )

        if not method_match:
            continue

        method = method_match.group(
            1
        ).upper()

        operations.add(
            (
                route,
                method,
                key,
                prefix_var,
            )
        )

    return [
        {
            "path": path,
            "method": method,
            "frontend_constant": key,
            "prefix_variable": prefix_var,
            "source": "frontend_javascript",
        }
        for (
            path,
            method,
            key,
            prefix_var,
        ) in sorted(operations)
    ]

# ==========================================================

def extract_routes_from_file(
    raw_file: str | Path,
) -> Dict[str, Any]:

    raw_file = Path(raw_file)

    javascript = raw_file.read_text(
        encoding="utf-8",
        errors="replace",
    )

    routes = extract_frontend_routes(
        javascript
    )

    grouped = {
        "/identity": [],
        "/community": [],
        "/workshop": [],
    }

    for route in routes:

        for root in grouped:

            if (
                route == root
                or route.startswith(
                    root + "/"
                )
            ):
                grouped[root].append(
                    route
                )
                break

    return {
        "source": "frontend_javascript",
        "source_file": str(raw_file),
        "route_candidates_count": len(routes),
        "route_candidates": routes,
        "grouped_candidates": grouped,
    }


def write_extraction_report(
    raw_file: str | Path,
    output_file: str | Path,
) -> Dict[str, Any]:

    result = extract_routes_from_file(
        raw_file
    )

    output_file = Path(output_file)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return result