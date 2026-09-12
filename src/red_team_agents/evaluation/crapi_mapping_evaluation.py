from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]

GROUND_TRUTH_PATH = (
    PROJECT_ROOT
    / "reports"
    / "ground_truth"
    / "crapi_mapping_ground_truth.json"
)

VALIDATED_MAPPING_PATH = (
    PROJECT_ROOT
    / "outputs"
    / "compliance"
    / "validated_compliance_mapping.json"
)

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_mapping_evaluation.json"
)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalise_method(value: Any) -> str:
    return str(value or "").strip().upper()


def _normalise_path(value: Any) -> str:
    path = str(value or "").strip()

    if not path:
        return ""

    if not path.startswith("/"):
        path = "/" + path

    return path.rstrip("/") or "/"


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    normalised = _normalise_path(pattern)
    escaped = re.escape(normalised)
    escaped = re.sub(r"\\\{[^/]+?\\\}", r"[^/]+", escaped)
    return re.compile("^" + escaped + "$")


def _endpoint_matches(expected_pattern: str, actual_endpoint: str) -> bool:
    expected_pattern = _normalise_path(expected_pattern)
    actual_endpoint = _normalise_path(actual_endpoint)

    if "{" in expected_pattern and "}" in expected_pattern:
        return bool(_pattern_to_regex(expected_pattern).match(actual_endpoint))

    return expected_pattern == actual_endpoint


def _extract_secondary_nis2_articles(mapping: Dict[str, Any]) -> List[str]:
    secondary = mapping.get("nis2", {}).get("secondary", [])

    if not isinstance(secondary, list):
        return []

    articles = []

    for item in secondary:
        if isinstance(item, dict) and item.get("article"):
            articles.append(str(item["article"]))

    return sorted(set(articles))


def _extract_mitre_techniques(mapping: Dict[str, Any]) -> List[str]:
    techniques = mapping.get("mitre_attack", {}).get("techniques", [])

    if not isinstance(techniques, list):
        return []

    result = []

    for technique in techniques:
        if isinstance(technique, dict) and technique.get("technique_id"):
            result.append(str(technique["technique_id"]))
        elif isinstance(technique, str):
            result.append(technique)

    return sorted(set(result))


def _normalise_framework_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "canonical_id": mapping.get("canonical_id"),
        "finding_type": str(mapping.get("finding_type", "")).strip().upper(),
        "method": _normalise_method(mapping.get("http_method")),
        "endpoint": _normalise_path(mapping.get("endpoint")),
        "owasp_category_id": mapping.get("owasp", {}).get("category_id"),
        "owasp_category_name": mapping.get("owasp", {}).get("category_name"),
        "mitre_direct_mapping": bool(
            mapping.get("mitre_attack", {}).get("direct_mapping", False)
        ),
        "mitre_techniques": _extract_mitre_techniques(mapping),
        "nis2_primary_article": (
            mapping.get("nis2", {}).get("primary", {}).get("article")
        ),
        "nis2_secondary_articles": _extract_secondary_nis2_articles(mapping),
        "source_mapping": mapping,
    }


def _framework_mappings(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    mappings = document.get("validated_mappings", [])

    if not isinstance(mappings, list):
        return []

    return [
        _normalise_framework_mapping(mapping)
        for mapping in mappings
        if isinstance(mapping, dict)
    ]


def _find_matching_framework_mapping(
    gt: Dict[str, Any],
    mappings: List[Dict[str, Any]],
    used_indexes: set[int],
) -> Optional[tuple[int, Dict[str, Any]]]:

    expected_method = _normalise_method(gt.get("expected_method"))
    expected_pattern = gt.get("expected_endpoint_pattern", "")

    candidates = []

    for index, mapping in enumerate(mappings):
        if index in used_indexes:
            continue

        if expected_method and mapping["method"] != expected_method:
            continue

        if not _endpoint_matches(expected_pattern, mapping["endpoint"]):
            continue

        candidates.append((index, mapping))

    if not candidates:
        return None

    expected_type = str(gt.get("expected_finding_type", "")).strip().upper()

    candidates.sort(
        key=lambda item: (
            item[1]["finding_type"] != expected_type,
            item[1]["canonical_id"] or "",
        )
    )

    return candidates[0]


def _evaluate_mapping_dimensions(
    gt: Dict[str, Any],
    mapping: Dict[str, Any],
) -> Dict[str, Any]:

    expected_type = str(gt.get("expected_finding_type", "")).strip().upper()

    expected_owasp = gt.get("expected_owasp", {})
    expected_mitre = gt.get("expected_mitre_attack", {})
    expected_nis2 = gt.get("expected_nis2", {})

    expected_secondary = sorted(
        set(expected_nis2.get("secondary_articles", []))
    )

    actual_secondary = mapping["nis2_secondary_articles"]

    dimensions = {
        "finding_type_match": mapping["finding_type"] == expected_type,
        "owasp_category_match": (
            mapping["owasp_category_id"]
            == expected_owasp.get("category_id")
        ),
        "mitre_direct_mapping_match": (
            mapping["mitre_direct_mapping"]
            == bool(expected_mitre.get("direct_mapping", False))
        ),
        "mitre_techniques_match": (
            mapping["mitre_techniques"]
            == sorted(set(expected_mitre.get("techniques", [])))
        ),
        "nis2_primary_article_match": (
            mapping["nis2_primary_article"]
            == expected_nis2.get("primary_article")
        ),
        "nis2_secondary_articles_valid": set(actual_secondary).issubset(
            set(expected_secondary)
        ),
    }

    core_checks = [
        dimensions["finding_type_match"],
        dimensions["owasp_category_match"],
        dimensions["mitre_direct_mapping_match"],
        dimensions["mitre_techniques_match"],
        dimensions["nis2_primary_article_match"],
        dimensions["nis2_secondary_articles_valid"],
    ]

    dimensions["fully_correct_mapping"] = all(core_checks)

    return dimensions


def evaluate_crapi_mapping(
    ground_truth_path: Path = GROUND_TRUTH_PATH,
    validated_mapping_path: Path = VALIDATED_MAPPING_PATH,
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    ground_truth_path = Path(ground_truth_path)
    validated_mapping_path = Path(validated_mapping_path)
    output_path = Path(output_path)

    ground_truth = _load_json(ground_truth_path)
    validated_mapping_document = _load_json(validated_mapping_path)

    gt_mappings = ground_truth.get("ground_truth_mappings", [])
    framework_mappings = _framework_mappings(validated_mapping_document)

    used_framework_indexes: set[int] = set()

    matched_mappings = []
    missing_ground_truth_mappings = []

    for gt in gt_mappings:
        match = _find_matching_framework_mapping(
            gt=gt,
            mappings=framework_mappings,
            used_indexes=used_framework_indexes,
        )

        if match is None:
            missing_ground_truth_mappings.append(gt)
            continue

        index, framework_mapping = match
        used_framework_indexes.add(index)

        dimensions = _evaluate_mapping_dimensions(
            gt=gt,
            mapping=framework_mapping,
        )

        matched_mappings.append(
            {
                "ground_truth_id": gt.get("ground_truth_id"),
                "linked_detection_ground_truth_id": gt.get(
                    "linked_detection_ground_truth_id"
                ),
                "challenge_name": gt.get("challenge_name"),
                "framework_canonical_id": framework_mapping["canonical_id"],
                "method": framework_mapping["method"],
                "endpoint": framework_mapping["endpoint"],
                "expected_finding_type": gt.get("expected_finding_type"),
                "actual_finding_type": framework_mapping["finding_type"],
                "expected_owasp": gt.get("expected_owasp"),
                "actual_owasp": {
                    "category_id": framework_mapping["owasp_category_id"],
                    "category_name": framework_mapping["owasp_category_name"],
                },
                "expected_mitre_attack": gt.get("expected_mitre_attack"),
                "actual_mitre_attack": {
                    "direct_mapping": framework_mapping[
                        "mitre_direct_mapping"
                    ],
                    "techniques": framework_mapping["mitre_techniques"],
                },
                "expected_nis2": gt.get("expected_nis2"),
                "actual_nis2": {
                    "primary_article": framework_mapping[
                        "nis2_primary_article"
                    ],
                    "secondary_articles": framework_mapping[
                        "nis2_secondary_articles"
                    ],
                },
                "dimension_checks": dimensions,
            }
        )

    out_of_scope_framework_mappings = []

    for index, mapping in enumerate(framework_mappings):
        if index in used_framework_indexes:
            continue

        out_of_scope_framework_mappings.append(
            {
                "framework_canonical_id": mapping["canonical_id"],
                "finding_type": mapping["finding_type"],
                "method": mapping["method"],
                "endpoint": mapping["endpoint"],
                "scope_status": "outside_selected_challenge_ground_truth",
            }
        )

    fully_correct = [
        item
        for item in matched_mappings
        if item["dimension_checks"]["fully_correct_mapping"]
    ]

    type_correct = [
        item
        for item in matched_mappings
        if item["dimension_checks"]["finding_type_match"]
    ]

    owasp_correct = [
        item
        for item in matched_mappings
        if item["dimension_checks"]["owasp_category_match"]
    ]

    mitre_correct = [
        item
        for item in matched_mappings
        if (
            item["dimension_checks"]["mitre_direct_mapping_match"]
            and item["dimension_checks"]["mitre_techniques_match"]
        )
    ]

    nis2_primary_correct = [
        item
        for item in matched_mappings
        if item["dimension_checks"]["nis2_primary_article_match"]
    ]

    gt_total = len(gt_mappings)
    matched_total = len(matched_mappings)

    def pct(numerator: int, denominator: int) -> float:
        return (numerator / denominator * 100) if denominator else 0.0

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_challenge_scoped_mapping_evaluation",
        "status": "completed",
        "methodological_boundary": {
            "ground_truth_used_for_discovery": False,
            "ground_truth_used_for_detection": False,
            "ground_truth_used_for_mapping_generation": False,
            "ground_truth_used_only_for_final_evaluation": True,
        },
        "scope_note": (
            "This is a challenge-scoped mapping evaluation. Framework "
            "mappings that do not correspond to the selected official "
            "BOLA/BFLA challenge ground truth are reported as out of scope, "
            "not as substantive false positives."
        ),
        "inputs": {
            "ground_truth": str(ground_truth_path),
            "validated_mapping": str(validated_mapping_path),
        },
        "summary": {
            "ground_truth_mappings": gt_total,
            "framework_validated_mappings": len(framework_mappings),
            "matched_ground_truth_mappings": matched_total,
            "missing_ground_truth_mappings": len(
                missing_ground_truth_mappings
            ),
            "out_of_scope_framework_mappings": len(
                out_of_scope_framework_mappings
            ),
            "fully_correct_mappings": len(fully_correct),
            "finding_type_correct": len(type_correct),
            "owasp_category_correct": len(owasp_correct),
            "mitre_mapping_correct": len(mitre_correct),
            "nis2_primary_correct": len(nis2_primary_correct),
            "mapping_precision_percent": pct(
                len(fully_correct),
                len(framework_mappings),
            ),
            "mapping_recall_percent": pct(
                len(fully_correct),
                gt_total,
            ),
            "challenge_scope_recall_percent": pct(matched_total, gt_total),
            "fully_correct_mapping_percent": pct(len(fully_correct), gt_total),
            "owasp_category_accuracy_on_matched_percent": pct(
                len(owasp_correct),
                matched_total,
            ),
            "nis2_primary_accuracy_on_matched_percent": pct(
                len(nis2_primary_correct),
                matched_total,
            ),
        },
        "matched_mappings": matched_mappings,
        "missing_ground_truth_mappings": missing_ground_truth_mappings,
        "out_of_scope_framework_mappings": out_of_scope_framework_mappings,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_mapping()

    summary = result["summary"]

    print()
    print("crAPI CHALLENGE-SCOPED MAPPING EVALUATION")
    print("=" * 70)

    print("Ground-truth mappings:", summary["ground_truth_mappings"])
    print("Framework validated mappings:", summary["framework_validated_mappings"])
    print("Matched ground-truth mappings:", summary["matched_ground_truth_mappings"])
    print("Missing ground-truth mappings:", summary["missing_ground_truth_mappings"])
    print("Out-of-scope framework mappings:", summary["out_of_scope_framework_mappings"])

    print()
    print("MAPPING QUALITY")
    print("-" * 70)

    print("Fully correct mappings:", summary["fully_correct_mappings"])
    print("Finding-type correct:", summary["finding_type_correct"])
    print("OWASP category correct:", summary["owasp_category_correct"])
    print("MITRE mapping correct:", summary["mitre_mapping_correct"])
    print("NIS2 primary correct:", summary["nis2_primary_correct"])

    print()
    print("METRICS")
    print("-" * 70)

    print(
        f'Mapping Precision: '
        f'{summary["mapping_precision_percent"]:.2f}%'
    )
    print(
        f'Mapping Recall:    '
        f'{summary["mapping_recall_percent"]:.2f}%'
    )
    print(
        f'Challenge-scope recall: '
        f'{summary["challenge_scope_recall_percent"]:.2f}%'
    )
    print(
        f'Fully correct mapping: '
        f'{summary["fully_correct_mapping_percent"]:.2f}%'
    )
    print(
        f'OWASP accuracy on matched: '
        f'{summary["owasp_category_accuracy_on_matched_percent"]:.2f}%'
    )
    print(
        f'NIS2 primary accuracy on matched: '
        f'{summary["nis2_primary_accuracy_on_matched_percent"]:.2f}%'
    )

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()

