import json
import re
from pathlib import Path
from typing import Any, Dict, List


class ComplianceMappingPostProcessor:

    OWASP_BY_FINDING_TYPE = {
        "BOLA": {
            "category_id": "API1:2023",
            "category_name": "Broken Object Level Authorization",
        },
        "BFLA": {
            "category_id": "API5:2023",
            "category_name": "Broken Function Level Authorization",
        },
        "SHADOW_API": {
            "category_id": "API9:2023",
            "category_name": "Improper Inventory Management",
        },
    }

    ALLOWED_NIS2_ARTICLES = {
        "21(2)(a)",
        "21(2)(e)",
        "21(2)(f)",
        "21(2)(i)",
    }

    MITRE_TECHNIQUE_PATTERN = re.compile(
        r"^T\d{4}(?:\.\d{3})?$"
    )

    def __init__(
        self,
        findings_path: Path | str = (
            "outputs/analysis/validated_analyst_findings.json"
        ),
        draft_path: Path | str = (
            "outputs/compliance/compliance_mapping_draft.json"
        ),
        output_path: Path | str = (
            "outputs/compliance/validated_compliance_mapping.json"
        ),
        markdown_path: Path | str = (
            "reports/compliance_and_threat_mapping_report.md"
        ),
    ) -> None:

        self.findings_path = Path(findings_path)
        self.draft_path = Path(draft_path)
        self.output_path = Path(output_path)
        self.markdown_path = Path(markdown_path)

    def run(self) -> Dict[str, Any]:

        findings_document = self._load_json(
            self.findings_path
        )

        draft_document = self._load_json(
            self.draft_path
        )

        authoritative_findings = findings_document.get(
            "threat_compliance_context_findings"
        )

        if authoritative_findings is None:
            authoritative_findings = findings_document.get(
                "mapping_ready_findings",
                [],
            )

        draft_mappings = self._extract_draft_mappings(
            draft_document
        )

        self._validate_unique_ids(draft_mappings)

        draft_by_id = {
            item["canonical_id"]: item
            for item in draft_mappings
            if item.get("canonical_id")
        }

        validated_mappings = []

        mapping_checks = []

        for finding in authoritative_findings:

            canonical_id = finding["canonical_id"]

            draft = draft_by_id.get(canonical_id)

            if draft is None:
                available_ids = sorted(
                    draft_by_id.keys()
                )

                raise ValueError(
                    f"Compliance mapping missing for {canonical_id}. "
                    f"Draft contains canonical IDs: {available_ids}"
                )

            validated = self._validate_mapping(
                finding=finding,
                draft=draft,
                checks=mapping_checks,
            )

            validated_mappings.append(validated)

        authoritative_ids = {
            item["canonical_id"]
            for item in authoritative_findings
        }

        mapped_ids = {
            item["canonical_id"]
            for item in validated_mappings
        }

        if authoritative_ids != mapped_ids:
            raise ValueError(
                "Compliance mapping IDs do not match "
                "mapping_ready_findings."
            )

        summary = self._build_summary(
            validated_mappings
        )

        metadata = findings_document[
            "metadata"
        ]

        expected_count = metadata.get(
            "threat_compliance_context_count",
            metadata["mapping_ready_count"],
        )

        consistency_checks = (
            self._build_consistency_checks(
                mappings=validated_mappings,
                summary=summary,
                expected_count=expected_count,
            )
        )

        result = {
            "status": "completed",
            "processor": "ComplianceMappingPostProcessor",

            "source": str(self.findings_path),

            "source_provenance": findings_document.get(
                "provenance",
                {},
            ),

            "validated_mappings": validated_mappings,

            "mapping_summary": summary,

            "mapping_checks": mapping_checks,

            "consistency_checks": consistency_checks,
        }

        self._write_json(
            self.output_path,
            result,
        )

        self._write_markdown(
            self.markdown_path,
            result,
        )

        return result


    def _validate_mapping(
        self,
        finding: Dict[str, Any],
        draft: Dict[str, Any],
        checks: List[Dict[str, Any]],
    ) -> Dict[str, Any]:

        canonical_id = finding["canonical_id"]

        expected_type = self._resolve_finding_type(
            finding
        )

        expected_owasp = self.OWASP_BY_FINDING_TYPE[
            expected_type
        ]

        draft_owasp = draft.get("owasp", {})

        draft_category = draft_owasp.get(
            "category_id"
        )

        owasp_corrected = (
            draft_category
            != expected_owasp["category_id"]
        )

        checks.append({
            "canonical_id": canonical_id,
            "check": "owasp_classification",
            "draft_value": draft_category,
            "validated_value": expected_owasp[
                "category_id"
            ],
            "corrected": owasp_corrected,
        })

        mitre = self._validate_mitre(
            draft.get(
                "mitre_attack",
                {},
            )
        )

        nis2 = self._validate_nis2(
            draft.get(
                "nis2",
                {},
            )
        )

        return {
            # Authoritative fields are NEVER taken
            # from the Compliance LLM.

            "canonical_id": canonical_id,

            "final_status": finding.get(
                "final_status"
            ),

            "finding_type": expected_type,

            "test_id": finding.get(
                "test_id"
            ),

            "endpoint": finding.get(
                "endpoint"
            ),

            "http_method": finding.get(
                "http_method"
            ),

            "owasp": {
                "category_id": expected_owasp[
                    "category_id"
                ],
                "category_name": expected_owasp[
                    "category_name"
                ],
                "authorization_class": expected_type,

                "rationale": self._build_owasp_rationale(
                    finding=finding,
                    draft_owasp=draft_owasp,
                    expected_type=expected_type,
                    expected_owasp=expected_owasp,
                    owasp_corrected=owasp_corrected,
                ),
            },

            "mitre_attack": mitre,

            "nis2": nis2,
        }

    # A regra que elimina definitivamente a oscilação BOLA/BFLA
    def _build_owasp_rationale(
        self,
        finding: Dict[str, Any],
        draft_owasp: Dict[str, Any],
        expected_type: str,
        expected_owasp: Dict[str, str],
        owasp_corrected: bool,
    ) -> str:

        draft_rationale = str(
            draft_owasp.get("rationale", "")
        ).strip()

        if not owasp_corrected and draft_rationale:
            return draft_rationale

        endpoint = finding.get("endpoint")
        method = finding.get("http_method")
        canonical_id = finding.get("canonical_id")

        if expected_type == "BOLA":
            return (
                f"{canonical_id} was deterministically validated as a BOLA finding "
                f"on {method} {endpoint}; therefore it maps to "
                f"{expected_owasp['category_id']} - {expected_owasp['category_name']}."
            )

        if expected_type == "BFLA":
            return (
                f"{canonical_id} was deterministically validated as a BFLA finding "
                f"on {method} {endpoint}; therefore it maps to "
                f"{expected_owasp['category_id']} - {expected_owasp['category_name']}."
            )

        if expected_type == "SHADOW_API":
            return (
                f"{canonical_id} was deterministically validated as a Shadow API "
                f"finding on {method} {endpoint}; therefore it maps to "
                f"{expected_owasp['category_id']} - {expected_owasp['category_name']}."
            )

        return (
            f"{canonical_id} was deterministically mapped to "
            f"{expected_owasp['category_id']} - {expected_owasp['category_name']}."
        )


    def _resolve_finding_type(
        self,
        finding: Dict[str, Any],
    ) -> str:

        endpoint = str(
            finding.get("endpoint", "")
        ).lower()

        related_test_ids = [
            str(item.get("test_id", "")).upper()
            for item in finding.get("related_evidence", [])
            if isinstance(item, dict)
        ]

        test_id = str(
            finding.get("test_id", "")
        ).strip().upper()

        finding_type = str(
            finding.get("finding_type", "")
        ).strip().upper()

        # Deterministic override for clearly role/function-restricted endpoints
        if (
            "/management/" in endpoint
            or any(value.startswith("BFLA") for value in related_test_ids)
        ):
            return "BFLA"

        if finding_type in {"BOLA", "BFLA", "SHADOW_API"}:
            return finding_type

        if test_id.startswith("BOLA"):
            return "BOLA"

        if test_id.startswith("BFLA"):
            return "BFLA"

        raise ValueError(
            "Cannot deterministically determine "
            f"BOLA/BFLA classification for {finding.get('canonical_id')}. "
            "finding_type must be BOLA, BFLA, or SHADOW_API, "
            "or test_id must preserve BOLA/BFLA provenance upstream."
        )

    # MITRE passa a ser reconciliado deterministicamente
    def _validate_mitre(
        self,
        mitre: Dict[str, Any],
    ) -> Dict[str, Any]:

        techniques = mitre.get(
            "techniques",
            []
        )

        if not isinstance(techniques, list):
            techniques = []

        valid_techniques = []

        for technique in techniques:

            technique_id = str(
                technique.get(
                    "technique_id",
                    ""
                )
            ).strip()

            if self.MITRE_TECHNIQUE_PATTERN.match(
                technique_id
            ):
                valid_techniques.append(
                    technique
                )

        direct_mapping = bool(
            valid_techniques
        )

        return {
            "direct_mapping": direct_mapping,
            "techniques": valid_techniques,
            "rationale": mitre.get(
                "rationale",
                "",
            ),
        }

    # NIS2 também fica controlado
    def _validate_nis2(
        self,
        nis2: Dict[str, Any],
    ) -> Dict[str, Any]:

        primary = nis2.get("primary")

        secondary = nis2.get(
            "secondary",
            []
        )

        if not isinstance(secondary, list):
            secondary = []

        validated_secondary = []

        validated_primary = None

        if isinstance(primary, dict):

            article = self._normalise_nis2_article(
                primary.get("article")
            )

            if article in self.ALLOWED_NIS2_ARTICLES:

                validated_primary = {
                    **primary,
                    "article": article,
                }

        for item in secondary:

            if not isinstance(item, dict):
                continue

            article = self._normalise_nis2_article(
                item.get("article")
            )

            if article in self.ALLOWED_NIS2_ARTICLES:

                validated_secondary.append({
                    **item,
                    "article": article,
                })

        if validated_primary is None:

            raise ValueError(
                "Each mapping-ready finding must "
                "contain a valid primary NIS2 mapping."
            )

        return {
            "primary": validated_primary,
            "secondary": validated_secondary,
        }


    def _normalise_nis2_article(
        self,
        article: Any,
    ) -> str:

        text = str(article or "").strip()

        match = re.search(
            r"21\s*\(\s*2\s*\)\s*\(\s*([a-z])\s*\)",
            text,
            flags=re.IGNORECASE,
        )

        if not match:
            return text.replace(
                "Article ",
                "",
            ).strip()

        letter = match.group(1).lower()

        return f"21(2)({letter})"

    # E as contagens deixam completamente de pertencer ao LLM
    def _build_summary(
        self,
        mappings: List[Dict[str, Any]],
    ) -> Dict[str, int]:

        bola_count = sum(
            1
            for item in mappings
            if item["finding_type"] == "BOLA"
        )

        bfla_count = sum(
            1
            for item in mappings
            if item["finding_type"] == "BFLA"
        )

        shadow_api_count = sum(
            1
            for item in mappings
            if item["finding_type"] == "SHADOW_API"
        )

        direct_mitre_count = sum(
            1
            for item in mappings
            if item["mitre_attack"][
                "direct_mapping"
            ]
        )

        nis2_count = sum(
            1
            for item in mappings
            if item["nis2"]["primary"]
        )

        total = len(mappings)

        return {
            "mapping_ready_count": total,
            "bola_count": bola_count,
            "bfla_count": bfla_count,
            "shadow_api_count": shadow_api_count,
            "direct_mitre_count": direct_mitre_count,
            "no_direct_mitre_count": (
                total - direct_mitre_count
            ),
            "nis2_mapped_count": nis2_count,
        }

     # método run() chama _validate_unique_ids, _build_consistency_checks, _write_json, 
     # _write_markdown e _load_json, mas essas funções ainda não existem no ficheiro
     # então adicionamos estes metodos
    def _validate_unique_ids(
        self,
        mappings: List[Dict[str, Any]],
    ) -> None:
        seen = set()

        for item in mappings:
            canonical_id = item.get("canonical_id")

            if not canonical_id:
                raise ValueError(
                    "Every compliance mapping must contain canonical_id."
                )

            if canonical_id in seen:
                raise ValueError(
                    f"Duplicate compliance mapping for {canonical_id}."
                )

            seen.add(canonical_id)


    def _build_consistency_checks(
        self,
        mappings: List[Dict[str, Any]],
        summary: Dict[str, int],
        expected_count: int,
    ) -> List[Dict[str, Any]]:

        total = len(mappings)

        checks = [
            {
                "name": "mapped_count_equals_metadata_mapping_ready_count",
                "passed": total == expected_count,
                "message": (
                    f"mapped={total}, "
                    f"metadata.mapping_ready_count={expected_count}"
                ),
            },
            {
                "name": "bola_bfla_shadow_equals_context_count",
                "passed": (
                    summary["bola_count"]
                    + summary["bfla_count"]
                    + summary["shadow_api_count"]
                    == expected_count
                ),
                "message": (
                    f"BOLA={summary['bola_count']}, "
                    f"BFLA={summary['bfla_count']}, "
                    f"SHADOW_API={summary['shadow_api_count']}, "
                    f"expected={expected_count}"
                ),
            },
            {
                "name": "mitre_counts_equal_mapping_ready_count",
                "passed": (
                    summary["direct_mitre_count"]
                    + summary["no_direct_mitre_count"]
                    == expected_count
                ),
                "message": (
                    f"direct={summary['direct_mitre_count']}, "
                    f"no_direct={summary['no_direct_mitre_count']}, "
                    f"expected={expected_count}"
                ),
            },
            {
                "name": "nis2_mapped_count_equals_mapping_ready_count",
                "passed": (
                    summary["nis2_mapped_count"]
                    == expected_count
                ),
                "message": (
                    f"NIS2={summary['nis2_mapped_count']}, "
                    f"expected={expected_count}"
                ),
            },
            {
                "name": "unique_canonical_ids",
                "passed": (
                    len({item["canonical_id"] for item in mappings})
                    == total
                ),
                "message": "All validated compliance mappings use unique canonical IDs.",
            },
        ]

        return checks


    def _load_json(
        self,
        path: Path,
    ) -> Dict[str, Any]:

        if not path.exists():
            raise FileNotFoundError(
                f"Required file not found: {path}"
            )

        raw_text = path.read_text(
            encoding="utf-8"
        ).strip()

        try:
            return json.loads(raw_text)

        except json.JSONDecodeError:
            # Handles cases where an LLM writes JSON inside Markdown fences.
            fenced_match = re.search(
                r"```(?:json)?\s*(.*?)\s*```",
                raw_text,
                flags=re.DOTALL | re.IGNORECASE,
            )

            if fenced_match:
                return json.loads(
                    fenced_match.group(1)
                )

            raise


    def _write_json(
        self,
        path: Path,
        payload: Dict[str, Any],
    ) -> None:

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            json.dumps(
                payload,
                indent=4,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


    def _write_markdown(
        self,
        path: Path,
        result: Dict[str, Any],
    ) -> None:

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        summary = result["mapping_summary"]
        provenance = result.get("source_provenance", {})
        mappings = result["validated_mappings"]
        checks = result["consistency_checks"]

        lines = [
            "# Compliance and Threat Mapping Report",
            "",
            "## 1. Compliance mapping scope",
            "",
            "This report is generated from deterministically validated compliance mappings.",
            "The technical finding set remains authoritative from `validated_analyst_findings.json`.",
            "",
            "No HTTP execution, vulnerability revalidation, deduplication, merging, splitting, or status changes were performed during this phase.",
            "",
            "---",
            "",
            "## 2. Validated evidence provenance",
            "",
            f"- generated_at_utc: `{provenance.get('generated_at_utc')}`",
            f"- source_file: `{provenance.get('source_file')}`",
            f"- source_file_mtime_utc: `{provenance.get('source_file_mtime_utc')}`",
            f"- source_file_sha256: `{provenance.get('source_file_sha256')}`",
            "",
            "---",
            "",
            "## 3. Mapping summary",
            "",
            f"- Total mapping-ready findings: `{summary['mapping_ready_count']}`",
            f"- API1:2023 BOLA count: `{summary['bola_count']}`",
            f"- API5:2023 BFLA count: `{summary['bfla_count']}`",
            f"- API9:2023 Shadow API count: `{summary['shadow_api_count']}`",
            f"- Findings with direct defensible MITRE ATT&CK mapping: `{summary['direct_mitre_count']}`",
            f"- Findings with no direct defensible MITRE ATT&CK mapping: `{summary['no_direct_mitre_count']}`",
            f"- Findings with NIS2 relevance mapping: `{summary['nis2_mapped_count']}`",
            "",
            "---",
            "",
            "## 4. Reconciliation checks",
            "",
        ]

        for check in checks:
            status = "PASS" if check["passed"] else "FAIL"
            lines.extend(
                [
                    f"- `{status}` — {check['name']}: {check['message']}",
                ]
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "## 5. Finding-by-finding mapping",
                "",
            ]
        )

        for item in mappings:
            mitre = item["mitre_attack"]
            nis2 = item["nis2"]
            owasp = item["owasp"]

            if mitre["direct_mapping"]:
                mitre_text = ", ".join(
                    technique.get("technique_id", "")
                    for technique in mitre["techniques"]
                )
            else:
                mitre_text = "No direct defensible MITRE ATT&CK mapping identified from the validated evidence."

            secondary_nis2 = nis2.get("secondary", [])

            lines.extend(
                [
                    f"### {item['canonical_id']}",
                    "",
                    f"- Endpoint: `{item.get('endpoint')}`",
                    f"- HTTP method: `{item.get('http_method')}`",
                    f"- Final status: `{item.get('final_status')}`",
                    f"- Finding type: `{item.get('finding_type')}`",
                    f"- Test ID: `{item.get('test_id')}`",
                    "",
                    "**OWASP API Security Top 10 2023**",
                    "",
                    f"- Primary: `{owasp['category_id']} - {owasp['category_name']}`",
                    f"- Authorization class: `{owasp['authorization_class']}`",
                    f"- Rationale: {owasp.get('rationale', '')}",
                    "",
                    "**MITRE ATT&CK**",
                    "",
                    f"- {mitre_text}",
                    f"- Rationale: {mitre.get('rationale', '')}",
                    "",
                    "**NIS2 relevance**",
                    "",
                    f"- Primary: `Article {nis2['primary']['article']}`",
                    f"- Rationale: {nis2['primary'].get('rationale', '')}",
                ]
            )

            if secondary_nis2:
                lines.append("")
                lines.append("Secondary NIS2 relevance:")

                for secondary in secondary_nis2:
                    lines.append(
                        f"- `Article {secondary['article']}` — {secondary.get('rationale', '')}"
                    )

            lines.extend(
                [
                    "",
                    "---",
                    "",
                ]
            )

        lines.extend(
            [
                "## 6. Compliance conclusions",
                "",
                f"- Total findings mapped: `{summary['mapping_ready_count']}`",
                f"- OWASP reconciliation: `BOLA {summary['bola_count']} + BFLA {summary['bfla_count']} + SHADOW_API {summary['shadow_api_count']} = {summary['mapping_ready_count']}`",
                f"- MITRE reconciliation: `{summary['direct_mitre_count']} direct + {summary['no_direct_mitre_count']} no-direct = {summary['mapping_ready_count']}`",
                f"- NIS2 reconciliation: `{summary['nis2_mapped_count']} mapped = {summary['mapping_ready_count']}`",
                "",
                "The NIS2 mappings express cybersecurity risk-management relevance and do not constitute a legal determination of non-compliance.",
            ]
        )

        path.write_text(
            "\n".join(lines),
            encoding="utf-8",
        )


    # E para tornar o pós-processador mais robusto caso o CrewAI grave 
    # o JSON dentro de uma chave como raw, adiciona este método:
    def _extract_draft_mappings(
        self,
        draft_document: Dict[str, Any],
    ) -> List[Dict[str, Any]]:

        mappings = draft_document.get("mappings")

        if isinstance(mappings, list):
            return mappings

        for key in ["raw", "output", "result", "content"]:
            value = draft_document.get(key)

            if not isinstance(value, str):
                continue

            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                continue

            if (
                isinstance(parsed, dict)
                and isinstance(parsed.get("mappings"), list)
            ):
                return parsed["mappings"]

        raise ValueError(
            "No valid 'mappings' array found in compliance_mapping_draft.json."
        )