from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import shlex
from urllib.parse import urlparse

import hashlib
from datetime import datetime, timezone


class AnalystFindingsPostProcessor:
    """
    Deterministic post-processor for Analyst findings.

    This class does not execute HTTP requests and does not use an LLM.
    It reads structured authorization evidence and produces canonical,
    deduplicated and mapping-ready findings for the Compliance Agent.
    """

    def __init__(
        self,
        evidence_summary_path: str | Path = "outputs/execution/authorization_evidence_summary.json",
        output_json_path: str | Path = "outputs/analysis/validated_analyst_findings.json",
        output_markdown_path: str | Path = "reports/validated_analyst_findings.md",
    ) -> None:
        self.evidence_summary_path = Path(evidence_summary_path)
        self.output_json_path = Path(output_json_path)
        self.output_markdown_path = Path(output_markdown_path)

    def run(self) -> Dict[str, Any]:
        evidence = self._load_json(self.evidence_summary_path)

        confirmed_static_candidates = self._collect_static_candidates(evidence)
        dynamic_candidates = self._collect_dynamic_candidates(evidence)
        review_candidates = self._collect_review_candidates(evidence)

        confirmed_static = self._build_confirmed_static_findings(
            confirmed_static_candidates
        )

        confirmed_dynamic = self._build_confirmed_dynamic_findings(
            dynamic_candidates
        )

        review_findings = self._build_review_findings(
            review_candidates=review_candidates,
            confirmed_static=confirmed_static,
            confirmed_dynamic=confirmed_dynamic,
        )

        expected_denials = self._build_expected_denials(evidence)

        mapping_ready = confirmed_static + confirmed_dynamic

        result = {
            "status": "completed",
            "processor": "AnalystFindingsPostProcessor",
            "source": str(self.evidence_summary_path),

            "provenance": {
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "source_file": str(self.evidence_summary_path),
                "source_file_mtime_utc": self._file_mtime_iso(self.evidence_summary_path),
                "source_file_sha256": self._file_sha256(self.evidence_summary_path),
            },


            "confirmed_static_findings": confirmed_static,
            "confirmed_dynamic_findings": confirmed_dynamic,
            "review_findings": review_findings,
            "expected_denials": expected_denials,
            "mapping_ready_findings": mapping_ready,
            "metadata": {
                "confirmed_static_count": len(confirmed_static),
                "confirmed_dynamic_count": len(confirmed_dynamic),
                "review_count": len(review_findings),
                "expected_denial_count": len(expected_denials),
                "total_confirmed_count": len(mapping_ready),
                "mapping_ready_count": len(mapping_ready),
            },
            "consistency_checks": self._build_consistency_checks(
                confirmed_static=confirmed_static,
                confirmed_dynamic=confirmed_dynamic,
                review_findings=review_findings,
                mapping_ready=mapping_ready,
            ),
        }

        self._write_json(self.output_json_path, result)
        self._write_markdown(self.output_markdown_path, result)

        return result

    # ----------------------------------------------------
    # Métodos que adicionamos depois de fazer imports de: 
    # import shlex | from urllib.parse import urlparse
    # ---------------------------------------------------

    def _extract_http_method(self, item: Dict[str, Any]) -> str:
        method = self._get(item, "http_method") or self._get(item, "method")

        if method:
            return self._normalise_method(method)

        arguments = self._get(item, "arguments")

        if not isinstance(arguments, str):
            return ""

        try:
            parts = shlex.split(arguments)
        except ValueError:
            parts = arguments.split()

        for index, part in enumerate(parts):
            if part in {"-X", "--request"} and index + 1 < len(parts):
                return self._normalise_method(parts[index + 1])

        return ""


    def _extract_endpoint(self, item: Dict[str, Any]) -> str:
        endpoint = (
            self._get(item, "endpoint")
            or self._get(item, "follow_up_endpoint")
            or self._get(item, "source_endpoint")
        )

        if endpoint:
            return self._normalise_endpoint(endpoint)

        arguments = self._get(item, "arguments")

        if not isinstance(arguments, str):
            return ""

        try:
            parts = shlex.split(arguments)
        except ValueError:
            parts = arguments.split()

        for part in parts:
            if part.startswith("http://") or part.startswith("https://"):
                parsed = urlparse(part)
                endpoint_path = parsed.path

                if parsed.query:
                    endpoint_path = f"{endpoint_path}?{parsed.query}"

                return self._normalise_endpoint(endpoint_path)

        return ""

    # ------------------------------------------------------------------
    # Loading / writing
    # ------------------------------------------------------------------

    def _load_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise FileNotFoundError(f"Evidence summary not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise ValueError("Evidence summary must be a JSON object.")

        return data

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False,
            )

    def _write_markdown(self, path: Path, data: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        metadata = data["metadata"]

        lines = [
            "# Validated Analyst Findings",
            "",
            "## Deterministic totals",
            "",
            f"- Confirmed static findings: {metadata['confirmed_static_count']}",
            f"- Confirmed dynamic findings: {metadata['confirmed_dynamic_count']}",
            f"- Review findings: {metadata['review_count']}",
            f"- Expected denials: {metadata['expected_denial_count']}",
            f"- Total confirmed findings: {metadata['total_confirmed_count']}",
            f"- Mapping-ready findings: {metadata['mapping_ready_count']}",
            "",
            "## Confirmed static findings",
            "",
        ]

        for finding in data["confirmed_static_findings"]:
            lines.extend(self._markdown_finding_block(finding))

        lines.extend(
            [
                "",
                "## Confirmed dynamic findings",
                "",
            ]
        )

        for finding in data["confirmed_dynamic_findings"]:
            lines.extend(self._markdown_finding_block(finding))

        lines.extend(
            [
                "",
                "## Review findings",
                "",
            ]
        )

        for finding in data["review_findings"]:
            lines.extend(self._markdown_finding_block(finding))

        lines.extend(
            [
                "",
                "## Expected denials",
                "",
            ]
        )

        for finding in data["expected_denials"]:
            lines.extend(self._markdown_finding_block(finding))

        lines.extend(
            [
                "",
                "## Findings ready for OWASP, MITRE ATT&CK and NIS2 mapping",
                "",
            ]
        )

        for finding in data["mapping_ready_findings"]:
            lines.append(f"- {finding['canonical_id']}")

        lines.extend(
            [
                "",
                "## Consistency checks",
                "",
            ]
        )

        for check in data["consistency_checks"]:
            status = "PASS" if check["passed"] else "FAIL"
            lines.append(f"- **{status}** — {check['name']}: {check['message']}")

        path.write_text("\n".join(lines), encoding="utf-8")

    def _markdown_finding_block(self, finding: Dict[str, Any]) -> List[str]:
        lines = [
            f"### {finding['canonical_id']}",
            "",
            f"- Status: {finding['final_status']}",
            f"- Finding type: {finding.get('finding_type')}",
            f"- Test ID: {finding.get('test_id')}",
            f"- Endpoint: `{finding.get('endpoint')}`",
            f"- HTTP method: {finding.get('http_method')}",
            f"- Baseline comparison: {finding.get('baseline_comparison')}",
            f"- Vulnerability decision: {finding.get('vulnerability_decision')}",
            f"- Mapping ready: {finding.get('mapping_ready')}",
            f"- Reason: {finding.get('reason')}",
            "",
        ]

        return lines

    # ------------------------------------------------------------------
    # Candidate collection
    # ------------------------------------------------------------------

    def _collect_static_candidates(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = evidence.get("confirmed_static_findings", [])

        if isinstance(candidates, list):
            return candidates

        return []

    def _collect_dynamic_candidates(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates = evidence.get("dynamic_follow_up_findings", [])

        if isinstance(candidates, list):
            return candidates

        return []

    def _collect_review_candidates(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        review: List[Dict[str, Any]] = []

        for bucket_name in [
            "inconclusive_due_to_missing_fixture",
            "inconclusive_findings",
            "inconclusive_results",
            "analyst_review_findings",
        ]:
            bucket = evidence.get(bucket_name, [])
            if isinstance(bucket, list):
                review.extend(bucket)

        static_candidates = self._collect_static_candidates(evidence)

        for item in static_candidates:
            if not self._is_confirmed_static(item):
                review.append(item)

        return review

    # ------------------------------------------------------------------
    # Static findings
    # ------------------------------------------------------------------

    def _build_confirmed_static_findings(
        self,
        candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        canonical: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

        for item in candidates:
            if not self._is_confirmed_static(item):
                continue

            if self._has_dynamic_follow_up(item):
                continue

            key = self._static_dedup_key(item)

            finding = self._to_canonical_static(item)

            if key not in canonical:
                canonical[key] = finding
            else:
                canonical[key]["related_evidence"].extend(
                    finding.get("related_evidence", [])
                )

        findings = list(canonical.values())

        for index, finding in enumerate(findings, start=1):
            original_test_id = finding.get("test_id")

            if original_test_id:
                finding["canonical_id"] = original_test_id
            else:
                finding["canonical_id"] = f"CF-STATIC-{index:02d}"

        return findings

    def _is_confirmed_static(self, item: Dict[str, Any]) -> bool:
        """
        Confirmed static findings are accepted only when the execution
        evidence shows a vulnerable decision and a confirmed authorization
        bypass baseline.

        The authorization_finding field is useful when present, but it is
        not mandatory here because items already come from the
        confirmed_static_findings bucket.
        """

        vulnerability_decision = str(
            self._get(item, "vulnerability_decision", "")
        ).strip().lower()

        baseline_comparison = str(
            self._get(item, "baseline_comparison", "")
        ).strip().lower()

        return (
            vulnerability_decision == "vulnerable"
            and baseline_comparison == "confirms_authorization_bypass"
        )

    def _to_canonical_static(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "canonical_id": None,
            "final_status": "confirmed_static",
            "mapping_ready": True,
            "finding_type": self._get(item, "test_type") or self._get(item, "finding_type"),
            "test_id": self._get(item, "test_id") or self._get(item, "test_case_id"),
            "endpoint": self._extract_endpoint(item),
            "http_method": self._extract_http_method(item),
            "authorization_outcome": self._get(item, "authorization_outcome"),
            "authorization_finding": self._get(
                item,
                "authorization_finding",
                "potential_authorization_bypass",
            ),
            "vulnerability_decision": self._get(item, "vulnerability_decision"),
            "baseline_comparison": self._get(item, "baseline_comparison"),
            "matched_identifiers": self._get(item, "baseline_matched_identifiers")
            or self._get(item, "matched_identifiers")
            or [],
            "related_evidence": [self._evidence_ref(item)],
            "reason": "Static authorization bypass confirmed by vulnerable decision and baseline_comparison: confirms_authorization_bypass.",
            "source_item": item,
        }

    def _static_dedup_key(self, item: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            self._extract_http_method(item),
            self._extract_endpoint(item),
            self._get(item, "authorization_finding"),
            self._get(item, "baseline_comparison"),
        )

    # ------------------------------------------------------------------
    # Dynamic findings
    # ------------------------------------------------------------------

    def _build_confirmed_dynamic_findings(
        self,
        candidates: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        canonical: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

        for item in candidates:
            if not self._is_confirmed_dynamic(item):
                continue

            key = self._dynamic_dedup_key(item)
            finding = self._to_canonical_dynamic(item)

            if key not in canonical:
                canonical[key] = finding
            else:
                canonical[key]["related_evidence"].extend(
                    finding.get("related_evidence", [])
                )

        findings = list(canonical.values())

        for index, finding in enumerate(findings, start=1):
            original_test_id = finding.get("test_id")

            if original_test_id:
                finding["canonical_id"] = f"{original_test_id}-DYN"
            else:
                finding["canonical_id"] = f"CF-DYN-{index:02d}"

        return findings

    def _is_confirmed_dynamic(self, item: Dict[str, Any]) -> bool:
        follow_up = self._get_follow_up_execution(item)

        status_code = self._get(follow_up, "http_status") or self._get(
            follow_up, "status_code"
        )

        if not isinstance(status_code, int):
            return False

        return (
            200 <= status_code < 300
            and self._get(follow_up, "authorization_outcome") == "allowed"
            and self._get(follow_up, "authorization_finding")
            == "potential_authorization_bypass"
            and self._get(follow_up, "vulnerability_decision") == "vulnerable"
        )

    def _to_canonical_dynamic(self, item: Dict[str, Any]) -> Dict[str, Any]:

        follow_up = self._get_follow_up_execution(item)

        test_id = (
            self._get(item, "test_id")
            or self._get(item, "test_case_id")
        )

        # Determinar deterministicamente BOLA/BFLA
        finding_type = self._get(item, "finding_type")

        if str(finding_type).upper() not in {"BOLA", "BFLA"}:
            test_id_upper = str(test_id or "").upper()

            if test_id_upper.startswith("BOLA"):
                finding_type = "BOLA"
            elif test_id_upper.startswith("BFLA"):
                finding_type = "BFLA"
            else:
                finding_type = None

        return {
            "canonical_id": None,
            "final_status": "confirmed_dynamic",
            "mapping_ready": True,

            # OWASP authorization family
            "finding_type": finding_type,

            # Preserva a natureza dinâmica separadamente
            "finding_mode": "dynamic_authorization_bypass_chain",

            "test_id": test_id,

            "source_endpoint": (
                self._extract_endpoint(item)
                or self._get(item, "source_endpoint")
            ),

            "source_direct_decision": (
                self._get(item, "vulnerability_decision")
                or "inconclusive"
            ),

            # Follow-up confirmado
            "endpoint": (
                self._extract_endpoint(follow_up)
                or self._get(follow_up, "follow_up_endpoint")
            ),

            "http_method": (
                self._extract_http_method(follow_up)
                or self._get(follow_up, "http_method")
                or self._get(follow_up, "method")
            ),

            "http_status": (
                self._get(follow_up, "http_status")
                or self._get(follow_up, "status_code")
            ),

            "authorization_outcome": self._get(
                follow_up,
                "authorization_outcome"
            ),

            "authorization_finding": self._get(
                follow_up,
                "authorization_finding"
            ),

            "vulnerability_decision": self._get(
                follow_up,
                "vulnerability_decision"
            ),

            "baseline_comparison": "dynamic_follow_up_confirmed",

            "protected_object": (
                self._get(follow_up, "object_id")
                or self._get(follow_up, "report_id")
                or self._get(item, "generated_object_id")
            ),

            "related_evidence": [
                self._evidence_ref(item)
            ],

            "reason": (
                "Source endpoint remained inconclusive directly, "
                "but validated follow-up access confirmed a dynamic "
                "authorization bypass chain."
            ),

            "source_item": item,
        }

    def _dynamic_dedup_key(self, item: Dict[str, Any]) -> Tuple[Any, ...]:
        follow_up = self._get_follow_up_execution(item)

        return (
            self._normalise_endpoint(
                self._get(item, "endpoint") or self._get(item, "source_endpoint")
            ),
            self._normalise_endpoint(
                self._get(follow_up, "endpoint")
                or self._get(follow_up, "follow_up_endpoint")
            ),
            self._get(follow_up, "object_id")
            or self._get(follow_up, "report_id")
            or self._get(item, "generated_object_id"),
            self._get(follow_up, "vulnerability_decision"),
        )

    def _has_dynamic_follow_up(self, item: Dict[str, Any]) -> bool:
        return bool(
            item.get("state_changing_follow_up_execution")
            or item.get("follow_up_execution")
            or item.get("dynamic_follow_up_execution")
        )

    def _get_follow_up_execution(self, item: Dict[str, Any]) -> Dict[str, Any]:
        for key in [
            "state_changing_follow_up_execution",
            "follow_up_execution",
            "dynamic_follow_up_execution",
        ]:
            value = item.get(key)
            if isinstance(value, dict):
                return value

        return item

    # ------------------------------------------------------------------
    # Review and expected denials
    # ------------------------------------------------------------------

    def _build_review_findings(
        self,
        review_candidates: List[Dict[str, Any]],
        confirmed_static: List[Dict[str, Any]],
        confirmed_dynamic: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        confirmed_keys = {
            self._review_dedup_key(item["source_item"])
            for item in confirmed_static + confirmed_dynamic
            if isinstance(item.get("source_item"), dict)
        }

        canonical: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

        for item in review_candidates:
            key = self._review_dedup_key(item)

            if key in confirmed_keys:
                continue

            if key not in canonical:
                canonical[key] = self._to_review_finding(item)

        findings = list(canonical.values())

        for index, finding in enumerate(findings, start=1):
            finding["canonical_id"] = f"REVIEW-{index:02d}"

        return findings

    def _to_review_finding(self, item: Dict[str, Any]) -> Dict[str, Any]:
        baseline = self._get(item, "baseline_comparison")

        if baseline == "inconclusive":
            reason = "Suspicious or executed case, but baseline comparison is inconclusive; not mapping-ready."
        elif self._get(item, "missing_fixture_key"):
            reason = "Missing deterministic fixture prevented reliable validation."
        else:
            reason = "Evidence is insufficient for confirmed authorization bypass."

        return {
            "canonical_id": None,
            "final_status": "review",
            "mapping_ready": False,
            "finding_type": self._get(item, "test_type") or self._get(item, "finding_type"),
            "test_id": self._get(item, "test_id") or self._get(item, "test_case_id"),
            "endpoint": self._get(item, "endpoint"),
            "http_method": self._get(item, "http_method") or self._get(item, "method"),
            "authorization_outcome": self._get(item, "authorization_outcome"),
            "authorization_finding": self._get(item, "authorization_finding"),
            "vulnerability_decision": self._get(item, "vulnerability_decision"),
            "baseline_comparison": baseline,
            "related_evidence": [self._evidence_ref(item)],
            "reason": reason,
            "source_item": item,
        }

    def _build_expected_denials(self, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        expected_denials: List[Dict[str, Any]] = []

        all_candidates = []

        for bucket_name in [
            "expected_denials",
            "not_vulnerable_findings",
            "authorization_evidence",
            "evidence_summaries",
        ]:
            bucket = evidence.get(bucket_name, [])
            if isinstance(bucket, list):
                all_candidates.extend(bucket)

        canonical: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

        for item in all_candidates:
            if not self._is_expected_denial(item):
                continue

            key = self._review_dedup_key(item)

            if key not in canonical:
                canonical[key] = {
                    "canonical_id": None,
                    "final_status": "expected_denial",
                    "mapping_ready": False,
                    "finding_type": self._get(item, "test_type")
                    or self._get(item, "finding_type"),
                    "test_id": self._get(item, "test_id")
                    or self._get(item, "test_case_id"),
                    "endpoint": self._get(item, "endpoint"),
                    "http_method": self._get(item, "http_method")
                    or self._get(item, "method"),
                    "authorization_outcome": self._get(item, "authorization_outcome"),
                    "authorization_finding": self._get(item, "authorization_finding"),
                    "vulnerability_decision": self._get(item, "vulnerability_decision"),
                    "baseline_comparison": self._get(item, "baseline_comparison"),
                    "related_evidence": [self._evidence_ref(item)],
                    "reason": "Authorization boundary was meaningfully exercised and denied as expected.",
                    "source_item": item,
                }

        expected_denials = list(canonical.values())

        for index, finding in enumerate(expected_denials, start=1):
            finding["canonical_id"] = f"DENIAL-{index:02d}"

        return expected_denials

    def _is_expected_denial(self, item: Dict[str, Any]) -> bool:
        return (
            self._get(item, "authorization_outcome") == "denied"
            or self._get(item, "authorization_finding") == "expected_denial"
            or self._get(item, "vulnerability_decision") == "not_vulnerable"
        )

    def _review_dedup_key(self, item: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            self._normalise_method(self._get(item, "http_method") or self._get(item, "method")),
            self._normalise_endpoint(self._get(item, "endpoint")),
            self._get(item, "test_id") or self._get(item, "test_case_id"),
            self._get(item, "baseline_comparison"),
            self._get(item, "vulnerability_decision"),
        )

    # ------------------------------------------------------------------
    # Consistency checks
    # ------------------------------------------------------------------

    def _build_consistency_checks(
        self,
        confirmed_static: List[Dict[str, Any]],
        confirmed_dynamic: List[Dict[str, Any]],
        review_findings: List[Dict[str, Any]],
        mapping_ready: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        checks = []

        total_confirmed = len(confirmed_static) + len(confirmed_dynamic)

        checks.append(
            {
                "name": "total_confirmed_equals_mapping_ready",
                "passed": total_confirmed == len(mapping_ready),
                "message": f"confirmed={total_confirmed}, mapping_ready={len(mapping_ready)}",
            }
        )

        checks.append(
            {
                "name": "review_not_mapping_ready",
                "passed": all(not item["mapping_ready"] for item in review_findings),
                "message": "All review findings are excluded from mapping.",
            }
        )

        checks.append(
            {
                "name": "static_baseline_requirement",
                "passed": all(
                    item["baseline_comparison"] == "confirms_authorization_bypass"
                    for item in confirmed_static
                ),
                "message": "All static findings require baseline_comparison: confirms_authorization_bypass.",
            }
        )

        checks.append(
            {
                "name": "dynamic_not_static",
                "passed": all(
                    item["final_status"] != "confirmed_static"
                    for item in confirmed_dynamic
                ),
                "message": "Dynamic findings are not counted as static findings.",
            }
        )

        checks.append(
            {
                "name": "unique_mapping_ready_ids",
                "passed": len({item["canonical_id"] for item in mapping_ready})
                == len(mapping_ready),
                "message": "Mapping-ready finding IDs are unique.",
            }
        )

        return checks

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get(self, item: Any, key: str, default: Any = None) -> Any:
        if not isinstance(item, dict):
            return default

        return item.get(key, default)

    def _normalise_method(self, method: Optional[str]) -> str:
        if not method:
            return ""

        return str(method).strip().upper()

    def _normalise_endpoint(self, endpoint: Optional[str]) -> str:
        if not endpoint:
            return ""

        return str(endpoint).strip().split("?")[0]

    def _evidence_ref(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "test_id": self._get(item, "test_id") or self._get(item, "test_case_id"),
            "endpoint": self._get(item, "endpoint"),
            "http_method": self._get(item, "http_method") or self._get(item, "method"),
            "execution_index": self._get(item, "execution_index")
            or self._get(item, "index"),
        }


    # -----------------------------------------
    # Adicionamos estes métodos que adiciona metadados de 
    # proveniência para sabermos sempre qual ficheiro ele leu.
    # ------------------------------------------------
    def _file_sha256(self, path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                digest.update(chunk)

        return digest.hexdigest()


    def _file_mtime_iso(self, path: Path) -> str:
        return datetime.fromtimestamp(
            path.stat().st_mtime,
            tz=timezone.utc,
        ).isoformat()