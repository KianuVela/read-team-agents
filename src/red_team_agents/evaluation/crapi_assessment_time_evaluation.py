from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[3]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "reports"
    / "evaluation"
    / "crapi_assessment_time_evaluation.json"
)


TIMED_ARTIFACTS = [
    PROJECT_ROOT / "reports" / "api_discovery" / "runtime_evidence_aggregated.json",
    PROJECT_ROOT / "reports" / "shadow_api" / "shadow_candidate_validation.json",
    PROJECT_ROOT / "outputs" / "analysis" / "validated_analyst_findings.json",
    PROJECT_ROOT / "outputs" / "compliance" / "validated_compliance_mapping.json",
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_endpoint_coverage_evaluation.json",
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_shadow_api_evaluation.json",
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_bola_bfla_evaluation.json",
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_mapping_evaluation.json",
    PROJECT_ROOT / "reports" / "evaluation" / "crapi_artifact_completeness_evaluation.json",
]


def _iso_from_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def evaluate_crapi_assessment_time(
    output_path: Path = OUTPUT_PATH,
) -> Dict[str, Any]:

    output_path = Path(output_path)

    artifact_records: List[Dict[str, Any]] = []

    for path in TIMED_ARTIFACTS:
        if not path.exists():
            artifact_records.append(
                {
                    "path": str(path),
                    "exists": False,
                    "modified_at_utc": None,
                    "mtime": None,
                }
            )
            continue

        mtime = path.stat().st_mtime

        artifact_records.append(
            {
                "path": str(path),
                "exists": True,
                "modified_at_utc": _iso_from_timestamp(mtime),
                "mtime": mtime,
            }
        )

    existing = [
        record
        for record in artifact_records
        if record["exists"] and record["mtime"] is not None
    ]

    if existing:
        start_record = min(existing, key=lambda item: item["mtime"])
        end_record = max(existing, key=lambda item: item["mtime"])

        start_time = start_record["mtime"]
        end_time = end_record["mtime"]
        duration_seconds = end_time - start_time
    else:
        start_record = None
        end_record = None
        start_time = None
        end_time = None
        duration_seconds = 0.0

    result = {
        "schema_version": "1.0",
        "evaluation": "crapi_assessment_time",
        "status": "completed" if existing else "no_artifacts_found",
        "metric_definition": {
            "name": "Assessment Time",
            "formula": "End Time - Start Time",
            "unit": "seconds",
        },
        "measurement_policy": {
            "measurement_source": "filesystem_artifact_modification_time",
            "interpretation": (
                "This measures the elapsed time between the earliest and latest "
                "assessment artefact timestamps available in the local filesystem. "
                "It is suitable as an audit proxy for the completed assessment run, "
                "but a clean benchmark run should be used for final performance claims."
            ),
        },
        "summary": {
            "evaluated_artifacts": len(TIMED_ARTIFACTS),
            "existing_artifacts": len(existing),
            "missing_artifacts": len(TIMED_ARTIFACTS) - len(existing),
            "start_time_utc": _iso_from_timestamp(start_time)
            if start_time is not None
            else None,
            "end_time_utc": _iso_from_timestamp(end_time)
            if end_time is not None
            else None,
            "duration_seconds": duration_seconds,
            "duration_minutes": duration_seconds / 60,
        },
        "start_artifact": start_record,
        "end_artifact": end_record,
        "artifacts": artifact_records,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result


def main() -> None:
    result = evaluate_crapi_assessment_time()
    summary = result["summary"]

    print()
    print("crAPI ASSESSMENT TIME EVALUATION")
    print("=" * 70)

    print("Evaluated artefacts:", summary["evaluated_artifacts"])
    print("Existing artefacts:", summary["existing_artifacts"])
    print("Missing artefacts:", summary["missing_artifacts"])
    print("Start time UTC:", summary["start_time_utc"])
    print("End time UTC:", summary["end_time_utc"])

    print()
    print("METRIC")
    print("-" * 70)
    print(f'Assessment Time: {summary["duration_seconds"]:.2f} seconds')
    print(f'Assessment Time: {summary["duration_minutes"]:.2f} minutes')

    print()
    print("Output:", OUTPUT_PATH)


if __name__ == "__main__":
    main()
