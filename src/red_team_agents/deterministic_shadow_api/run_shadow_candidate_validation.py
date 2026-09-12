import json
from pathlib import Path

from red_team_agents.deterministic_shadow_api.shadow_candidate_validation import (
    validate_shadow_endpoint_candidates,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_ROOT
    / "reports"
    / "shadow_api"
    / "runtime_shadow_api_reconciliation.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "reports"
    / "shadow_api"
    / "shadow_candidate_validation.json"
)


def run_shadow_candidate_validation(
    input_file: Path = INPUT_FILE,
    output_file: Path = OUTPUT_FILE,
):

    input_file = Path(input_file)
    output_file = Path(output_file)

    with input_file.open(
        "r",
        encoding="utf-8",
    ) as file:
        reconciliation = json.load(file)

    validation = validate_shadow_endpoint_candidates(
        reconciliation
    )

    if "summary" not in validation:
        validation["summary"] = {
            "candidate_count": validation.get("candidate_count", 0),
            "confirmed_count": validation.get("confirmed_count", 0),
            "rejected_count": validation.get("rejected_count", 0),
        }

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            validation,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return validation


if __name__ == "__main__":

    result = run_shadow_candidate_validation()

    print("=" * 80)
    print("SHADOW API CANDIDATE VALIDATION")
    print("=" * 80)

    print(
        "Candidates:",
        result["candidate_count"],
    )

    print(
        "Confirmed:",
        result["confirmed_count"],
    )

    print(
        "Rejected:",
        result["rejected_count"],
    )

    print()

    for candidate in result["confirmed_candidates"]:

        print(
            candidate["method"],
            candidate["path"],
            "=>",
            candidate["validation_status"],
        )

    print()
    print(
        "Output:",
        OUTPUT_FILE,
    )