from urllib.parse import urlparse


class StateChangingFollowUpBuilder:
    """
    Builds follow-up validation targets from state-changing create flows.
    """

    def build_from_evidence(
        self,
        evidence: dict,
    ) -> dict | None:
        body_json = evidence.get(
            "body_json"
        )

        if not isinstance(
            body_json,
            dict,
        ):
            return None

        report_link = body_json.get(
            "report_link"
        )

        if not report_link:
            return None

        parsed = urlparse(
            str(
                report_link
            )
        )

        if parsed.path != "/workshop/api/mechanic/mechanic_report":
            return None

        if "report_id=" not in parsed.query:
            return None

        return {
            "flow_type": "state_changing_create_follow_up",
            "source_endpoint": "/workshop/api/mechanic/receive_report",
            "follow_up_method": "GET",
            "follow_up_endpoint": (
                f"{parsed.path}"
                f"?{parsed.query}"
            ),
            "expected_secure_behavior": (
                "A non-authorized actor should not be able to access "
                "the generated mechanic report by report_id."
            ),
        }