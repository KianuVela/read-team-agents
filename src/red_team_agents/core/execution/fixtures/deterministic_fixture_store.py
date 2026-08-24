from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DeterministicFixtureStore:
    """
    Stores stable actors and object identifiers used to make
    execution evidence reproducible across runs.
    """

    DEFAULT_PATH = Path(
        "outputs/execution/deterministic_fixtures.json"
    )

    REQUIRED_FIXTURE_KEYS = (
        "user_a_vehicle_id",
        "user_a_vin",
        "user_a_order_id",
        "user_a_post_id",
        "mechanic_code",
        "coupon_code",
    )

    def __init__(
        self,
        path: str | Path | None = None,
    ) -> None:
        self.path = Path(
            path or self.DEFAULT_PATH
        )

        self.data = self._load()

    def _load(
        self,
    ) -> dict[str, Any]:
        if not self.path.exists():
            self.path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            data = self._default_data()

            self.path.write_text(
                json.dumps(
                    data,
                    indent=4,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            return data

        return json.loads(
            self.path.read_text(
                encoding="utf-8",
            )
        )

    def _default_data(
        self,
    ) -> dict[str, Any]:
        return {
            "enabled": True,
            "profile": "crapi_local_deterministic",
            "note": (
                "This result was produced using deterministic fixtures."
            ),
            "actors": {
                "user_a": "user_a",
                "user_b": "user_b",
                "admin": "admin",
                "mechanic": "mechanic",
            },
            "fixtures": {
                "user_a_vehicle_id": None,
                "user_a_vin": None,
                "user_a_order_id": None,
                "user_a_post_id": None,
                "user_a_video_id": None,
                "user_a_report_id": None,
                "mechanic_code": "TRAC_JHN",
                "coupon_code": None,
            },
        }

    @property
    def enabled(
        self,
    ) -> bool:
        return bool(
            self.data.get(
                "enabled",
                False,
            )
        )

    def note(
        self,
    ) -> str:
        return str(
            self.data.get(
                "note",
                "This result was produced using deterministic fixtures.",
            )
        )

    def actor(
        self,
        actor_name: str,
    ) -> str | None:
        actors = self.data.get(
            "actors",
            {},
        )

        if not isinstance(
            actors,
            dict,
        ):
            return None

        value = actors.get(
            actor_name
        )

        if value is None:
            return None

        return str(
            value
        )

    def fixture(
        self,
        key: str,
    ) -> Any:
        fixtures = self.data.get(
            "fixtures",
            {},
        )

        if not isinstance(
            fixtures,
            dict,
        ):
            return None

        return fixtures.get(
            key
        )

    def set_fixture(
        self,
        key: str,
        value: Any,
        overwrite: bool = False,
    ) -> None:
        if value in (
            None,
            "",
            [],
            {},
        ):
            return

        fixtures = self.data.setdefault(
            "fixtures",
            {},
        )

        if (
            not overwrite
            and fixtures.get(key) not in (
                None,
                "",
                [],
                {},
            )
        ):
            return

        fixtures[key] = value

        self.save()

    def save(
        self,
    ) -> None:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.path.write_text(
            json.dumps(
                self.data,
                indent=4,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    def missing_required_fixtures(
        self,
    ) -> list[str]:
        return [
            key
            for key in self.REQUIRED_FIXTURE_KEYS
            if self.fixture(key) in (
                None,
                "",
                [],
                {},
            )
        ]

    def metadata(
        self,
    ) -> dict[str, Any]:
        return {
            "deterministic_fixtures_used": self.enabled,
            "deterministic_fixture_profile": self.data.get(
                "profile"
            ),
            "deterministic_fixture_note": self.note(),
            "missing_deterministic_fixtures": (
                self.missing_required_fixtures()
            ),
        }

    def resolve_fixture_for_endpoint(
        self,
        endpoint: str,
    ) -> tuple[str | None, Any]:
        endpoint = endpoint.lower()

        if "/vehicle/" in endpoint:
            return (
                "user_a_vehicle_id",
                self.fixture(
                    "user_a_vehicle_id"
                ),
            )

        if "/shop/orders/{order_id}" in endpoint:
            return (
                "user_a_order_id",
                self.fixture(
                    "user_a_order_id"
                ),
            )

        if "/community/posts/{postid}" in endpoint:
            return (
                "user_a_post_id",
                self.fixture(
                    "user_a_post_id"
                ),
            )

        if "/user/videos/{video_id}" in endpoint:
            return (
                "user_a_video_id",
                self.fixture(
                    "user_a_video_id"
                ),
            )

        if "/admin/videos/{video_id}" in endpoint:
            return (
                "user_a_video_id",
                self.fixture(
                    "user_a_video_id"
                ),
            )

        if "/mechanic/mechanic_report" in endpoint:
            return (
                "user_a_report_id",
                self.fixture(
                    "user_a_report_id"
                ),
            )

        if "/mechanic/receive_report" in endpoint:
            vin = self.fixture(
                "user_a_vin"
            )

            mechanic_code = self.fixture(
                "mechanic_code"
            )

            if vin and mechanic_code:
                return (
                    "receive_report_fixture",
                    {
                        "vin": vin,
                        "mechanic_code": mechanic_code,
                    },
                )

            return (
                "receive_report_fixture",
                None,
            )

        if "coupon" in endpoint:
            return (
                "coupon_code",
                self.fixture(
                    "coupon_code"
                ),
            )

        return (
            None,
            None,
        )