from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExecutionContext:

    data: dict[str, Any] = field(default_factory=dict)

    @property
    def resource_models(self):
        return self.data.get("resource_models", [])

    @property
    def authentication(self):
        return self.data.get("authentication", {})

    @property
    def inventory(self):
        return self.data.get("inventory", {})

    @property
    def credentials(self):
        return self.data.get("credentials", {})

    @property
    def objects(self):
        return self.data.get("objects", {})