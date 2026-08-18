from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CollectionDescriptor:
    """
    Immutable description of a collection endpoint.
    """

    endpoint: str

    collection_key: str

    id_field: str = "id"