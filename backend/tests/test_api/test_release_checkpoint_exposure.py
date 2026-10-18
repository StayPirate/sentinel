"""Ticket and package API responses expose no release checkpoint.

See docs/features/packages/ibs-track-release-detection.md (Track Release
Checkpoint: "It is not included in normal Ticket or package API
responses") and docs/data-model.md (TicketPackageTrack,
TrackReleaseCheckpoint). The checkpoint and its `srcmd5` are operational
state of the release detection, not Ticket domain data.

Two complementary proofs:

- the OpenAPI document: no property reachable from the response of any
  Ticket, package, or maintainer package operation is named after the
  checkpoint or its `srcmd5`, so no response model can declare one;
- the wire: with a checkpoint stored for a track, the Ticket detail, the
  Ticket package tree, and the package search return that track or
  package but never the checkpoint value, so no serializer can leak it
  under another name.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, Final

import pytest
from httpx import AsyncClient

from app.main import app
from tests.support.ticket_api import locator

Factory = Callable[..., Awaitable[Any]]

_PREFIXES: Final = ("/api/v1/tickets", "/api/v1/packages", "/api/v1/my/packages")
_CHECKPOINT_NAME: Final = re.compile(r"(?i)checkpoint|srcmd5")
_HTTP_METHODS: Final = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

# Fictional checksum, distinctive enough to appear in no other response field.
_SRCMD5: Final = "c0ffee00c0ffee00c0ffee00c0ffee00"


def _resolve(document: dict[str, Any], reference: str) -> Any:
    node: Any = document
    for part in reference.removeprefix("#/").split("/"):
        node = node[part]
    return node


def _property_names(document: dict[str, Any], root: Any) -> set[str]:
    """Every property name reachable from `root`: nested `properties`,
    `items`, `anyOf`/`oneOf`/`allOf`, and every `$ref`, each referenced
    schema walked once."""
    names: set[str] = set()
    visited: set[str] = set()
    pending: list[Any] = [root]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            pending.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        reference = node.get("$ref")
        if isinstance(reference, str) and reference not in visited:
            visited.add(reference)
            pending.append(_resolve(document, reference))
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(properties)
        pending.extend(node.values())
    return names


def _operations(
    document: dict[str, Any],
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, item in document["paths"].items():
        if not path.startswith(_PREFIXES):
            continue
        for method, operation in item.items():
            if method in _HTTP_METHODS:
                yield method.upper(), path, operation


def _exposed_checkpoint_names(document: dict[str, Any]) -> dict[str, set[str]]:
    """`METHOD path` -> the checkpoint-like property names of its responses."""
    found: dict[str, set[str]] = {}
    for method, path, operation in _operations(document):
        names = {
            name
            for name in _property_names(document, operation.get("responses", {}))
            if _CHECKPOINT_NAME.search(name)
        }
        if names:
            found[f"{method} {path}"] = names
    return found


@pytest.mark.unit
class TestOpenAPIResponsesDeclareNoCheckpoint:
    def test_no_ticket_or_package_response_declares_a_checkpoint(self) -> None:
        document = app.openapi()

        assert list(_operations(document)), "no Ticket or package operation found"
        assert _exposed_checkpoint_names(document) == {}

    def test_detector_finds_a_nested_checkpoint_property(self) -> None:
        """A `release_checkpoint` reached through a response `$ref`, an
        `anyOf`, a second `$ref`, and an array `items` is found; an
        unrelated path is not walked."""
        document: dict[str, Any] = {
            "paths": {
                "/api/v1/tickets/{ticket_id}/packages": {
                    "parameters": [],
                    "get": {
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Page"}
                                    }
                                }
                            }
                        }
                    },
                },
                "/api/v1/cves": {
                    "get": {
                        "responses": {
                            "200": {"content": {"application/json": {"schema": {}}}}
                        }
                    }
                },
            },
            "components": {
                "schemas": {
                    "Page": {
                        "properties": {
                            "data": {
                                "anyOf": [
                                    {"$ref": "#/components/schemas/Track"},
                                    {"type": "null"},
                                ]
                            }
                        }
                    },
                    "Track": {
                        "properties": {
                            "id": {"type": "string"},
                            "history": {
                                "type": "array",
                                "items": {
                                    "properties": {
                                        "release_checkpoint": {"type": "string"},
                                        "self": {"$ref": "#/components/schemas/Track"},
                                    }
                                },
                            },
                        }
                    },
                }
            },
        }

        assert _exposed_checkpoint_names(document) == {
            "GET /api/v1/tickets/{ticket_id}/packages": {"release_checkpoint"}
        }

    @pytest.mark.parametrize("name", ["srcmd5", "SRCMD5", "checkpoint_at"])
    def test_detector_matches_every_checkpoint_name_form(self, name: str) -> None:
        document: dict[str, Any] = {
            "paths": {
                "/api/v1/packages": {
                    "get": {"responses": {"200": {"properties": {name: {}}}}}
                }
            }
        }

        assert _exposed_checkpoint_names(document) == {"GET /api/v1/packages": {name}}

    def test_detector_ignores_names_that_are_not_checkpoints(self) -> None:
        document: dict[str, Any] = {
            "paths": {
                "/api/v1/my/packages/pending": {
                    "get": {
                        "responses": {
                            "200": {"properties": {"reference": {}, "released_at": {}}}
                        }
                    }
                }
            }
        }

        assert _exposed_checkpoint_names(document) == {}


@pytest.mark.e2e
class TestResponsesOmitTheStoredCheckpoint:
    async def test_ticket_and_package_reads_do_not_return_the_checkpoint(
        self,
        client: AsyncClient,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_package_factory: Factory,
        ticket_package_track_factory: Factory,
        ticket_package_product_factory: Factory,
        track_release_checkpoint_factory: Factory,
    ) -> None:
        cve = await cve_factory()
        ticket = await ticket_factory(cve_id=cve.id)
        package = await ticket_package_factory(
            ticket_id=ticket.id, package_name="example-checkpoint-lib"
        )
        track = await ticket_package_track_factory(
            ticket_package_id=package.id, reference="Example:Codestream:1:Update"
        )
        await ticket_package_product_factory(ticket_package_track_id=track.id)
        await track_release_checkpoint_factory(
            ticket_package_track_id=track.id, srcmd5=_SRCMD5
        )

        reads = [
            (f"/api/v1/tickets/{locator(ticket)}", {}, str(track.id)),
            (f"/api/v1/tickets/{locator(ticket)}/packages", {}, str(track.id)),
            ("/api/v1/packages", {"name": "example-checkpoint-lib"}, str(package.id)),
        ]
        for path, params, anchor in reads:
            response = await client.get(path, params=params)

            assert response.status_code == 200, response.text
            assert anchor in response.text, path
            assert _SRCMD5 not in response.text, path
