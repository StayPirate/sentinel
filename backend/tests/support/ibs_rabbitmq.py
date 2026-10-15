"""Shared IBS RabbitMQ delivery fixtures.

The files under `backend/tests/fixtures/ibs_rabbitmq/` hold sanitized
deliveries of the IBS event bus (docs/data-sources.md, IBS/OBS RabbitMQ
Event Bus):

- `deliveries.json`: the observed AMQP properties and one delivery per
  observed `suse.obs.package.commit` member set, a personal `home:` project,
  and the unbound non-JSON `suse.obs.metrics` family. Every value is
  fictional; routing keys, properties, member sets and order, value types,
  and the compact JSON serialization are the observed ones.
- `hostile_deliveries.json`: synthetic malformed and edge-case deliveries,
  each with its expected outcome.

`Delivery` carries the parts of one delivery the consumer reads: routing
key, content type, content encoding, and the exact body bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Final

FIXTURE_DIR: Final = Path(__file__).resolve().parents[1] / "fixtures" / "ibs_rabbitmq"

PACKAGE_COMMIT: Final = "suse.obs.package.commit"

PACKAGE_COMMIT_FIXTURES: Final = (
    "package_commit_files",
    "package_commit_comment_files",
    "package_commit_comment_files_requestid",
    "package_commit_comment",
    "package_commit_bare",
    "package_commit_comment_requestid",
)
"""The observed `SUSE:` package-commit member sets, most frequent first."""

HOME_PROJECT_FIXTURE: Final = "package_commit_home_project"
METRICS_FIXTURE: Final = "metrics_line_protocol"


@dataclass(frozen=True, slots=True)
class Delivery:
    """The consumer-visible parts of one AMQP delivery."""

    routing_key: str
    content_type: str | None
    content_encoding: str | None
    body: bytes


@dataclass(frozen=True, slots=True)
class HostileCase:
    """One synthetic delivery and its expected outcome."""

    id: str
    delivery: Delivery
    outcome: str
    reason: str | None
    project: str | None
    package: str | None


@cache
def _document(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURE_DIR / name).read_text("utf-8"))
    return data


def observed_properties() -> dict[str, Any]:
    """The AMQP properties observed on every delivery."""
    properties: dict[str, Any] = _document("deliveries.json")["properties"]
    return properties


def delivery_names() -> tuple[str, ...]:
    return tuple(_document("deliveries.json")["deliveries"])


def load_delivery(name: str) -> Delivery:
    """One sanitized delivery with the observed properties."""
    entry = _document("deliveries.json")["deliveries"][name]
    properties = observed_properties()
    return Delivery(
        routing_key=entry["routing_key"],
        content_type=properties["content_type"],
        content_encoding=properties["content_encoding"],
        body=entry["body"].encode("utf-8"),
    )


def hostile_cases() -> tuple[HostileCase, ...]:
    """Every synthetic case of `hostile_deliveries.json`, in file order."""
    cases = []
    for entry in _document("hostile_deliveries.json")["cases"]:
        body = (
            entry["body"].encode("utf-8")
            if "body" in entry
            else bytes.fromhex(entry["body_hex"])
        )
        expected = entry["expected"]
        cases.append(
            HostileCase(
                id=entry["id"],
                delivery=Delivery(
                    routing_key=entry["routing_key"],
                    content_type=entry["content_type"],
                    content_encoding=entry.get("content_encoding"),
                    body=body,
                ),
                outcome=expected["outcome"],
                reason=expected.get("reason"),
                project=expected.get("project"),
                package=expected.get("package"),
            )
        )
    return tuple(cases)
