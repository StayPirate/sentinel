"""Contract tests for the IBS RabbitMQ deliveries the consumer reads.

Contract under test: docs/features/integrations/ibs-rabbitmq-integration.md
(AMQP Contract > Message Encoding; Consumed Events > Package Commit) and
docs/data-sources.md (IBS/OBS RabbitMQ Event Bus, Contract verification),
verified read-only and structure-only against `rabbit.suse.de` (RabbitMQ
4.1.5, exchange `pubsub`, default shared account): dedicated
`suse.obs.package.commit` captures from 2026-09-04 to 2026-09-07 (72.4 h,
9,620 deliveries) and on 2026-10-15 (1 h), and a re-verification on
2026-10-15 with aio-pika 10.1.1 and aiormq 7.2.2
(docs/conventions.md, External Integration Contract Verification). The
fixtures keep every observed structure and replace every value by a
fictional one. Every consumed field is asserted through a strict test-local
typed model, independent of the production decoder and parser.

Live observations:

- Every delivery had content type `application/octet-stream`, no content
  encoding, `delivery_mode` 2, priority 0, empty headers, an empty
  `cluster_id`, `redelivered = false`, and no message ID, correlation ID,
  timestamp, application ID, type, user ID, expiration, or reply-to.
- Every package-commit body was strict UTF-8 compact JSON with an object
  root whose members were, in order, `project`, `package`, optional
  `comment`, `user`, optional `files`, `rev`, and optional `requestid`, in
  six member sets; every value was a string; `srcmd5` and `sender` never
  occurred.
- `project` and `package` were always non-empty, without surrounding
  whitespace, control characters, or non-ASCII characters; 16-84 % of the
  events named a personal `home:` project.
- The unbound `suse.obs.metrics` family uses the same content type with an
  Influx line protocol body, which is not JSON.

Not observable live, and therefore covered by the synthetic cases of
`hostile_deliveries.json` in the decoder and parser tests: every other
content type, invalid UTF-8, malformed or non-object JSON, missing,
duplicated, non-string, empty, whitespace-only, or inadmissible `project`
or `package`, and non-string or inadmissible unconsumed members.
"""

from __future__ import annotations

import json
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.external_strings import contains_inadmissible_character
from tests.support.ibs_rabbitmq import (
    HOME_PROJECT_FIXTURE,
    METRICS_FIXTURE,
    PACKAGE_COMMIT,
    PACKAGE_COMMIT_FIXTURES,
    delivery_names,
    hostile_cases,
    load_delivery,
    observed_properties,
)

_OBSERVED_MEMBER_ORDER = (
    "project",
    "package",
    "comment",
    "user",
    "files",
    "rev",
    "requestid",
)
_OBSERVED_MEMBER_SETS = {
    frozenset({"project", "package", "user", "files", "rev"}),
    frozenset({"project", "package", "comment", "user", "files", "rev"}),
    frozenset({"project", "package", "comment", "user", "files", "rev", "requestid"}),
    frozenset({"project", "package", "comment", "user", "rev"}),
    frozenset({"project", "package", "user", "rev"}),
    frozenset({"project", "package", "comment", "user", "rev", "requestid"}),
}
_REASONS = {
    "unsupported_routing_key",
    "unsupported_content_type",
    "invalid_utf8",
    "invalid_json",
    "non_object_root",
    "invalid_project",
    "invalid_package",
}


class _PackageCommit(TypedDict):
    """The consumed members as observed live; others are ignored."""

    project: str
    package: str


_PACKAGE_COMMIT = TypeAdapter(_PackageCommit)


def _strict_object(body: bytes) -> dict[str, Any]:
    """Decode `body` as strict UTF-8 RFC 8259 JSON with unique members."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        names = [name for name, _ in pairs]
        assert len(names) == len(set(names)), names
        return dict(pairs)

    def reject(literal: str) -> None:
        raise AssertionError(literal)

    value = json.loads(
        body.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject
    )
    assert isinstance(value, dict)
    return value


def _clean(value: str) -> bool:
    return (
        value != ""
        and value == value.strip()
        and value.isascii()
        and value.isprintable()
        and not contains_inadmissible_character(value)
    )


@pytest.mark.unit
class TestProperties:
    def test_observed_properties_are_the_documented_ones(self) -> None:
        assert observed_properties() == {
            "content_type": "application/octet-stream",
            "content_encoding": None,
            "delivery_mode": 2,
            "priority": 0,
            "headers": {},
            "cluster_id": "",
            "redelivered": False,
            "message_id": None,
            "correlation_id": None,
            "timestamp": None,
            "app_id": None,
            "type": None,
            "user_id": None,
            "expiration": None,
            "reply_to": None,
        }

    def test_fixture_set_covers_every_observed_shape(self) -> None:
        assert set(delivery_names()) == {
            *PACKAGE_COMMIT_FIXTURES,
            HOME_PROJECT_FIXTURE,
            METRICS_FIXTURE,
        }


@pytest.mark.unit
class TestPackageCommit:
    @pytest.mark.parametrize("name", [*PACKAGE_COMMIT_FIXTURES, HOME_PROJECT_FIXTURE])
    def test_body_is_compact_strict_utf8_json_object(self, name: str) -> None:
        delivery = load_delivery(name)
        body = _strict_object(delivery.body)

        assert delivery.routing_key == PACKAGE_COMMIT
        assert (
            json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            == delivery.body
        )

    @pytest.mark.parametrize("name", [*PACKAGE_COMMIT_FIXTURES, HOME_PROJECT_FIXTURE])
    def test_members_follow_an_observed_set_and_order(self, name: str) -> None:
        body = _strict_object(load_delivery(name).body)

        assert frozenset(body) in _OBSERVED_MEMBER_SETS
        assert list(body) == [m for m in _OBSERVED_MEMBER_ORDER if m in body]
        assert all(isinstance(value, str) for value in body.values())
        assert "srcmd5" not in body
        assert "sender" not in body

    @pytest.mark.parametrize("name", [*PACKAGE_COMMIT_FIXTURES, HOME_PROJECT_FIXTURE])
    def test_consumed_members_validate_strictly(self, name: str) -> None:
        commit = _PACKAGE_COMMIT.validate_python(
            _strict_object(load_delivery(name).body), strict=True
        )

        assert _clean(commit["project"])
        assert _clean(commit["package"])

    def test_every_observed_suse_fixture_names_a_suse_project(self) -> None:
        for name in PACKAGE_COMMIT_FIXTURES:
            body = _strict_object(load_delivery(name).body)
            assert body["project"].startswith("SUSE:")

    def test_home_project_is_a_personal_identifier(self) -> None:
        body = _strict_object(load_delivery(HOME_PROJECT_FIXTURE).body)

        assert body["project"].startswith("home:")
        assert _clean(body["package"])

    @pytest.mark.parametrize(
        "body",
        [
            {"project": 1, "package": "example-pkg"},
            {"project": "SUSE:SLE-15-SP6:Update", "package": None},
            {"package": "example-pkg"},
        ],
    )
    def test_typed_model_rejects_unobserved_consumed_shapes(
        self, body: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _PACKAGE_COMMIT.validate_python(body, strict=True)


@pytest.mark.unit
class TestMetrics:
    def test_unbound_family_shares_the_content_type_and_is_not_json(self) -> None:
        delivery = load_delivery(METRICS_FIXTURE)

        assert delivery.routing_key == "suse.obs.metrics"
        assert delivery.content_type == "application/octet-stream"
        with pytest.raises(json.JSONDecodeError):
            json.loads(delivery.body.decode("utf-8"))


@pytest.mark.unit
class TestHostileSet:
    def test_case_ids_are_unique(self) -> None:
        ids = [case.id for case in hostile_cases()]

        assert len(ids) == len(set(ids))

    def test_every_case_declares_a_bounded_expectation(self) -> None:
        for case in hostile_cases():
            if case.outcome == "malformed":
                assert case.reason in _REASONS, case.id
                assert case.project is None
                assert case.package is None
            else:
                assert case.outcome == "valid", case.id
                assert case.reason is None
                assert case.project is not None
                assert case.package is not None

    def test_every_reason_and_both_outcomes_are_exercised(self) -> None:
        cases = hostile_cases()

        assert {case.reason for case in cases if case.reason} == _REASONS
        assert {case.outcome for case in cases} == {"malformed", "valid"}
