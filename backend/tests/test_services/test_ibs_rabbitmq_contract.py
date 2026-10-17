"""Contract tests for the IBS RabbitMQ deliveries the consumer reads.

Contract under test: docs/features/integrations/ibs-rabbitmq-integration.md
(AMQP Contract > Message Encoding; Consumed Events > Package Commit, Request
Create and State Change) and docs/data-sources.md (IBS/OBS RabbitMQ Event
Bus, Contract verification), verified read-only and structure-only against
`rabbit.suse.de` (RabbitMQ 4.1.5, exchange `pubsub`, default shared
account): dedicated `suse.obs.package.commit` captures from 2026-09-04 to
2026-09-07 (72.4 h, 9,620 deliveries) and on 2026-10-15 (1 h), a
re-verification on 2026-10-15 with aio-pika 10.1.1 and aiormq 7.2.2, and
dedicated `suse.obs.request.#` captures over the same windows (71.7 h and
1 h; 157 create and 195 state_change deliveries) with IBS request
point-detail correlation, whose member order and serialization were
re-analyzed on 2026-10-17 (docs/conventions.md, External Integration
Contract Verification). The fixtures keep every observed structure and
replace every value by a fictional one. Every consumed field is asserted
through a strict test-local typed model, independent of the production
decoder and parser.

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
- Every request-event body was strict UTF-8 compact JSON with an object
  root (exact byte length in 439 of 441 bodies; the other two differed only
  in the escaping of control characters in free text). Create members, in
  order: `author`, optional `description`, `id`, `number`, `actions`,
  `state`, `when`, `who`, `namespace`; state_change adds `comment` after
  `author`, `oldstate` after `state`, and an optional trailing `duration`;
  the unbound reviews_done has the state_change members without `oldstate`
  and `duration`.
- `number` was a JSON integer from 1 to 2,147,483,647 in every event and
  equal to the `id` of the `<request>` of `GET /request/{number}` (13 of
  13); the event `id` was a different integer in every event. `state`,
  `oldstate`, and the action `type` were members of their closed OBS sets;
  each action began with an integer `action_id`.

Not observable live, and therefore covered by the synthetic cases of
`hostile_deliveries.json` in the decoder and parser tests: every other
content type, invalid UTF-8, malformed or non-object JSON, missing,
duplicated, non-string, empty, whitespace-only, or inadmissible `project`
or `package`, missing, duplicated, non-integer, or out-of-range `number`,
and non-string or inadmissible unconsumed members.
"""

from __future__ import annotations

import json
from typing import Any, TypedDict

import pytest
from pydantic import TypeAdapter, ValidationError

from app.core.external_strings import contains_inadmissible_character
from tests.support.ibs_rabbitmq import (
    DUPLICATE_CREATE_FIXTURE,
    HOME_PROJECT_FIXTURE,
    METRICS_FIXTURE,
    PACKAGE_COMMIT,
    PACKAGE_COMMIT_FIXTURES,
    REQUEST_CREATE,
    REQUEST_FIXTURES,
    REQUEST_REVIEWS_DONE,
    REQUEST_STATE_CHANGE,
    REVIEWS_DONE_FIXTURE,
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
    "invalid_number",
}

_REQUEST_MEMBER_ORDERS: dict[str, set[tuple[str, ...]]] = {
    REQUEST_CREATE: {
        (
            "author",
            "description",
            "id",
            "number",
            "actions",
            "state",
            "when",
            "who",
            "namespace",
        ),
        ("author", "id", "number", "actions", "state", "when", "who", "namespace"),
    },
    REQUEST_STATE_CHANGE: {
        (
            "author",
            "comment",
            "description",
            "id",
            "number",
            "actions",
            "state",
            "oldstate",
            "when",
            "who",
            "namespace",
            "duration",
        ),
        (
            "author",
            "comment",
            "description",
            "id",
            "number",
            "actions",
            "state",
            "oldstate",
            "when",
            "who",
            "namespace",
        ),
        (
            "author",
            "comment",
            "id",
            "number",
            "actions",
            "state",
            "oldstate",
            "when",
            "who",
            "namespace",
            "duration",
        ),
    },
    REQUEST_REVIEWS_DONE: {
        (
            "author",
            "comment",
            "description",
            "id",
            "number",
            "actions",
            "state",
            "when",
            "who",
            "namespace",
        ),
        (
            "author",
            "comment",
            "id",
            "number",
            "actions",
            "state",
            "when",
            "who",
            "namespace",
        ),
    },
}
"""The observed member orders of each request family."""

_ACTION_MEMBER_ORDERS: dict[str, set[tuple[str, ...]]] = {
    "delete": {("action_id", "type", "targetproject", "makeoriginolder")},
    "maintenance_incident": {
        (
            "action_id",
            "type",
            "sourceproject",
            "sourcepackage",
            "sourcerevision",
            "targetproject",
            "target_releaseproject",
            "makeoriginolder",
        ),
        (
            "action_id",
            "type",
            "sourceproject",
            "sourcepackage",
            "targetproject",
            "target_releaseproject",
            "makeoriginolder",
        ),
        (
            "action_id",
            "type",
            "sourceproject",
            "sourcepackage",
            "sourcerevision",
            "targetproject",
            "targetpackage",
            "target_releaseproject",
            "makeoriginolder",
        ),
    },
    "maintenance_release": {
        (
            "action_id",
            "type",
            "sourceproject",
            "sourcepackage",
            "targetproject",
            "targetpackage",
            "makeoriginolder",
        ),
        (
            "action_id",
            "type",
            "sourceproject",
            "sourcepackage",
            "sourcerevision",
            "targetproject",
            "targetpackage",
            "makeoriginolder",
        ),
    },
}
"""The observed member orders of the action types the fixtures carry."""

_REQUEST_STATES = {"new", "review", "accepted", "declined", "revoked", "superseded"}
"""The `state` and `oldstate` values observed in the request families."""

_ACTION_TYPES = {
    "submit",
    "delete",
    "add_role",
    "set_bugowner",
    "change_devel",
    "release",
    "maintenance_incident",
    "maintenance_release",
}
"""The closed set of OBS request action types."""

_INTEGER_MAX = 2_147_483_647


class _PackageCommit(TypedDict):
    """The consumed members as observed live; others are ignored."""

    project: str
    package: str


_PACKAGE_COMMIT = TypeAdapter(_PackageCommit)


class _RequestEvent(TypedDict):
    """The consumed member as observed live; others are ignored."""

    number: int


_REQUEST_EVENT = TypeAdapter(_RequestEvent)


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
            *REQUEST_FIXTURES,
            REVIEWS_DONE_FIXTURE,
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


_REQUEST_SHAPES = [*REQUEST_FIXTURES, REVIEWS_DONE_FIXTURE]


@pytest.mark.unit
class TestRequestEvents:
    @pytest.mark.parametrize("name", _REQUEST_SHAPES)
    def test_body_is_compact_strict_utf8_json_object(self, name: str) -> None:
        delivery = load_delivery(name)
        body = _strict_object(delivery.body)

        assert (
            json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            == delivery.body
        )

    @pytest.mark.parametrize("name", _REQUEST_SHAPES)
    def test_members_follow_an_observed_order_of_their_family(self, name: str) -> None:
        delivery = load_delivery(name)
        body = _strict_object(delivery.body)

        assert tuple(body) in _REQUEST_MEMBER_ORDERS[delivery.routing_key]
        for action in body["actions"]:
            assert tuple(action) in _ACTION_MEMBER_ORDERS[action["type"]]

    @pytest.mark.parametrize("name", _REQUEST_SHAPES)
    def test_number_validates_strictly_and_differs_from_the_event_id(
        self, name: str
    ) -> None:
        body = _strict_object(load_delivery(name).body)

        event = _REQUEST_EVENT.validate_python(body, strict=True)

        assert 1 <= event["number"] <= _INTEGER_MAX
        assert type(body["id"]) is int
        assert body["id"] != event["number"]

    @pytest.mark.parametrize("name", _REQUEST_SHAPES)
    def test_closed_enumerations_and_ignored_member_types(self, name: str) -> None:
        body = _strict_object(load_delivery(name).body)

        assert body["state"] in _REQUEST_STATES
        assert body.get("oldstate", "new") in _REQUEST_STATES
        assert isinstance(body["actions"], list)
        for action in body["actions"]:
            assert action["type"] in _ACTION_TYPES
            assert type(action["action_id"]) is int
            assert type(action["makeoriginolder"]) is bool
        for member in ("author", "when", "who", "namespace"):
            assert isinstance(body[member], str)
        if "duration" in body:
            assert type(body["duration"]) is int

    def test_fixtures_cover_both_bound_families_and_the_observed_states(
        self,
    ) -> None:
        bodies = [
            (load_delivery(name).routing_key, _strict_object(load_delivery(name).body))
            for name in REQUEST_FIXTURES
        ]

        assert {key for key, _ in bodies} == {REQUEST_CREATE, REQUEST_STATE_CHANGE}
        assert {(key, body["state"], body.get("oldstate")) for key, body in bodies} >= {
            (REQUEST_CREATE, "review", None),
            (REQUEST_CREATE, "new", None),
            (REQUEST_STATE_CHANGE, "accepted", "new"),
            (REQUEST_STATE_CHANGE, "superseded", "declined"),
        }
        assert any(len(body["actions"]) >= 5 for _, body in bodies)
        assert any("description" not in body for _, body in bodies)

    def test_duplicate_create_is_a_delete_only_new_request(self) -> None:
        delivery = load_delivery(DUPLICATE_CREATE_FIXTURE)
        body = _strict_object(delivery.body)

        assert delivery.routing_key == REQUEST_CREATE
        assert body["state"] == "new"
        assert [action["type"] for action in body["actions"]] == ["delete"]

    def test_reviews_done_shares_the_shape_and_is_not_a_bound_family(self) -> None:
        delivery = load_delivery(REVIEWS_DONE_FIXTURE)
        body = _strict_object(delivery.body)

        assert delivery.routing_key == REQUEST_REVIEWS_DONE
        assert delivery.content_type == "application/octet-stream"
        assert _REQUEST_EVENT.validate_python(body, strict=True)["number"] > 0

    def test_personal_values_occur_only_in_ignored_members(self) -> None:
        """The personal branch project and the actor appear only inside the
        ignored action array and actor members, never in `number`."""
        body = _strict_object(load_delivery("request_create_multi_action").body)

        assert body["author"] == body["who"] == "example-user"
        assert any(
            action.get("sourceproject", "").startswith("home:")
            for action in body["actions"]
        )

    @pytest.mark.parametrize(
        "body",
        [
            {"number": "400001"},
            {"number": 400001.0},
            {"number": True},
            {"number": None},
            {"id": 9100001},
        ],
    )
    def test_typed_model_rejects_unobserved_consumed_shapes(
        self, body: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError):
            _REQUEST_EVENT.validate_python(body, strict=True)


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
                assert (case.project, case.package, case.number) == (None,) * 3
            elif case.delivery.routing_key == PACKAGE_COMMIT:
                assert case.outcome == "valid", case.id
                assert case.reason is None
                assert case.project is not None
                assert case.package is not None
                assert case.number is None
            else:
                assert case.outcome == "valid", case.id
                assert case.delivery.routing_key in {
                    REQUEST_CREATE,
                    REQUEST_STATE_CHANGE,
                }
                assert (case.reason, case.project, case.package) == (None,) * 3
                assert case.number is not None
                assert 1 <= case.number <= _INTEGER_MAX

    def test_every_reason_and_both_outcomes_are_exercised(self) -> None:
        cases = hostile_cases()

        assert {case.reason for case in cases if case.reason} == _REASONS
        assert {case.outcome for case in cases} == {"malformed", "valid"}
        valid_keys = {case.delivery.routing_key for case in cases if case.number}
        assert valid_keys == {REQUEST_CREATE, REQUEST_STATE_CHANGE}
