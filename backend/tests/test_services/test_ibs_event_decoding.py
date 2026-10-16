"""Tests for the generic IBS RabbitMQ delivery decoding
(backend/app/services/ibs_event_decoding.py).

Owning specification: docs/features/integrations/ibs-rabbitmq-integration.md
(AMQP Contract > Message Encoding: the fixed bindings, the exact content
type, strict UTF-8, exactly one RFC 8259 JSON text, an object root, ignored
content encoding, duplicated members, no size limit). The synthetic cases
come from `tests/fixtures/ibs_rabbitmq/hostile_deliveries.json`; schema
reasons (`invalid_project`, `invalid_package`) belong to the package-commit
parser and are covered in `test_packages/test_ibs_event_handlers.py`.
"""

from __future__ import annotations

import pytest

from app.services.ibs_event_decoding import (
    BOUND_ROUTING_KEYS,
    CONTENT_TYPE,
    PACKAGE_COMMIT_ROUTING_KEY,
    MalformedDeliveryError,
    MalformedReason,
    decode_delivery,
)
from tests.support.ibs_rabbitmq import (
    HOME_PROJECT_FIXTURE,
    METRICS_FIXTURE,
    PACKAGE_COMMIT_FIXTURES,
    HostileCase,
    hostile_cases,
    load_delivery,
)
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)

pytestmark = pytest.mark.unit

_DECODING_REASONS = {
    "unsupported_routing_key",
    "unsupported_content_type",
    "invalid_utf8",
    "invalid_json",
    "non_object_root",
}

_VALID = (
    b'{"project":"SUSE:SLE-15-SP6:Update","package":"example-pkg",'
    b'"user":"example-user","rev":"46"}'
)


def _decoding_cases() -> list[HostileCase]:
    return [case for case in hostile_cases() if case.reason in _DECODING_REASONS]


def _decodable_cases() -> list[HostileCase]:
    return [case for case in hostile_cases() if case.reason not in _DECODING_REASONS]


def _decode(case: HostileCase) -> object:
    delivery = case.delivery
    return decode_delivery(delivery.routing_key, delivery.content_type, delivery.body)


class TestBindings:
    def test_package_commit_is_the_only_binding_until_request_handlers_exist(
        self,
    ) -> None:
        assert BOUND_ROUTING_KEYS == (PACKAGE_COMMIT_ROUTING_KEY,)
        assert CONTENT_TYPE == "application/octet-stream"


class TestObservedDeliveries:
    @pytest.mark.parametrize("name", [*PACKAGE_COMMIT_FIXTURES, HOME_PROJECT_FIXTURE])
    def test_every_observed_package_commit_decodes_to_its_object(
        self, name: str
    ) -> None:
        delivery = load_delivery(name)

        event = decode_delivery(
            delivery.routing_key, delivery.content_type, delivery.body
        )

        assert event.routing_key == PACKAGE_COMMIT_ROUTING_KEY
        assert set(event.members) >= {"project", "package"}
        assert event.duplicated == frozenset()

    def test_unbound_metrics_family_is_an_unsupported_routing_key(self) -> None:
        delivery = load_delivery(METRICS_FIXTURE)

        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery(delivery.routing_key, delivery.content_type, delivery.body)

        assert raised.value.reason is MalformedReason.UNSUPPORTED_ROUTING_KEY


class TestHostileDeliveries:
    @pytest.mark.parametrize("case", _decoding_cases(), ids=lambda case: case.id)
    def test_malformed_encoding_raises_its_bounded_reason(
        self, case: HostileCase
    ) -> None:
        with pytest.raises(MalformedDeliveryError) as raised:
            _decode(case)

        assert raised.value.reason.value == case.reason
        assert str(raised.value) == case.reason

    @pytest.mark.parametrize("case", _decodable_cases(), ids=lambda case: case.id)
    def test_schema_cases_decode_to_an_object(self, case: HostileCase) -> None:
        event = _decode(case)

        assert event is not None

    def test_routing_key_none_is_unsupported(self) -> None:
        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery(None, CONTENT_TYPE, _VALID)

        assert raised.value.reason is MalformedReason.UNSUPPORTED_ROUTING_KEY

    def test_routing_key_is_checked_before_the_content_type_and_body(self) -> None:
        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery("suse.obs.metrics", "text/plain", b"\xff")

        assert raised.value.reason is MalformedReason.UNSUPPORTED_ROUTING_KEY

    def test_content_type_is_checked_before_the_body(self) -> None:
        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, "application/json", b"\xff")

        assert raised.value.reason is MalformedReason.UNSUPPORTED_CONTENT_TYPE

    def test_nesting_beyond_the_parser_limit_is_invalid_json(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nesting in an unconsumed member: accepted within the parser's
        limit, invalid JSON beyond it (External JSON Decoding)."""
        body = _VALID[:-1] + b',"x":' + NESTED_ARRAY.encode() + b"}"
        assert decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        limit_parser_nesting(monkeypatch)

        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        assert raised.value.reason is MalformedReason.INVALID_JSON

    def test_integer_beyond_the_conversion_limit_is_invalid_json(self) -> None:
        body = _VALID[:-1] + b',"count":' + OVERSIZED_INTEGER.encode() + b"}"

        with pytest.raises(MalformedDeliveryError) as raised:
            decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        assert raised.value.reason is MalformedReason.INVALID_JSON

    def test_oversized_unconsumed_member_is_accepted(self) -> None:
        """About 1 MiB in an ignored member: no size limit applies."""
        body = _VALID[:-1] + b',"comment":"' + b"x" * (1024 * 1024) + b'"}'

        event = decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        assert event.members["package"] == "example-pkg"
        assert len(event.members["comment"]) == 1024 * 1024


class TestDuplicatedMembers:
    def test_duplicated_root_members_are_reported_with_the_last_value(self) -> None:
        body = (
            b'{"project":"SUSE:A","package":"example-pkg","user":"a",'
            b'"user":"b","project":"SUSE:B"}'
        )

        event = decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        assert event.duplicated == frozenset({"project", "user"})
        assert event.members["project"] == "SUSE:B"

    def test_duplicates_inside_nested_objects_are_not_root_duplicates(self) -> None:
        body = _VALID[:-1] + b',"meta":{"a":1,"a":2}}'

        event = decode_delivery(PACKAGE_COMMIT_ROUTING_KEY, CONTENT_TYPE, body)

        assert event.duplicated == frozenset()
