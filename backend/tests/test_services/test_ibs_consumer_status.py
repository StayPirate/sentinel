"""Tests for the IBS consumer heartbeat and status read
(`backend/app/services/ibs_consumer_status.py`).

See docs/features/integrations/ibs-rabbitmq-integration.md (Monitoring and
Observability > Heartbeat Storage, Consumer States; Status API > Get IBS
Consumer Status > Behavior; Security; Testing Requirements),
docs/conventions.md (Redis Error Handling; Timestamps & Timezones), and
docs/features/platform/testing-strategy.md (Redis Strategy; Application-Owned
Redis Operations).

- `parse_heartbeat()` / `evaluate_heartbeat()`: the complete heartbeat schema,
  its invariants, future timestamps, and the 60-second freshness bound (unit).
- `HeartbeatDocument`: serialization and construction invariants (unit).
- `ConsumerStatusState`: transitions, counters, `last_error`, and the
  non-decreasing clock, with an injected fake clock (unit).
- `HeartbeatWriter`: immediate, change-driven, and periodic writes and the
  `RedisError` / write-bound degradation, with an injected store and timer
  that never sleep (unit).
- `write_heartbeat_value()` / `get_ibs_consumer_status()`: the Redis key,
  TTL, disabled short-circuit, and `RedisError` handling through the
  replaceable `_new_redis_client` boundary (integration).

Every value is fictional.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Final

import pytest
import redis.asyncio as redis_asyncio
from redis import exceptions as redis_exceptions
from structlog.testing import capture_logs

from app.config import settings
from app.core.enums import IBSConsumerErrorCategory, IBSConsumerStatus
from app.services import ibs_consumer_status
from app.services.ibs_consumer_status import (
    STATUS_KEY,
    ConsumerStatusState,
    HeartbeatDocument,
    HeartbeatWriter,
    evaluate_heartbeat,
    get_ibs_consumer_status,
    parse_heartbeat,
    write_heartbeat_value,
)
from tests.support.json_decoding import (
    NESTED_ARRAY,
    OVERSIZED_INTEGER,
    limit_parser_nesting,
)

_NOW: Final = datetime(2026, 9, 8, 15, 42, 40, tzinfo=UTC)
"""The fixed evaluation instant: ten seconds after the example heartbeat."""

_CONNECTED: Final[Mapping[str, Any]] = {
    "status": "connected",
    "heartbeat_at": "2026-09-08T15:42:30Z",
    "process_started_at": "2026-09-08T14:00:00Z",
    "status_since": "2026-09-08T15:40:12Z",
    "events_received": 12847,
    "events_relevant": 342,
    "events_processed": 338,
    "processing_failed": 4,
    "reconnect_attempts": 2,
    "next_retry_seconds": None,
    "last_error": "request_reconciliation_failed",
    "last_error_at": "2026-09-08T15:31:04Z",
}
"""The connected example of Heartbeat Storage."""

_RECONNECTING: Final[Mapping[str, Any]] = {
    **_CONNECTED,
    "status": "reconnecting",
    "next_retry_seconds": 10,
}

_FIELDS: Final = tuple(_CONNECTED)
_COUNTERS: Final = (
    "events_received",
    "events_relevant",
    "events_processed",
    "processing_failed",
    "reconnect_attempts",
)
_DATETIMES: Final = (
    "heartbeat_at",
    "process_started_at",
    "status_since",
    "last_error_at",
)

_ARABIC_INDIC_DIGITS: Final = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")


def _encode(document: Mapping[str, Any], **raw: str) -> bytes:
    """`document` as JSON; each `raw` member's value is the given JSON text
    verbatim (for literals `json.dumps` cannot produce, such as `1e3`)."""
    members = {**document, **{name: f"@@{name}@@" for name in raw}}
    text = json.dumps(members)
    for name, fragment in raw.items():
        text = text.replace(json.dumps(f"@@{name}@@"), fragment)
    return text.encode()


def _with(**overrides: Any) -> dict[str, Any]:
    return {**_CONNECTED, **overrides}


def _without(name: str) -> dict[str, Any]:
    return {key: value for key, value in _CONNECTED.items() if key != name}


def _utc(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _expected_document(members: Mapping[str, Any]) -> HeartbeatDocument:
    """The document a valid `members` mapping must parse into."""
    last_error = members["last_error"]
    last_error_at = members["last_error_at"]
    return HeartbeatDocument(
        status=IBSConsumerStatus(members["status"]),
        heartbeat_at=_utc(members["heartbeat_at"]),
        process_started_at=_utc(members["process_started_at"]),
        status_since=_utc(members["status_since"]),
        events_received=members["events_received"],
        events_relevant=members["events_relevant"],
        events_processed=members["events_processed"],
        processing_failed=members["processing_failed"],
        reconnect_attempts=members["reconnect_attempts"],
        next_retry_seconds=members["next_retry_seconds"],
        last_error=None if last_error is None else IBSConsumerErrorCategory(last_error),
        last_error_at=None if last_error_at is None else _utc(last_error_at),
    )


def _datetime_variants(name: str) -> list[Any]:
    """Invalid renderings of the valid value of datetime field `name`."""
    valid: str = _CONNECTED[name]
    other_offset = _utc(valid).astimezone(timezone(timedelta(hours=2))).isoformat()
    variants = {
        "naive": json.dumps(valid[:-1]),
        "other-offset": json.dumps(other_offset),
        "minus-zero-offset": json.dumps(valid[:-1] + "-00:00"),
        "lowercase-z": json.dumps(valid[:-1] + "z"),
        # `datetime.fromisoformat()` accepts both separators below.
        "lowercase-t": json.dumps(valid.replace("T", "t")),
        "space-separator": json.dumps(valid.replace("T", " ")),
        "date-only": json.dumps(valid[:10]),
        "basic-format": json.dumps(valid.replace("-", "").replace(":", "")),
        "month-13": json.dumps(valid[:5] + "13" + valid[7:]),
        "non-string": "1788795750",
        "seven-fraction-digits": json.dumps(valid[:-1] + ".1234567Z"),
        "non-ascii-digits": json.dumps(valid.translate(_ARABIC_INDIC_DIGITS)),
    }
    return [
        pytest.param(_encode(_CONNECTED, **{name: fragment}), id=f"{name}-{label}")
        for label, fragment in variants.items()
    ]


_BAD_COUNTERS: Final = {
    "negative": "-1",
    "float": "1.0",
    "exponent": "1e3",
    "string": '"1"',
    "bool": "true",
    "null": "null",
}


def _invalid_values() -> list[Any]:
    valid = _encode(_CONNECTED)
    cases = [
        pytest.param(b"\xff", id="not-utf8"),
        pytest.param(b"\xed\xa0\x80", id="utf8-encoded-surrogate"),
        pytest.param(b"\xef\xbb\xbf" + valid, id="utf8-bom"),
        pytest.param(b"", id="empty"),
        pytest.param(b'{"status": "connected", ', id="malformed-json"),
        pytest.param(valid + b" {}", id="trailing-content"),
        pytest.param(b"[]", id="root-array"),
        pytest.param(b'"connected"', id="root-string"),
        pytest.param(b"1", id="root-number"),
        pytest.param(b"null", id="root-null"),
        pytest.param(b"true", id="root-true"),
        pytest.param(_encode(_CONNECTED, extra="NaN"), id="nan-in-ignored-member"),
        pytest.param(
            _encode(_CONNECTED, extra="Infinity"), id="infinity-in-ignored-member"
        ),
        pytest.param(
            _encode(_CONNECTED, extra="-Infinity"),
            id="negative-infinity-in-ignored-member",
        ),
        pytest.param(
            _encode(_CONNECTED, extra=OVERSIZED_INTEGER),
            id="integer-beyond-the-conversion-limit-in-ignored-member",
        ),
        pytest.param(_encode(_with(status="paused")), id="status-unknown"),
        pytest.param(_encode(_with(status="CONNECTED")), id="status-uppercase"),
        pytest.param(_encode(_with(status="disabled")), id="status-disabled"),
        pytest.param(_encode(_with(status="unreachable")), id="status-unreachable"),
        pytest.param(_encode(_with(status=1)), id="status-non-string"),
        pytest.param(_encode(_with(status=None)), id="status-null"),
        pytest.param(
            _encode(_RECONNECTING, next_retry_seconds="-1"),
            id="next_retry_seconds-negative",
        ),
        pytest.param(
            _encode(_RECONNECTING, next_retry_seconds="1.5"),
            id="next_retry_seconds-float",
        ),
        pytest.param(
            _encode(_RECONNECTING, next_retry_seconds="true"),
            id="next_retry_seconds-bool",
        ),
        pytest.param(
            _encode(_RECONNECTING, next_retry_seconds='"5"'),
            id="next_retry_seconds-string",
        ),
        pytest.param(
            _encode(_with(next_retry_seconds=5)), id="connected-with-next_retry_seconds"
        ),
        pytest.param(
            _encode(_with(next_retry_seconds=0)),
            id="connected-with-zero-next_retry_seconds",
        ),
        pytest.param(
            _encode(_with(last_error="database_failed")), id="last_error-unknown"
        ),
        pytest.param(_encode(_with(last_error=3)), id="last_error-non-string"),
        pytest.param(
            _encode(_with(last_error_at=None)), id="last_error-without-last_error_at"
        ),
        pytest.param(
            _encode(_with(last_error=None)), id="last_error_at-without-last_error"
        ),
        pytest.param(
            _encode(_with(status_since="2026-09-08T13:59:59Z")),
            id="status_since-before-process_started_at",
        ),
        pytest.param(
            _encode(_with(heartbeat_at="2026-09-08T15:40:11Z")),
            id="heartbeat_at-before-status_since",
        ),
        pytest.param(
            _encode(_with(events_processed=343)),
            id="events_processed-above-events_relevant",
        ),
        pytest.param(
            _encode(_with(events_processed=0, processing_failed=343)),
            id="processing_failed-above-events_relevant",
        ),
        pytest.param(
            _encode(_with(events_relevant=12848)),
            id="events_relevant-above-events_received",
        ),
    ]
    cases += [
        pytest.param(_encode(_without(name)), id=f"missing-{name}") for name in _FIELDS
    ]
    cases += [
        pytest.param(_encode(_CONNECTED, **{name: fragment}), id=f"{name}-{label}")
        for name in _COUNTERS
        for label, fragment in _BAD_COUNTERS.items()
    ]
    for name in _DATETIMES:
        cases += _datetime_variants(name)
    return cases


# ---------------------------------------------------------------------------
# parse_heartbeat / evaluate_heartbeat
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParseHeartbeat:
    def test_parse_connected_example_round_trips_every_field(self) -> None:
        document = parse_heartbeat(_encode(_CONNECTED))

        assert document == _expected_document(_CONNECTED)
        assert document is not None
        assert document.status is IBSConsumerStatus.CONNECTED
        assert document.heartbeat_at == datetime(2026, 9, 8, 15, 42, 30, tzinfo=UTC)
        assert document.process_started_at == datetime(2026, 9, 8, 14, 0, tzinfo=UTC)
        assert document.status_since == datetime(2026, 9, 8, 15, 40, 12, tzinfo=UTC)
        assert document.last_error_at == datetime(2026, 9, 8, 15, 31, 4, tzinfo=UTC)
        for name in ("heartbeat_at", "process_started_at", "status_since"):
            value = getattr(document, name)
            assert value.utcoffset() == timedelta(0)
        assert (
            document.events_received,
            document.events_relevant,
            document.events_processed,
            document.processing_failed,
            document.reconnect_attempts,
        ) == (12847, 342, 338, 4, 2)
        assert all(type(getattr(document, name)) is int for name in _COUNTERS)
        assert document.next_retry_seconds is None
        assert (
            document.last_error
            is IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED
        )

    def test_parse_additional_members_are_ignored(self) -> None:
        raw = _encode(
            _with(
                extra={"project": "SUSE:SLE-15-SP6:Update", "package": "example-pkg"},
                version=2,
            )
        )

        assert parse_heartbeat(raw) == _expected_document(_CONNECTED)

    @pytest.mark.parametrize(
        "members",
        [
            pytest.param(_RECONNECTING, id="reconnecting-with-retry"),
            pytest.param(
                {**_RECONNECTING, "next_retry_seconds": 0}, id="reconnecting-zero-retry"
            ),
            pytest.param(
                {
                    **_CONNECTED,
                    "status": "disconnected",
                    "next_retry_seconds": 300,
                    "last_error": "rabbitmq_connection_lost",
                },
                id="disconnected-with-retry",
            ),
            pytest.param(
                _with(last_error=None, last_error_at=None), id="no-last-error"
            ),
            pytest.param(
                _with(
                    events_received=0,
                    events_relevant=0,
                    events_processed=0,
                    processing_failed=0,
                    reconnect_attempts=0,
                ),
                id="all-counters-zero",
            ),
            pytest.param(
                _with(events_received=342, events_processed=342, processing_failed=342),
                id="counter-invariants-at-equality",
            ),
            pytest.param(
                _with(
                    process_started_at="2026-09-08T15:42:30Z",
                    status_since="2026-09-08T15:42:30Z",
                ),
                id="ordering-at-equality",
            ),
        ],
    )
    def test_parse_valid_variant_is_accepted(self, members: Mapping[str, Any]) -> None:
        assert parse_heartbeat(_encode(members)) == _expected_document(members)

    @pytest.mark.parametrize("name", _DATETIMES)
    @pytest.mark.parametrize(
        ("suffix", "microsecond"),
        [
            pytest.param("+00:00", 0, id="plus-zero-offset"),
            pytest.param(".5Z", 500_000, id="one-fraction-digit"),
            pytest.param(".123456Z", 123_456, id="six-fraction-digits"),
            pytest.param(".000001+00:00", 1, id="fraction-and-plus-zero-offset"),
        ],
    )
    def test_parse_utc_datetime_forms_are_accepted(
        self, name: str, suffix: str, microsecond: int
    ) -> None:
        raw = _encode(_with(**{name: _CONNECTED[name][:-1] + suffix}))

        document = parse_heartbeat(raw)

        assert document is not None
        value = getattr(document, name)
        assert value == _utc(_CONNECTED[name]).replace(microsecond=microsecond)
        assert value.utcoffset() == timedelta(0)

    @pytest.mark.parametrize("raw", _invalid_values())
    def test_parse_invalid_value_returns_none(self, raw: bytes) -> None:
        assert parse_heartbeat(raw) is None
        assert evaluate_heartbeat(raw, now=_NOW) is None

    def test_parse_nesting_beyond_the_parser_limit_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nesting in an ignored member that the parser cannot represent
        makes the value invalid (External JSON Decoding)."""
        raw = _encode(_CONNECTED, extra=NESTED_ARRAY)
        assert parse_heartbeat(raw) == _expected_document(_CONNECTED)

        limit_parser_nesting(monkeypatch)

        assert parse_heartbeat(raw) is None
        assert evaluate_heartbeat(raw, now=_NOW) is None


@pytest.mark.unit
class TestEvaluateHeartbeat:
    def test_evaluate_absent_value_returns_none(self) -> None:
        assert evaluate_heartbeat(None, now=_NOW) is None

    def test_evaluate_valid_fresh_value_returns_document(self) -> None:
        assert evaluate_heartbeat(_encode(_CONNECTED), now=_NOW) == _expected_document(
            _CONNECTED
        )

    def test_evaluate_value_without_an_error_returns_document(self) -> None:
        members = _with(last_error=None, last_error_at=None)

        assert evaluate_heartbeat(_encode(members), now=_NOW) == _expected_document(
            members
        )

    def test_evaluate_every_timestamp_equal_to_now_is_accepted(self) -> None:
        now = "2026-09-08T15:42:40Z"
        members = _with(
            heartbeat_at=now,
            process_started_at=now,
            status_since=now,
            last_error_at=now,
        )

        assert evaluate_heartbeat(_encode(members), now=_NOW) == _expected_document(
            members
        )

    @pytest.mark.parametrize(
        "future",
        [
            pytest.param(("heartbeat_at",), id="heartbeat_at"),
            pytest.param(("status_since", "heartbeat_at"), id="status_since"),
            pytest.param(
                ("process_started_at", "status_since", "heartbeat_at"),
                id="process_started_at",
            ),
            pytest.param(("last_error_at",), id="last_error_at"),
        ],
    )
    def test_evaluate_timestamp_one_second_in_the_future_returns_none(
        self, future: tuple[str, ...]
    ) -> None:
        """Ordering forces the later timestamps forward with an earlier one;
        the value stays schema-valid, so only the future check rejects it."""
        later = "2026-09-08T15:42:41Z"
        raw = _encode(_with(**dict.fromkeys(future, later)))

        assert parse_heartbeat(raw) is not None
        assert evaluate_heartbeat(raw, now=_NOW) is None

    def test_evaluate_heartbeat_exactly_sixty_seconds_old_is_accepted(self) -> None:
        members = _with(heartbeat_at="2026-09-08T15:41:40Z")

        assert evaluate_heartbeat(_encode(members), now=_NOW) == _expected_document(
            members
        )

    @pytest.mark.parametrize(
        "heartbeat_at",
        [
            pytest.param("2026-09-08T15:41:39.999999Z", id="sixty-seconds-and-1us"),
            pytest.param("2026-09-08T15:41:39Z", id="sixty-one-seconds"),
        ],
    )
    def test_evaluate_heartbeat_older_than_sixty_seconds_returns_none(
        self, heartbeat_at: str
    ) -> None:
        raw = _encode(_with(heartbeat_at=heartbeat_at))

        assert parse_heartbeat(raw) is not None
        assert evaluate_heartbeat(raw, now=_NOW) is None


# ---------------------------------------------------------------------------
# HeartbeatDocument
# ---------------------------------------------------------------------------


def _document(**overrides: Any) -> HeartbeatDocument:
    values: dict[str, Any] = {
        "status": IBSConsumerStatus.CONNECTED,
        "heartbeat_at": datetime(2026, 9, 8, 15, 42, 30, tzinfo=UTC),
        "process_started_at": datetime(2026, 9, 8, 14, 0, tzinfo=UTC),
        "status_since": datetime(2026, 9, 8, 15, 40, 12, tzinfo=UTC),
        "events_received": 12847,
        "events_relevant": 342,
        "events_processed": 338,
        "processing_failed": 4,
        "reconnect_attempts": 2,
        "next_retry_seconds": None,
        "last_error": IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED,
        "last_error_at": datetime(2026, 9, 8, 15, 31, 4, tzinfo=UTC),
    }
    values.update(overrides)
    return HeartbeatDocument(**values)


@pytest.mark.unit
class TestHeartbeatDocument:
    def test_to_json_writes_the_exact_compact_value(self) -> None:
        assert _document().to_json() == json.dumps(_CONNECTED, separators=(",", ":"))

    def test_to_json_writes_whole_seconds_with_z(self) -> None:
        document = _document(
            heartbeat_at=datetime(2026, 9, 8, 15, 42, 30, 750_000, tzinfo=UTC),
            last_error_at=datetime(2026, 9, 8, 15, 31, 4, 1, tzinfo=UTC),
        )

        written = json.loads(document.to_json())

        assert list(written) == list(_FIELDS)
        assert written["heartbeat_at"] == "2026-09-08T15:42:30Z"
        assert written["last_error_at"] == "2026-09-08T15:31:04Z"

    @pytest.mark.parametrize(
        "document",
        [
            pytest.param(_document(), id="connected"),
            pytest.param(
                _document(
                    status=IBSConsumerStatus.RECONNECTING,
                    next_retry_seconds=20,
                    last_error=None,
                    last_error_at=None,
                ),
                id="reconnecting-without-error",
            ),
        ],
    )
    def test_to_json_parses_back_to_an_equal_document(
        self, document: HeartbeatDocument
    ) -> None:
        assert parse_heartbeat(document.to_json().encode()) == document

    @pytest.mark.parametrize(
        ("overrides", "secret"),
        [
            pytest.param(
                {"status": IBSConsumerStatus.DISABLED}, "disabled", id="disabled"
            ),
            pytest.param(
                {"status": IBSConsumerStatus.UNREACHABLE},
                "unreachable",
                id="unreachable",
            ),
            pytest.param(
                {"heartbeat_at": datetime(2026, 9, 8, 15, 42, 30)},  # noqa: DTZ001 - naive input under test
                "15",
                id="naive",
            ),
            pytest.param(
                {
                    "heartbeat_at": datetime(
                        2026, 9, 8, 17, 42, 30, tzinfo=timezone(timedelta(hours=2))
                    )
                },
                "17",
                id="other-offset",
            ),
            pytest.param(
                {"status_since": datetime(2026, 9, 8, 13, 59, 59, tzinfo=UTC)},
                "13",
                id="ordering",
            ),
            pytest.param({"events_received": -7}, "-7", id="negative-counter"),
            pytest.param({"reconnect_attempts": True}, "True", id="bool-counter"),
            pytest.param({"events_processed": 343}, "343", id="counter-invariant"),
            pytest.param({"next_retry_seconds": 9}, "9", id="connected-with-retry"),
            pytest.param({"last_error_at": None}, "request", id="error-without-time"),
        ],
    )
    def test_invalid_document_raises_value_error_naming_no_value(
        self, overrides: dict[str, Any], secret: str
    ) -> None:
        with pytest.raises(ValueError, match=r"\A\D+\Z") as excinfo:
            _document(**overrides)

        assert secret not in str(excinfo.value)


# ---------------------------------------------------------------------------
# ConsumerStatusState
# ---------------------------------------------------------------------------


_START: Final = datetime(2026, 9, 8, 14, 0, 0, 250_000, tzinfo=UTC)
_START_SECOND: Final = datetime(2026, 9, 8, 14, 0, 0, tzinfo=UTC)


@dataclass(eq=False)
class _Clock:
    """A settable aware wall clock."""

    now: datetime = _START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now += timedelta(seconds=seconds)
        return self.now.replace(microsecond=0)


def _counters(state: ConsumerStatusState) -> tuple[int, int, int, int, int]:
    return (
        state.events_received,
        state.events_relevant,
        state.events_processed,
        state.processing_failed,
        state.reconnect_attempts,
    )


@pytest.mark.unit
class TestConsumerStatusState:
    def test_new_state_is_reconnecting_with_zero_counters_at_whole_seconds(
        self,
    ) -> None:
        state = ConsumerStatusState(_Clock())

        assert state.status is IBSConsumerStatus.RECONNECTING
        assert _counters(state) == (0, 0, 0, 0, 0)
        assert state.next_retry_seconds is None
        assert state.last_error is None
        assert state.last_error_at is None
        assert state.process_started_at == state.status_since == _START_SECOND
        assert not state.changed.is_set()

    def test_clock_with_other_offset_is_stored_in_utc(self) -> None:
        clock = _Clock(_START.astimezone(timezone(timedelta(hours=2))))

        state = ConsumerStatusState(clock)

        assert state.process_started_at == _START_SECOND
        assert state.process_started_at.tzinfo is UTC

    def test_initial_attempt_without_wait_changes_nothing(self) -> None:
        state = ConsumerStatusState(_Clock())

        state.attempt_started(reconnect=False)

        assert state.status is IBSConsumerStatus.RECONNECTING
        assert state.reconnect_attempts == 0
        assert state.status_since == _START_SECOND
        assert not state.changed.is_set()

    def test_reconnect_attempt_counts_and_signals_a_change(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        clock.advance(5)

        state.attempt_started(reconnect=True)

        assert state.reconnect_attempts == 1
        assert state.status_since == _START_SECOND
        assert state.changed.is_set()

    def test_retry_scheduled_sets_the_delay_and_signals_a_change(self) -> None:
        state = ConsumerStatusState(_Clock())

        state.retry_scheduled(5)

        assert state.next_retry_seconds == 5
        assert state.status is IBSConsumerStatus.RECONNECTING
        assert state.changed.is_set()

    def test_attempt_after_a_wait_clears_the_delay(self) -> None:
        state = ConsumerStatusState(_Clock())
        state.retry_scheduled(5)
        state.changed.clear()

        state.attempt_started(reconnect=True)

        assert state.next_retry_seconds is None
        assert state.reconnect_attempts == 1
        assert state.changed.is_set()

    def test_connected_changes_status_and_since_and_clears_the_delay(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        state.retry_scheduled(5)
        state.changed.clear()
        connected_at = clock.advance(7.9)

        state.connected()

        assert state.status is IBSConsumerStatus.CONNECTED
        assert state.status_since == connected_at
        assert state.next_retry_seconds is None
        assert state.changed.is_set()

    def test_connected_again_changes_nothing(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        state.connected()
        since = state.status_since
        state.changed.clear()
        clock.advance(30)

        state.connected()

        assert state.status_since == since
        assert not state.changed.is_set()

    def test_connection_lost_disconnects_and_records_the_error(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        state.connected()
        state.changed.clear()
        lost_at = clock.advance(60)

        state.connection_lost()

        assert state.status is IBSConsumerStatus.DISCONNECTED
        assert state.status_since == lost_at
        assert state.last_error is IBSConsumerErrorCategory.RABBITMQ_CONNECTION_LOST
        assert state.last_error_at == lost_at
        assert state.next_retry_seconds is None
        assert state.changed.is_set()

    def test_connection_failed_records_the_error_without_a_change(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        failed_at = clock.advance(2)

        state.connection_failed()

        assert state.last_error is IBSConsumerErrorCategory.RABBITMQ_CONNECTION_FAILED
        assert state.last_error_at == failed_at
        assert state.status is IBSConsumerStatus.RECONNECTING
        assert state.status_since == _START_SECOND
        assert not state.changed.is_set()

    def test_delivery_methods_update_counters_without_a_change(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        state.connected()
        state.changed.clear()

        state.delivery_started()
        assert _counters(state) == (1, 0, 0, 0, 0)
        state.delivery_succeeded()
        assert _counters(state) == (1, 1, 1, 0, 0)
        state.delivery_started()
        failed_at = clock.advance(3)
        state.delivery_failed(IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED)

        assert _counters(state) == (2, 2, 1, 1, 0)
        assert (
            state.last_error is IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED
        )
        assert state.last_error_at == failed_at
        assert not state.changed.is_set()

    def test_later_failure_replaces_and_success_or_reconnect_keeps_last_error(
        self,
    ) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        clock.advance(1)
        state.delivery_started()
        state.delivery_failed(IBSConsumerErrorCategory.PACKAGE_RECONCILIATION_FAILED)
        replaced_at = clock.advance(1)
        state.delivery_started()
        state.delivery_failed(IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED)
        clock.advance(1)

        state.delivery_started()
        state.delivery_succeeded()
        state.connected()

        assert (
            state.last_error is IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED
        )
        assert state.last_error_at == replaced_at

    def test_counters_are_retained_across_reconnects(self) -> None:
        state = ConsumerStatusState(_Clock())
        state.connected()
        state.delivery_started()
        state.delivery_succeeded()

        state.connection_lost()
        state.attempt_started(reconnect=True)
        state.connected()

        assert _counters(state) == (1, 1, 1, 0, 1)

    def test_clock_stepping_backwards_never_decreases_a_timestamp(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        latest = clock.advance(100)
        state.connected()
        clock.now = _START - timedelta(hours=1)

        state.connection_lost()
        state.delivery_started()
        state.delivery_failed(IBSConsumerErrorCategory.REQUEST_RECONCILIATION_FAILED)
        document = state.document()

        assert state.process_started_at == _START_SECOND
        assert state.status_since == latest
        assert state.last_error_at == latest
        assert document.heartbeat_at == latest
        assert (
            document.process_started_at
            <= document.status_since
            <= document.heartbeat_at
        )

    def test_document_reflects_the_state_at_now(self) -> None:
        clock = _Clock()
        state = ConsumerStatusState(clock)
        state.attempt_started(reconnect=True)
        state.retry_scheduled(10)
        state.delivery_started()
        state.connection_failed()
        failed_at = state.last_error_at
        written_at = clock.advance(12.5)

        document = state.document()

        assert document == HeartbeatDocument(
            status=IBSConsumerStatus.RECONNECTING,
            heartbeat_at=written_at,
            process_started_at=_START_SECOND,
            status_since=_START_SECOND,
            events_received=1,
            events_relevant=0,
            events_processed=0,
            processing_failed=0,
            reconnect_attempts=1,
            next_retry_seconds=10,
            last_error=IBSConsumerErrorCategory.RABBITMQ_CONNECTION_FAILED,
            last_error_at=failed_at,
        )


# ---------------------------------------------------------------------------
# HeartbeatWriter
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class _Store:
    """The heartbeat store: records each written value; the first attempts
    raise `errors` in order; every attempt first waits for `gate` when set."""

    values: list[str] = field(default_factory=list)
    attempts: int = 0
    errors: list[BaseException] = field(default_factory=list)
    gate: asyncio.Event | None = None

    async def __call__(self, value: str) -> None:
        self.attempts += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.errors:
            raise self.errors.pop(0)
        self.values.append(value)

    def statuses(self) -> list[str]:
        return [json.loads(value)["status"] for value in self.values]


@dataclass(eq=False)
class _Timer:
    """The refresh wait: never ends on its own; `elapse()` ends the pending
    waits as if 30 seconds had passed; `error` makes every wait raise."""

    calls: list[float] = field(default_factory=list)
    error: BaseException | None = None
    _waiters: list[asyncio.Future[None]] = field(default_factory=list)

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.error is not None:
            raise self.error
        waiter: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.append(waiter)
        await waiter

    @property
    def pending(self) -> int:
        return sum(1 for waiter in self._waiters if not waiter.done())

    def elapse(self) -> None:
        for waiter in self._waiters:
            if not waiter.done():
                waiter.set_result(None)


async def _until(predicate: Callable[[], bool]) -> None:
    """Yield to the loop until `predicate` holds (bounded; no real sleep)."""
    for _ in range(100_000):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


async def _settle() -> None:
    for _ in range(20):
        await asyncio.sleep(0)


@dataclass(eq=False)
class _WriterWorld:
    clock: _Clock
    state: ConsumerStatusState
    store: _Store
    timer: _Timer
    writer: HeartbeatWriter


@pytest.fixture
async def world() -> AsyncIterator[_WriterWorld]:
    clock = _Clock()
    state = ConsumerStatusState(clock)
    store = _Store()
    timer = _Timer()
    writer = HeartbeatWriter(state, store=store, timer=timer)
    try:
        yield _WriterWorld(clock, state, store, timer, writer)
    finally:
        await writer.stop()


async def _started(world: _WriterWorld) -> None:
    """Start the writer and wait until its first write is followed by the
    refresh wait."""
    task = world.writer.start()
    await _until(lambda: world.timer.pending == 1)
    assert not task.done()


_WRITE_FAILED: Final = "ibs_consumer_heartbeat_write_failed"


@pytest.mark.unit
class TestHeartbeatWriter:
    async def test_start_writes_at_once_then_waits_thirty_seconds(
        self, world: _WriterWorld
    ) -> None:
        await _started(world)

        assert world.store.values == [world.state.document().to_json()]
        assert world.timer.calls == [30.0]

    async def test_start_twice_returns_the_same_task(self, world: _WriterWorld) -> None:
        task = world.writer.start()

        assert world.writer.start() is task
        await _until(lambda: world.timer.pending == 1)
        assert world.store.attempts == 1

    async def test_refresh_elapsed_writes_the_current_document(
        self, world: _WriterWorld
    ) -> None:
        await _started(world)
        world.state.delivery_started()
        world.clock.advance(30)

        world.timer.elapse()
        await _until(lambda: len(world.store.values) == 2)

        latest = json.loads(world.store.values[1])
        assert latest["events_received"] == 1
        assert latest["heartbeat_at"] == "2026-09-08T14:00:30Z"
        await _until(lambda: world.timer.pending == 1)
        assert world.timer.calls == [30.0, 30.0]

    async def test_state_change_writes_at_once_and_restarts_the_refresh(
        self, world: _WriterWorld
    ) -> None:
        await _started(world)

        world.state.connected()
        await _until(lambda: len(world.store.values) == 2)

        assert world.store.statuses() == ["reconnecting", "connected"]
        await _until(lambda: world.timer.pending == 1)
        assert world.timer.calls == [30.0, 30.0]

    async def test_counter_update_alone_waits_for_the_next_write(
        self, world: _WriterWorld
    ) -> None:
        await _started(world)

        world.state.delivery_started()
        world.state.delivery_succeeded()
        await _settle()

        assert world.store.attempts == 1

    async def test_changes_during_an_in_flight_write_cause_exactly_one_more_write(
        self, world: _WriterWorld
    ) -> None:
        world.store.gate = asyncio.Event()
        task = world.writer.start()
        await _until(lambda: world.store.attempts == 1)

        world.state.connected()
        world.state.connection_lost()
        world.store.gate.set()
        await _until(lambda: world.timer.pending == 1)
        await _settle()

        assert not task.done()
        assert world.store.attempts == 2
        assert world.store.statuses() == ["reconnecting", "disconnected"]

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                redis_exceptions.ConnectionError("fictional connection refused"),
                id="connection-error",
            ),
            pytest.param(
                redis_exceptions.TimeoutError("fictional timeout"), id="timeout-error"
            ),
            pytest.param(
                redis_exceptions.ResponseError(
                    "OOM command not allowed when used memory > 'maxmemory'."
                ),
                id="oom-response-error",
            ),
        ],
    )
    async def test_redis_error_logs_one_bounded_warning_and_the_loop_continues(
        self, world: _WriterWorld, error: redis_exceptions.RedisError
    ) -> None:
        world.store.errors = [error, error]

        with capture_logs() as logs:
            await _started(world)
            world.timer.elapse()
            await _until(lambda: world.store.attempts == 2 and world.timer.pending == 1)
            world.timer.elapse()
            await _until(lambda: len(world.store.values) == 1)

        expected = {
            "event": _WRITE_FAILED,
            "log_level": "warning",
            "error_type": type(error).__name__,
        }
        assert logs == [expected, expected]
        assert "fictional" not in repr(logs)
        assert "maxmemory" not in repr(logs)
        assert world.store.attempts == 3

    async def test_hanging_write_is_bounded_and_logs_timeout_error(
        self, world: _WriterWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ibs_consumer_status, "WRITE_TIMEOUT_SECONDS", 0.01)
        hanging = asyncio.Event()
        world.store.gate = hanging

        with capture_logs() as logs:
            await _started(world)
            world.store.gate = None
            world.timer.elapse()
            await _until(lambda: len(world.store.values) == 1)

        assert logs == [
            {
                "event": _WRITE_FAILED,
                "log_level": "warning",
                "error_type": "TimeoutError",
            }
        ]
        assert world.store.attempts == 2

    async def test_other_store_exception_ends_the_task(
        self, world: _WriterWorld
    ) -> None:
        world.store.errors = [RuntimeError("fictional failure")]

        with capture_logs() as logs:
            task = world.writer.start()
            with pytest.raises(RuntimeError, match="fictional failure"):
                await task

        assert logs == []
        assert world.timer.calls == []

    async def test_failing_timer_ends_the_task(self, world: _WriterWorld) -> None:
        world.timer.error = RuntimeError("fictional timer failure")

        task = world.writer.start()
        with pytest.raises(RuntimeError, match="fictional timer failure"):
            await task

        assert world.store.attempts == 1

    async def test_stop_cancels_without_a_further_write(
        self, world: _WriterWorld
    ) -> None:
        await _started(world)
        task = world.writer.start()

        await world.writer.stop()
        world.state.connected()
        world.timer.elapse()
        await _settle()

        assert task.cancelled()
        assert world.store.attempts == 1
        await world.writer.stop()
        assert world.store.attempts == 1

    async def test_stop_during_an_in_flight_write_completes_no_write(
        self, world: _WriterWorld
    ) -> None:
        gate = asyncio.Event()
        world.store.gate = gate
        task = world.writer.start()
        await _until(lambda: world.store.attempts == 1)

        await world.writer.stop()
        gate.set()
        await _settle()

        assert task.cancelled()
        assert world.store.values == []
        assert world.store.attempts == 1

    async def test_stop_before_start_is_a_no_op(self, world: _WriterWorld) -> None:
        await world.writer.stop()

        assert world.store.attempts == 0
        await _started(world)
        assert world.store.attempts == 1


# ---------------------------------------------------------------------------
# Redis: the heartbeat write and the status read
# ---------------------------------------------------------------------------


@dataclass(eq=False)
class _FakeRedis:
    """A replacement for `_new_redis_client()`'s client."""

    value: bytes | None = None
    error: redis_exceptions.RedisError | None = None
    close_error: redis_exceptions.RedisError | None = None
    closed: int = 0

    async def get(self, key: str) -> bytes | None:
        assert key == STATUS_KEY
        if self.error is not None:
            raise self.error
        return self.value

    async def set(self, key: str, value: str, ex: int) -> None:
        assert (key, ex) == (STATUS_KEY, 60)
        if self.error is not None:
            raise self.error

    async def aclose(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    monkeypatch.setattr(ibs_consumer_status, "_new_redis_client", lambda: fake)


def _forbid_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_redis() -> redis_asyncio.Redis:
        raise AssertionError("Redis must not be read")

    monkeypatch.setattr(ibs_consumer_status, "_new_redis_client", _no_redis)


_REDIS_ERRORS: Final = [
    pytest.param(
        redis_exceptions.ConnectionError("fictional refused"), id="connection"
    ),
    pytest.param(redis_exceptions.TimeoutError("fictional timeout"), id="timeout"),
    pytest.param(
        redis_exceptions.ResponseError("OOM command not allowed"), id="oom-response"
    ),
]


@pytest.fixture
def enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "ibs_rabbitmq_enabled", True)
    monkeypatch.setattr(ibs_consumer_status, "utc_now", lambda: _NOW)


@pytest.mark.unit
class TestDefaults:
    def test_default_redis_url_is_redis_url(self) -> None:
        assert ibs_consumer_status.get_ibs_consumer_status_redis_url() == (
            settings.redis_url
        )

    async def test_default_refresh_timer_is_an_asyncio_sleep(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        slept: list[float] = []

        async def recorded(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", recorded)

        await ibs_consumer_status._sleep(30.0)

        assert slept == [30.0]


@pytest.mark.unit
class TestRedisClientFactory:
    async def test_client_uses_boundary_url_two_second_timeouts_and_no_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ibs_consumer_status,
            "get_ibs_consumer_status_redis_url",
            lambda: "redis://redis.example.test:6390/3",
        )

        client = ibs_consumer_status._new_redis_client()
        try:
            kwargs = client.connection_pool.connection_kwargs
            assert (kwargs["host"], kwargs["port"], kwargs["db"]) == (
                "redis.example.test",
                6390,
                3,
            )
            assert kwargs["socket_connect_timeout"] == 2
            assert kwargs["socket_timeout"] == 2
            assert kwargs["retry"].get_retries() == 0
        finally:
            await client.aclose()


@pytest.mark.integration
class TestWriteHeartbeatValue:
    async def test_write_stores_the_value_with_a_sixty_second_ttl(
        self, redis_client: redis_asyncio.Redis
    ) -> None:
        value = _document().to_json()

        await write_heartbeat_value(value)

        assert await redis_client.get(STATUS_KEY) == value
        assert 0 < await redis_client.ttl(STATUS_KEY) <= 60

    async def test_second_write_replaces_the_value_and_resets_the_ttl(
        self, redis_client: redis_asyncio.Redis
    ) -> None:
        await write_heartbeat_value(_document().to_json())
        await redis_client.expire(STATUS_KEY, 10)
        replacement = _document(status=IBSConsumerStatus.DISCONNECTED).to_json()

        await write_heartbeat_value(replacement)

        assert await redis_client.get(STATUS_KEY) == replacement
        assert 10 < await redis_client.ttl(STATUS_KEY) <= 60

    @pytest.mark.parametrize("error", _REDIS_ERRORS)
    async def test_write_redis_error_propagates_and_closes_the_client(
        self, monkeypatch: pytest.MonkeyPatch, error: redis_exceptions.RedisError
    ) -> None:
        fake = _FakeRedis(error=error)
        _install(monkeypatch, fake)

        with pytest.raises(type(error)):
            await write_heartbeat_value(_document().to_json())

        assert fake.closed == 1


@pytest.mark.integration
class TestGetIBSConsumerStatus:
    @pytest.mark.parametrize(
        "members",
        [
            pytest.param(_CONNECTED, id="connected"),
            pytest.param(_RECONNECTING, id="reconnecting"),
            pytest.param(
                _with(status="disconnected", last_error="rabbitmq_connection_lost"),
                id="disconnected",
            ),
        ],
    )
    async def test_valid_fresh_heartbeat_returns_its_status_and_document(
        self,
        redis_client: redis_asyncio.Redis,
        enabled: None,
        members: Mapping[str, Any],
    ) -> None:
        await redis_client.set(STATUS_KEY, _encode(members), ex=60)

        view = await get_ibs_consumer_status()

        assert view.status is IBSConsumerStatus(members["status"])
        assert view.heartbeat == _expected_document(members)

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(None, id="absent"),
            pytest.param(b"not json", id="invalid"),
            pytest.param(
                _encode(_with(heartbeat_at="2026-09-08T15:41:39Z")), id="stale"
            ),
        ],
    )
    async def test_absent_invalid_or_stale_value_returns_unreachable(
        self, redis_client: redis_asyncio.Redis, enabled: None, raw: bytes | None
    ) -> None:
        if raw is not None:
            await redis_client.set(STATUS_KEY, raw, ex=60)

        view = await get_ibs_consumer_status()

        assert view.status is IBSConsumerStatus.UNREACHABLE
        assert view.heartbeat is None

    async def test_disabled_returns_disabled_without_reading_redis(
        self, redis_client: redis_asyncio.Redis, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings, "ibs_rabbitmq_enabled", False)
        monkeypatch.setattr(ibs_consumer_status, "utc_now", lambda: _NOW)
        await redis_client.set(STATUS_KEY, _encode(_CONNECTED), ex=60)
        _forbid_redis(monkeypatch)

        view = await get_ibs_consumer_status()

        assert view.status is IBSConsumerStatus.DISABLED
        assert view.heartbeat is None

    @pytest.mark.parametrize("error", _REDIS_ERRORS)
    async def test_redis_error_returns_unreachable_and_closes_the_client(
        self,
        enabled: None,
        monkeypatch: pytest.MonkeyPatch,
        error: redis_exceptions.RedisError,
    ) -> None:
        fake = _FakeRedis(error=error)
        _install(monkeypatch, fake)

        view = await get_ibs_consumer_status()

        assert view.status is IBSConsumerStatus.UNREACHABLE
        assert view.heartbeat is None
        assert fake.closed == 1

    async def test_clock_is_read_after_the_get(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A heartbeat written while the `GET` is in flight is never judged to
        be in the future: freshness uses the clock read after the read."""
        monkeypatch.setattr(settings, "ibs_rabbitmq_enabled", True)
        order: list[str] = []
        written_during_get = _with(heartbeat_at="2026-09-08T15:42:40Z")

        class _Racing(_FakeRedis):
            async def get(self, key: str) -> bytes | None:
                order.append("get")
                return await super().get(key)

        def now() -> datetime:
            order.append("clock")
            return _NOW

        _install(monkeypatch, _Racing(value=_encode(written_during_get)))
        monkeypatch.setattr(ibs_consumer_status, "utc_now", now)

        view = await get_ibs_consumer_status()

        assert order == ["get", "clock"]
        assert view.status is IBSConsumerStatus.CONNECTED

    async def test_close_failure_does_not_affect_the_observation(
        self, enabled: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakeRedis(
            value=_encode(_CONNECTED),
            close_error=redis_exceptions.ConnectionError("fictional reset"),
        )
        _install(monkeypatch, fake)

        view = await get_ibs_consumer_status()

        assert view.status is IBSConsumerStatus.CONNECTED
        assert view.heartbeat == _expected_document(_CONNECTED)
        assert fake.closed == 1
