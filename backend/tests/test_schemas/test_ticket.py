"""Unit tests for the Ticket request schemas (`backend/app/schemas/ticket.py`).

See docs/features/tickets/tickets.md (Create Ticket, Set Coordinated Release
Date) and docs/conventions.md (Timestamps & Timezones) for the authoritative
contract under test.

The complete input matrix of the shared Coordinated Release Date parser,
`parse_coordinated_release_at()`, is proven once here (testing-strategy.md,
Tier Responsibility and Proportionality); each request model is proven to be
wired to it. The e2e modules keep only representative endpoint cases.
Expected values are transcribed from the specifications.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.schemas.ticket import (
    TicketCoordinatedReleaseDateUpdateRequest,
    TicketCreateRequest,
    parse_coordinated_release_at,
)

_NOT_A_STRING = "coordinated_release_at must be an ISO 8601 datetime string."
_NO_TIME = "coordinated_release_at must include a time component."
_INVALID = "coordinated_release_at must be a valid ISO 8601 datetime."
_OUT_OF_RANGE = "coordinated_release_at is out of the representable datetime range."

_CRD_INSTANT = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)


@pytest.mark.unit
class TestParseCoordinatedReleaseAt:
    def test_null_is_none(self) -> None:
        assert parse_coordinated_release_at(None) is None

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param("2026-10-06T14:00:00Z", _CRD_INSTANT, id="utc-z"),
            pytest.param("2026-10-06T14:00:00", _CRD_INSTANT, id="naive-is-utc"),
            pytest.param("2026-10-06T16:00:00+02:00", _CRD_INSTANT, id="offset"),
            pytest.param(
                "2026-10-06T14:00:00+00:00", _CRD_INSTANT, id="explicit-zero-offset"
            ),
            pytest.param(
                "2026-12-31T23:30:00-05:00",
                datetime(2027, 1, 1, 4, 30, tzinfo=UTC),
                id="offset-crossing-midnight",
            ),
            pytest.param(
                "2026-10-06T14:00:00.5Z",
                datetime(2026, 10, 6, 14, 0, 0, 500000, tzinfo=UTC),
                id="sub-second",
            ),
            pytest.param(
                "2020-01-02T03:04:05Z",
                datetime(2020, 1, 2, 3, 4, 5, tzinfo=UTC),
                id="past",
            ),
        ],
    )
    def test_datetime_is_returned_as_the_aware_utc_instant(
        self, value: str, expected: datetime
    ) -> None:
        parsed = parse_coordinated_release_at(value)

        assert parsed == expected
        assert parsed is not None
        assert parsed.utcoffset() == timedelta(0)

    @pytest.mark.parametrize(
        ("value", "message"),
        [
            pytest.param("2026-10-06", _NO_TIME, id="date-only"),
            pytest.param("20261006", _NO_TIME, id="basic-date"),
            pytest.param(1791295200, _NOT_A_STRING, id="int"),
            pytest.param(1791295200.5, _NOT_A_STRING, id="float"),
            pytest.param(True, _NOT_A_STRING, id="bool"),
            pytest.param({"at": "2026-10-06T14:00:00Z"}, _NOT_A_STRING, id="dict"),
            pytest.param(["2026-10-06T14:00:00Z"], _NOT_A_STRING, id="list"),
            pytest.param("", _INVALID, id="empty-string"),
            pytest.param("not-a-date", _INVALID, id="not-a-date"),
            pytest.param("2026-13-01T00:00:00Z", _INVALID, id="invalid-month"),
            pytest.param("0001-01-01T00:00:00+01:00", _OUT_OF_RANGE, id="underflow"),
            pytest.param("9999-12-31T23:59:59-01:00", _OUT_OF_RANGE, id="overflow"),
        ],
    )
    def test_invalid_value_is_rejected(self, value: object, message: str) -> None:
        with pytest.raises(ValueError, match=re.escape(message)):
            parse_coordinated_release_at(value)


@pytest.mark.unit
class TestTicketCoordinatedReleaseDateUpdateRequest:
    def test_value_is_parsed_to_the_utc_instant(self) -> None:
        request = TicketCoordinatedReleaseDateUpdateRequest.model_validate(
            {"coordinated_release_at": "2026-10-06T16:00:00+02:00"}
        )

        assert request.coordinated_release_at == _CRD_INSTANT

    def test_parser_rejection_is_a_validation_error(self) -> None:
        with pytest.raises(ValidationError, match=re.escape(_NO_TIME)):
            TicketCoordinatedReleaseDateUpdateRequest.model_validate(
                {"coordinated_release_at": "2026-10-06"}
            )

    def test_null_clears(self) -> None:
        request = TicketCoordinatedReleaseDateUpdateRequest.model_validate(
            {"coordinated_release_at": None}
        )

        assert request.coordinated_release_at is None

    def test_omitted_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Field required"):
            TicketCoordinatedReleaseDateUpdateRequest.model_validate({})


@pytest.mark.unit
class TestTicketCreateRequestCoordinatedReleaseAt:
    def test_value_is_parsed_to_the_utc_instant(self) -> None:
        request = TicketCreateRequest.model_validate(
            {
                "is_confidential": True,
                "coordinated_release_at": "2026-10-06T16:00:00+02:00",
            }
        )

        assert request.coordinated_release_at == _CRD_INSTANT

    def test_parser_rejection_is_a_validation_error(self) -> None:
        with pytest.raises(ValidationError, match=re.escape(_NOT_A_STRING)):
            TicketCreateRequest.model_validate(
                {"is_confidential": True, "coordinated_release_at": 1791295200}
            )
