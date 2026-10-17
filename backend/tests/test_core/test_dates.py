"""Tests for shared date-range parsing/validation (`backend/app/core/dates.py`).

See `docs/api-spec.md` (Date Range Interpretation) for the authoritative
contract under test.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from fastapi.exceptions import RequestValidationError

from app.core.dates import (
    normalize_date_bound,
    parse_date_range_bound,
    validate_date_range_order,
)
from app.core.errors import AppError, ErrorCode


@pytest.mark.unit
class TestParseDateRangeBound:
    def test_none_passes_through(self) -> None:
        assert parse_date_range_bound("from_date", None) is None

    def test_bare_date_parses_as_date(self) -> None:
        result = parse_date_range_bound("from_date", "2025-01-15")
        assert result == date(2025, 1, 15)

    def test_naive_datetime_parses_as_naive_datetime(self) -> None:
        result = parse_date_range_bound("from_date", "2025-01-15T14:30:00")
        # Intentionally naive — this test verifies the raw parse result
        # is a naive datetime; UTC interpretation happens separately in
        # `normalize_date_bound()`.
        assert result == datetime(2025, 1, 15, 14, 30, 0)  # noqa: DTZ001

    def test_offset_datetime_preserves_offset(self) -> None:
        result = parse_date_range_bound("to_date", "2025-01-15T14:30:00+02:00")
        assert isinstance(result, datetime)
        assert result.utcoffset() is not None
        assert result.astimezone(UTC) == datetime(2025, 1, 15, 12, 30, 0, tzinfo=UTC)

    def test_malformed_value_raises_request_validation_error(self) -> None:
        with pytest.raises(RequestValidationError) as exc_info:
            parse_date_range_bound("from_date", "not-a-date")
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["loc"] == ["query", "from_date"]
        assert errors[0]["type"] == "value_error"

    def test_pure_numeric_string_is_rejected_not_treated_as_epoch(self) -> None:
        """A pure numeric string is not a valid ISO 8601 date/datetime —
        rejecting it here prevents Pydantic's default `datetime`
        coercion (which treats numeric strings as Unix epoch seconds)
        from silently producing a nonsensical, far-past date."""
        with pytest.raises(RequestValidationError):
            parse_date_range_bound("to_date", "1700000000")

    def test_error_loc_reflects_field_name(self) -> None:
        with pytest.raises(RequestValidationError) as exc_info:
            parse_date_range_bound("to_date", "garbage")
        assert exc_info.value.errors()[0]["loc"] == ["query", "to_date"]

    @pytest.mark.parametrize("field_name", ["from_date", "to_date"])
    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("9999-12-31T23:59:59-00:01", id="above-by-one-minute"),
            pytest.param("9999-12-31T23:59:59-23:59", id="above-by-largest-offset"),
            pytest.param("0001-01-01T00:00:00+00:01", id="below-by-one-minute"),
            pytest.param("0001-01-01T00:00:00+23:59", id="below-by-largest-offset"),
        ],
    )
    def test_offset_moving_utc_instant_out_of_range_raises_request_validation_error(
        self, field_name: str, raw: str
    ) -> None:
        """`astimezone()` signals an out-of-range UTC instant with
        `OverflowError`, not `ValueError`; the value is malformed
        (`docs/api-spec.md`, Date Range Interpretation)."""
        with pytest.raises(RequestValidationError) as exc_info:
            parse_date_range_bound(field_name, raw)
        assert exc_info.value.errors() == [
            {
                "loc": ["query", field_name],
                "msg": "Value is out of the representable datetime range.",
                "type": "value_error",
            }
        ]

    @pytest.mark.parametrize(
        ("raw", "utc"),
        [
            (
                "9999-12-31T23:59:59.999999+00:00",
                datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
            ),
            (
                "9999-12-31T23:59:59.999999",
                datetime(9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
            ),
            (
                "9999-12-31T23:59:59+23:59",
                datetime(9999, 12, 31, 0, 0, 59, tzinfo=UTC),
            ),
            ("0001-01-01T00:00:00Z", datetime(1, 1, 1, tzinfo=UTC)),
            ("0001-01-01T00:00:00-23:59", datetime(1, 1, 1, 23, 59, tzinfo=UTC)),
        ],
    )
    def test_representable_extreme_is_accepted_as_parsed_and_normalizes(
        self, raw: str, utc: datetime
    ) -> None:
        parsed = parse_date_range_bound("from_date", raw)
        expected = datetime.fromisoformat(raw)
        assert isinstance(parsed, datetime)
        assert (parsed, parsed.tzinfo) == (expected, expected.tzinfo)
        assert normalize_date_bound(parsed, end_of_day=False) == utc
        assert normalize_date_bound(parsed, end_of_day=True) == utc


@pytest.mark.unit
class TestNormalizeDateBound:
    def test_date_start_of_day(self) -> None:
        result = normalize_date_bound(date(2025, 1, 15), end_of_day=False)
        assert result == datetime(2025, 1, 15, 0, 0, 0, tzinfo=UTC)

    def test_date_end_of_day(self) -> None:
        result = normalize_date_bound(date(2025, 1, 15), end_of_day=True)
        assert result == datetime(2025, 1, 15, 23, 59, 59, 999999, tzinfo=UTC)

    def test_naive_datetime_interpreted_as_utc(self) -> None:
        # Intentionally naive — this test verifies naive input is
        # interpreted as UTC.
        naive = datetime(2025, 1, 15, 14, 30, 0)  # noqa: DTZ001
        result = normalize_date_bound(naive, end_of_day=False)
        assert result == datetime(2025, 1, 15, 14, 30, 0, tzinfo=UTC)

    def test_offset_datetime_converted_to_utc(self) -> None:
        aware = datetime.fromisoformat("2025-01-15T14:30:00+02:00")
        result = normalize_date_bound(aware, end_of_day=False)
        assert result == datetime(2025, 1, 15, 12, 30, 0, tzinfo=UTC)

    def test_extreme_dates_expand_within_range(self) -> None:
        assert normalize_date_bound(date(1, 1, 1), end_of_day=False) == datetime(
            1, 1, 1, tzinfo=UTC
        )
        assert normalize_date_bound(date(9999, 12, 31), end_of_day=True) == datetime(
            9999, 12, 31, 23, 59, 59, 999999, tzinfo=UTC
        )


@pytest.mark.unit
class TestValidateDateRangeOrder:
    def test_both_none_is_a_no_op(self) -> None:
        validate_date_range_order(None, None)

    def test_only_from_date_is_a_no_op(self) -> None:
        validate_date_range_order(date(2025, 1, 15), None)

    def test_only_to_date_is_a_no_op(self) -> None:
        validate_date_range_order(None, date(2025, 1, 15))

    def test_same_day_bounds_are_not_inverted(self) -> None:
        """`from_date=2025-01-15, to_date=2025-01-15` normalizes to
        start-of-day vs end-of-day of the same date — not inverted."""
        validate_date_range_order(date(2025, 1, 15), date(2025, 1, 15))

    def test_ascending_range_is_accepted(self) -> None:
        validate_date_range_order(date(2025, 1, 1), date(2025, 1, 31))

    def test_inverted_date_range_raises_app_error(self) -> None:
        with pytest.raises(AppError) as exc_info:
            validate_date_range_order(date(2025, 1, 16), date(2025, 1, 15))
        assert exc_info.value.status_code == 400
        assert exc_info.value.code == ErrorCode.DATE_RANGE_INVERTED

    def test_inverted_datetime_range_same_day_raises(self) -> None:
        """Same-day datetimes where `from_date` is later in the day
        than `to_date` are inverted too — NULLS/day-boundary handling
        for `date` values must not mask this."""
        # Intentionally naive — UTC interpretation is exercised by
        # TestNormalizeDateBound; this test only cares about ordering.
        later = datetime(2025, 1, 15, 23, 0, 0)  # noqa: DTZ001
        earlier = datetime(2025, 1, 15, 22, 0, 0)  # noqa: DTZ001
        with pytest.raises(AppError) as exc_info:
            validate_date_range_order(later, earlier)
        assert exc_info.value.code == ErrorCode.DATE_RANGE_INVERTED

    def test_mixed_date_and_datetime_bounds(self) -> None:
        """A `date` `to_date` normalizes to end-of-day, so a `from_date`
        datetime earlier that same day is not inverted."""
        naive = datetime(2025, 1, 15, 8, 0, 0)  # noqa: DTZ001
        validate_date_range_order(naive, date(2025, 1, 15))

    def test_representable_extreme_bounds_are_ordered(self) -> None:
        validate_date_range_order(
            parse_date_range_bound("from_date", "0001-01-01T00:00:00-23:59"),
            parse_date_range_bound("to_date", "9999-12-31T23:59:59+23:59"),
        )
