"""Shared date-range parsing, normalization, and validation utilities.

See `docs/api-spec.md` (Date Range Interpretation) for the authoritative
contract this module implements: strict ISO 8601 parsing of `from_date`/
`to_date` values, UTC normalization of date-only bounds, and the global
`400 DATE_RANGE_INVERTED` response for an inverted range. This validation
is cross-cutting — every endpoint that declares both `from_date` and
`to_date` query parameters applies it, not only audit trail endpoints —
so it lives in Core rather than in any single service module.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time

from fastapi import status
from fastapi.exceptions import RequestValidationError

from app.core.errors import AppError, ErrorCode


def parse_date_range_bound(field_name: str, raw: str | None) -> date | datetime | None:
    """Parse one `from_date`/`to_date` query value.

    Q1: `field_name` is the query parameter name (used only to build the
    error `loc`); `raw` is the raw string value from the query string, or
    `None` when the parameter was omitted.

    Q3: `None` passes through unchanged. Otherwise accepts a bare ISO
    8601 date (`YYYY-MM-DD`) or a full ISO 8601 datetime, with or
    without a UTC offset, via `date.fromisoformat()` /
    `datetime.fromisoformat()`. Rejects any other input, including a
    pure numeric string — which Pydantic's default `datetime` coercion
    would otherwise silently accept as a Unix epoch timestamp, diverging
    from the documented ISO-8601-only contract. Also rejects a datetime
    whose offset moves its UTC instant outside the representable range
    (`0001-01-01T00:00:00Z` to `9999-12-31T23:59:59.999999Z`), which
    `astimezone()` signals with `OverflowError` rather than `ValueError`,
    so every accepted value normalizes to UTC without failing. The
    accepted value is returned as parsed, offset included.

    Q6: raises `RequestValidationError` — rendered as the standard `422
    VALIDATION_ERROR` envelope by the handler registered in `app.main`
    — for a value that is neither a valid ISO 8601 date nor datetime
    string, or whose UTC instant is out of range. Otherwise infallible.
    """
    if raw is None:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise _invalid_bound(
            field_name, "Value must be a valid ISO 8601 date or datetime string."
        ) from None
    if parsed.tzinfo is not None:
        try:
            parsed.astimezone(UTC)
        except OverflowError:
            raise _invalid_bound(
                field_name, "Value is out of the representable datetime range."
            ) from None
    return parsed


def _invalid_bound(field_name: str, message: str) -> RequestValidationError:
    return RequestValidationError(
        [{"loc": ["query", field_name], "msg": message, "type": "value_error"}]
    )


def normalize_date_bound(value: date | datetime, *, end_of_day: bool) -> datetime:
    """Normalize a date-filter bound to a UTC `datetime`.

    A `date` value is expanded to the start (`00:00:00`) or end
    (`23:59:59.999999`) of that UTC day, per `end_of_day`. A naive
    `datetime` is interpreted as UTC. An offset-aware `datetime` is
    converted to UTC. See `docs/api-spec.md` (Date Range Interpretation).
    Infallible for a value accepted by `parse_date_range_bound()`, which
    rejects an offset whose conversion would overflow.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    bound_time = time.max if end_of_day else time.min
    return datetime.combine(value, bound_time, tzinfo=UTC)


def validate_date_range_order(
    from_date: date | datetime | None, to_date: date | datetime | None
) -> None:
    """Raise the global `400 DATE_RANGE_INVERTED` response when inverted.

    Q1: `from_date`/`to_date` are the endpoint's optional date-range
    bounds as accepted by `parse_date_range_bound()`, which has already
    rejected malformed and out-of-range values.

    Q3: a no-op when either bound is absent — inversion is only defined
    when both bounds are present. Otherwise normalizes both bounds per
    `docs/api-spec.md` (Date Range Interpretation) and raises when the
    normalized `from_date` is strictly after the normalized `to_date`.

    Q6: raises `AppError` (400, `DATE_RANGE_INVERTED`) on an inverted
    range. Otherwise infallible.
    """
    if from_date is None or to_date is None:
        return
    normalized_from = normalize_date_bound(from_date, end_of_day=False)
    normalized_to = normalize_date_bound(to_date, end_of_day=True)
    if normalized_from > normalized_to:
        raise AppError(
            status_code=status.HTTP_400_BAD_REQUEST,
            code=ErrorCode.DATE_RANGE_INVERTED,
            detail="from_date must not be after to_date.",
        )
