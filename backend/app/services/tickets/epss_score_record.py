"""Typed models and pure conversion of one FIRST.org EPSS response.

Implements docs/features/tickets/cve-sync-epss.md (Algorithm steps 2-4,
Field Mapping) for the body of one `GET /data/v1/epss?cve={CVE-ID}`
HTTP 200 response. The module performs no HTTP, database, or logging
work; `SyncEpssScores` (`sync_epss_scores.py`) owns the request and the
ingestion.

`parse_response()` validates only the consumed fields, strictly and
without coercion: the root is an object whose `data` is an array of at
most one object carrying `epss`, `percentile`, and `date` as strings in
the API's encodings. Any other shape raises `pydantic.ValidationError`,
whose message never renders the input. `to_epss_entry()` converts the
entry into the persisted `EPSSEntry` (float scores in [0, 1] and a
calendar date), so no received string reaches PostgreSQL.
"""

from __future__ import annotations

from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from app.services.cve_ingest import EPSSEntry

_DECIMAL_PATTERN: Final = r"^[0-9]+(\.[0-9]+)?$"
"""An unsigned ASCII decimal: no sign, exponent, whitespace, or `NaN`."""

_DATE_PATTERN: Final = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
"""`YYYY-MM-DD`; the calendar check is `EPSSEntry`'s."""


class _ConsumedFields(BaseModel):
    """Strict, unknown-field-ignoring shape of consumed fields only."""

    model_config = ConfigDict(
        strict=True, extra="ignore", frozen=True, hide_input_in_errors=True
    )


class EpssScoreRecord(_ConsumedFields):
    """One `data[]` entry; the redundant `cve` member is not consumed."""

    epss: str = Field(pattern=_DECIMAL_PATTERN)
    percentile: str = Field(pattern=_DECIMAL_PATTERN)
    date: str = Field(pattern=_DATE_PATTERN)


class EpssResponse(_ConsumedFields):
    """The consumed envelope: `data` with at most one entry (Algorithm
    step 2); every other envelope member is ignored."""

    data: list[EpssScoreRecord] = Field(max_length=1)


def parse_response(data: object) -> EpssResponse:
    """Validate a decoded response body (Algorithm step 2).

    Raises `pydantic.ValidationError` for a non-object root, a missing or
    non-array `data`, more than one entry, or a missing, mistyped, or
    mis-encoded consumed entry field.
    """
    return EpssResponse.model_validate(data)


def to_epss_entry(record: EpssScoreRecord) -> EPSSEntry:
    """Algorithm step 4: the persisted `EPSSEntry` of one entry.

    Raises `pydantic.ValidationError` for a score or percentile outside
    [0, 1] or an invalid calendar date.
    """
    return EPSSEntry.model_validate(
        {
            "score": record.epss,
            "percentile": record.percentile,
            "assessed_at": record.date,
        }
    )
