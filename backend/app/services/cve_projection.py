"""The shared `CVEDetail` semantic projection and its SQL building blocks.

See `docs/features/tickets/tickets.md` (Response Schemas > Shared
Sub-Schemas: `CVEDetail`, `CVEKEVResponse`, `CVEEPSSResponse`,
`CVESSVCResponse`, `CVEWeaknessResponse`, `CVEExternalIdentifierResponse`)
for the projected fields and their ordering rules. Two reads project the
same `CVEDetail`: the Ticket detail (`TicketDetail.cve`, owned by
`ticket_service`) and the CVE detail (`CVEResourceDetail`, owned by
`cve_service`; `docs/features/tickets/cve-service.md`, CVE Detail).

This leaf module imports only Models and Core, so both services use one
projection without `cve_service` importing `ticket_service`. It owns no
query: each caller builds its own single statement, selects
`cve_detail_columns()`, adds `join_cve_evidence()`, applies its own
selection and accessibility, and assembles the row with
`cve_detail_from_row()`.

Every collection is a correlated scalar subquery and every joined
evidence relation is unique by `cve_id`, so these building blocks never
multiply the enclosing statement's rows. Building them performs no I/O;
assembling a row is pure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final

from sqlalchemy import (
    ColumnElement,
    Select,
    SQLColumnExpression,
    func,
    literal_column,
    select,
    type_coerce,
)
from sqlalchemy.dialects.postgresql import JSON, aggregate_order_by
from sqlalchemy.engine import Row

from app.core.enums import CveState, Severity
from app.models.cve import CVE
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_ssvc_assessment import CVESSVCAssessment

CODE_POINT_COLLATION: Final = "C"
"""PostgreSQL collation that compares strings by code point, giving
Unicode code-point order for UTF-8 text independent of the database
default collation."""

_EMPTY_JSON_ARRAY: Final[ColumnElement[Any]] = literal_column("'[]'::json")


@dataclass(frozen=True, slots=True)
class CVEKEVProjection:
    """The persisted CISA KEV catalog entry of a CVE."""

    date_added: date
    reference_url: str | None


@dataclass(frozen=True, slots=True)
class CVEEPSSProjection:
    """The latest persisted FIRST EPSS snapshot of a CVE."""

    score: float
    percentile: float
    assessed_at: date


@dataclass(frozen=True, slots=True)
class CVESSVCProjection:
    """The persisted CISA SSVC decision points of a CVE (stored labels)."""

    exploitation: str
    automatable: str
    technical_impact: str
    version: str
    assessed_at: datetime | None


@dataclass(frozen=True, slots=True)
class CVEWeaknessProjection:
    """One distinct CWE of a CVE with every provider that assigned it,
    exact-deduplicated and in ascending Unicode code-point order."""

    cwe_id: str
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CVEExternalIdentifierProjection:
    """One external vulnerability identifier of a CVE.

    `source` is the stored `CVEExternalIdentifierSource` value (for
    example `"GHSA"`); the wire format lowercases it.
    """

    source: str
    identifier: str
    url: str | None


@dataclass(frozen=True, slots=True)
class CVEDetailProjection:
    """The expanded CVE projection represented by `CVEDetail`.

    `severity` is the CVE-owned unified severity (`None` is SQL `NULL`,
    unresolved; `Severity.NONE` is the resolved `None` label).
    `external_identifiers` are ordered by source, identifier, then
    `CVEExternalIdentifier.id`; `cwes` by `cwe_id`, all in ascending
    Unicode code-point order. The internal CVE UUID, Ticket content, a
    priority, and CVSS assessments are never part of it.
    """

    cve_id: str
    title: str | None
    description: str | None
    published_date: datetime | None
    modified_date: datetime | None
    cve_state: CveState
    date_rejected: datetime | None
    severity: Severity | None
    external_identifiers: tuple[CVEExternalIdentifierProjection, ...]
    kev: CVEKEVProjection | None
    epss: CVEEPSSProjection | None
    ssvc: CVESSVCProjection | None
    cwes: tuple[CVEWeaknessProjection, ...]


# ---------------------------------------------------------------------------
# SQL building blocks
# ---------------------------------------------------------------------------


def _key(name: str) -> ColumnElement[str]:
    """An inline JSON object key (a SQL literal, not a bound parameter)."""
    return literal_column(f"'{name}'")


def _json_array(
    element: ColumnElement[Any], *order_by: SQLColumnExpression[Any]
) -> ColumnElement[Any]:
    """`COALESCE(json_agg(element ORDER BY ...), '[]')`."""
    return func.coalesce(
        func.json_agg(aggregate_order_by(element, *order_by)), _EMPTY_JSON_ARRAY
    )


def _cwe_assignments_column() -> ColumnElement[Any]:
    """Every `(cwe_id, source)` pair of the enclosing CVE as a JSON array,
    ordered by `cwe_id` then `source` in code-point order; `[]` when none
    exist (grouped into `CVEWeaknessProjection` values by `_cwes()`)."""
    pairs = (
        select(
            _json_array(
                func.json_build_array(CVECWE.cwe_id, CVECWE.source),
                CVECWE.cwe_id.collate(CODE_POINT_COLLATION),
                CVECWE.source.collate(CODE_POINT_COLLATION),
            )
        )
        .where(CVECWE.cve_id == CVE.id)
        .correlate_except(CVECWE)
        .scalar_subquery()
    )
    return type_coerce(pairs, JSON)


def _external_identifiers_column() -> ColumnElement[Any]:
    """External identifiers of the enclosing CVE as a JSON array, ordered by
    source, identifier (code point), then `CVEExternalIdentifier.id`."""
    identifier = func.json_build_object(
        _key("source"),
        CVEExternalIdentifier.source,
        _key("identifier"),
        CVEExternalIdentifier.identifier,
        _key("url"),
        CVEExternalIdentifier.url,
    )
    identifiers = (
        select(
            _json_array(
                identifier,
                CVEExternalIdentifier.source.collate(CODE_POINT_COLLATION),
                CVEExternalIdentifier.identifier.collate(CODE_POINT_COLLATION),
                CVEExternalIdentifier.id,
            )
        )
        .where(CVEExternalIdentifier.cve_id == CVE.id)
        .correlate_except(CVEExternalIdentifier)
        .scalar_subquery()
    )
    return type_coerce(identifiers, JSON)


def cve_detail_columns() -> tuple[ColumnElement[Any], ...]:
    """The labeled columns `cve_detail_from_row()` reads.

    They reference the `CVE` entity and the evidence relations joined by
    `join_cve_evidence()`; the enclosing statement must make `CVE`
    available (as its root or through an outer join). `cve_pk` is the
    internal CVE UUID, selected only to detect an absent CVE and never
    projected.
    """
    return (
        CVE.id.label("cve_pk"),
        CVE.cve_id.label("cve_id"),
        CVE.title.label("cve_title"),
        CVE.description.label("cve_description"),
        CVE.published_date.label("cve_published_date"),
        CVE.modified_date.label("cve_modified_date"),
        CVE.cve_state.label("cve_state"),
        CVE.date_rejected.label("cve_date_rejected"),
        CVE.severity.label("cve_severity"),
        CVEKEVEntry.id.label("kev_pk"),
        CVEKEVEntry.date_added.label("kev_date_added"),
        CVEKEVEntry.reference_url.label("kev_reference_url"),
        CVEEPSSScore.id.label("epss_pk"),
        CVEEPSSScore.score.label("epss_score"),
        CVEEPSSScore.percentile.label("epss_percentile"),
        CVEEPSSScore.assessed_at.label("epss_assessed_at"),
        CVESSVCAssessment.id.label("ssvc_pk"),
        CVESSVCAssessment.exploitation.label("ssvc_exploitation"),
        CVESSVCAssessment.automatable.label("ssvc_automatable"),
        CVESSVCAssessment.technical_impact.label("ssvc_technical_impact"),
        CVESSVCAssessment.version.label("ssvc_version"),
        CVESSVCAssessment.assessed_at.label("ssvc_assessed_at"),
        _cwe_assignments_column().label("cve_cwe_assignments"),
        _external_identifiers_column().label("cve_external_identifiers"),
    )


def join_cve_evidence[*Ts](statement: Select[*Ts]) -> Select[*Ts]:
    """Outer-join the one-to-one KEV, EPSS, and SSVC rows of `CVE`.

    Each relation is unique by `cve_id`, so the joins add at most one row
    per CVE and never multiply the statement.
    """
    return (
        statement.outerjoin(CVEKEVEntry, CVEKEVEntry.cve_id == CVE.id)
        .outerjoin(CVEEPSSScore, CVEEPSSScore.cve_id == CVE.id)
        .outerjoin(CVESSVCAssessment, CVESSVCAssessment.cve_id == CVE.id)
    )


# ---------------------------------------------------------------------------
# Row assembly
# ---------------------------------------------------------------------------


def _cwes(assignments: Sequence[Sequence[str]]) -> tuple[CVEWeaknessProjection, ...]:
    """Group ordered `(cwe_id, source)` pairs by CWE, exact-deduplicating
    the sources while keeping their code-point order."""
    grouped: dict[str, dict[str, None]] = {}
    for cwe_id, source in assignments:
        grouped.setdefault(cwe_id, {})[source] = None
    return tuple(
        CVEWeaknessProjection(cwe_id=cwe_id, sources=tuple(sources))
        for cwe_id, sources in grouped.items()
    )


def _external_identifiers(
    raw: Sequence[Mapping[str, Any]],
) -> tuple[CVEExternalIdentifierProjection, ...]:
    return tuple(
        CVEExternalIdentifierProjection(
            source=item["source"], identifier=item["identifier"], url=item["url"]
        )
        for item in raw
    )


def cve_detail_from_row(row: Row[Any]) -> CVEDetailProjection | None:
    """Assemble the projection from a row selecting `cve_detail_columns()`.

    Returns `None` when the row has no CVE (`cve_pk` is `NULL`, for
    example a CVE-less Ticket). Pure.
    """
    if row.cve_pk is None:
        return None
    return CVEDetailProjection(
        cve_id=row.cve_id,
        title=row.cve_title,
        description=row.cve_description,
        published_date=row.cve_published_date,
        modified_date=row.cve_modified_date,
        cve_state=CveState(row.cve_state),
        date_rejected=row.cve_date_rejected,
        severity=Severity(row.cve_severity) if row.cve_severity is not None else None,
        external_identifiers=_external_identifiers(row.cve_external_identifiers),
        kev=(
            CVEKEVProjection(
                date_added=row.kev_date_added, reference_url=row.kev_reference_url
            )
            if row.kev_pk is not None
            else None
        ),
        epss=(
            CVEEPSSProjection(
                score=row.epss_score,
                percentile=row.epss_percentile,
                assessed_at=row.epss_assessed_at,
            )
            if row.epss_pk is not None
            else None
        ),
        ssvc=(
            CVESSVCProjection(
                exploitation=row.ssvc_exploitation,
                automatable=row.ssvc_automatable,
                technical_impact=row.ssvc_technical_impact,
                version=row.ssvc_version,
                assessed_at=row.ssvc_assessed_at,
            )
            if row.ssvc_pk is not None
            else None
        ),
        cwes=_cwes(row.cve_cwe_assignments),
    )
