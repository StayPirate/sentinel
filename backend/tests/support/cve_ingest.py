"""Shared helpers for the source-neutral CVE ingestion tests of
`cve_service.upsert_cve()` and `cve_service.record_source_status()`.

Consumers:

- `tests/test_services/test_upsert_cve.py` (the single-session CVE
  Ingestion Persistence matrix: guards, global merge, child persistence,
  canonical duplicates, affected-version scopes, `UpsertResult.action`,
  CVSS candidate skips, and `record_source_status()`);
- the later `upsert_cve()` composition and independent-session race
  modules, which build the same payloads and observe the same rows.

The helpers only build inputs and read persisted state; nothing here
computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, literal_column, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.system_setting import SystemSetting
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVSSAssessmentEntry,
)

Factory = Callable[..., Awaitable[Any]]

SKIP_EVENT = "cve_cvss_candidate_skipped"
"""The sanitized warning of one skipped CVSS candidate (cve-service.md,
Phase 1 > CVSS assessment ingestion)."""

SKIP_EVENT_KEYS = frozenset(
    {"event", "log_level", "cve_id", "source", "ordinal", "reason"}
)
"""Every key of a captured skip warning: structlog's `event` and
`log_level` plus exactly the four permitted fields."""

BACKDATED = datetime(2001, 2, 3, 4, 5, 6, tzinfo=UTC)
"""A fixed past `updated_at` (testing-strategy.md, `server_default=
func.now()` and `onupdate=func.now()` Testing: `now()` is constant within
the test transaction, so a no-churn proof backdates first)."""

CHILD_MODELS: tuple[Any, ...] = (
    CVECVSSAssessment,
    CVECWE,
    CVEExternalIdentifier,
    CVEAffectedVersion,
    CVESSVCAssessment,
    CVEKEVEntry,
    CVEEPSSScore,
)
"""The seven CVE child tables of the Child Persistence Matrix."""


async def create_default_cvss_version(
    system_setting_factory: Factory, value: str = "3.1"
) -> SystemSetting:
    """Persist `default_cvss_version`, which the test schema lacks and the
    trusted-external CVSS batch reads for a non-empty candidate set."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value=value
    )
    return setting


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def cvss(provider: object, vector: object) -> CVSSAssessmentEntry:
    """One untrusted vector-only CVSS candidate."""
    return CVSSAssessmentEntry(provider_name=provider, vector_string=vector)


def av_entry(**values: Any) -> AffectedVersionEntry:
    """One affected-version entry with the given fields (others absent)."""
    return AffectedVersionEntry(**values)


def replace(
    scope: str, *entries: AffectedVersionEntry
) -> AffectedVersionScopeOperation:
    """A `replace` snapshot of `scope` (no entries is an empty snapshot)."""
    return AffectedVersionScopeOperation(
        source_container=scope,
        operation=AffectedVersionOperation.REPLACE,
        entries=list(entries),
    )


def remove(scope: str) -> AffectedVersionScopeOperation:
    """A `remove` operation of `scope`."""
    return AffectedVersionScopeOperation(
        source_container=scope, operation=AffectedVersionOperation.REMOVE
    )


# ---------------------------------------------------------------------------
# Persisted-state observation
# ---------------------------------------------------------------------------


async def child_counts(db: AsyncSession, cve_id: uuid.UUID) -> dict[str, int]:
    """The row count of every child table for one CVE, by table name."""
    counts: dict[str, int] = {}
    for model in CHILD_MODELS:
        counts[model.__tablename__] = (
            await db.scalar(
                select(func.count()).select_from(model).where(model.cve_id == cve_id)
            )
        ) or 0
    return counts


async def ctid(db: AsyncSession, model: Any, row_id: uuid.UUID) -> str:
    """The physical tuple location of one row.

    PostgreSQL MVCC writes a new tuple version for every `UPDATE`, even
    one assigning identical values, and the superseded version of an
    in-progress transaction cannot be pruned, so an unchanged `ctid`
    proves the row was not rewritten in the test transaction. A row lock
    (`FOR UPDATE`, or an `ON CONFLICT DO UPDATE` whose `WHERE` is false)
    marks the tuple in place and keeps its `ctid`.
    """
    value: str = (
        await db.execute(
            select(literal_column("ctid::text"))
            .select_from(model)
            .where(model.id == row_id)
        )
    ).scalar_one()
    return value


async def backdate(
    db: AsyncSession, model: Any, row_id: uuid.UUID, when: datetime = BACKDATED
) -> None:
    """Set one row's `updated_at` to `when` (an explicit value overrides
    `onupdate`)."""
    await db.execute(
        update(model)
        .where(model.id == row_id)
        .values(updated_at=when)
        .execution_options(synchronize_session=False)
    )


async def row_state(db: AsyncSession, model: Any, row_id: uuid.UUID) -> tuple[str, Any]:
    """`(ctid, updated_at)` of one row: the rewrite and timestamp-churn
    observation of a no-op proof."""
    row = (
        await db.execute(
            select(literal_column("ctid::text"), model.updated_at).where(
                model.id == row_id
            )
        )
    ).one()
    return row[0], row[1]


async def source_rows(
    db: AsyncSession, cve_id: uuid.UUID
) -> list[tuple[str, str, datetime, datetime | None]]:
    """Every `(source, status, fetched_at, first_failed_at)` of one CVE, by
    source."""
    rows = await db.execute(
        select(
            CVESource.source,
            CVESource.status,
            CVESource.fetched_at,
            CVESource.first_failed_at,
        )
        .where(CVESource.cve_id == cve_id)
        .order_by(CVESource.source)
        .execution_options(populate_existing=True)
    )
    return [(s, st, f, ff) for s, st, f, ff in rows]


def skip_events(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The captured `cve_cvss_candidate_skipped` entries, in emission order."""
    return [dict(entry) for entry in entries if entry.get("event") == SKIP_EVENT]
