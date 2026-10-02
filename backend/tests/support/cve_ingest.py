"""Shared helpers for the source-neutral CVE ingestion tests of
`cve_service.upsert_cve()` and `cve_service.record_source_status()`.

Consumers:

- `tests/test_services/test_upsert_cve.py` (the single-session CVE
  Ingestion Persistence matrix: guards, global merge, child persistence,
  canonical duplicates, affected-version scopes, `UpsertResult.action`,
  CVSS candidate skips, and `record_source_status()`);
- `tests/test_services/test_upsert_cve_composition.py` (the
  single-session CVE Ingestion and Ticket Composition matrix: phase order
  and the shared evaluation date through `CompositionTimeline`, Ticket
  creation, rejection and republication lifecycles, priority refresh,
  composed references, and whole-transaction rollback through
  `persisted_snapshot()`);
- the later independent-session race modules, which build the same
  payloads and observe the same rows.

The helpers only build inputs, record calls, and read persisted state;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import Engine, event, func, literal_column, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_reference import TicketReference
from app.services import cve_service, ticket_mutations, ticket_service
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVSSAssessmentEntry,
)
from app.services.cvss import validate_cvss_vector

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


# ---------------------------------------------------------------------------
# Composition observation
# ---------------------------------------------------------------------------

SNAPSHOT_MODELS: tuple[Any, ...] = (
    CVE,
    CVESource,
    *CHILD_MODELS,
    Ticket,
    TicketAuditEvent,
    TicketPackageProduct,
    TicketReference,
)
"""Every table one per-CVE ingestion transaction may write, including the
automatic references the fetcher adds before its commit."""


async def persisted_snapshot(db: AsyncSession) -> dict[str, list[tuple[Any, ...]]]:
    """Every column of every row of `SNAPSHOT_MODELS`, by table and `id`.

    Equality of two snapshots taken around a rolled-back scope proves that
    no CVE, source-status, child, Ticket, audit, Product, or reference
    effect survived, not only the rows a test happens to name."""
    snapshot: dict[str, list[tuple[Any, ...]]] = {}
    for model in SNAPSHOT_MODELS:
        table = model.__table__
        rows = await db.execute(select(*table.columns).order_by(table.c.id))
        snapshot[table.name] = [tuple(row) for row in rows]
    return snapshot


class _RecordingLogger:
    """Stands in for `cve_service.logger`, appending each call to a
    timeline instead of emitting it."""

    def __init__(self, entries: list[tuple[str, str]]) -> None:
        self._entries = entries

    def __getattr__(self, level: str) -> Callable[..., None]:
        def _log(event_name: str, **fields: Any) -> None:
            self._entries.append((level, event_name))

        return _log


@dataclass(slots=True)
class DelegateCall:
    """One recorded delegate call; `result` is set when the call returns."""

    name: str
    depth: int
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    result: Any = None


class CompositionTimeline:
    """One ordered record of an `upsert_cve()` call.

    Records, in a single list of `(kind, detail)` entries, every SQL
    statement on the test engine (`("sql", statement)`), each
    `cve_service.validate_cvss_vector()` call (`("parse", vector)`), each
    `cve_service.logger` call (`(level, event)`), and each call of the
    delegates `upsert_cve()` composes (`("call", name)`). Delegates are
    wrapped where `cve_service` resolves them (module attributes of
    `ticket_service`, `ticket_mutations`, and `cve_service`), so a nested
    call, such as the batch's own `refresh_priority_auto()`, is recorded
    too; `top_level()` lists only the calls made by `cve_service` itself.
    The wrappers call through to the real functions.

    The spies are installed at construction (restored by `monkeypatch`);
    SQL statements are recorded only inside the `with` block.
    """

    DELEGATES: tuple[tuple[ModuleType, str], ...] = (
        (ticket_service, "create_ticket"),
        (ticket_mutations, "upsert_external_cvss_batch"),
        (ticket_mutations, "refresh_priority_auto"),
        (ticket_service, "ignore_new_for_rejected_cve"),
        (ticket_service, "reopen_from_ignored_as_system"),
        (cve_service, "record_source_status"),
    )

    def __init__(self, db: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> None:
        self._engine: Engine = db.get_bind().engine
        self.entries: list[tuple[str, str]] = []
        self.calls: list[DelegateCall] = []
        self._depth = 0
        for module, name in self.DELEGATES:
            self._wrap(monkeypatch, module, name)

        def parse(vector: str) -> Any:
            self.entries.append(("parse", vector))
            return validate_cvss_vector(vector)

        monkeypatch.setattr(cve_service, "validate_cvss_vector", parse)
        monkeypatch.setattr(cve_service, "logger", _RecordingLogger(self.entries))

    def _wrap(
        self, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str
    ) -> None:
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            call = DelegateCall(name, self._depth, args, kwargs)
            self.calls.append(call)
            self.entries.append(("call", name))
            self._depth += 1
            try:
                call.result = await original(*args, **kwargs)
            finally:
                self._depth -= 1
            return call.result

        monkeypatch.setattr(module, name, _wrapper)

    def _record(self, *args: Any) -> None:
        self.entries.append(("sql", args[2]))

    def __enter__(self) -> CompositionTimeline:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)

    def top_level(self) -> list[str]:
        """The delegates called directly by `upsert_cve()`, in order."""
        return [call.name for call in self.calls if call.depth == 0]

    def calls_of(self, name: str) -> list[DelegateCall]:
        """Every call of one delegate, nested or not, in order."""
        return [call for call in self.calls if call.name == name]

    def positions(self, kind: str) -> list[int]:
        """The timeline positions of every entry of one kind."""
        return [i for i, (k, _) in enumerate(self.entries) if k == kind]

    def statements(self) -> list[str]:
        """The recorded SQL statements, in execution order."""
        return [detail for kind, detail in self.entries if kind == "sql"]
