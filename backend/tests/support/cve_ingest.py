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
- `tests/test_services/test_upsert_cve_atomicity.py` (the
  independent-session races: create/create, create/ensure, lifecycle,
  Ticket creation, manual SUSE CVSS, CVE association, same-source status,
  and the composed reference race, through `IngestionWorld`,
  `SessionCallSpy`, `root_lock_order()`, and `lock_not_available()`).

The helpers only build inputs, record calls, and read persisted state;
nothing here computes an expectation with the module under test.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest
from sqlalchemy import (
    Engine,
    Select,
    delete,
    event,
    func,
    literal_column,
    select,
    update,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CveState, Severity
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
from tests.support.suse_cvss import Vector
from tests.support.suse_cvss_races import CommittedWorld

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

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


# ---------------------------------------------------------------------------
# Independent-session races
# ---------------------------------------------------------------------------

DEFAULT_SETTING_KEY = "default_cvss_version"
DEFAULT_VERSION = "3.1"
"""The committed `default_cvss_version` of the racing tests."""

LOCK_NOT_AVAILABLE = "55P03"
"""PostgreSQL SQLSTATE `lock_not_available`, raised by `NOWAIT`."""

_FIRST_FROM = re.compile(r"\bFROM\s+(\"user\"|[a-z_]+)(?=\s|$)")


class IngestionWorld(CommittedWorld):
    """A `CommittedWorld` for the CVE ingestion races.

    It also owns the committed `default_cvss_version` setting (the test
    schema has none; a row this world created is deleted at teardown, a
    pre-existing row is restored), and it deletes every CVE named by
    `new_cve_id()` together with every Ticket associated with a world
    CVE, so rows created by the code under test cannot leak when an
    assertion fails. CVE children, `CVESource` rows, and Ticket
    references follow by their `ON DELETE CASCADE` foreign keys.
    """

    probe: AsyncSession
    """The independent session that observes committed state and probes
    locks; separate from `session`, whose committed instances the tests
    keep reading."""

    def __init__(self, factory: SessionFactory, session: AsyncSession) -> None:
        super().__init__(factory, session)
        self.cve_id_strings: list[str] = []
        self._owns_setting = False
        self._original_setting: str | None = None

    def new_cve_id(self) -> str:
        """A fresh fictional CVE-ID, deleted at teardown when created."""
        cve_id = f"CVE-2099-{uuid.uuid4().int % 10**8:08d}"
        self.cve_id_strings.append(cve_id)
        return cve_id

    async def ensure_default_setting(self) -> None:
        setting = await self.session.get(SystemSetting, DEFAULT_SETTING_KEY)
        if setting is None:
            self.session.add(
                SystemSetting(key=DEFAULT_SETTING_KEY, value=DEFAULT_VERSION)
            )
            self._owns_setting = True
        else:
            self._original_setting = setting.value
            setting.value = DEFAULT_VERSION
        await self.session.commit()

    async def cve_in(
        self,
        *,
        state: CveState = CveState.PUBLISHED,
        date_rejected: datetime | None = None,
        severity: Severity | None = None,
        assessments: Iterable[tuple[str, Vector]] = (),
    ) -> CVE:
        """A committed CVE in `state` with `(provider, vector)` assessments
        whose vector-derived units are consistent."""
        cve = CVE(
            cve_id=self.new_cve_id(),
            cve_state=state.value,
            date_rejected=date_rejected,
            severity=severity.value if severity is not None else None,
        )
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        for provider, vector in assessments:
            self.session.add(
                CVECVSSAssessment(
                    cve_id=cve.id, provider_name=provider, **vector.columns()
                )
            )
        await self.session.commit()
        return cve

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        found = (
            await self.session.scalars(
                select(CVE.id).where(CVE.cve_id.in_(self.cve_id_strings))
            )
        ).all()
        self.cve_ids.extend(set(found) - set(self.cve_ids))
        tickets = (
            await self.session.scalars(
                select(Ticket.id).where(Ticket.cve_id.in_(self.cve_ids))
            )
        ).all()
        self.ticket_ids.extend(set(tickets) - set(self.ticket_ids))
        await self.session.rollback()
        await super().cleanup()
        if self._owns_setting:
            await self.session.execute(
                delete(SystemSetting).where(SystemSetting.key == DEFAULT_SETTING_KEY)
            )
        elif self._original_setting is not None:
            await self.session.execute(
                update(SystemSetting)
                .where(SystemSetting.key == DEFAULT_SETTING_KEY)
                .values(value=self._original_setting)
            )
        await self.session.commit()


@dataclass(slots=True)
class SessionCall:
    """One recorded call: its session and, once it returned, its result."""

    session: AsyncSession
    result: Any = None


class SessionCallSpy:
    """Wraps one async module function and records, per call, the session
    passed as positional argument `index` (racing sessions share the
    module attribute) and the returned value. The wrapper calls through
    to the real function; it is installed where the caller resolves the
    name and restored by `monkeypatch`."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        module: ModuleType,
        name: str,
        *,
        index: int = 0,
    ) -> None:
        self.calls: list[SessionCall] = []
        original = getattr(module, name)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            call = SessionCall(args[index])
            self.calls.append(call)
            call.result = await original(*args, **kwargs)
            return call.result

        monkeypatch.setattr(module, name, _wrapper)

    @property
    def sessions(self) -> list[AsyncSession]:
        """The session of every call, in call order."""
        return [call.session for call in self.calls]

    def results(self, session: AsyncSession) -> list[Any]:
        """The results of the calls made in `session`, in call order."""
        return [call.result for call in self.calls if call.session is session]


def _root_kind(statement: str) -> str | None:
    """`user`, `cve`, or `ticket` for a root row-lock statement
    (`docs/conventions.md`, Cross-Domain Root Lock Order: the acting User
    `FOR SHARE`, the CVE `FOR NO KEY UPDATE`, the Ticket `FOR UPDATE`)."""
    text = statement.rstrip()
    match = _FIRST_FROM.search(text)
    table = match.group(1) if match is not None else None
    if table == '"user"' and text.endswith("FOR SHARE"):
        return "user"
    if table == "cve" and text.endswith("FOR NO KEY UPDATE"):
        return "cve"
    if table == "ticket" and text.endswith("FOR UPDATE"):
        return "ticket"
    return None


def root_lock_order(statements: Iterable[str]) -> list[str]:
    """The roots in the order this session first requested their lock;
    later same-transaction re-locks are ignored."""
    order: list[str] = []
    for statement in statements:
        kind = _root_kind(statement)
        if kind is not None and kind not in order:
            order.append(kind)
    return order


def is_root_lock(statement: str, kind: str) -> bool:
    """Whether `statement` requests the `kind` root lock."""
    return _root_kind(statement) == kind


async def lock_not_available(probe: AsyncSession, statement: Select[Any]) -> bool:
    """Whether another transaction holds a lock conflicting with `statement`
    taken `NOWAIT` (the caller chooses the lock mode). Only SQLSTATE
    `55P03` counts as held; any other database error propagates. The probe
    transaction is rolled back either way."""
    try:
        await probe.execute(statement)
    except DBAPIError as exc:
        await probe.rollback()
        if getattr(exc.orig, "sqlstate", None) != LOCK_NOT_AVAILABLE:
            raise
        return True
    await probe.rollback()
    return False


async def cve_ids_of(db: AsyncSession, cve_id: str) -> list[uuid.UUID]:
    """The UUID of every CVE row named `cve_id` (at most one)."""
    return list((await db.scalars(select(CVE.id).where(CVE.cve_id == cve_id))).all())


async def tickets_of(db: AsyncSession, cve_id: str) -> list[uuid.UUID]:
    """The UUID of every Ticket associated with the CVE named `cve_id`."""
    rows = await db.scalars(
        select(Ticket.id).join(CVE, Ticket.cve_id == CVE.id).where(CVE.cve_id == cve_id)
    )
    return list(rows.all())
