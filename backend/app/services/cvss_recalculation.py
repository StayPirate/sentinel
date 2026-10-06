"""All-CVE default-version CVSS recalculation runner.

Implements `docs/features/platform/default-cvss-version-operations.md`
(All-CVE Recalculation Runner; Retry, Rerun, and Recovery; Absence of
Persistent Run State; and the task side of Complete-Run Coordination). The
thin Celery wrapper `recalculate_cvss_derived_state` in
`app/tasks/cvss_tasks.py` validates its inputs with
`validate_target_version()` and `validate_task_id()`, then bridges into
`run_cvss_derived_state_recalculation()` with exactly one `asyncio.run()`.

The workflow:

1. derives its dedicated fenced connection from the session factory's bind
   (own-or-borrow): an `AsyncEngine` bind is connected and owned, and the
   engine is disposed once at the outer boundary; an `AsyncConnection` bind
   is borrowed and never closed, invalidated, or disposed by the workflow;
2. adopts the run: non-blocking fence acquisition, then one exact
   compare-and-renew of the `cvss_recalc_active` lease (Task Adoption);
3. reads the persisted setting once and terminates `stale` when it differs
   from `target_version`;
4. captures the `max(CVE.id)` watermark and enumerates keyset pages of at
   most 500 identities;
5. processes each CVE in one fresh session and transaction on the fenced
   connection through `ticket_mutations.recalculate_cvss_chain()` in
   default-version mode, commits, closes, and drains the unit's Ticket
   convergence effects before the next unit;
6. renews the lease between units at least 60 seconds after the last
   successful renewal; and
7. on every interceptable terminal path closes the current unit session,
   compare-and-deletes the lease while still fenced, releases the fence,
   then emits exactly one terminal event.

The only isolable unit failure is a pre-commit `40P01` deadlock on a
still-valid connection (Error Taxonomy). The runner defines no exception
class; an ownership loss by `mismatch` or `absent` raises the built-in
`RuntimeError` after its terminal event. Nothing is persisted, returned,
or published to a result backend.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Final

import redis.asyncio as redis_asyncio
import structlog
from celery.exceptions import SoftTimeLimitExceeded, WorkerShutdown, WorkerTerminate
from kombu.exceptions import (  # type: ignore[import-untyped]
    EncodeError,
    SerializerNotInstalled,
)
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.exc import (
    DataError,
    DBAPIError,
    IntegrityError,
    ProgrammingError,
    SQLAlchemyError,
)
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)

from app.core.enums import CVSSVersion
from app.models.cve import CVE
from app.services import settings as settings_service
from app.services import ticket_mutations
from app.services.cvss import DEFAULT_CVSS_VERSIONS
from app.services.cvss_recalculation_coordination import (
    LEASE_RENEWAL_INTERVAL_SECONDS,
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseRenewOutcome,
    compare_and_delete_lease,
    compare_and_renew_lease,
    is_canonical_task_id,
    new_cvss_recalculation_redis_client,
    release_execution_fence,
    try_acquire_execution_fence,
)
from app.services.ticket_convergence_publication import drain_ticket_convergence

logger = structlog.get_logger(__name__)

RECALCULATE_CVSS_DERIVED_STATE_TASK: Final = "recalculate_cvss_derived_state"
"""Explicit registered name of the all-CVE recalculation Celery task."""

CVE_PAGE_SIZE: Final = 500
"""Maximum candidate identities per keyset page (feature constant)."""

OWNERSHIP_LOST_MESSAGE: Final = "CVSS recalculation ownership lost"
"""Fixed message of the built-in `RuntimeError` raised after an ownership
loss by lease `mismatch` or `absent`."""

_DEADLOCK_DETECTED: Final = "40P01"

# Runner events (Logging).
STARTED_EVENT: Final = "cvss_recalculation_started"
CVE_FAILED_EVENT: Final = "cvss_recalculation_cve_failed"
COMPLETED_EVENT: Final = "cvss_recalculation_completed"
PARTIAL_EVENT: Final = "cvss_recalculation_partial"
STALE_EVENT: Final = "cvss_recalculation_stale"
CANCELLED_EVENT: Final = "cvss_recalculation_cancelled"
OWNERSHIP_LOST_EVENT: Final = "cvss_recalculation_ownership_lost"
FAILED_EVENT: Final = "cvss_recalculation_failed"

# Coordination events of the task side (Coordination Logging).
ADOPTED_EVENT: Final = "cvss_recalculation_adopted"
ADOPTION_REJECTED_EVENT: Final = "cvss_recalculation_adoption_rejected"
RENEWAL_FAILED_EVENT: Final = "cvss_recalculation_renewal_failed"
CLEANUP_FAILED_EVENT: Final = "cvss_recalculation_cleanup_failed"

ENGINE_DISPOSE_FAILED_EVENT: Final = "cvss_recalculation_engine_dispose_failed"
"""Infrastructure WARNING when disposal fails while an exception propagates."""


class Outcome(StrEnum):
    """The closed terminal outcome vocabulary of one delivery."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    STALE = "stale"
    CANCELLED = "cancelled"
    OWNERSHIP_LOST = "ownership_lost"
    FAILED = "failed"


class Phase(StrEnum):
    """The closed failure phase vocabulary."""

    SETTING_READ = "setting_read"
    ENUMERATION = "enumeration"
    UNIT = "unit"
    PUBLICATION = "publication"
    CONTROL = "control"


class Cause(StrEnum):
    """The closed sanitized cause category vocabulary."""

    DATABASE = "database"
    DOMAIN = "domain"
    PROGRAMMING = "programming"
    INFRASTRUCTURE = "infrastructure"
    INTERRUPTED = "interrupted"
    UNEXPECTED = "unexpected"


class RejectionReason(StrEnum):
    """Closed `reason` categories of the task-side coordination events."""

    TASK_ID_INVALID = "task_id_invalid"
    FENCE_BUSY = "fence_busy"
    LEASE_ABSENT = "lease_absent"
    LEASE_MISMATCH = "lease_mismatch"
    REDIS_ERROR = "redis_error"
    FENCE_RELEASE_FAILED = "fence_release_failed"


_TERMINAL_EVENTS: Final = {
    Outcome.COMPLETED: (COMPLETED_EVENT, "info"),
    Outcome.PARTIAL: (PARTIAL_EVENT, "warning"),
    Outcome.STALE: (STALE_EVENT, "info"),
    Outcome.CANCELLED: (CANCELLED_EVENT, "warning"),
    Outcome.OWNERSHIP_LOST: (OWNERSHIP_LOST_EVENT, "warning"),
    Outcome.FAILED: (FAILED_EVENT, "error"),
}

_CANCELLATION: Final = (asyncio.CancelledError, WorkerShutdown, WorkerTerminate)

_CONTRACT_ERRORS: Final = (
    ValueError,
    TypeError,
    AttributeError,
    LookupError,
    AssertionError,
    NotImplementedError,
)
"""Exception types that signal a contract violation or a programming error."""

_DEFECT_DATABASE_ERRORS: Final = (IntegrityError, DataError, ProgrammingError)
"""Database errors that signal a code or contract defect (Error Taxonomy)."""

_SERIALIZATION_ERRORS: Final = (EncodeError, SerializerNotInstalled)

_RENEW_REJECTIONS: Final = {
    LeaseRenewOutcome.ABSENT: RejectionReason.LEASE_ABSENT,
    LeaseRenewOutcome.MISMATCH: RejectionReason.LEASE_MISMATCH,
}


def _monotonic() -> float:
    """The renewal-checkpoint clock (patched by controlled-clock tests)."""
    return time.monotonic()


def _utc_today() -> date:
    """The current UTC date of one unit (patched by controlled-clock tests)."""
    return datetime.now(UTC).date()


def validate_target_version(target_version: object) -> CVSSVersion:
    """Validate the task's only semantic input from input alone.

    Returns the `CVSSVersion` for exactly `"3.1"` or `"4.0"`. Any other
    value raises a non-retryable `ValueError` with a fixed message and emits
    no event (Task Identity and Workflow, wrapper step 1).
    """
    if not isinstance(target_version, str) or target_version not in (
        DEFAULT_CVSS_VERSIONS
    ):
        raise ValueError(
            "recalculate_cvss_derived_state requires target_version '3.1' or '4.0'"
        )
    return CVSSVersion(target_version)


def validate_task_id(task_id: object, *, target_version: str) -> str:
    """Validate the Celery request ID as the canonical run identity.

    Returns the canonical lowercase hyphenated UUID version 4 unchanged. An
    absent or malformed ID first unbinds `celery_task_id` from the logging
    context, so neither it nor the raw value reaches the event, then emits
    exactly one `cvss_recalculation_adoption_rejected` (`task_id_invalid`)
    and raises a non-retryable `ValueError` (wrapper step 2).
    """
    if is_canonical_task_id(task_id):
        assert isinstance(task_id, str)
        return task_id
    structlog.contextvars.unbind_contextvars("celery_task_id")
    logger.warning(
        ADOPTION_REJECTED_EVENT,
        reason=RejectionReason.TASK_ID_INVALID.value,
        target_version=target_version,
    )
    raise ValueError(
        "recalculate_cvss_derived_state requires a canonical UUIDv4 task ID"
    )


@dataclass(slots=True)
class _Aggregate:
    """The one fixed-size in-memory aggregate of a delivery."""

    target_version: str
    watermark: uuid.UUID | None = None
    changed: int = 0
    unchanged: int = 0
    skipped: int = 0
    failed: int = 0

    def fields(self) -> dict[str, Any]:
        """The bounded run fields of the start and terminal events."""
        succeeded = self.changed + self.unchanged
        values: dict[str, Any] = {"target_version": self.target_version}
        if self.watermark is not None:
            values["watermark"] = str(self.watermark)
        values.update(
            changed=self.changed,
            unchanged=self.unchanged,
            skipped=self.skipped,
            failed=self.failed,
            succeeded=succeeded,
            processed=succeeded + self.skipped + self.failed,
        )
        return values


def _sqlstate(exc: DBAPIError) -> str | None:
    orig = exc.orig
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return sqlstate if isinstance(sqlstate, str) else None


def _is_deadlock(exc: BaseException) -> bool:
    """A `DBAPIError` with SQLSTATE `40P01` on a still-valid connection."""
    return (
        isinstance(exc, DBAPIError)
        and not exc.connection_invalidated
        and _sqlstate(exc) == _DEADLOCK_DETECTED
    )


def _classify(exc: BaseException, phase: Phase) -> tuple[Outcome, Cause]:
    """Map a whole-run condition to its terminal outcome and cause."""
    if isinstance(exc, _CANCELLATION):
        return Outcome.CANCELLED, Cause.INTERRUPTED
    if isinstance(exc, SoftTimeLimitExceeded):
        return Outcome.FAILED, Cause.INTERRUPTED
    if isinstance(exc, settings_service.RequiredSystemSettingMissingError):
        return Outcome.FAILED, Cause.DOMAIN
    if phase is Phase.PUBLICATION:
        if isinstance(exc, _SERIALIZATION_ERRORS + _CONTRACT_ERRORS):
            return Outcome.FAILED, Cause.PROGRAMMING
        return Outcome.FAILED, Cause.UNEXPECTED
    if isinstance(exc, _CONTRACT_ERRORS + _DEFECT_DATABASE_ERRORS):
        return Outcome.FAILED, Cause.PROGRAMMING
    if isinstance(exc, SQLAlchemyError):
        return Outcome.FAILED, Cause.DATABASE
    return Outcome.FAILED, Cause.UNEXPECTED


class _FenceState(StrEnum):
    NOT_HELD = "not_held"
    HELD = "held"
    RELEASED = "released"
    LOST = "lost"


_POOL_SAFE: Final = frozenset({_FenceState.NOT_HELD, _FenceState.RELEASED})
"""Fence states in which an owned connection may return to the pool."""


class _Run:
    """One delivery's state: the fenced connection, the lease client, the
    aggregate, and the open unit session."""

    def __init__(
        self,
        *,
        target_version: str,
        celery_task_id: str,
        session_factory: async_sessionmaker[AsyncSession],
        connection: AsyncConnection,
        client: redis_asyncio.Redis,
    ) -> None:
        self.target_version = target_version
        self.task_id = celery_task_id
        self.session_factory = session_factory
        self.connection = connection
        self.client = client
        self.fence = _FenceState.NOT_HELD
        self.aggregate = _Aggregate(target_version=target_version)
        self.phase = Phase.SETTING_READ
        self.unit_session: AsyncSession | None = None
        self.last_renewal = 0.0
        self.ownership_lost_cause: Cause | None = None

    def _session(self) -> AsyncSession:
        """A fresh session on the fenced connection, never another one."""
        return self.session_factory(bind=self.connection)

    def _lease(self) -> dict[str, str]:
        return {"task_id": self.task_id, "target_version": self.target_version}

    # -- adoption ---------------------------------------------------------

    async def adopt(self) -> bool:
        """Task Adoption steps 3-5; `False` after an adoption rejection."""
        try:
            acquired = await try_acquire_execution_fence(self.connection)
        except BaseException:
            # The fence may have been granted; the helper invalidated the
            # connection. No adoption outcome is reached: propagate.
            self.fence = _FenceState.LOST
            raise
        if acquired is FenceAcquireOutcome.BUSY:
            self._reject(RejectionReason.FENCE_BUSY)
            return False
        self.fence = _FenceState.HELD
        try:
            renewed = await compare_and_renew_lease(self.client, **self._lease())
        except RedisError:
            await self._release_fence()
            self._reject(RejectionReason.REDIS_ERROR)
            return False
        except BaseException:
            # No run outcome is reached: release and propagate, no event.
            await self._release_fence()
            raise
        if renewed is not LeaseRenewOutcome.RENEWED:
            await self._release_fence()
            self._reject(_RENEW_REJECTIONS[renewed])
            return False
        self.last_renewal = _monotonic()
        logger.info(ADOPTED_EVENT, target_version=self.target_version)
        return True

    def _reject(self, reason: RejectionReason) -> None:
        logger.warning(
            ADOPTION_REJECTED_EVENT,
            reason=reason.value,
            target_version=self.target_version,
        )

    # -- run workflow -----------------------------------------------------

    async def run(self) -> None:
        """Run the adopted workflow, clean up, and emit the terminal event."""
        try:
            outcome = await self._scan()
        except BaseException as exc:
            if self.ownership_lost_cause is not None:
                outcome, cause = Outcome.OWNERSHIP_LOST, self.ownership_lost_cause
            else:
                outcome, cause = _classify(exc, self.phase)
            await self._cleanup()
            self._terminal(outcome, (self.phase, cause))
            raise
        signal = await self._cleanup()
        self._terminal(outcome)
        if signal is not None:
            raise signal

    async def _scan(self) -> Outcome:
        self.phase = Phase.SETTING_READ
        async with self._session() as session:
            current = await settings_service.get_default_cvss_version(session)
        if current != self.target_version:
            return Outcome.STALE

        self.phase = Phase.ENUMERATION
        async with self._session() as session:
            watermark = (
                await session.execute(select(CVE.id).order_by(CVE.id.desc()).limit(1))
            ).scalar_one_or_none()
        self.aggregate.watermark = watermark
        logger.info(STARTED_EVENT, **self.aggregate.fields())
        if watermark is None:
            return Outcome.COMPLETED

        last_id: uuid.UUID | None = None
        while True:
            self.phase = Phase.ENUMERATION
            page = await self._read_page(last_id, watermark)
            for cve_row_id, cve_identifier in page:
                await self._checkpoint()
                await self._unit(cve_row_id, cve_identifier)
            if len(page) < CVE_PAGE_SIZE:
                break
            last_id = page[-1][0]
        return Outcome.PARTIAL if self.aggregate.failed else Outcome.COMPLETED

    async def _read_page(
        self, last_id: uuid.UUID | None, watermark: uuid.UUID
    ) -> Sequence[tuple[uuid.UUID, str]]:
        """One keyset page `last_id < id <= watermark`, ascending; carries
        only the row identifier and the canonical CVE identifier."""
        statement = select(CVE.id, CVE.cve_id).where(CVE.id <= watermark)
        if last_id is not None:
            statement = statement.where(CVE.id > last_id)
        statement = statement.order_by(CVE.id).limit(CVE_PAGE_SIZE)
        async with self._session() as session:
            rows = (await session.execute(statement)).all()
        return [(row.id, row.cve_id) for row in rows]

    async def _checkpoint(self) -> None:
        """Renewal Checkpoints: compare-and-renew between units when at
        least 60 seconds elapsed since the last successful renewal."""
        if _monotonic() - self.last_renewal < LEASE_RENEWAL_INTERVAL_SECONDS:
            return
        self.phase = Phase.CONTROL
        try:
            renewed = await compare_and_renew_lease(self.client, **self._lease())
        except RedisError:
            self.ownership_lost_cause = Cause.INFRASTRUCTURE
            self._renewal_failed(RejectionReason.REDIS_ERROR)
            raise
        if renewed is not LeaseRenewOutcome.RENEWED:
            self.ownership_lost_cause = Cause.INTERRUPTED
            self._renewal_failed(_RENEW_REJECTIONS[renewed])
            raise RuntimeError(OWNERSHIP_LOST_MESSAGE)
        self.last_renewal = _monotonic()

    def _renewal_failed(self, reason: RejectionReason) -> None:
        logger.warning(
            RENEWAL_FAILED_EVENT,
            reason=reason.value,
            target_version=self.target_version,
        )

    async def _unit(self, cve_row_id: uuid.UUID, cve_identifier: str) -> None:
        """Per-CVE Transactional Unit steps 1-12."""
        self.phase = Phase.UNIT
        session = self._session()
        self.unit_session = session
        try:
            result = await ticket_mutations.recalculate_cvss_chain(
                session,
                cve_id=cve_row_id,
                mode=ticket_mutations.CVSSChainMode.DEFAULT_VERSION,
                default_cvss_version=self.target_version,
                evaluation_date=_utc_today(),
            )
        except DBAPIError as exc:
            if not _is_deadlock(exc):
                raise
            await session.rollback()
            await session.close()
            self.unit_session = None
            if self.connection.invalidated:
                raise
            self.aggregate.failed += 1
            logger.warning(
                CVE_FAILED_EVENT,
                cve_id=cve_identifier,
                target_version=self.target_version,
                phase=Phase.UNIT.value,
                cause=Cause.DATABASE.value,
            )
            return
        await session.commit()

        classification = result.classification
        if classification is ticket_mutations.CVSSChainClassification.CHANGED:
            self.aggregate.changed += 1
        elif classification is ticket_mutations.CVSSChainClassification.UNCHANGED:
            self.aggregate.unchanged += 1
        else:
            self.aggregate.skipped += 1

        await session.close()
        self.unit_session = None
        self.phase = Phase.PUBLICATION
        await drain_ticket_convergence(session)

    # -- cleanup ----------------------------------------------------------

    async def _cleanup(self) -> BaseException | None:
        """Cleanup and Recovery Matrix order: close the unit session,
        compare-and-delete while fenced, release the fence.

        Expected Redis and database cleanup failures emit
        `cleanup_failed` and never change the outcome. Any other signal
        raised by a step is returned after the remaining steps ran."""
        signal: BaseException | None = None
        if self.unit_session is not None:
            session, self.unit_session = self.unit_session, None
            try:
                # A failed close leaves the release to report the loss.
                with suppress(Exception):
                    await session.close()
            except BaseException as exc:
                signal = exc
        try:
            await compare_and_delete_lease(self.client, **self._lease())
        except RedisError:
            self._cleanup_failed(RejectionReason.REDIS_ERROR)
        except BaseException as exc:
            signal = signal or exc
        try:
            await self._release_fence()
        except BaseException as exc:
            signal = signal or exc
        return signal

    async def _release_fence(self) -> None:
        """Explicitly release the fence; a failure emits `cleanup_failed`
        (the helper has invalidated the connection) and is absorbed, except
        a signal, which propagates after the state is recorded.

        An invalidated connection is never used again: a statement on it
        would silently reconnect to a new backend, and its closure has
        already released the fence (Cleanup and Recovery Matrix, fenced
        connection loss)."""
        if self.connection.invalidated:
            self.fence = _FenceState.LOST
            return
        try:
            released = await release_execution_fence(self.connection)
        except Exception:
            self.fence = _FenceState.LOST
            self._cleanup_failed(RejectionReason.FENCE_RELEASE_FAILED)
            return
        except BaseException:
            self.fence = _FenceState.LOST
            self._cleanup_failed(RejectionReason.FENCE_RELEASE_FAILED)
            raise
        if released is FenceReleaseOutcome.RELEASED:
            self.fence = _FenceState.RELEASED
            return
        self.fence = _FenceState.LOST
        self._cleanup_failed(RejectionReason.FENCE_RELEASE_FAILED)

    def _cleanup_failed(self, reason: RejectionReason) -> None:
        logger.warning(
            CLEANUP_FAILED_EVENT,
            reason=reason.value,
            target_version=self.target_version,
        )

    def _terminal(
        self, outcome: Outcome, failure: tuple[Phase, Cause] | None = None
    ) -> None:
        """Emit the one terminal event; `failure` carries the phase and
        cause of a `failed`, `cancelled`, or `ownership_lost` outcome."""
        event, level = _TERMINAL_EVENTS[outcome]
        fields = self.aggregate.fields()
        if failure is not None:
            phase, cause = failure
            fields["phase"] = phase.value
            fields["cause"] = cause.value
        getattr(logger, level)(event, **fields)


async def _execute(run: _Run) -> None:
    """Adopt and run one delivery; the lease client is closed inside the
    owning event loop on every path."""
    try:
        if await run.adopt():
            await run.run()
    finally:
        with suppress(RedisError):
            await run.client.aclose()


def _new_run(
    *,
    target_version: str,
    celery_task_id: str,
    session_factory: async_sessionmaker[AsyncSession],
    connection: AsyncConnection,
) -> _Run:
    return _Run(
        target_version=target_version,
        celery_task_id=celery_task_id,
        session_factory=session_factory,
        connection=connection,
        client=new_cvss_recalculation_redis_client(),
    )


async def _run_owned(
    *,
    target_version: str,
    celery_task_id: str,
    session_factory: async_sessionmaker[AsyncSession],
    engine: AsyncEngine,
) -> None:
    """Owned path: the workflow's own connection, closed back to the pool
    only when no fence is held (never acquired, or a confirmed unlock);
    otherwise invalidated, so a fenced connection never returns to it."""
    connection = await engine.connect()
    run: _Run | None = None
    try:
        run = _new_run(
            target_version=target_version,
            celery_task_id=celery_task_id,
            session_factory=session_factory,
            connection=connection,
        )
        await _execute(run)
    finally:
        with suppress(Exception):
            if run is None or run.fence in _POOL_SAFE:
                await connection.close()
            else:
                await connection.invalidate()


async def _dispose_engine(engine: AsyncEngine, *, primary_failed: bool) -> None:
    """Dispose the engine once; never mask a propagating primary exception."""
    try:
        await engine.dispose()
    except Exception:
        if not primary_failed:
            raise
        logger.warning(ENGINE_DISPOSE_FAILED_EVENT)


async def run_cvss_derived_state_recalculation(
    target_version: str,
    celery_task_id: str,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Apply `target_version` to every persisted CVE as one delivery.

    Category A workflow owning one independent transaction per CVE
    (default-cvss-version-operations.md, All-CVE Recalculation Runner;
    Complete-Run Coordination, task side).

    Q1: `target_version` and `celery_task_id` were validated by the
    wrapper (`validate_target_version()`, `validate_task_id()`); the task
    ID is never recovered from Celery or logging state. `session_factory`
    is bound to an `AsyncEngine` (production: owned connection, disposal
    at the outer boundary) or to an `AsyncConnection` (borrowed: never
    closed, invalidated, or disposed by the workflow).

    Q2: holds the session-level execution fence on its one dedicated
    connection for the complete delivery; each unit takes the CVE then its
    optional Ticket through the chain. No Redis or broker I/O runs inside a
    unit transaction.

    Q3: adoption (fence, then exact compare-and-renew), one setting read
    (`stale` on a different value), the watermark, keyset pages of at most
    500 identities, per-CVE units with commit, close, and drain, renewal
    checkpoints, then cleanup and exactly one terminal event.

    Q4: returns `None` for `completed`, `partial`, `stale`, and an
    adoption rejection. Emits only bounded structured events.

    Q5: a rerun recomputes from committed state; converged units classify
    `unchanged`.

    Q6: a database error during fence acquisition propagates with no
    event. `cancelled` and `failed` re-raise the original exception after
    the terminal event; an ownership loss re-raises the `RedisError`, or
    raises `RuntimeError(OWNERSHIP_LOST_MESSAGE)` for `mismatch`/`absent`.
    A factory bound to anything else raises `TypeError` before any I/O.
    """
    bind = session_factory.kw.get("bind")
    if isinstance(bind, AsyncConnection):
        await _execute(
            _new_run(
                target_version=target_version,
                celery_task_id=celery_task_id,
                session_factory=session_factory,
                connection=bind,
            )
        )
        return
    if not isinstance(bind, AsyncEngine):
        raise TypeError(
            "session_factory must be bound to an AsyncEngine or an AsyncConnection"
        )
    try:
        await _run_owned(
            target_version=target_version,
            celery_task_id=celery_task_id,
            session_factory=session_factory,
            engine=bind,
        )
    except BaseException:
        await _dispose_engine(bind, primary_failed=True)
        raise
    await _dispose_engine(bind, primary_failed=False)
