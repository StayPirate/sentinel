"""Manual admission and publication of the all-CVE CVSS recalculation.

Implements `docs/features/platform/default-cvss-version-operations.md`
(Admission Ordering; Manual Admission Service; Publication Uncertainty; the
admission rows of the Cleanup and Recovery Matrix and of Coordination
Logging). `admit_cvss_recalculation()` is the service-owned boundary of
`POST /api/v1/admin/settings/default-cvss-version/recalculate`:

1. acquire the execution fence without blocking on one dedicated
   connection; a busy fence is `409`;
2. read `default_cvss_version` while the fence is held: the run's only
   target version;
3. still fenced, allocate the run's task ID (a canonical UUIDv4 from a
   CSPRNG) and acquire the `cvss_recalc_active` lease; a held lease is
   `409`, a `RedisError` is `503 REDIS_UNAVAILABLE`;
4. release the fence and confirm the release before any broker call; a
   release that raises or returns a definitive `false` invokes no
   publisher, invalidates the connection, attempts owner-safe lease
   removal, and propagates (the built-in `RuntimeError` for `false`);
5. publish `recalculate_cvss_derived_state` with the preallocated task ID
   and classify the outcome by exception class only: a normal return is
   `submitted`; `kombu.exceptions.OperationalError` is
   `acceptance_unconfirmed` (`503 CELERY_UNAVAILABLE`, lease retained);
   every other exception propagates unchanged and keeps the lease.

Connection ownership follows the own-or-borrow rule (umbrella #833 P9):
`get_cvss_admission_bind()` returns the production engine, whose connection
is owned and returns to the pool only after a confirmed unlock (otherwise
it is invalidated); a test-supplied `AsyncConnection` is borrowed and never
closed or invalidated here. Admission creates no audit record, run row, or
compensation record; its events correlate through the bound `request_id`
only and carry neither the task ID nor the lease token.
"""

from __future__ import annotations

import uuid
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Literal

import redis.asyncio as redis_asyncio
import structlog
from celery.exceptions import OperationalError  # kombu.exceptions.OperationalError
from redis.exceptions import RedisError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from app import database
from app.services import settings as settings_service
from app.services import task_publication
from app.services.cvss_recalculation import RECALCULATE_CVSS_DERIVED_STATE_TASK
from app.services.cvss_recalculation_coordination import (
    FenceAcquireOutcome,
    FenceReleaseOutcome,
    LeaseAcquireOutcome,
    acquire_lease,
    compare_and_delete_lease,
    new_cvss_recalculation_redis_client,
    release_execution_fence,
    try_acquire_execution_fence,
)
from app.services.settings import (
    CVSSRecalculationAlreadyInProgressError,
    SettingsServiceError,
)

logger = structlog.get_logger(__name__)

REDIS_UNAVAILABLE_MESSAGE: Final = (
    "Recalculation could not be admitted because Redis is unavailable."
)
"""Fixed message of `CVSSRecalculationRedisUnavailableError` and the 503
detail."""

BROKER_UNAVAILABLE_MESSAGE: Final = (
    "Recalculation task publication could not be confirmed"
)
"""Fixed message of `CVSSRecalculationBrokerUnavailableError` and the 503
detail (Trigger CVSS Recalculation)."""

FENCE_RELEASE_NOT_CONFIRMED_MESSAGE: Final = (
    "CVSS recalculation fence release not confirmed"
)
"""Fixed message of the built-in `RuntimeError` raised after a definitive
`false` unlock."""

# Admission events (Coordination Logging).
ADMITTED_EVENT: Final = "cvss_recalculation_admitted"
ADMISSION_REJECTED_EVENT: Final = "cvss_recalculation_admission_rejected"
SUBMITTED_EVENT: Final = "cvss_recalculation_submitted"
PUBLICATION_UNCONFIRMED_EVENT: Final = "cvss_recalculation_publication_unconfirmed"
CLEANUP_FAILED_EVENT: Final = "cvss_recalculation_cleanup_failed"


class AdmissionRejectionReason(StrEnum):
    """Closed `reason` categories of `cvss_recalculation_admission_rejected`."""

    FENCE_BUSY = "fence_busy"
    LEASE_HELD = "lease_held"
    REDIS_ERROR = "redis_error"


class CleanupFailureReason(StrEnum):
    """Closed `reason` categories of `cvss_recalculation_cleanup_failed`."""

    REDIS_ERROR = "redis_error"
    FENCE_RELEASE_FAILED = "fence_release_failed"


class CVSSRecalculationRedisUnavailableError(SettingsServiceError):
    """Lease acquisition raised `RedisError` or its completion was
    uncertain; the fence is released and nothing is published. Maps to
    `503 REDIS_UNAVAILABLE`; the message is fixed and never contains the
    Redis exception text."""

    def __init__(self) -> None:
        super().__init__(REDIS_UNAVAILABLE_MESSAGE)


class CVSSRecalculationBrokerUnavailableError(SettingsServiceError):
    """The publication call raised `kombu.exceptions.OperationalError`, so
    broker acceptance is unconfirmed and the lease is retained. Maps to
    `503 CELERY_UNAVAILABLE`; the message is fixed and never contains the
    broker exception text."""

    def __init__(self) -> None:
        super().__init__(BROKER_UNAVAILABLE_MESSAGE)


@dataclass(frozen=True, slots=True)
class CVSSRecalculationAdmission:
    """The successful admission: the run was submitted for
    `target_version`, the persisted setting read under the fence. The
    run's task ID is deliberately absent (Run Identity)."""

    outcome: Literal["submitted"]
    target_version: str


def get_cvss_admission_bind() -> AsyncEngine | AsyncConnection:
    """Return the bind of the admission's dedicated fenced connection.

    Performs no I/O — returns the production engine (`app.database`).
    Extracted as its own function so tests can supply a borrowed
    connection (umbrella #833 P9): an `AsyncEngine` yields a connection the
    admission owns, an `AsyncConnection` is borrowed and never closed or
    invalidated by the admission.
    """
    return database.engine


class _FenceState(StrEnum):
    NOT_HELD = "not_held"
    HELD = "held"
    RELEASED = "released"
    LOST = "lost"


_POOL_SAFE: Final = frozenset({_FenceState.NOT_HELD, _FenceState.RELEASED})
"""Fence states in which an owned connection may return to the pool."""


class _Admission:
    """One admission's dedicated connection and fence state."""

    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection
        self.fence = _FenceState.NOT_HELD

    async def run(self) -> CVSSRecalculationAdmission:
        # 1. Fence. A database or session error is never `fence_busy`: the
        # helper has invalidated the connection, and the error propagates.
        try:
            acquired = await try_acquire_execution_fence(self.connection)
        except BaseException:
            self.fence = _FenceState.LOST
            raise
        if acquired is FenceAcquireOutcome.BUSY:
            _rejected(AdmissionRejectionReason.FENCE_BUSY)
            raise CVSSRecalculationAlreadyInProgressError()
        self.fence = _FenceState.HELD

        # 2. Setting read under the fence: the only source of the target.
        try:
            target_version = await self._read_setting()
        except BaseException:
            await self._release_after_failure(None)
            raise

        # 3-5. Lease, confirmed release, publication.
        try:
            client = new_cvss_recalculation_redis_client()
        except BaseException:
            await self._release_after_failure(target_version)
            raise
        try:
            return await self._lease_and_publish(client, target_version)
        finally:
            with suppress(RedisError):
                await client.aclose()

    async def _read_setting(self) -> str:
        async with AsyncSession(bind=self.connection) as session:
            return await settings_service.get_default_cvss_version(session)

    async def _lease_and_publish(
        self, client: redis_asyncio.Redis, target_version: str
    ) -> CVSSRecalculationAdmission:
        task_id = str(uuid.uuid4())
        try:
            acquired = await acquire_lease(
                client, task_id=task_id, target_version=target_version
            )
        except RedisError:
            # The write may have landed: no removal, the key expires by TTL.
            await self._release(target_version)
            _rejected(AdmissionRejectionReason.REDIS_ERROR, target_version)
            raise CVSSRecalculationRedisUnavailableError() from None
        except BaseException:
            await self._release_after_failure(target_version)
            raise
        if acquired is LeaseAcquireOutcome.NOT_ACQUIRED:
            await self._release(target_version)
            _rejected(AdmissionRejectionReason.LEASE_HELD, target_version)
            raise CVSSRecalculationAlreadyInProgressError()
        logger.info(ADMITTED_EVENT, target_version=target_version)

        await self._confirm_release(client, task_id, target_version)

        try:
            await task_publication.publish_task(
                RECALCULATE_CVSS_DERIVED_STATE_TASK,
                kwargs={"target_version": target_version},
                task_id=task_id,
            )
        except OperationalError:
            logger.error(PUBLICATION_UNCONFIRMED_EVENT, target_version=target_version)
            raise CVSSRecalculationBrokerUnavailableError() from None
        logger.info(SUBMITTED_EVENT, target_version=target_version)
        return CVSSRecalculationAdmission(
            outcome="submitted", target_version=target_version
        )

    # -- fence release --------------------------------------------------

    async def _confirm_release(
        self, client: redis_asyncio.Redis, task_id: str, target_version: str
    ) -> None:
        """Step 4: release and confirm before any broker call. A release
        that raises or returns `NOT_CONFIRMED` (the helper has invalidated
        the connection) invokes no publisher: attempt owner-safe lease
        removal, emit `cleanup_failed`, then propagate the raised
        exception unchanged, or the built-in `RuntimeError` for `false`."""
        try:
            released = await release_execution_fence(self.connection)
        except BaseException:
            self.fence = _FenceState.LOST
            await self._remove_lease(client, task_id, target_version)
            _cleanup_failed(CleanupFailureReason.FENCE_RELEASE_FAILED, target_version)
            raise
        if released is FenceReleaseOutcome.RELEASED:
            self.fence = _FenceState.RELEASED
            return
        self.fence = _FenceState.LOST
        signal = await self._remove_lease(client, task_id, target_version)
        _cleanup_failed(CleanupFailureReason.FENCE_RELEASE_FAILED, target_version)
        if signal is not None:
            raise signal
        raise RuntimeError(FENCE_RELEASE_NOT_CONFIRMED_MESSAGE)

    async def _remove_lease(
        self, client: redis_asyncio.Redis, task_id: str, target_version: str
    ) -> BaseException | None:
        """Owner-safe compare-and-delete after a failed release. A
        `RedisError` emits `cleanup_failed` and the key expires by its TTL;
        any other exception is returned for the caller to rank below the
        original error."""
        try:
            await compare_and_delete_lease(
                client, task_id=task_id, target_version=target_version
            )
        except RedisError:
            _cleanup_failed(CleanupFailureReason.REDIS_ERROR, target_version)
        except BaseException as exc:
            return exc
        return None

    async def _release(self, target_version: str | None) -> None:
        """Explicitly release the held fence (also on the 409/503
        branches, whose rejection stands after a failed release); a failure
        emits `cleanup_failed`, and an `Exception` is absorbed while a
        control signal propagates. An invalidated connection is never used again:
        a statement on it would reconnect, and its closure has already
        released the fence."""
        if self.connection.invalidated:
            self.fence = _FenceState.LOST
            return
        try:
            released = await release_execution_fence(self.connection)
        except Exception:
            self.fence = _FenceState.LOST
            _cleanup_failed(CleanupFailureReason.FENCE_RELEASE_FAILED, target_version)
            return
        except BaseException:
            self.fence = _FenceState.LOST
            _cleanup_failed(CleanupFailureReason.FENCE_RELEASE_FAILED, target_version)
            raise
        if released is FenceReleaseOutcome.RELEASED:
            self.fence = _FenceState.RELEASED
            return
        self.fence = _FenceState.LOST
        _cleanup_failed(CleanupFailureReason.FENCE_RELEASE_FAILED, target_version)

    async def _release_after_failure(self, target_version: str | None) -> None:
        """Release while an original exception propagates: that exception
        keeps precedence over any failure of the release itself."""
        try:
            await self._release(target_version)
        except BaseException:
            self.fence = _FenceState.LOST


def _rejected(
    reason: AdmissionRejectionReason, target_version: str | None = None
) -> None:
    fields = {"reason": reason.value}
    if target_version is not None:
        fields["target_version"] = target_version
    logger.warning(ADMISSION_REJECTED_EVENT, **fields)


def _cleanup_failed(reason: CleanupFailureReason, target_version: str | None) -> None:
    fields = {"reason": reason.value}
    if target_version is not None:
        fields["target_version"] = target_version
    logger.warning(CLEANUP_FAILED_EVENT, **fields)


async def admit_cvss_recalculation() -> CVSSRecalculationAdmission:
    """Admit and publish one complete all-CVE recalculation run.

    Category A orchestration boundary owning its dedicated connection for
    the complete sequence, including the post-release publication attempt
    (default-cvss-version-operations.md, Manual Admission Service).

    Q1: no caller input: no session, target version, or task ID. The
    target is the persisted `default_cvss_version` read under the fence.

    Q2: the session-level execution fence is held, without waiting, only
    from step 1 through its confirmed release in step 4; no row lock is
    taken. Redis I/O happens only under the fence and outside any
    transaction; broker I/O only after the confirmed release.

    Q3: fence, setting read, task-ID allocation and lease acquisition,
    confirmed release, publication (see the module docstring). Creates no
    audit record, run row, or compensation record.

    Q4: on `submitted`, returns the admission with the published target
    version; the task ID is never returned.

    Q5: repeatable: every admission that reaches publication allocates a
    new run identity; a blocked admission publishes nothing.

    Q6:
    - `CVSSRecalculationAlreadyInProgressError` when the fence (`fence_busy`)
      or the lease (`lease_held`) is held;
    - `CVSSRecalculationRedisUnavailableError` on any `RedisError` during
      lease acquisition, including a timeout after send;
    - `CVSSRecalculationBrokerUnavailableError` on `OperationalError` from
      the publisher; the lease is retained;
    - a database or session error during fence acquisition, the setting
      read's `RequiredSystemSettingMissingError` or database error, and an
      exception raised by the fence release propagate unchanged; a
      definitive `false` unlock raises the built-in `RuntimeError`; every
      other publisher exception propagates unchanged and keeps the lease.
    A bind other than an engine or a connection raises `TypeError` before
    any I/O.
    """
    bind = get_cvss_admission_bind()
    if isinstance(bind, AsyncConnection):
        return await _Admission(bind).run()
    if not isinstance(bind, AsyncEngine):
        raise TypeError("the admission bind must be an AsyncEngine or AsyncConnection")
    connection = await bind.connect()
    admission = _Admission(connection)
    try:
        return await admission.run()
    finally:
        with suppress(Exception):
            if admission.fence in _POOL_SAFE:
                await connection.close()
            else:
                await connection.invalidate()
