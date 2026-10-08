"""Atomic fetcher run acquisition.

See `docs/features/platform/fetcher-infrastructure.md` (Concurrency
Control — Atomic Run Acquisition Protocol, Stale Run Detection) for the
full specification this module implements.

`acquire_fetcher_run()` and `finalize_manual_run_as_failure()` are
called exclusively by the `run_fetcher` Celery task wrapper
(`app/tasks/fetchers.py`) — neither is an API-facing service, and
neither raises an HTTP-mapped exception. Every exception defined or
raised by them either propagates uncaught to Celery (permanent task
failure, no retry — see fetcher-infrastructure.md, Celery Integration,
"No top-level retry") or is a plain `ValueError` per the
specification's literal text for manual `run_id` rejection.

`mark_run_stale()` and `mark_queued_run_stale()` are also called by
`app.services.fetcher_operations.update_fetcher_config()` (an
API-facing service) under its own `FetcherConfig` lock — see that
function's docstring. `update_fetcher_config()`'s Run Timeout Active
Guard covers both active statuses (`queued` and `running`), calling
whichever of these two functions matches the active row's own status
(see `docs/features/platform/fetcher-operations.md`,
`update_fetcher_config`, Run Timeout Active Guard).

`resolve_effective_hard_limit()` and `is_run_stale()` are the single
source of truth for staleness evaluation, shared by this module's own
`acquire_fetcher_run()` (step 5 of the Atomic Run Acquisition
Protocol) and by `app.services.fetcher_operations` — both the
`update_fetcher_config()` Run Timeout Active Guard and every read
function that surfaces the `stale` field (`list_fetchers`,
`list_fetcher_runs`, `get_fetcher_run`). A single implementation
prevents the acquisition protocol, the Active Guard, and the API-facing
`stale` field from silently drifting apart on the threshold formula.

`get_fetcher_enabled()` is the execution-time enabled read of the
`run_catch_up` sub-operation (fetcher-infrastructure.md, Per-Ticket
Catch-Up — Celery task wrapper).

`get_derived_cursor()` is the run-history cursor read of the time-window
CVE fetchers (cve-sync-ghsa.md, Cursor Mechanism).

Registry lookup (`FETCHER_REGISTRY` membership) is the caller's
responsibility: the task wrapper determines whether `fetcher_name` is
a known, registered fetcher before calling `acquire_fetcher_run()`.
This module only handles fetchers that are registered but may be
disabled, and the run-record acquisition/adoption/stale-recovery
protocol for those fetchers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FetcherRunStatus, FetcherRunTriggeredBy
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import FetcherRunConfig

logger = structlog.get_logger(__name__)

# Hardcoded stale-detection margin (seconds) for `running` runs — see
# fetcher-infrastructure.md (Stale Run Detection, Running Stale
# Threshold). Not configurable.
_STALE_MARGIN_SECONDS = 60

# Hardcoded stale-detection threshold (seconds) for `queued` runs — see
# fetcher-infrastructure.md (Stale Run Detection, Queued Stale
# Threshold). Fixed and independent of `run_timeout`: a `queued` run's
# own execution has not started, so the fetcher's execution budget has
# no bearing on how long it may sit unclaimed. Not configurable.
_QUEUED_STALE_SECONDS = 600


class FetcherConfigMissingError(RuntimeError):
    """Raised when a registered fetcher has no `FetcherConfig` row.

    Indicates `bootstrap_fetcher_configs()`
    (`app/services/fetcher_bootstrap.py`) has not yet run for this
    fetcher — see fetcher-infrastructure.md (Data Model —
    FetcherConfig). Propagates uncaught to the `run_fetcher` task
    wrapper — no retry is attempted.
    """


def resolve_effective_hard_limit(
    hard_time_limit_seconds: int | None, fallback_run_timeout: int
) -> int:
    """Resolve the effective per-run hard time limit for stale
    evaluation and stale-finalization messages.

    Prefers the run's own persisted `hard_time_limit_seconds`. Falls
    back to `fallback_run_timeout` (the fetcher's current
    `FetcherConfig.run_timeout`) only when the column is `NULL` —
    historical rows that predate it. See
    `docs/features/platform/fetcher-infrastructure.md` (Stale Run
    Detection, Running Stale Threshold).
    """
    return (
        hard_time_limit_seconds
        if hard_time_limit_seconds is not None
        else fallback_run_timeout
    )


def is_run_stale(
    *,
    status: str,
    created_at: datetime,
    started_at: datetime | None,
    hard_time_limit_seconds: int | None,
    fallback_run_timeout: int,
    now: datetime,
) -> bool:
    """`True` when the run's elapsed time exceeds the threshold that
    matches its own status.

    Queued Stale Threshold (`created_at`, fixed 600 seconds) for
    `queued`; Running Stale Threshold (`started_at`,
    `effective_limit + _STALE_MARGIN_SECONDS`) for `running`, where
    `effective_limit` is resolved via `resolve_effective_hard_limit()`.
    `False` for any terminal status. See
    `docs/features/platform/fetcher-infrastructure.md` (Stale Run
    Detection).

    Single source of truth shared by `acquire_fetcher_run()` (below),
    `fetcher_operations.update_fetcher_config()`'s Run Timeout Active
    Guard, and every `fetcher_operations` read function that surfaces
    the `stale` field.
    """
    if status == FetcherRunStatus.QUEUED.value:
        elapsed = (now - created_at).total_seconds()
        return elapsed > _QUEUED_STALE_SECONDS
    if status == FetcherRunStatus.RUNNING.value:
        assert started_at is not None, (
            "a 'running' FetcherRun always has a non-NULL started_at"
        )
        elapsed = (now - started_at).total_seconds()
        effective_limit = resolve_effective_hard_limit(
            hard_time_limit_seconds, fallback_run_timeout
        )
        return elapsed > effective_limit + _STALE_MARGIN_SECONDS
    return False


@dataclass(frozen=True)
class FetcherAcquisition:
    """A successfully acquired (or adopted) `FetcherRun`, ready for
    `BaseFetcher.run()`.

    `run_id` identifies the committed `running` row — freshly inserted
    for a scheduled trigger, or adopted (transitioned from `queued`)
    for a manual trigger. `config` is the immutable runtime
    configuration snapshot taken under the same `FetcherConfig` lock.
    """

    run_id: UUID
    config: FetcherRunConfig


async def acquire_fetcher_run(
    db: AsyncSession,
    *,
    fetcher_name: str,
    triggered_by: FetcherRunTriggeredBy,
    run_id: UUID | None,
    now: datetime,
    hard_time_limit_seconds: int,
) -> FetcherAcquisition | None:
    """Lock `FetcherConfig`, evaluate active/stale run state, and
    acquire (schedule) or adopt (manual) the `FetcherRun` for
    execution.

    Implements steps 1-6 of "Atomic Run Acquisition Protocol" in
    `docs/features/platform/fetcher-infrastructure.md`. The caller
    (the `run_fetcher` task wrapper) owns the transaction: it commits
    after this function returns (including a `None` return) and rolls
    back only if an exception propagates from this function.

    `hard_time_limit_seconds` is the already-validated effective Celery
    hard time limit for this delivery (extracted by the task wrapper
    from `self.request.timelimit` — see "Per-Run Hard Time Limit"). It
    is persisted on the acquired/adopted `FetcherRun` row and used to
    populate the runtime configuration snapshot's
    `hard_time_limit_seconds` field — never the live
    `FetcherConfig.run_timeout` column.

    Assumes `fetcher_name` is present in `FETCHER_REGISTRY` — the
    caller checks registry membership before invoking this function.
    `triggered_by` and `run_id` are assumed already validated for
    mutual consistency (`SCHEDULE` implies `run_id is None`, `MANUAL`
    implies `run_id is not None`) — the caller performs that
    validation before invoking this function.

    A manual `run_id` identifies a `FetcherRun` pre-created by the API
    as `queued`. This function never receives (and never creates) a
    `queued` row itself — it only ever adopts one via an atomic
    `queued -> running` transition (step 6) or finalizes one as stale
    (step 5). A scheduled trigger has no pre-created row: it is always
    created directly as `running`.

    Returns:
        `FetcherAcquisition` when a run was created or adopted and
        execution should proceed. `None` when the caller should return
        without executing the fetcher: the fetcher is disabled, a
        non-stale scheduled duplicate was discarded, or the manually
        supplied run was already finalized or adopted by a concurrent
        path (e.g., broker-failure compensation, a redelivered Celery
        message).

    Raises:
        FetcherConfigMissingError: no `FetcherConfig` row exists for
            `fetcher_name`.
        ValueError: (manual trigger only) the supplied `run_id` does
            not exist, or exists for a different `fetcher_name`.
        RuntimeError: more than one active (`queued` or `running`) row
            exists for `fetcher_name`. The `FetcherConfig` lock and the
            API-level guard are expected to make this impossible; if
            observed, it is a data-integrity bug and this function
            fails loudly rather than silently choosing a row to act on.
    """
    result = await db.execute(
        select(FetcherConfig)
        .where(FetcherConfig.fetcher_name == fetcher_name)
        .with_for_update()
    )
    config = result.scalar_one_or_none()
    if config is None:
        raise FetcherConfigMissingError(
            f"No FetcherConfig row for registered fetcher '{fetcher_name}'"
        )

    if not config.enabled:
        if run_id is not None:
            await finalize_manual_run_as_failure(
                db,
                run_id=run_id,
                fetcher_name=fetcher_name,
                error_message="Fetcher disabled between trigger and execution",
                now=now,
            )
        else:
            logger.debug("fetcher_disabled_skipping_run", fetcher_name=fetcher_name)
        return None

    run_config = FetcherRunConfig(
        hard_time_limit_seconds=hard_time_limit_seconds,
        request_delay=config.request_delay,
        custom_settings=config.custom_settings,
    )

    active_result = await db.execute(
        select(FetcherRun).where(
            FetcherRun.fetcher_name == fetcher_name,
            FetcherRun.status.in_(
                [FetcherRunStatus.QUEUED.value, FetcherRunStatus.RUNNING.value]
            ),
        )
    )
    active_runs = active_result.scalars().all()
    if len(active_runs) > 1:
        raise RuntimeError(
            f"Multiple active FetcherRun rows for '{fetcher_name}': "
            f"{[str(run.id) for run in active_runs]} — the FetcherConfig "
            "lock and API-level guard should make this impossible"
        )
    active_run = active_runs[0] if active_runs else None

    if active_run is not None:
        is_stale = is_run_stale(
            status=active_run.status,
            created_at=active_run.created_at,
            started_at=active_run.started_at,
            hard_time_limit_seconds=active_run.hard_time_limit_seconds,
            fallback_run_timeout=config.run_timeout,
            now=now,
        )

        if is_stale:
            if active_run.status == FetcherRunStatus.QUEUED.value:
                mark_queued_run_stale(active_run, now=now, fetcher_name=fetcher_name)
            else:
                mark_run_stale(
                    active_run,
                    now=now,
                    hard_time_limit_seconds=resolve_effective_hard_limit(
                        active_run.hard_time_limit_seconds, config.run_timeout
                    ),
                    fetcher_name=fetcher_name,
                )
        elif run_id is None:
            logger.info(
                "scheduled_run_skipped_active_run_exists",
                fetcher_name=fetcher_name,
            )
            return None
        # else: manual trigger — the active row IS the supplied run_id
        # (still queued, not yet stale). Fall through to the adoption
        # attempt below, which re-targets it explicitly by identity.

    if run_id is None:
        new_run = FetcherRun(
            fetcher_name=fetcher_name,
            status=FetcherRunStatus.RUNNING.value,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE.value,
            started_at=now,
            hard_time_limit_seconds=hard_time_limit_seconds,
        )
        db.add(new_run)
        await db.flush()
        return FetcherAcquisition(run_id=new_run.id, config=run_config)

    adopted_result = await db.execute(
        update(FetcherRun)
        .where(
            FetcherRun.id == run_id,
            FetcherRun.fetcher_name == fetcher_name,
            FetcherRun.status == FetcherRunStatus.QUEUED.value,
        )
        .values(
            status=FetcherRunStatus.RUNNING.value,
            started_at=now,
            hard_time_limit_seconds=hard_time_limit_seconds,
        )
        .returning(FetcherRun.id)
    )
    adopted_id = adopted_result.scalar_one_or_none()
    await db.flush()
    if adopted_id is not None:
        return FetcherAcquisition(run_id=adopted_id, config=run_config)

    run = await db.get(FetcherRun, run_id)
    if run is None:
        logger.error(
            "manual_run_not_found", run_id=str(run_id), fetcher_name=fetcher_name
        )
        raise ValueError(f"FetcherRun '{run_id}' not found")
    if run.fetcher_name != fetcher_name:
        logger.error(
            "manual_run_fetcher_mismatch",
            run_id=str(run_id),
            fetcher_name=fetcher_name,
            actual_fetcher_name=run.fetcher_name,
        )
        raise ValueError(
            f"FetcherRun '{run_id}' belongs to fetcher '{run.fetcher_name}', "
            f"not '{fetcher_name}'"
        )
    if run.status == FetcherRunStatus.FAILURE.value:
        logger.info(
            "manual_run_already_finalized",
            run_id=str(run_id),
            status=run.status,
        )
        return None
    # `running`, `success`, or `partial`: a duplicate or redelivered
    # Celery message for a run already adopted or completed.
    logger.info(
        "manual_run_already_adopted_or_completed",
        run_id=str(run_id),
        status=run.status,
    )
    return None


async def finalize_manual_run_as_failure(
    db: AsyncSession,
    *,
    run_id: UUID,
    fetcher_name: str,
    error_message: str,
    now: datetime,
    error_detail: str | None = None,
    error_traceback: str | None = None,
) -> bool:
    """Finalize a manually pre-created, still-`queued` `FetcherRun` as
    an immediate failure with no accompanying audit event.

    Shared by three failure paths where the fetcher never executes: the
    fetcher was deregistered (caller: the `run_fetcher` task wrapper,
    before any `FetcherConfig` lock is taken), the fetcher was disabled
    (caller: `acquire_fetcher_run` above, under the `FetcherConfig`
    lock), or the manual trigger's Celery publication failed (caller:
    `fetcher_operations.trigger_fetcher()`, after its first transaction
    committed and with no lock held). See
    `docs/features/platform/fetcher-infrastructure.md` (Celery
    Integration — Unknown and deregistered fetcher handling; and
    Concurrency Control — Atomic Run Acquisition Protocol, step 2) and
    `docs/features/platform/fetcher-operations.md` (`trigger_fetcher`,
    Publication Failure Path).

    Performs a **conditional atomic UPDATE**
    (`WHERE id = :run_id AND fetcher_name = :fetcher_name AND
    status = 'queued'`) setting `status = failure`, the caller-supplied
    `error_message`/`error_detail`/`error_traceback`, and
    `finished_at = now`. `started_at` and `duration_seconds` are left
    untouched — they remain `NULL`, since the run was never adopted.
    This is safe to call even when a concurrent path (e.g., a
    concurrent worker adoption, or a redelivered Celery message racing
    this same call) has already transitioned the row away from
    `queued`: the UPDATE then matches zero rows and is silently a
    no-op, deferring to whichever transition already won. Flushes but
    does not commit — the caller's transaction owns durability.

    Returns:
        `True` if this call's conditional UPDATE won the race (the row
        was still `queued` and is now `failure`). `False` if a
        concurrent transition already moved the row away from `queued`
        before this call's UPDATE executed — the row is left
        untouched.

    Raises:
        ValueError: `run_id` does not identify an existing
            `FetcherRun` row for `fetcher_name`.
    """
    result = await db.execute(
        update(FetcherRun)
        .where(
            FetcherRun.id == run_id,
            FetcherRun.fetcher_name == fetcher_name,
            FetcherRun.status == FetcherRunStatus.QUEUED.value,
        )
        .values(
            status=FetcherRunStatus.FAILURE.value,
            error_message=error_message,
            error_detail=error_detail,
            error_traceback=error_traceback,
            finished_at=now,
        )
        .returning(FetcherRun.id)
    )
    updated_id = result.scalar_one_or_none()
    await db.flush()
    if updated_id is not None:
        return True

    run = await db.get(FetcherRun, run_id)
    if run is None or run.fetcher_name != fetcher_name:
        logger.error(
            "manual_run_finalization_target_missing",
            run_id=str(run_id),
            fetcher_name=fetcher_name,
        )
        raise ValueError(f"FetcherRun '{run_id}' not found")
    logger.info(
        "manual_run_already_transitioned",
        run_id=str(run_id),
        status=run.status,
    )
    return False


def mark_run_stale(
    run: FetcherRun, *, now: datetime, hard_time_limit_seconds: int, fetcher_name: str
) -> None:
    """Finalize a stale `running` `FetcherRun` in place (caller
    flushes/commits).

    `hard_time_limit_seconds` is the effective hard time limit to
    report in the error message and log event — the caller resolves it
    via `resolve_effective_hard_limit()` before calling this function
    (the run's own `hard_time_limit_seconds` when present, otherwise
    the fallback `FetcherConfig.run_timeout`). This function does not
    re-resolve it.

    See `docs/features/platform/fetcher-infrastructure.md` (Stale Run
    Detection, Running Stale Threshold) for the exact field values. The
    log event follows the project's structlog convention
    (`docs/conventions.md`, Logging) — a snake_case event name with
    structured keyword context — rather than the spec's illustrative
    message text.

    Shared by two callers under two different pessimistic locks:
    `acquire_fetcher_run()` above (locks `FetcherConfig` as part of the
    Atomic Run Acquisition Protocol) and
    `fetcher_operations.update_fetcher_config()` (locks `FetcherConfig`
    as part of the Run Timeout Active Guard — see
    `docs/features/platform/fetcher-operations.md`,
    `update_fetcher_config`, step 4). Public (no leading underscore)
    specifically to support this second caller in another module —
    duplicating this finalization logic would risk the two call sites
    drifting on the stale-run field values or log event shape.
    """
    assert run.started_at is not None, (
        "a 'running' FetcherRun always has a non-NULL started_at"
    )
    elapsed = (now - run.started_at).total_seconds()
    run.status = FetcherRunStatus.FAILURE.value
    run.error_message = (
        f"Marked as stale (running for {elapsed:.0f}s, timeout "
        f"{hard_time_limit_seconds}s)"
    )
    run.finished_at = now
    run.duration_seconds = elapsed
    logger.warning(
        "fetcher_run_marked_stale",
        run_id=str(run.id),
        fetcher_name=fetcher_name,
        started_at=run.started_at.isoformat(),
        hard_time_limit_seconds=hard_time_limit_seconds,
    )


def mark_queued_run_stale(run: FetcherRun, *, now: datetime, fetcher_name: str) -> None:
    """Finalize a stale `queued` `FetcherRun` in place (caller
    flushes/commits).

    See `docs/features/platform/fetcher-infrastructure.md` (Stale Run
    Detection, Queued Stale Threshold) for the exact field values and
    the fixed 600-second threshold. `started_at` and `duration_seconds`
    are left untouched — they remain `NULL`, since the run was never
    adopted.

    Called by `acquire_fetcher_run()` above, under the `FetcherConfig`
    lock, and by `fetcher_operations.update_fetcher_config()` (Run
    Timeout Active Guard), under its own `FetcherConfig` lock. Kept as
    a separate public function (mirroring `mark_run_stale()` above)
    rather than a branch inside it: the two finalizations set different
    fields (a `queued` run has no `started_at`/`duration_seconds` to
    preserve or compute) and use a different elapsed-time basis
    (`created_at`, not `started_at`).
    """
    elapsed = (now - run.created_at).total_seconds()
    run.status = FetcherRunStatus.FAILURE.value
    run.error_message = (
        f"Marked as stale (queued for {elapsed:.0f}s, timeout {_QUEUED_STALE_SECONDS}s)"
    )
    run.finished_at = now
    logger.warning(
        "fetcher_run_marked_stale_queued",
        run_id=str(run.id),
        fetcher_name=fetcher_name,
        created_at=run.created_at.isoformat(),
    )


async def get_fetcher_enabled(session: AsyncSession, fetcher_name: str) -> bool:
    """Read the current `FetcherConfig.enabled` of a registered fetcher.

    The execution-time enabled check of the `run_catch_up` sub-operation
    (fetcher-infrastructure.md, Per-Ticket Catch-Up — Celery task
    wrapper, step 2). A plain read: no lock, no write, no commit.

    Raises:
        FetcherConfigMissingError: no `FetcherConfig` row exists for
            `fetcher_name` (bootstrap invariant failure).
    """
    enabled = (
        await session.execute(
            select(FetcherConfig.enabled).where(
                FetcherConfig.fetcher_name == fetcher_name
            )
        )
    ).scalar_one_or_none()
    if enabled is None:
        raise FetcherConfigMissingError(
            f"No FetcherConfig row for registered fetcher '{fetcher_name}'"
        )
    return enabled


async def get_derived_cursor(
    session: AsyncSession, fetcher_name: str
) -> datetime | None:
    """Read the derived cursor of a fetcher: the `started_at` of its most
    recent `success` or `partial` `FetcherRun`.

    The cursor of the time-window fetchers whose specifications derive it
    from run history instead of storing `FetcherRun.cursor`
    (cve-sync-ghsa.md and cve-sync-nvd.md, Cursor Mechanism). The calling
    run is `running` and is therefore never its own cursor; a queued run
    has no `started_at` and never reaches either status. A plain read on
    the caller's session: no lock, no write, no commit.

    Returns `None` when the fetcher has no `success` or `partial` run.
    """
    started_at: datetime | None = await session.scalar(
        select(FetcherRun.started_at)
        .where(
            FetcherRun.fetcher_name == fetcher_name,
            FetcherRun.status.in_(
                [FetcherRunStatus.SUCCESS.value, FetcherRunStatus.PARTIAL.value]
            ),
        )
        .order_by(FetcherRun.started_at.desc())
        .limit(1)
    )
    return started_at
