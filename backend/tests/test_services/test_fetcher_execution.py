"""Tests for the atomic fetcher run acquisition service
(backend/app/services/fetcher_execution.py).

See `docs/features/platform/fetcher-infrastructure.md` (Concurrency
Control — Atomic Run Acquisition Protocol, Stale Run Detection) for
the contract under test: `FetcherConfig`-root locking, disabled/active/
stale run evaluation, scheduled acquisition vs. manual adoption, and
the exact stale-threshold boundary (`elapsed > run_timeout + 60`).
`get_fetcher_enabled()` is the execution-time enabled read of the
`run_catch_up` sub-operation (Per-Ticket Catch-Up — Celery task wrapper,
step 2). `get_derived_cursor()` is the run-history cursor read of
`docs/features/tickets/cve-sync-ghsa.md` (Algorithm step 2, Cursor
Mechanism): the latest `started_at` among the fetcher's `success` and
`partial` runs, read on the caller's session without a lock, write, or
commit.

Functional (non-concurrency) assertions use the standard `db_session`
fixture — `SELECT ... FOR UPDATE` is a no-op within a single
transaction, but the business logic executes identically (see
`docs/features/platform/testing-strategy.md`, Concurrency Testing).
True lock-serialization assertions use `db_session_factory` with the
canonical two-session pattern from the same section.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FetcherRunTriggeredBy
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.fetcher_execution import (
    FetcherAcquisition,
    FetcherConfigMissingError,
    acquire_fetcher_run,
    finalize_manual_run_as_failure,
    get_derived_cursor,
    get_fetcher_enabled,
    is_run_stale,
    resolve_effective_hard_limit,
)
from tests.support.database import assert_lock_wait
from tests.support.ticket_mutations import StatementRecorder


def _service_log_text(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.fetcher_execution"
    )


# ---------------------------------------------------------------------------
# Pure calculation unit tests: resolve_effective_hard_limit / is_run_stale
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestResolveEffectiveHardLimit:
    def test_prefers_persisted_value(self) -> None:
        assert resolve_effective_hard_limit(1800, 3600) == 1800

    def test_falls_back_when_none(self) -> None:
        assert resolve_effective_hard_limit(None, 3600) == 3600


@pytest.mark.unit
class TestIsRunStale:
    def test_terminal_status_is_never_stale(self) -> None:
        now = datetime.now(UTC)
        assert (
            is_run_stale(
                status="success",
                created_at=now - timedelta(hours=10),
                started_at=now - timedelta(hours=10),
                hard_time_limit_seconds=3600,
                fallback_run_timeout=3600,
                now=now,
            )
            is False
        )

    def test_running_under_threshold_is_not_stale(self) -> None:
        now = datetime.now(UTC)
        started_at = now - timedelta(seconds=3600 + 59)
        assert (
            is_run_stale(
                status="running",
                created_at=started_at,
                started_at=started_at,
                hard_time_limit_seconds=3600,
                fallback_run_timeout=3600,
                now=now,
            )
            is False
        )

    def test_running_at_exact_threshold_is_not_stale(self) -> None:
        """Boundary: `elapsed == effective_limit + 60` is NOT stale —
        the contract requires strictly greater than the threshold."""
        now = datetime.now(UTC)
        started_at = now - timedelta(seconds=3660)
        assert (
            is_run_stale(
                status="running",
                created_at=started_at,
                started_at=started_at,
                hard_time_limit_seconds=3600,
                fallback_run_timeout=3600,
                now=now,
            )
            is False
        )

    def test_running_over_threshold_is_stale(self) -> None:
        now = datetime.now(UTC)
        started_at = now - timedelta(seconds=3661)
        assert (
            is_run_stale(
                status="running",
                created_at=started_at,
                started_at=started_at,
                hard_time_limit_seconds=3600,
                fallback_run_timeout=3600,
                now=now,
            )
            is True
        )

    def test_running_uses_fallback_when_hard_limit_is_none(self) -> None:
        """A `NULL` `hard_time_limit_seconds` (a historical row
        predating the column) falls back to the live
        `FetcherConfig.run_timeout` for threshold evaluation."""
        now = datetime.now(UTC)
        started_at = now - timedelta(seconds=121)
        assert (
            is_run_stale(
                status="running",
                created_at=started_at,
                started_at=started_at,
                hard_time_limit_seconds=None,
                fallback_run_timeout=60,
                now=now,
            )
            is True
        )

    def test_running_ignores_fallback_when_hard_limit_present(self) -> None:
        """The persisted `hard_time_limit_seconds` always wins over the
        fallback, even when the two diverge."""
        now = datetime.now(UTC)
        started_at = now - timedelta(seconds=61)
        assert (
            is_run_stale(
                status="running",
                created_at=started_at,
                started_at=started_at,
                hard_time_limit_seconds=3600,
                fallback_run_timeout=60,
                now=now,
            )
            is False
        )

    def test_queued_under_threshold_is_not_stale(self) -> None:
        now = datetime.now(UTC)
        created_at = now - timedelta(seconds=599)
        assert (
            is_run_stale(
                status="queued",
                created_at=created_at,
                started_at=None,
                hard_time_limit_seconds=None,
                fallback_run_timeout=3600,
                now=now,
            )
            is False
        )

    def test_queued_at_exact_threshold_is_not_stale(self) -> None:
        """Boundary: `elapsed == 600` is NOT stale — strictly greater
        than the fixed Queued Stale Threshold."""
        now = datetime.now(UTC)
        created_at = now - timedelta(seconds=600)
        assert (
            is_run_stale(
                status="queued",
                created_at=created_at,
                started_at=None,
                hard_time_limit_seconds=None,
                fallback_run_timeout=3600,
                now=now,
            )
            is False
        )

    def test_queued_over_threshold_is_stale(self) -> None:
        now = datetime.now(UTC)
        created_at = now - timedelta(seconds=601)
        assert (
            is_run_stale(
                status="queued",
                created_at=created_at,
                started_at=None,
                hard_time_limit_seconds=None,
                fallback_run_timeout=3600,
                now=now,
            )
            is True
        )

    def test_queued_staleness_is_independent_of_run_timeout(self) -> None:
        """The Queued Stale Threshold is a fixed 600 seconds — an
        unusually large fallback `run_timeout` does not extend it."""
        now = datetime.now(UTC)
        created_at = now - timedelta(seconds=601)
        assert (
            is_run_stale(
                status="queued",
                created_at=created_at,
                started_at=None,
                hard_time_limit_seconds=None,
                fallback_run_timeout=604800,
                now=now,
            )
            is True
        )


# ---------------------------------------------------------------------------
# Missing FetcherConfig
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunConfigMissing:
    async def test_missing_config_raises(self, db_session: AsyncSession) -> None:
        with pytest.raises(FetcherConfigMissingError, match="no_such_fetcher"):
            await acquire_fetcher_run(
                db_session,
                fetcher_name="no_such_fetcher",
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )


# ---------------------------------------------------------------------------
# Catch-up enabled read: get_fetcher_enabled
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGetFetcherEnabled:
    @pytest.mark.parametrize("enabled", [True, False])
    async def test_returns_persisted_enabled_flag(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        enabled: bool,
    ) -> None:
        config = await fetcher_config_factory(enabled=enabled)

        assert await get_fetcher_enabled(db_session, config.fetcher_name) is enabled

    async def test_missing_config_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        # An unrelated row proves the read is scoped to `fetcher_name`.
        await fetcher_config_factory(enabled=True)

        with pytest.raises(FetcherConfigMissingError, match="no_such_catch_up_fetcher"):
            await get_fetcher_enabled(db_session, "no_such_catch_up_fetcher")


# ---------------------------------------------------------------------------
# Derived cursor read: get_derived_cursor
# ---------------------------------------------------------------------------

CURSOR_BASE = datetime(2026, 9, 1, 12, 0, 0, 123456, tzinfo=UTC)


@pytest.mark.integration
class TestGetDerivedCursor:
    async def test_no_run_returns_none(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()

        assert await get_derived_cursor(db_session, config.fetcher_name) is None

    async def test_unknown_fetcher_returns_none(self, db_session: AsyncSession) -> None:
        assert await get_derived_cursor(db_session, "no_such_cursor_fetcher") is None

    async def test_runs_that_never_reached_success_or_partial_return_none(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        name = config.fetcher_name
        await fetcher_run_factory(
            fetcher_name=name, status="failure", started_at=CURSOR_BASE
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status="failure",
            started_at=None,
            triggered_by="manual",
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status="running",
            started_at=CURSOR_BASE + timedelta(hours=1),
        )

        assert await get_derived_cursor(db_session, name) is None

    @pytest.mark.parametrize("latest_status", ["success", "partial"])
    async def test_latest_success_or_partial_started_at_wins(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        latest_status: str,
    ) -> None:
        config = await fetcher_config_factory()
        other = await fetcher_config_factory()
        name = config.fetcher_name
        latest = CURSOR_BASE + timedelta(hours=3)
        older_status = "partial" if latest_status == "success" else "success"
        # Inserted out of chronological order: insertion order, `created_at`,
        # and primary key never choose the cursor.
        await fetcher_run_factory(
            fetcher_name=name, status=older_status, started_at=CURSOR_BASE
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status=latest_status,
            started_at=latest,
            created_at=CURSOR_BASE - timedelta(days=1),
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status=older_status,
            started_at=CURSOR_BASE + timedelta(hours=2),
        )
        # Newer runs that never reached success/partial, and a queued run
        # whose NULL `started_at` would sort first in a descending order.
        await fetcher_run_factory(
            fetcher_name=name,
            status="failure",
            started_at=latest + timedelta(hours=1),
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status="running",
            started_at=latest + timedelta(hours=2),
        )
        await fetcher_run_factory(
            fetcher_name=name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )
        # Another fetcher's newer success is not this fetcher's cursor.
        await fetcher_run_factory(
            fetcher_name=other.fetcher_name,
            status="success",
            started_at=latest + timedelta(days=1),
        )

        cursor = await get_derived_cursor(db_session, name)

        assert cursor == latest
        assert cursor is not None
        assert cursor.utcoffset() == timedelta(0)
        assert await get_derived_cursor(db_session, other.fetcher_name) == (
            latest + timedelta(days=1)
        )

    async def test_read_takes_no_lock_and_writes_or_commits_nothing(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(status="success", started_at=CURSOR_BASE)
        name = run.fetcher_name

        with StatementRecorder(db_session) as recorder:
            cursor = await get_derived_cursor(db_session, name)

        assert cursor == CURSOR_BASE
        # Exactly one plain SELECT: no row lock, no write, and no commit
        # (a commit would release the test savepoint with its own statement).
        (statement,) = recorder.statements
        assert statement.lstrip().upper().startswith("SELECT")
        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()


# ---------------------------------------------------------------------------
# Disabled fetcher
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunDisabled:
    async def test_scheduled_creates_no_run_and_logs_debug(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory(enabled=False)

        with caplog.at_level("DEBUG"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

        assert result is None
        rows = (
            (
                await db_session.execute(
                    select(FetcherRun).where(
                        FetcherRun.fetcher_name == config.fetcher_name
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows == []
        assert "fetcher_disabled_skipping_run" in _service_log_text(caplog)

    async def test_manual_finalizes_supplied_run(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory(enabled=False)
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )
        now = datetime.now(UTC)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.MANUAL,
            run_id=run.id,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert result is None
        await db_session.refresh(run)
        assert run.status == "failure"
        assert run.error_message == ("Fetcher disabled between trigger and execution")
        assert run.finished_at == now
        assert run.started_at is None
        assert run.duration_seconds is None


# ---------------------------------------------------------------------------
# Scheduled acquisition
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunScheduledCreate:
    async def test_no_active_run_creates_new_running_row(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        """`hard_time_limit_seconds` (the effective Celery hard limit
        for this delivery) — not `FetcherConfig.run_timeout` — is
        persisted on the new row and populates the runtime snapshot's
        own `hard_time_limit_seconds` field. The two are deliberately
        different values here (2400 vs. 1800) to prove the snapshot
        reflects the delivered limit, never the live config column."""
        config = await fetcher_config_factory(
            run_timeout=1800,
            request_delay=2.5,
            custom_settings={"page_size": 50},
            schedule_override="0 */6 * * *",
        )
        now = datetime.now(UTC)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE,
            run_id=None,
            now=now,
            hard_time_limit_seconds=2400,
        )

        assert isinstance(result, FetcherAcquisition)
        assert result.config.hard_time_limit_seconds == 2400
        assert result.config.request_delay == 2.5
        assert result.config.custom_settings == {"page_size": 50}

        created = await db_session.get(FetcherRun, result.run_id)
        assert created is not None
        assert created.status == "running"
        assert created.triggered_by == "schedule"
        assert created.started_at == now
        assert created.hard_time_limit_seconds == 2400


@pytest.mark.integration
class TestAcquireFetcherRunScheduledDuplicate:
    async def test_active_non_stale_run_returns_none_and_creates_no_row(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory(run_timeout=3600)
        now = datetime.now(UTC)
        active = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            triggered_by="schedule",
            started_at=now,
        )

        with caplog.at_level("INFO"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=now,
                hard_time_limit_seconds=3600,
            )

        assert result is None
        rows = (
            (
                await db_session.execute(
                    select(FetcherRun).where(
                        FetcherRun.fetcher_name == config.fetcher_name
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].id == active.id
        assert rows[0].status == "running"
        assert "scheduled_run_skipped_active_run_exists" in _service_log_text(caplog)


# ---------------------------------------------------------------------------
# Stale run boundary and finalization
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunStaleBoundary:
    """The active `running` rows created via `fetcher_run_factory` below
    do not set `hard_time_limit_seconds` (defaults to `NULL`), so these
    tests exercise the NULL-fallback path of `is_run_stale()` /
    `resolve_effective_hard_limit()`: staleness is evaluated against
    the locked `FetcherConfig.run_timeout`, since the row predates (or
    never received) its own persisted hard limit."""

    async def test_elapsed_equal_to_threshold_is_not_stale(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory(run_timeout=60)
        started_at = datetime.now(UTC)
        active = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=started_at,
        )
        assert active.hard_time_limit_seconds is None
        # Exactly run_timeout + 60 == 120: NOT stale (strict `>`).
        now = started_at + timedelta(seconds=120)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE,
            run_id=None,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert result is None
        await db_session.refresh(active)
        assert active.status == "running"

    async def test_elapsed_one_second_beyond_threshold_is_stale(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory(run_timeout=60)
        started_at = datetime.now(UTC)
        stale_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            triggered_by="schedule",
            started_at=started_at,
        )
        # One second beyond run_timeout + 60 == 120: stale.
        now = started_at + timedelta(seconds=121)

        with caplog.at_level("WARNING"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=now,
                hard_time_limit_seconds=3600,
            )

        # Scheduled acquisition proceeds after stale finalization.
        assert isinstance(result, FetcherAcquisition)
        assert result.run_id != stale_run.id

        await db_session.refresh(stale_run)
        assert stale_run.status == "failure"
        assert stale_run.error_message == (
            "Marked as stale (running for 121s, timeout 60s)"
        )
        assert stale_run.finished_at == now
        assert stale_run.duration_seconds == 121.0

        new_run = await db_session.get(FetcherRun, result.run_id)
        assert new_run is not None
        assert new_run.status == "running"

        log_text = _service_log_text(caplog)
        assert "fetcher_run_marked_stale" in log_text
        assert config.fetcher_name in log_text
        assert "60" in log_text


# ---------------------------------------------------------------------------
# Persisted hard limit takes precedence over the live FetcherConfig value
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunPersistedHardLimitPrecedence:
    """Regression coverage for the core per-run hard time limit fix
    (`docs/features/platform/fetcher-infrastructure.md`, Per-Run Hard
    Time Limit): a `running` row's OWN persisted `hard_time_limit_seconds`
    is always authoritative for stale evaluation — never the fetcher's
    *current* `FetcherConfig.run_timeout`, which may have changed after
    the row was created/adopted (e.g., an admin's `run_timeout` PATCH
    landing after Celery Beat already dispatched the task with the old
    hard limit)."""

    async def test_config_decreased_after_dispatch_does_not_shrink_threshold(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        """Dispatch carried a hard limit of 3600; the fetcher's
        `run_timeout` is later decreased to 300 (e.g. via PATCH) before
        the worker adopts the delivery. A second acquisition attempt at
        an elapsed time beyond the new-but-irrelevant 300+60=360s
        threshold — but still within the row's own 3600+60=3660s
        threshold — must find the active run NOT stale and discard
        silently, exactly as if the config had never changed."""
        config = await fetcher_config_factory(run_timeout=3600)
        started_at = datetime.now(UTC)
        active = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            started_at=started_at,
            hard_time_limit_seconds=3600,
        )

        # Simulate the admin's PATCH lowering run_timeout after dispatch.
        config.run_timeout = 300
        await db_session.flush()

        # 400s elapsed: beyond 300+60=360, but well within 3600+60=3660.
        now = started_at + timedelta(seconds=400)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE,
            run_id=None,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert result is None
        await db_session.refresh(active)
        assert active.status == "running"

    async def test_config_increased_after_dispatch_does_not_grow_threshold(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Inverse scenario: dispatch carried a hard limit of 300; the
        fetcher's `run_timeout` is later increased to 3600. The row's
        own persisted 300+60=360s threshold still applies — an elapsed
        time beyond it is stale, even though the live config would
        suggest otherwise."""
        config = await fetcher_config_factory(run_timeout=300)
        started_at = datetime.now(UTC)
        stale_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            triggered_by="schedule",
            started_at=started_at,
            hard_time_limit_seconds=300,
        )

        # Simulate the admin's PATCH raising run_timeout after dispatch.
        config.run_timeout = 3600
        await db_session.flush()

        # 361s elapsed: beyond the row's own 300+60=360 threshold.
        now = started_at + timedelta(seconds=361)

        with caplog.at_level("WARNING"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=now,
                hard_time_limit_seconds=3600,
            )

        assert isinstance(result, FetcherAcquisition)
        assert result.run_id != stale_run.id
        await db_session.refresh(stale_run)
        assert stale_run.status == "failure"
        assert stale_run.error_message == (
            "Marked as stale (running for 361s, timeout 300s)"
        )


# ---------------------------------------------------------------------------
# Manual adoption
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunManualAdoption:
    async def test_adopts_precreated_run_not_treated_as_competitor(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )
        now = datetime.now(UTC)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.MANUAL,
            run_id=run.id,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert isinstance(result, FetcherAcquisition)
        assert result.run_id == run.id

        await db_session.refresh(run)
        assert run.status == "running"
        assert run.started_at == now
        assert run.hard_time_limit_seconds == 3600

        rows = (
            (
                await db_session.execute(
                    select(FetcherRun).where(
                        FetcherRun.fetcher_name == config.fetcher_name
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1

    async def test_run_not_found_raises_value_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()
        missing_run_id = uuid4()

        with pytest.raises(ValueError, match=str(missing_run_id)):
            await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=missing_run_id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

    async def test_run_fetcher_name_mismatch_raises_value_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        other_config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=other_config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )

        with pytest.raises(ValueError, match="belongs to fetcher"):
            await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=run.id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

    async def test_already_finalized_run_returns_none_without_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="failure",
            triggered_by="manual",
            finished_at=datetime.now(UTC),
        )

        with caplog.at_level("INFO"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=run.id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

        assert result is None
        await db_session.refresh(run)
        assert run.status == "failure"
        assert "manual_run_already_finalized" in _service_log_text(caplog)

    async def test_already_running_run_is_a_duplicate_delivery_skip(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A redelivered Celery message for a run a previous delivery
        already adopted (`status = running`) must not be re-executed —
        see fetcher-infrastructure.md, Atomic Run Acquisition Protocol,
        step 6, duplicate-delivery handling."""
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="running",
            triggered_by="manual",
        )

        with caplog.at_level("INFO"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=run.id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

        assert result is None
        await db_session.refresh(run)
        assert run.status == "running"
        assert "manual_run_already_adopted_or_completed" in _service_log_text(caplog)

    async def test_already_success_run_is_a_duplicate_delivery_skip(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="success",
            triggered_by="manual",
            finished_at=datetime.now(UTC),
        )

        with caplog.at_level("INFO"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=run.id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )

        assert result is None
        assert "manual_run_already_adopted_or_completed" in _service_log_text(caplog)

    async def test_manual_run_stale_before_adoption_marks_stale_and_returns_none(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A manual run picked up so late that its own pre-created
        `queued` row has already crossed the Queued Stale Threshold
        (600s from `created_at`) is marked stale at step 5 and then
        discarded as already-finalized at step 6 — it is never
        (re-)executed. See fetcher-infrastructure.md, Atomic Run
        Acquisition Protocol, step 5 note; Stale Run Detection, Queued
        Stale Threshold.
        """
        config = await fetcher_config_factory(run_timeout=60)
        created_at = datetime.now(UTC)
        manual_run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=created_at,
            triggered_by="manual",
        )
        # One second beyond the fixed 600s Queued Stale Threshold: stale.
        now = created_at + timedelta(seconds=601)

        with caplog.at_level("INFO"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=manual_run.id,
                now=now,
                hard_time_limit_seconds=3600,
            )

        assert result is None
        # The caller (`run_fetcher_async`) always commits the session
        # after `acquire_fetcher_run` returns, regardless of the return
        # value — this flush simulates that unconditional commit so the
        # in-place stale mutation becomes visible to a fresh SELECT.
        await db_session.flush()
        await db_session.refresh(manual_run)
        assert manual_run.status == "failure"
        assert manual_run.started_at is None
        assert manual_run.duration_seconds is None
        assert "Marked as stale (queued for" in (manual_run.error_message or "")
        assert "manual_run_already_finalized" in _service_log_text(caplog)

        # No replacement run was created for the manual trigger.
        rows = (
            (
                await db_session.execute(
                    select(FetcherRun).where(
                        FetcherRun.fetcher_name == config.fetcher_name
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Queued Stale Threshold boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunQueuedStaleBoundary:
    """Mirrors `TestAcquireFetcherRunStaleBoundary` for the fixed
    600-second Queued Stale Threshold
    (`docs/features/platform/fetcher-infrastructure.md`, Stale Run
    Detection, Queued Stale Threshold)."""

    async def test_elapsed_equal_to_threshold_is_not_stale(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        created_at = datetime.now(UTC)
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=created_at,
            triggered_by="manual",
        )
        # Exactly 600 seconds: NOT stale (strict `>`).
        now = created_at + timedelta(seconds=600)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.MANUAL,
            run_id=run.id,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert isinstance(result, FetcherAcquisition)
        await db_session.refresh(run)
        assert run.status == "running"

    async def test_elapsed_one_second_beyond_threshold_is_stale(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config = await fetcher_config_factory()
        created_at = datetime.now(UTC)
        run = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=created_at,
            triggered_by="manual",
        )
        now = created_at + timedelta(seconds=601)

        with caplog.at_level("WARNING"):
            result = await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=run.id,
                now=now,
                hard_time_limit_seconds=3600,
            )

        assert result is None
        await db_session.refresh(run)
        assert run.status == "failure"
        assert run.started_at is None
        assert run.duration_seconds is None
        assert run.finished_at == now
        assert run.error_message == "Marked as stale (queued for 601s, timeout 600s)"
        log_text = _service_log_text(caplog)
        assert "fetcher_run_marked_stale_queued" in log_text

    async def test_scheduled_trigger_finalizes_stale_queued_run_and_proceeds(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        """A stale `queued` manual run does not block a scheduled
        trigger from proceeding — it is finalized under the same lock
        and a fresh scheduled run is created."""
        config = await fetcher_config_factory()
        created_at = datetime.now(UTC)
        stale_queued = await fetcher_run_factory(
            fetcher_name=config.fetcher_name,
            status="queued",
            started_at=None,
            created_at=created_at,
            triggered_by="manual",
        )
        now = created_at + timedelta(seconds=601)

        result = await acquire_fetcher_run(
            db_session,
            fetcher_name=config.fetcher_name,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE,
            run_id=None,
            now=now,
            hard_time_limit_seconds=3600,
        )

        assert isinstance(result, FetcherAcquisition)
        assert result.run_id != stale_queued.id
        await db_session.refresh(stale_queued)
        assert stale_queued.status == "failure"

        new_run = await db_session.get(FetcherRun, result.run_id)
        assert new_run is not None
        assert new_run.status == "running"
        assert new_run.triggered_by == "schedule"


# ---------------------------------------------------------------------------
# Multiple active rows anomaly
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunMultipleActiveRowsAnomaly:
    """The `FetcherConfig` lock and the API-level guard are expected to
    make more than one simultaneous active (`queued` or `running`) row
    per fetcher impossible. If observed anyway (e.g. data corruption,
    a bug elsewhere), this is a fail-fast condition rather than a
    silently resolved one."""

    async def test_two_active_rows_raise_runtime_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(
            fetcher_name=config.fetcher_name, status="queued", started_at=None
        )
        await fetcher_run_factory(fetcher_name=config.fetcher_name, status="running")

        with pytest.raises(RuntimeError, match="Multiple active FetcherRun rows"):
            await acquire_fetcher_run(
                db_session,
                fetcher_name=config.fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )


# ---------------------------------------------------------------------------
# finalize_manual_run_as_failure()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFinalizeManualRunAsFailure:
    async def test_updates_fields_and_flushes(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(
            status="queued", started_at=None, triggered_by="manual"
        )
        now = datetime.now(UTC)

        won = await finalize_manual_run_as_failure(
            db_session,
            run_id=run.id,
            fetcher_name=run.fetcher_name,
            error_message="Fetcher deregistered between trigger and execution",
            now=now,
        )

        assert won is True
        await db_session.refresh(run)
        assert run.status == "failure"
        assert run.error_message == (
            "Fetcher deregistered between trigger and execution"
        )
        assert run.finished_at == now
        assert run.started_at is None
        assert run.duration_seconds is None
        assert run.error_detail is None
        assert run.error_traceback is None

    async def test_persists_error_detail_and_traceback_when_provided(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        """The manual-trigger broker-publication-failure path (used by
        `fetcher_operations.trigger_fetcher`) supplies `error_detail`
        (the exception class name only) and, per the sanitization
        contract, always passes `error_traceback=None` — but the
        parameter itself is a general capability of this function, not
        hardcoded to that one caller."""
        run = await fetcher_run_factory(
            status="queued", started_at=None, triggered_by="manual"
        )

        await finalize_manual_run_as_failure(
            db_session,
            run_id=run.id,
            fetcher_name=run.fetcher_name,
            error_message="Manual run could not be dispatched to the task broker",
            now=datetime.now(UTC),
            error_detail="OperationalError",
            error_traceback=None,
        )

        await db_session.refresh(run)
        assert run.error_detail == "OperationalError"
        assert run.error_traceback is None

    async def test_missing_run_raises_value_error(
        self, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        missing_run_id = uuid4()

        with (
            caplog.at_level("ERROR"),
            pytest.raises(ValueError, match=str(missing_run_id)),
        ):
            await finalize_manual_run_as_failure(
                db_session,
                run_id=missing_run_id,
                fetcher_name="some_fetcher",
                error_message="irrelevant",
                now=datetime.now(UTC),
            )

    async def test_fetcher_name_mismatch_raises_value_error(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The conditional UPDATE's `fetcher_name` predicate means a
        `run_id` that exists but belongs to a different fetcher matches
        zero rows — the same outcome as a wholly missing `run_id`.
        Unlike `acquire_fetcher_run`'s equivalent guard (which raises a
        distinct message and log event per cause), this function does
        NOT distinguish the two: both collapse into the same "not
        found" `ValueError` message and the same
        `manual_run_finalization_target_missing` log event, per
        `docs/features/platform/fetcher-infrastructure.md` (Celery
        Integration — Unknown and deregistered fetcher handling, which
        specifies a single combined case). The row is left untouched
        in both cases."""
        other_config = await fetcher_config_factory()
        run = await fetcher_run_factory(
            fetcher_name=other_config.fetcher_name,
            status="queued",
            started_at=None,
            triggered_by="manual",
        )

        with (
            caplog.at_level("ERROR"),
            pytest.raises(ValueError, match=str(run.id)),
        ):
            await finalize_manual_run_as_failure(
                db_session,
                run_id=run.id,
                fetcher_name="a_different_fetcher",
                error_message="Fetcher deregistered between trigger and execution",
                now=datetime.now(UTC),
            )

        await db_session.refresh(run)
        assert run.status == "queued"
        assert run.error_message is None
        assert run.finished_at is None

    async def test_already_transitioned_run_is_a_silent_no_op(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A run already adopted (`running`) by a concurrent path when
        this conditional UPDATE runs is left untouched — the caller
        (e.g. a redelivered deregistration finalize) defers to
        whichever transition already won."""
        run = await fetcher_run_factory(status="running", triggered_by="manual")

        with caplog.at_level("INFO"):
            won = await finalize_manual_run_as_failure(
                db_session,
                run_id=run.id,
                fetcher_name=run.fetcher_name,
                error_message="Fetcher deregistered between trigger and execution",
                now=datetime.now(UTC),
            )

        assert won is False
        await db_session.refresh(run)
        assert run.status == "running"
        assert "manual_run_already_transitioned" in _service_log_text(caplog)


# ---------------------------------------------------------------------------
# True concurrency — FetcherConfig-root lock serialization
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAcquireFetcherRunConcurrency:
    """See docs/features/platform/testing-strategy.md (Concurrency
    Testing) for the canonical two-session pattern applied here."""

    async def test_concurrent_scheduled_starts_only_one_creates_a_run(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        fetcher_name = f"concurrency_fetcher_{uuid4().hex[:8]}"

        session_a.add(FetcherConfig(fetcher_name=fetcher_name, run_timeout=3600))
        await session_a.commit()

        now = datetime.now(UTC)
        # Session A acquires the FetcherConfig lock, creates the run,
        # and flushes — but does not commit yet, so the lock is held.
        acquisition_a = await acquire_fetcher_run(
            session_a,
            fetcher_name=fetcher_name,
            triggered_by=FetcherRunTriggeredBy.SCHEDULE,
            run_id=None,
            now=now,
            hard_time_limit_seconds=3600,
        )
        assert acquisition_a is not None

        # Session B's concurrent acquisition attempt blocks on the same
        # FetcherConfig row — this is the empty-result race the
        # FetcherConfig-root lock (rather than a FetcherRun-only lock)
        # is designed to prevent (see fetcher-infrastructure.md,
        # Atomic Run Acquisition Protocol).
        task_b = asyncio.create_task(
            acquire_fetcher_run(
                session_b,
                fetcher_name=fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=now,
                hard_time_limit_seconds=3600,
            )
        )
        await assert_lock_wait(task_b, waiter=session_b, blocked_by=session_a)

        # Releasing A's lock lets B proceed — B now observes A's
        # committed running run and silently discards.
        await session_a.commit()
        acquisition_b = await asyncio.wait_for(task_b, timeout=5)
        await session_b.commit()

        assert acquisition_b is None

        rows = (
            (
                await session_a.execute(
                    select(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].id == acquisition_a.run_id

        # Explicit cleanup — committed rows are not covered by
        # db_session_factory's rollback-on-teardown.
        await session_a.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session_a.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session_a.commit()

    async def test_concurrent_manual_adoption_and_scheduled_duplicate(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        fetcher_name = f"concurrency_fetcher_{uuid4().hex[:8]}"

        session_a.add(FetcherConfig(fetcher_name=fetcher_name, run_timeout=3600))
        manual_run = FetcherRun(
            fetcher_name=fetcher_name,
            status="queued",
            triggered_by="manual",
        )
        session_a.add(manual_run)
        await session_a.commit()

        now = datetime.now(UTC)
        # Session A adopts its own pre-created manual run and holds
        # the FetcherConfig lock (no commit yet).
        acquisition_a = await acquire_fetcher_run(
            session_a,
            fetcher_name=fetcher_name,
            triggered_by=FetcherRunTriggeredBy.MANUAL,
            run_id=manual_run.id,
            now=now,
            hard_time_limit_seconds=3600,
        )
        assert acquisition_a is not None
        assert acquisition_a.run_id == manual_run.id

        # A concurrent scheduled trigger blocks on the same lock.
        task_b = asyncio.create_task(
            acquire_fetcher_run(
                session_b,
                fetcher_name=fetcher_name,
                triggered_by=FetcherRunTriggeredBy.SCHEDULE,
                run_id=None,
                now=now,
                hard_time_limit_seconds=3600,
            )
        )
        await assert_lock_wait(task_b, waiter=session_b, blocked_by=session_a)

        await session_a.commit()
        acquisition_b = await asyncio.wait_for(task_b, timeout=5)
        await session_b.commit()

        # "Schedule fires while manual run is active" — silent discard.
        assert acquisition_b is None

        rows = (
            (
                await session_a.execute(
                    select(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].id == manual_run.id
        assert rows[0].status == "running"
        assert rows[0].started_at == now

        await session_a.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session_a.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session_a.commit()

    async def test_adoption_wins_concurrent_compensation_is_a_no_op(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Simulates the ambiguous-broker-acknowledgement race described
        in `docs/features/platform/fetcher-operations.md` (Ambiguous
        Broker Acknowledgement): worker adoption (`queued -> running`)
        and a publication-failure compensation (`queued -> failure`)
        both attempt a conditional atomic UPDATE against the same
        `queued` row. Ordinary PostgreSQL row-level locking on `UPDATE`
        — not the `FetcherConfig` lock — is what makes exactly one of
        them win; the other observes zero rows affected and is a safe
        no-op."""
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        fetcher_name = f"concurrency_fetcher_{uuid4().hex[:8]}"

        session_a.add(FetcherConfig(fetcher_name=fetcher_name, run_timeout=3600))
        manual_run = FetcherRun(
            fetcher_name=fetcher_name,
            status="queued",
            triggered_by="manual",
        )
        session_a.add(manual_run)
        await session_a.commit()

        now = datetime.now(UTC)
        # Session A performs worker adoption — the UPDATE inside
        # acquire_fetcher_run() takes an uncommitted row lock on the
        # FetcherRun row (in addition to the FetcherConfig lock).
        acquisition_a = await acquire_fetcher_run(
            session_a,
            fetcher_name=fetcher_name,
            triggered_by=FetcherRunTriggeredBy.MANUAL,
            run_id=manual_run.id,
            now=now,
            hard_time_limit_seconds=3600,
        )
        assert acquisition_a is not None

        # Session B (the publication-failure compensation) attempts its
        # own conditional UPDATE concurrently — it blocks on the row
        # lock session A already holds, even though it never touches
        # FetcherConfig.
        task_b = asyncio.create_task(
            finalize_manual_run_as_failure(
                session_b,
                run_id=manual_run.id,
                fetcher_name=fetcher_name,
                error_message="Manual run could not be dispatched to the task broker",
                now=datetime.now(UTC),
            )
        )
        await assert_lock_wait(task_b, waiter=session_b, blocked_by=session_a)

        # Releasing A's locks lets B proceed — B's UPDATE re-evaluates
        # against the committed 'running' state and matches zero rows.
        await session_a.commit()
        await asyncio.wait_for(task_b, timeout=5)
        await session_b.commit()

        rows = (
            (
                await session_a.execute(
                    select(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].status == "running"
        assert rows[0].started_at == now

        await session_a.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session_a.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session_a.commit()

    async def test_compensation_wins_concurrent_worker_adoption_is_a_no_op(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """The reverse race: the publication-failure compensation
        commits first, so the worker's later adoption attempt finds the
        run already finalized and does not execute it."""
        session_a = await db_session_factory()
        session_b = await db_session_factory()
        fetcher_name = f"concurrency_fetcher_{uuid4().hex[:8]}"

        session_a.add(FetcherConfig(fetcher_name=fetcher_name, run_timeout=3600))
        manual_run = FetcherRun(
            fetcher_name=fetcher_name,
            status="queued",
            triggered_by="manual",
        )
        session_a.add(manual_run)
        await session_a.commit()

        now = datetime.now(UTC)
        # Session A performs the compensation first — takes an
        # uncommitted row lock on the FetcherRun row via its own
        # conditional UPDATE.
        await finalize_manual_run_as_failure(
            session_a,
            run_id=manual_run.id,
            fetcher_name=fetcher_name,
            error_message="Manual run could not be dispatched to the task broker",
            now=now,
        )

        # Session B (a worker that received the task despite the
        # publication error) attempts adoption concurrently — it
        # blocks on the same row lock.
        task_b = asyncio.create_task(
            acquire_fetcher_run(
                session_b,
                fetcher_name=fetcher_name,
                triggered_by=FetcherRunTriggeredBy.MANUAL,
                run_id=manual_run.id,
                now=datetime.now(UTC),
                hard_time_limit_seconds=3600,
            )
        )
        await assert_lock_wait(task_b, waiter=session_b, blocked_by=session_a)

        await session_a.commit()
        acquisition_b = await asyncio.wait_for(task_b, timeout=5)
        await session_b.commit()

        # Compensation won: the worker's adoption attempt found the run
        # already finalized and did not execute it.
        assert acquisition_b is None

        rows = (
            (
                await session_a.execute(
                    select(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].status == "failure"
        assert rows[0].started_at is None

        await session_a.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name == fetcher_name)
        )
        await session_a.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session_a.commit()
