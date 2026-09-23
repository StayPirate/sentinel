"""End-to-end local process system test for the generic scheduled
fetcher pipeline.

See `docs/features/platform/testing-strategy.md` (Local Process System
Testing) for the full behavioral contract this test proves: real worker
and Beat processes, real PostgreSQL and Redis, registration → config
bootstrap → RedBeat scheduling → broker delivery → worker execution →
`FetcherRun` finalization → Public API visibility, with no domain-table
mutation and no `FetcherAuditEvent` for a scheduled run. The fixture
also guards against a leftover terminal `FetcherRun` from an
interrupted prior invocation being mistaken for this invocation's own
dispatch (see `preexisting_run_ids` in `conftest.py`).

This is the ONLY test in this module — the harness fixture
(`fetcher_pipeline_harness` in `conftest.py`) owns all process spawning
and deterministic cleanup, so a single comprehensive test avoids paying
the worker/Beat startup cost more than once while still proving every
required step end-to-end.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from celery.schedules import crontab
from httpx import ASGITransport, AsyncClient
from redbeat import RedBeatSchedulerEntry
from sqlalchemy.ext.asyncio import AsyncSession

import app.api.v1.fetchers as fetchers_module
from app.database import get_db
from app.main import app
from tests.system.conftest import SYSTEM_FETCHER_NAME, FetcherPipelineHarness

_WORKER_OWNERSHIP_ENTRY_NAME = "worker_startup_ownership_probe"


def _redbeat_entry_snapshot(entry: RedBeatSchedulerEntry) -> tuple[object, ...]:
    """Capture every persisted schedule and execution field exposed by RedBeat."""
    return (
        entry.name,
        entry.task,
        entry.schedule,
        entry.args,
        entry.kwargs,
        entry.options,
        entry.enabled,
        entry.last_run_at,
        entry.total_run_count,
    )


@pytest.mark.system
async def test_scheduled_fetcher_pipeline_end_to_end(
    fetcher_pipeline_harness: FetcherPipelineHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = fetcher_pipeline_harness

    # Baseline: capture the domain-table snapshot BEFORE any process is
    # spawned, so the final comparison proves this test introduced no
    # domain mutation (testing-strategy.md, Behavioral Requirements,
    # point 6) — independent of whatever pre-existing state the shared
    # test database happens to hold.
    domain_snapshot_before = await harness.snapshot_domain_tables()

    # 1. Seed a RedBeat entry before worker startup. A real worker must
    # become reachable and register `run_fetcher` without creating,
    # updating, or deleting schedule state; only Beat and the API own
    # RedBeat writes (fetcher-infrastructure.md, Who Writes Where).
    ownership_entry = RedBeatSchedulerEntry(
        name=_WORKER_OWNERSHIP_ENTRY_NAME,
        task="run_fetcher",
        schedule=crontab.from_string("17 4 * * 2"),
        args=["fictional-probe"],
        kwargs={
            "fetcher_name": _WORKER_OWNERSHIP_ENTRY_NAME,
            "triggered_by": "schedule",
        },
        options={"queue": "never-dispatched"},
        app=harness.celery_app,
    ).save()
    ownership_key = ownership_entry.key
    ownership_before = _redbeat_entry_snapshot(
        RedBeatSchedulerEntry.from_key(ownership_key, app=harness.celery_app)
    )

    harness.start_worker()
    await harness.wait_worker_ready()

    ownership_after = _redbeat_entry_snapshot(
        RedBeatSchedulerEntry.from_key(ownership_key, app=harness.celery_app)
    )
    assert ownership_after == ownership_before

    # Remove the probe before Beat starts so the existing pipeline assertion
    # observes only state created by normal Beat reconciliation.
    ownership_entry.delete()
    with pytest.raises(KeyError):
        RedBeatSchedulerEntry.from_key(ownership_key, app=harness.celery_app)

    # 2. A real Beat starts, bootstraps the test fetcher's
    # `FetcherConfig`, and reconciles a RedBeat entry for it.
    harness.start_beat()
    config = await harness.wait_config_row()
    assert config.fetcher_name == SYSTEM_FETCHER_NAME
    assert config.enabled is True

    entry = await harness.wait_redbeat_entry()
    assert entry.task == "run_fetcher"
    assert entry.enabled is True
    assert entry.kwargs == {
        "fetcher_name": SYSTEM_FETCHER_NAME,
        "triggered_by": "schedule",
    }
    assert entry.schedule == crontab.from_string("0 0 1 1 *")

    # 3. Make the existing entry immediately overdue via RedBeat's own
    # public API — Beat still performs the actual dispatch through the
    # broker on its next tick (bounded by --max-interval=5), the broker
    # path is never bypassed with a manual send_task().
    harness.make_due()

    # 4. The worker executes the fetcher and finalizes a `FetcherRun`.
    run = await harness.wait_finalized_run()

    # Stop Beat immediately — before any further assertion — so a
    # second scheduling tick cannot fire another dispatch while this
    # test still runs (the schedule is annual; only one finalized run
    # must exist for the entire test — see `EvaluateTestPipeline`).
    harness.stop_beat()

    assert run.status == "success", (
        f"expected a successful run, got {run.status!r}: "
        f"error_message={run.error_message!r} error_detail={run.error_detail!r}"
    )
    assert run.items_succeeded == 0
    assert run.items_created == 0
    assert run.items_updated == 0
    assert run.items_failed == 0
    assert run.triggered_by == "schedule"
    assert run.triggered_by_user_id is None
    assert run.error_message is None
    assert run.error_detail is None
    assert run.error_traceback is None
    assert run.cursor is None
    assert run.started_at is not None
    assert run.finished_at is not None
    assert run.finished_at >= run.started_at
    # Proves the effective hard time limit traveled the whole path:
    # `FetcherConfig.run_timeout` -> RedBeat entry options -> Celery
    # message time-limit header -> `run_fetcher`'s extraction -> the
    # finalized `FetcherRun` row.
    assert run.hard_time_limit_seconds == config.run_timeout

    # Exactly one finalized run for the test fetcher — no duplicates
    # from a concurrent/second dispatch.
    all_runs = await harness.list_runs()
    assert len(all_runs) == 1, [r.id for r in all_runs]

    # No `FetcherAuditEvent` is created for a scheduled run.
    audit_events = await harness.list_audit_events()
    assert audit_events == []

    # 5. The finalized run is visible through the Public fetcher
    # observation API, via the in-process ASGI client with an
    # independently connecting database session and the isolated test
    # Celery/Redis instance.
    monkeypatch.setattr(fetchers_module, "celery_app", harness.celery_app)

    async def _override_get_db() -> AsyncIterator[AsyncSession]:
        async with harness.session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/fetchers")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200, response.text
    body = response.json()
    item = next(
        entry_data
        for entry_data in body["data"]
        if entry_data["fetcher_name"] == SYSTEM_FETCHER_NAME
    )
    assert item["registered"] is True
    assert item["last_run"] is not None
    # Proves the API surfaces exactly the run this invocation produced
    # — not merely a run with a matching status/fetcher_name.
    assert item["last_run"]["id"] == str(run.id)
    assert item["last_run"]["status"] == "success"
    assert item["last_run"]["items_succeeded"] == 0
    assert item["last_run"]["items_created"] == 0
    assert item["last_run"]["triggered_by"] == "schedule"

    # 6. No domain tables are mutated — compare the full pre/post
    # snapshot of every table outside the fetcher infrastructure.
    domain_snapshot_after = await harness.snapshot_domain_tables()
    assert domain_snapshot_after == domain_snapshot_before
