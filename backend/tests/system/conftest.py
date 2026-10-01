"""Fixtures and process-orchestration harness for the local process
system test suite.

See `docs/features/platform/testing-strategy.md` (Local Process System
Testing) for the full behavioral contract these fixtures support:
registration boundary, subprocess environment isolation, bounded
waiting/diagnostics, and deterministic cleanup ordering.

Nothing in this module imports `tests.support.system_fetcher` at module
level — that import (and the `FETCHER_REGISTRY` mutation it triggers as
a side effect) happens exclusively inside `fetcher_pipeline_harness`,
so a `pytest -m 'not system'` collection of this directory never
registers the test-only fetcher in the collecting process.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery import Celery
from redbeat import RedBeatSchedulerEntry
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.database import Base
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.fetcher_schedule import delete_fetcher_entry

_BACKEND_DIR = Path(__file__).resolve().parents[2]

# Duplicated from `tests.support.system_fetcher.SYSTEM_FETCHER_NAME` —
# deliberately NOT imported from that module at module level. That
# module's top-level import would execute `EvaluateTestPipeline`'s class
# body (registering it into `FETCHER_REGISTRY` as an
# `__init_subclass__` side effect) as soon as this `conftest.py` is
# collected — which pytest does unconditionally for every directory it
# walks, regardless of `-m 'not system'` deselection (deselection is a
# post-collection step). The `fetcher_pipeline_harness` fixture below
# imports that module lazily, inside the fixture body, so registration
# only ever happens for a test that actually requests the harness.
SYSTEM_FETCHER_NAME = "evaluate_test_pipeline"

# Tables owned by the fetcher infrastructure — excluded from the
# domain-mutation snapshot (see testing-strategy.md, Behavioral
# Requirements, point 6: "No domain tables are mutated").
_FETCHER_TABLE_NAMES = frozenset(
    {"fetcher_config", "fetcher_run", "fetcher_audit_event"}
)

# Bounded timeouts (seconds) — see testing-strategy.md (Bounded Waiting
# and Diagnostics). Generous enough for a loaded CI runner; still finite.
_WORKER_READY_TIMEOUT = 30.0
_CONFIG_BOOTSTRAP_TIMEOUT = 20.0
_REDBEAT_ENTRY_TIMEOUT = 20.0
_RUN_FINALIZED_TIMEOUT = 30.0
_PROCESS_TERM_TIMEOUT = 10.0
_POLL_INTERVAL = 0.2
# Reply timeout of one `inspect` call. kombu returns as soon as the single
# destination worker replies; the timeout is only paid in full when the
# worker is not consuming its control queue yet, so a short value keeps
# readiness detection prompt while `_WORKER_READY_TIMEOUT` bounds the wait.
_INSPECT_TIMEOUT = 1.0

# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_SYSTEM_TEST_JWT_SECRET_KEY = "system-test-jwt-secret-key-not-for-production-32ch"

# Minimal OS-level context every subprocess needs to actually run
# (locate the interpreter, resolve locale) — NOT application
# configuration. `HOME` is deliberately excluded: it is set explicitly
# to a per-invocation temporary directory instead (see
# `build_system_process_env`), so the subprocess never reads dotfiles
# from the developer's real home directory. Anything not listed here,
# and not one of the explicit values `build_system_process_env` sets,
# is deliberately absent from the spawned process's environment
# (testing-strategy.md, Registration Boundary) — every `Settings`
# field this suite does not set falls back to its own declared
# default, which is safe because the spawned process's fetcher
# registry is pruned to exactly the test fetcher (see
# `tests/support/system_fetcher_app.py`): no code path in the spawned
# process ever reads a field this function does not set.
_INHERITED_OS_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")


def build_system_process_env(
    *, database_url: str, redis_url: str, jwt_secret_key: str, home_dir: Path
) -> dict[str, str]:
    """Build the explicit environment for spawned worker/Beat subprocesses.

    Pure function (no fixture dependencies) so the isolation contract
    can be tested directly against ambient/canary environment variables
    — see `test_system_process_env.py`. The `system_process_env` fixture
    below is a thin wrapper supplying the real per-invocation dynamic
    values.

    Built from a minimal OS-level allowlist (`_INHERITED_OS_ENV_KEYS`)
    plus a handful of explicit application values — never
    `os.environ.copy()`. This ensures the subprocess can never observe a
    developer's shell-exported application configuration, nor
    `backend/.env` file content: the spawned process's `cwd` is a
    per-invocation temporary directory (see `_spawn_celery_process`),
    not `backend/`, so the relative `.env` path in `Settings`'s
    `model_config` never resolves to a real file — see
    testing-strategy.md (Registration Boundary): "The subprocess
    environment MUST NOT inherit application-configured values from the
    developer's shell or `.env` file." `PYTHONPATH` is set explicitly so
    `-m celery` module resolution does not depend on `cwd`.
    """
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env["HOME"] = str(home_dir)
    env["PYTHONPATH"] = str(_BACKEND_DIR)
    env["DATABASE_URL"] = database_url
    env["REDIS_URL"] = redis_url
    env["CELERY_BROKER_URL"] = redis_url
    env["JWT_SECRET_KEY"] = jwt_secret_key
    return env


@pytest.fixture
def system_process_env(
    _engine: AsyncEngine, _redis_test_url: str, tmp_path: Path
) -> dict[str, str]:
    """Explicit environment for spawned worker/Beat subprocesses — see
    `build_system_process_env` for the full isolation contract.

    `DATABASE_URL` is derived from the same test engine `_engine` (and
    therefore the same physical PostgreSQL database) the rest of the
    suite uses — `render_as_string(hide_password=False)` is required
    because `str(engine.url)` masks the password (see
    `test_cross_loop_engine_lifecycle.py` for the identical pattern).
    `CELERY_BROKER_URL`/`REDIS_URL` both point at this pytest worker's
    dedicated Redis logical database (`_redis_test_url`). `home_dir` is
    the same per-test temporary directory used as the spawned
    processes' `cwd` (`fetcher_pipeline_harness`'s `tmp_path`).
    """
    return build_system_process_env(
        database_url=_engine.url.render_as_string(hide_password=False),
        redis_url=_redis_test_url,
        jwt_secret_key=_SYSTEM_TEST_JWT_SECRET_KEY,
        home_dir=tmp_path,
    )


@dataclass
class _SpawnedProcess:
    """A worker or Beat subprocess spawned via the test-owned launcher
    (`tests.support.system_fetcher_app`), with its combined stdout/stderr
    captured to a per-process log file for failure diagnostics.
    """

    name: str
    popen: subprocess.Popen[bytes]
    log_path: Path
    _log_fh: Any = field(repr=False)

    def is_alive(self) -> bool:
        return self.popen.poll() is None

    def assert_alive(self) -> None:
        """Fail immediately, with captured log output, if this process
        already exited — per testing-strategy.md: "Early failure if the
        worker or Beat process exits unexpectedly."
        """
        code = self.popen.poll()
        if code is not None:
            pytest.fail(
                f"{self.name} process exited unexpectedly with code {code}.\n"
                f"--- {self.name} log (tail) ---\n{self.tail_log()}"
            )

    def tail_log(self, max_bytes: int = 4000) -> str:
        try:
            data = self.log_path.read_bytes()
        except OSError:
            return "<log unavailable>"
        return data[-max_bytes:].decode("utf-8", errors="replace")

    def terminate(self, timeout: float) -> None:
        """SIGTERM the process group; escalate to SIGKILL after `timeout`s.

        `start_new_session=True` at spawn time makes this process its
        own session/process-group leader, so `os.killpg(self.popen.pid,
        ...)` reaches it and any child it may have forked (relevant for
        the worker's prefork pool).
        """
        if self.popen.poll() is not None:
            self._close_log()
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.popen.pid, signal.SIGTERM)
        try:
            self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.popen.pid, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.popen.wait(timeout=timeout)
        self._close_log()

    def _close_log(self) -> None:
        if not self._log_fh.closed:
            self._log_fh.close()


def _spawn_celery_process(
    name: str, args: list[str], env: dict[str, str], run_dir: Path
) -> _SpawnedProcess:
    """Spawn `python -m celery -A tests.support.system_fetcher_app <args>`.

    The test-owned launcher module registers `EvaluateTestPipeline`
    before re-exporting the real `app.celery_app.celery_app` singleton
    (see `tests/support/system_fetcher_app.py`) — production entrypoints
    never see this registration since they only ever import
    `app.celery_app` directly.

    `run_dir` (the harness's `tmp_path`) is used both as the process's
    `cwd` — so a relative `backend/.env` file is never in scope for
    `Settings()` to load, see `build_system_process_env` — and as the
    directory for this process's captured log file. `PYTHONPATH` (set
    by `build_system_process_env`) makes `-m celery` module resolution
    independent of `cwd`.
    """
    log_path = run_dir / f"{name}.log"
    log_fh = log_path.open("wb")
    popen = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "celery",
            "-A",
            "tests.support.system_fetcher_app",
            *args,
        ],
        cwd=str(run_dir),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return _SpawnedProcess(name=name, popen=popen, log_path=log_path, _log_fh=log_fh)


@dataclass
class FetcherPipelineHarness:
    """Drives the end-to-end scheduled fetcher pipeline against real
    worker/Beat subprocesses and real PostgreSQL/Redis test
    infrastructure. See `test_fetcher_pipeline.py` for the test that
    consumes this harness's methods in sequence.
    """

    env: dict[str, str]
    run_dir: Path
    celery_app: Celery
    session_factory: async_sessionmaker[AsyncSession]
    worker_hostname: str
    worker_process: _SpawnedProcess | None = None
    beat_process: _SpawnedProcess | None = None
    #: ids of `FetcherRun` rows for the test fetcher that already
    #: existed BEFORE this invocation's preflight purge — captured from
    #: a prior invocation of this suite that was interrupted before its
    #: own teardown could run (relevant when `TEST_DATABASE_URL` points
    #: at a persistent local database — see testing-strategy.md,
    #: Execution). `wait_finalized_run` and `list_runs` both exclude
    #: these ids, so a leftover terminal run can never be mistaken for
    #: evidence of this invocation's own dispatch, independent of
    #: whether the preflight purge itself succeeded.
    preexisting_run_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    # -- Process lifecycle ---------------------------------------------

    def start_worker(self) -> None:
        self.worker_process = _spawn_celery_process(
            "worker",
            [
                "worker",
                "--pool=prefork",
                "--concurrency=1",
                f"--hostname={self.worker_hostname}",
                "--loglevel=info",
            ],
            self.env,
            self.run_dir,
        )

    def start_beat(self) -> None:
        self.beat_process = _spawn_celery_process(
            "beat",
            ["beat", "--max-interval=1", "--loglevel=info"],
            self.env,
            self.run_dir,
        )

    def stop_beat(self, timeout: float = _PROCESS_TERM_TIMEOUT) -> None:
        """Stop Beat now, before it can fire a second scheduled dispatch.

        Safe to call again from fixture teardown — `_SpawnedProcess.terminate`
        is a no-op once the process has already exited.
        """
        if self.beat_process is not None:
            self.beat_process.terminate(timeout)

    def _inspect_worker(self, method: str) -> dict[str, Any] | None:
        """Call `celery_app.control.inspect().<method>()`, scoped to this
        harness's worker hostname, and return its reply — or `None` on
        any failure (broker unreachable, no reply within the timeout) —
        the caller's polling loop treats `None` as "not ready yet".

        Uses the pytest-host `celery_app` (`celery_test_app`, pointed at
        the same test broker as the spawned worker — see
        `system_process_env`) rather than spawning a `celery inspect`
        subprocess: the control command still round-trips through the
        real broker to the real spawned worker process, without paying
        a fresh Python interpreter start on every poll attempt. This is
        a blocking call (kombu's control API is synchronous) — callers
        run it via `asyncio.to_thread()`.
        """
        try:
            inspector = self.celery_app.control.inspect(
                destination=[self.worker_hostname], timeout=_INSPECT_TIMEOUT
            )
            reply: dict[str, Any] | None = getattr(inspector, method)()
        except Exception:
            return None
        return reply

    async def _timeout_diagnostics(self) -> str:
        """Best-effort diagnostic snapshot attached to every bounded-wait
        timeout failure: captured process output, return codes, current
        `FetcherConfig`/`FetcherRun` state, and RedBeat entry state (when
        readable) — see testing-strategy.md, Bounded Waiting and
        Diagnostics. Every section degrades independently to an
        explanatory placeholder on its own failure, so a
        diagnostics-gathering error never masks the real timeout being
        reported.
        """
        sections: list[str] = []
        for proc in (self.worker_process, self.beat_process):
            if proc is None:
                continue
            sections.append(
                f"--- {proc.name} process (return code: "
                f"{proc.popen.poll()!r}) log (tail) ---\n{proc.tail_log()}"
            )
        try:
            async with self.session_factory() as session:
                config_result = await session.execute(
                    select(FetcherConfig).where(
                        FetcherConfig.fetcher_name == SYSTEM_FETCHER_NAME
                    )
                )
                config = config_result.scalar_one_or_none()
                run_result = await session.execute(
                    select(FetcherRun)
                    .where(FetcherRun.fetcher_name == SYSTEM_FETCHER_NAME)
                    .order_by(FetcherRun.created_at.desc())
                )
                runs = list(run_result.scalars().all())
        except Exception as exc:
            sections.append(
                f"--- FetcherConfig/FetcherRun state: unavailable ({exc!r}) ---"
            )
        else:
            config_repr = (
                f"fetcher_name={config.fetcher_name!r} enabled={config.enabled!r} "
                f"schedule_override={config.schedule_override!r}"
                if config is not None
                else "no row"
            )
            sections.append(f"--- FetcherConfig state: {config_repr} ---")
            runs_repr = [
                f"(id={r.id}, status={r.status!r}, started_at={r.started_at!r}, "
                f"finished_at={r.finished_at!r})"
                for r in runs
            ]
            sections.append(f"--- FetcherRun rows ({len(runs)}): {runs_repr} ---")
        try:
            key = RedBeatSchedulerEntry.generate_key(
                self.celery_app, SYSTEM_FETCHER_NAME
            )
            entry = RedBeatSchedulerEntry.from_key(key, app=self.celery_app)
        except KeyError:
            sections.append("--- RedBeat entry state: not present ---")
        except Exception as exc:
            sections.append(f"--- RedBeat entry state: unreadable ({exc!r}) ---")
        else:
            sections.append(
                f"--- RedBeat entry state: task={entry.task!r} "
                f"enabled={entry.enabled!r} last_run_at={entry.last_run_at!r} "
                f"total_run_count={entry.total_run_count!r} ---"
            )
        return "\n".join(sections)

    async def wait_worker_ready(
        self, timeout_seconds: float = _WORKER_READY_TIMEOUT
    ) -> None:
        """Poll until the worker replies to `inspect ping` under its own
        hostname AND has the generic `run_fetcher` task registered.
        """
        assert self.worker_process is not None
        deadline = time.monotonic() + timeout_seconds
        last_status = "no successful inspect reply yet"
        while time.monotonic() < deadline:
            self.worker_process.assert_alive()
            ping_reply = await asyncio.to_thread(self._inspect_worker, "ping")
            if ping_reply and self.worker_hostname in ping_reply:
                registered_reply = await asyncio.to_thread(
                    self._inspect_worker, "registered"
                )
                registered_tasks = (registered_reply or {}).get(
                    self.worker_hostname
                ) or []
                if "run_fetcher" in registered_tasks:
                    return
                last_status = (
                    f"worker replied to ping but run_fetcher not yet "
                    f"registered: {registered_reply!r}"
                )
            else:
                last_status = f"no ping reply yet: {ping_reply!r}"
            await asyncio.sleep(_POLL_INTERVAL)
        self.worker_process.assert_alive()
        diagnostics = await self._timeout_diagnostics()
        pytest.fail(
            f"worker did not become ready within {timeout_seconds}s: "
            f"{last_status}\n{diagnostics}"
        )

    # -- RedBeat ---------------------------------------------------------

    async def wait_redbeat_entry(
        self, timeout_seconds: float = _REDBEAT_ENTRY_TIMEOUT
    ) -> RedBeatSchedulerEntry:
        """Poll until Beat's startup reconciliation has written the
        canonical redbeat entry for the test fetcher."""
        assert self.beat_process is not None
        key = RedBeatSchedulerEntry.generate_key(self.celery_app, SYSTEM_FETCHER_NAME)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            self.beat_process.assert_alive()
            try:
                return RedBeatSchedulerEntry.from_key(key, app=self.celery_app)
            except KeyError:
                await asyncio.sleep(_POLL_INTERVAL)
        self.beat_process.assert_alive()
        diagnostics = await self._timeout_diagnostics()
        pytest.fail(
            f"RedBeat entry for '{SYSTEM_FETCHER_NAME}' did not appear "
            f"within {timeout_seconds}s\n{diagnostics}"
        )

    def make_due(self, *, days_ago: int = 400) -> None:
        """Force the existing redbeat entry to be immediately overdue,
        via RedBeat's own public `reschedule()` API — Beat still performs
        the actual dispatch through the broker on its next tick (bounded
        by `--max-interval=1`); this only removes the wait for a real
        cron boundary. See testing-strategy.md, Behavioral Requirements.

        The default fetcher (`EvaluateTestPipeline.default_schedule`) is
        an annual cron expression (`0 0 1 1 *`), so `last_run_at` is
        pushed back far enough (> 366 days) that at least one
        occurrence of the schedule has necessarily passed since —
        making the entry due without risking a second occurrence firing
        before the test tears down Beat (see `EvaluateTestPipeline` for
        the rationale of using a yearly, rather than a per-minute,
        schedule here).
        """
        key = RedBeatSchedulerEntry.generate_key(self.celery_app, SYSTEM_FETCHER_NAME)
        entry = RedBeatSchedulerEntry.from_key(key, app=self.celery_app)
        entry.reschedule(last_run_at=datetime.now(UTC) - timedelta(days=days_ago))

    # -- PostgreSQL (FetcherConfig / FetcherRun / FetcherAuditEvent) ----

    async def wait_config_row(
        self, timeout_seconds: float = _CONFIG_BOOTSTRAP_TIMEOUT
    ) -> FetcherConfig:
        """Poll until a `FetcherConfig` row exists for the test fetcher
        (created by either the worker's or Beat's startup bootstrap —
        both call the same idempotent `bootstrap_fetcher_configs()`)."""
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.worker_process is not None:
                self.worker_process.assert_alive()
            if self.beat_process is not None:
                self.beat_process.assert_alive()
            async with self.session_factory() as session:
                result = await session.execute(
                    select(FetcherConfig).where(
                        FetcherConfig.fetcher_name == SYSTEM_FETCHER_NAME
                    )
                )
                config = result.scalar_one_or_none()
            if config is not None:
                return config
            await asyncio.sleep(_POLL_INTERVAL)
        diagnostics = await self._timeout_diagnostics()
        pytest.fail(
            f"FetcherConfig row for '{SYSTEM_FETCHER_NAME}' did not appear "
            f"within {timeout_seconds}s\n{diagnostics}"
        )

    async def wait_finalized_run(
        self, timeout_seconds: float = _RUN_FINALIZED_TIMEOUT
    ) -> FetcherRun:
        """Poll until a terminal (`success` or `failure`) `FetcherRun`
        row exists for the test fetcher, excluding any row already
        present before this invocation's preflight purge
        (`preexisting_run_ids`) — see the field's docstring. This
        guarantees the returned run is evidence of this invocation's
        own worker/Beat/broker path, independent of whether the
        preflight purge itself succeeded.
        """
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.worker_process is not None:
                self.worker_process.assert_alive()
            if self.beat_process is not None:
                self.beat_process.assert_alive()
            async with self.session_factory() as session:
                query = (
                    select(FetcherRun)
                    .where(FetcherRun.fetcher_name == SYSTEM_FETCHER_NAME)
                    .where(FetcherRun.status.in_(["success", "failure"]))
                    .order_by(FetcherRun.created_at.desc())
                )
                if self.preexisting_run_ids:
                    query = query.where(FetcherRun.id.notin_(self.preexisting_run_ids))
                result = await session.execute(query)
                run = result.scalars().first()
            if run is not None:
                return run
            await asyncio.sleep(_POLL_INTERVAL)
        diagnostics = await self._timeout_diagnostics()
        pytest.fail(
            f"No finalized FetcherRun for '{SYSTEM_FETCHER_NAME}' within "
            f"{timeout_seconds}s\n{diagnostics}"
        )

    async def list_runs(self) -> list[FetcherRun]:
        """Return every `FetcherRun` row for the test fetcher created
        during this invocation — excludes `preexisting_run_ids` (see
        `wait_finalized_run`).
        """
        async with self.session_factory() as session:
            query = select(FetcherRun).where(
                FetcherRun.fetcher_name == SYSTEM_FETCHER_NAME
            )
            if self.preexisting_run_ids:
                query = query.where(FetcherRun.id.notin_(self.preexisting_run_ids))
            result = await session.execute(query)
            return list(result.scalars().all())

    async def list_audit_events(self) -> list[FetcherAuditEvent]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(FetcherAuditEvent).where(
                    FetcherAuditEvent.fetcher_name == SYSTEM_FETCHER_NAME
                )
            )
            return list(result.scalars().all())

    # -- Domain mutation proof -------------------------------------------

    async def snapshot_domain_tables(self) -> dict[str, list[str]]:
        """A comparable snapshot of every table's rows EXCEPT the three
        fetcher-infrastructure tables — see testing-strategy.md,
        Behavioral Requirements: "No domain tables are mutated." Row
        tuples are rendered via `repr()` (not hashed directly) so JSONB
        columns, which are unhashable dicts, do not break comparison.
        """
        async with self.session_factory() as session:
            snapshot: dict[str, list[str]] = {}
            for table in Base.metadata.sorted_tables:
                if table.name in _FETCHER_TABLE_NAMES:
                    continue
                result = await session.execute(select(table))
                snapshot[table.name] = sorted(repr(tuple(row)) for row in result.all())
            return snapshot


async def _delete_fetcher_artifacts(
    session_factory: async_sessionmaker[AsyncSession], names: set[str]
) -> None:
    """Delete all `FetcherRun`/`FetcherAuditEvent`/`FetcherConfig` rows
    for `names`, in FK-safe order, and commit. No-op if `names` is
    empty.

    Shared by two callers: the fixture's preflight purge (removes
    residue from a prior invocation that was interrupted before its own
    teardown could run — e.g. SIGKILL, OOM, host crash — so a leftover
    terminal `FetcherRun` can never satisfy this invocation's own
    `wait_finalized_run()` poll) and its final teardown (removes rows
    created during this invocation). See testing-strategy.md,
    Deterministic Cleanup, step 6.
    """
    if not names:
        return
    async with session_factory() as session:
        await session.execute(
            delete(FetcherRun).where(FetcherRun.fetcher_name.in_(names))
        )
        await session.execute(
            delete(FetcherAuditEvent).where(FetcherAuditEvent.fetcher_name.in_(names))
        )
        await session.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(names))
        )
        await session.commit()


async def _residual_fetcher_artifacts(
    session_factory: async_sessionmaker[AsyncSession], names: set[str]
) -> list[str]:
    """Read-only check: describe every `FetcherConfig`/`FetcherRun`/
    `FetcherAuditEvent` row still present for any name in `names`, or
    return an empty list if none remain.

    Used to verify that `_delete_fetcher_artifacts` actually removed
    what it claims to — see testing-strategy.md, Deterministic Cleanup,
    step 8: "Verify that processes are dead and test artifacts are
    absent." A silent regression in the delete filter or FK ordering
    would otherwise surface only later, as the *next* invocation's own
    preflight purge quietly absorbing residue this invocation's cleanup
    was supposed to have removed.
    """
    if not names:
        return []
    residues: list[str] = []
    async with session_factory() as session:
        config_result = await session.execute(
            select(FetcherConfig.fetcher_name).where(
                FetcherConfig.fetcher_name.in_(names)
            )
        )
        residues.extend(
            f"FetcherConfig(fetcher_name={name!r})"
            for name in config_result.scalars().all()
        )
        run_result = await session.execute(
            select(FetcherRun.id, FetcherRun.fetcher_name).where(
                FetcherRun.fetcher_name.in_(names)
            )
        )
        residues.extend(
            f"FetcherRun(id={run_id}, fetcher_name={name!r})"
            for run_id, name in run_result.all()
        )
        event_result = await session.execute(
            select(FetcherAuditEvent.id, FetcherAuditEvent.fetcher_name).where(
                FetcherAuditEvent.fetcher_name.in_(names)
            )
        )
        residues.extend(
            f"FetcherAuditEvent(id={event_id}, fetcher_name={name!r})"
            for event_id, name in event_result.all()
        )
    return residues


@pytest_asyncio.fixture
async def fetcher_pipeline_harness(
    tmp_path: Path,
    celery_test_app: Celery,
    redis_client: redis_asyncio.Redis,
    real_session_factory: async_sessionmaker[AsyncSession],
    system_process_env: dict[str, str],
) -> AsyncIterator[FetcherPipelineHarness]:
    """Registers the test-only fetcher, yields a `FetcherPipelineHarness`,
    then performs deterministic cleanup — in the exact order mandated by
    testing-strategy.md (Deterministic Cleanup) — regardless of whether
    the test succeeded or failed. A cleanup failure fails the test even
    when the primary assertion already passed.

    Depends on `redis_client` (rather than opening a separate Redis
    connection) to reuse its existing FLUSHDB-before/after isolation
    guarantee and connection lifecycle management — this fixture's own
    teardown still performs the mandated `FLUSHDB` at the documented
    step (4), `redis_client`'s own teardown is an additional safety net,
    not a substitute.
    """
    # Snapshot the registry BEFORE the lazy import below: the first
    # import of `tests.support.system_fetcher` already registers
    # `EvaluateTestPipeline` through `BaseFetcher.__init_subclass__`, so
    # a snapshot taken afterwards would treat the test fetcher as prior
    # state and teardown would leave it registered in this process —
    # leaking into every later test that runs in the same pytest worker
    # (testing-strategy.md, Registration Boundary).
    registry_before = dict(FETCHER_REGISTRY)

    # Registration boundary: import only now — never at collection time
    # — so a `pytest -m 'not system'` run of the wider suite never
    # registers this class (see testing-strategy.md, Registration
    # Boundary).
    import tests.support.system_fetcher as system_fetcher_module

    fetcher_cls = system_fetcher_module.EvaluateTestPipeline
    assert fetcher_cls.name == SYSTEM_FETCHER_NAME, (
        f"tests/system/conftest.py's duplicated SYSTEM_FETCHER_NAME "
        f"constant ({SYSTEM_FETCHER_NAME!r}) has drifted from "
        f"EvaluateTestPipeline.name ({fetcher_cls.name!r})"
    )
    FETCHER_REGISTRY[SYSTEM_FETCHER_NAME] = fetcher_cls

    # Baseline: capture any `FetcherRun` ids that already exist for the
    # test fetcher BEFORE the preflight purge below — residue left by a
    # prior invocation of this suite that was interrupted before its
    # own teardown could run (e.g. SIGKILL, OOM, host crash; relevant
    # when `TEST_DATABASE_URL` points at a persistent local database
    # rather than an ephemeral per-run container). `wait_finalized_run`
    # and `list_runs` exclude these ids, so a leftover terminal run can
    # never be mistaken for evidence of this invocation's own dispatch
    # — independent of whether the purge below itself succeeds. See
    # testing-strategy.md, Execution.
    async with real_session_factory() as baseline_run_session:
        baseline_run_result = await baseline_run_session.execute(
            select(FetcherRun.id).where(FetcherRun.fetcher_name == SYSTEM_FETCHER_NAME)
        )
        preexisting_run_ids = frozenset(baseline_run_result.scalars().all())

    # Preflight: purge any genuine residue from that same scenario. This
    # also removes a leftover `FetcherConfig` row that could otherwise
    # be disabled or hold a stale `schedule_override` from a prior
    # invocation.
    await _delete_fetcher_artifacts(real_session_factory, {SYSTEM_FETCHER_NAME})

    async with real_session_factory() as baseline_session:
        baseline_result = await baseline_session.execute(
            select(FetcherConfig.fetcher_name)
        )
        baseline_names = set(baseline_result.scalars().all())

    worker_hostname = f"systemtest-{uuid.uuid4().hex[:10]}@{socket.gethostname()}"
    harness = FetcherPipelineHarness(
        env=system_process_env,
        run_dir=tmp_path,
        celery_app=celery_test_app,
        session_factory=real_session_factory,
        worker_hostname=worker_hostname,
        preexisting_run_ids=preexisting_run_ids,
    )

    cleanup_errors: list[str] = []
    try:
        yield harness
    finally:
        # 1. Stop Beat first (prevents new task enqueues). No-op if the
        # test already called stop_beat() itself.
        try:
            harness.stop_beat(_PROCESS_TERM_TIMEOUT)
        except Exception as exc:
            cleanup_errors.append(f"beat termination failed: {exc!r}")

        # 2-3. Worker: bounded grace period, then escalate to SIGKILL —
        # both handled internally by `_SpawnedProcess.terminate`.
        if harness.worker_process is not None:
            try:
                harness.worker_process.terminate(_PROCESS_TERM_TIMEOUT)
            except Exception as exc:
                cleanup_errors.append(f"worker termination failed: {exc!r}")

        # 4. Delete the test redbeat entry through the library's public API.
        try:
            delete_fetcher_entry(celery_test_app, SYSTEM_FETCHER_NAME)
        except Exception as exc:
            cleanup_errors.append(f"redbeat entry deletion failed: {exc!r}")

        # 5. Clear only the designated Redis logical database.
        try:
            await redis_client.flushdb()
        except Exception as exc:
            cleanup_errors.append(f"redis flushdb failed: {exc!r}")

        # 6. Delete committed test rows from PostgreSQL, FK-safe order,
        # restricted to fetcher names absent from the pre-spawn baseline
        # — never a table-wide delete (testing-strategy.md, Parallel
        # Safety). Computed by diffing against the baseline (rather than
        # hardcoding SYSTEM_FETCHER_NAME) as defense-in-depth: the
        # spawned processes' registry is pruned to exactly the test
        # fetcher (see `tests/support/system_fetcher_app.py`), so this
        # is expected to equal exactly {SYSTEM_FETCHER_NAME} in
        # practice — a diff-based delete still catches any subprocess
        # bootstrap regression without silently leaving orphaned rows.
        created_names: set[str] = set()
        try:
            async with real_session_factory() as cleanup_session:
                current_result = await cleanup_session.execute(
                    select(FetcherConfig.fetcher_name)
                )
                created_names = set(current_result.scalars().all()) - baseline_names
            await _delete_fetcher_artifacts(real_session_factory, created_names)
        except Exception as exc:
            cleanup_errors.append(f"postgres row cleanup failed: {exc!r}")

        # 7. Remove the test registry entry from the pytest process —
        # without clearing the global registry. The test-only fetcher is
        # never registered in the pytest host outside this fixture, so
        # removal (not restoration of a prior entry) is the correct
        # pre-fixture state.
        FETCHER_REGISTRY.pop(SYSTEM_FETCHER_NAME, None)

        # 8. Verify processes are dead and test artifacts are absent —
        # reads back exactly what steps 4-7 claim to have removed, so a
        # silent regression in any of them (wrong filter, FK-order bug,
        # a swallowed exception, a leaked registry entry) fails THIS
        # invocation instead of surfacing later as the next invocation's
        # preflight purge quietly absorbing the leftover residue, or as
        # a later test in the same pytest worker observing the test
        # fetcher.
        for proc in (harness.worker_process, harness.beat_process):
            if proc is not None and proc.is_alive():
                cleanup_errors.append(f"{proc.name} process still alive after cleanup")

        # Two independent registry checks: absence of the test fetcher
        # holds even if the snapshot itself were taken too late (after
        # the import already registered the class), and equality with the
        # snapshot catches any other entry this fixture added or dropped.
        if SYSTEM_FETCHER_NAME in FETCHER_REGISTRY:
            cleanup_errors.append(
                f"test-only fetcher '{SYSTEM_FETCHER_NAME}' still registered in "
                "the pytest process after cleanup"
            )
        if registry_before != FETCHER_REGISTRY:
            changed = sorted(
                name
                for name in FETCHER_REGISTRY.keys() & registry_before.keys()
                if FETCHER_REGISTRY[name] is not registry_before[name]
            )
            cleanup_errors.append(
                "FETCHER_REGISTRY differs from its pre-fixture state after "
                f"cleanup: added={sorted(FETCHER_REGISTRY.keys() - registry_before)} "
                f"removed={sorted(registry_before.keys() - FETCHER_REGISTRY)} "
                f"changed={changed}"
            )

        try:
            residues = await _residual_fetcher_artifacts(
                real_session_factory, created_names | {SYSTEM_FETCHER_NAME}
            )
            if residues:
                cleanup_errors.append(
                    f"PostgreSQL artifacts still present after cleanup: {residues}"
                )
        except Exception as exc:
            cleanup_errors.append(f"postgres residue verification failed: {exc!r}")

        try:
            key = RedBeatSchedulerEntry.generate_key(
                celery_test_app, SYSTEM_FETCHER_NAME
            )
            RedBeatSchedulerEntry.from_key(key, app=celery_test_app)
        except KeyError:
            pass
        except Exception as exc:
            cleanup_errors.append(f"redbeat residue verification failed: {exc!r}")
        else:
            cleanup_errors.append(
                f"RedBeat entry for '{SYSTEM_FETCHER_NAME}' still present after cleanup"
            )

        try:
            remaining_keys = await redis_client.dbsize()
            if remaining_keys != 0:
                cleanup_errors.append(
                    "Redis logical database not empty after FLUSHDB: "
                    f"{remaining_keys} key(s) remain"
                )
        except Exception as exc:
            cleanup_errors.append(f"redis residue verification failed: {exc!r}")

        if cleanup_errors:
            pytest.fail(
                "Local process system suite cleanup failed:\n"
                + "\n".join(cleanup_errors)
            )
