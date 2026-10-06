"""Test-owned launcher for the hard-process-loss tests of the all-CVE CVSS
recalculation runner (`run_cvss_derived_state_recalculation()`,
backend/app/services/cvss_recalculation.py).

Consumer: `tests/test_services/test_cvss_recalculation_process_loss.py`.

Issue #836 decision U8: the SIGKILL test is a default-suite `integration`
test. This module is both sides of it:

- the parent side, `recalculation_process()`, spawns
  `python -m tests.support.cvss_recalculation_process` with
  `start_new_session=True`, an explicit environment that names only the
  worker test database and the worker Redis logical database
  (`build_process_env()`, the `tests/system/conftest.py` isolation rule),
  and a per-test working directory, so neither the developer's shell nor a
  `backend/.env` file is in scope. Combined stdout and stderr go to a log
  file, which carries the child's JSON structured events. Every exit path
  kills the process group with `os.killpg(..., SIGKILL)` and waits with a
  finite timeout;
- the child side, `main()`, configures logging from that environment,
  validates its inputs as the task wrapper does, binds `celery_task_id` as
  the `task_prerun` signal does (U7), replaces the broker call with a
  no-op, and runs the real workflow with exactly one `asyncio.run()` on
  the production `async_session_factory` (the owned connection path). In
  this process only, the runner's post-commit `drain_ticket_convergence()`
  is wrapped: after the real drain of the k-th unit (committed and
  closed), the wrapper writes a readiness marker and blocks at that unit
  boundary. There is no production hook.

The block is bounded only as an orphan guard, as in
`tests/test_cli/_signal_probe.py`: a child whose parent died before
killing it exits on its own, and its connection closure releases the fence.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import signal
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

_BACKEND_DIR = Path(__file__).resolve().parents[2]

_MODULE = "tests.support.cvss_recalculation_process"

# Minimal OS-level context the interpreter needs, never application
# configuration (the `tests/system/conftest.py` allowlist).
_INHERITED_OS_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TZ")

# Fictional JWT secret, required by `Settings` and never a real credential
# (AGENTS.md, language and PII stop; the system-suite precedent).
_PROCESS_TEST_JWT_SECRET_KEY = "process-test-jwt-secret-key-not-for-production-32"

_ORPHAN_GUARD_SECONDS = 120.0
"""How long a paused child waits for its parent's SIGKILL before exiting
on its own."""

ORPHAN_EXIT_CODE = 3
"""Exit code of a paused child that was never killed."""

RAN_PAST_PAUSE_EXIT_CODE = 4
"""Exit code of a child whose workflow returned without reaching the
pause (fewer committed units than requested)."""

_READY_TIMEOUT = 30.0
_KILL_TIMEOUT = 10.0
_POLL_INTERVAL = 0.05


# ---------------------------------------------------------------------------
# Parent side
# ---------------------------------------------------------------------------


def build_process_env(
    *, database_url: str, redis_url: str, home_dir: Path
) -> dict[str, str]:
    """The child's complete environment: the OS allowlist plus explicit
    test values only, never `os.environ.copy()`. `REDIS_URL` and
    `CELERY_BROKER_URL` both name the worker Redis logical database; the
    child publishes nothing to the broker."""
    env = {key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ}
    env["HOME"] = str(home_dir)
    env["PYTHONPATH"] = str(_BACKEND_DIR)
    env["DATABASE_URL"] = database_url
    env["REDIS_URL"] = redis_url
    env["CELERY_BROKER_URL"] = redis_url
    env["JWT_SECRET_KEY"] = _PROCESS_TEST_JWT_SECRET_KEY
    env["LOG_FORMAT"] = "json"
    env["LOG_LEVEL"] = "INFO"
    return env


@dataclass
class RecalculationProcess:
    """One spawned child, its marker path, and its captured log."""

    popen: subprocess.Popen[bytes]
    log_path: Path
    marker_path: Path
    _log_fh: IO[bytes] = field(repr=False)

    @property
    def pid(self) -> int:
        return self.popen.pid

    def tail_log(self, max_bytes: int = 6000) -> str:
        try:
            data = self.log_path.read_bytes()
        except OSError:
            return "<log unavailable>"
        return data[-max_bytes:].decode("utf-8", errors="replace")

    def events(self) -> list[dict[str, Any]]:
        """Every JSON structured event the child wrote, in order."""
        events: list[dict[str, Any]] = []
        for line in self.log_path.read_text(errors="replace").splitlines():
            if not line.startswith("{"):
                continue
            with contextlib.suppress(ValueError):
                entry = json.loads(line)
                if isinstance(entry, dict):
                    events.append(entry)
        return events

    async def wait_paused(self) -> str:
        """Wait, with a monotonic deadline, for the readiness marker; fail
        early with the captured log when the child exits first. Returns
        the marker content."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _READY_TIMEOUT
        while not self.marker_path.exists():
            code = self.popen.poll()
            if code is not None:
                raise AssertionError(
                    f"the recalculation child exited with {code} before pausing\n"
                    f"--- child log (tail) ---\n{self.tail_log()}"
                )
            if loop.time() >= deadline:
                raise AssertionError(
                    f"the recalculation child did not pause within {_READY_TIMEOUT} s\n"
                    f"--- child log (tail) ---\n{self.tail_log()}"
                )
            await asyncio.sleep(_POLL_INTERVAL)
        return self.marker_path.read_text()

    def kill(self, *, timeout: float = _KILL_TIMEOUT) -> int:
        """SIGKILL the child's process group and return its exit code."""
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.popen.pid, signal.SIGKILL)
        return self.popen.wait(timeout=timeout)

    def close(self) -> None:
        """Kill the group when still alive, reap it, and close the log."""
        try:
            if self.popen.poll() is None:
                self.kill()
        finally:
            if not self._log_fh.closed:
                self._log_fh.close()


@contextlib.contextmanager
def recalculation_process(
    *,
    database_url: str,
    redis_url: str,
    task_id: str,
    target_version: str,
    pause_after: int,
    run_dir: Path,
) -> Iterator[RecalculationProcess]:
    """Spawn the child in its own session with `run_dir` as its working
    directory and `HOME`; always kill and reap its process group on exit."""
    log_path = run_dir / "cvss-recalculation-child.log"
    marker_path = run_dir / "cvss-recalculation-child.paused"
    log_fh = log_path.open("wb")
    try:
        popen = subprocess.Popen(
            [
                sys.executable,
                "-m",
                _MODULE,
                "--target-version",
                target_version,
                "--task-id",
                task_id,
                "--pause-after",
                str(pause_after),
                "--marker",
                str(marker_path),
            ],
            cwd=str(run_dir),
            env=build_process_env(
                database_url=database_url, redis_url=redis_url, home_dir=run_dir
            ),
            stdin=subprocess.DEVNULL,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except BaseException:
        log_fh.close()
        raise
    process = RecalculationProcess(
        popen=popen, log_path=log_path, marker_path=marker_path, _log_fh=log_fh
    )
    try:
        yield process
    finally:
        process.close()


# ---------------------------------------------------------------------------
# Child side
# ---------------------------------------------------------------------------


def _parse(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=_MODULE)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--pause-after", type=int, required=True)
    parser.add_argument("--marker", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> None:
    """Run the real workflow and pause after the k-th unit's drain."""
    args = _parse(argv)
    pause_after: int = args.pause_after
    marker: Path = args.marker
    if pause_after < 1:
        raise SystemExit("--pause-after must be at least 1")

    # The environment is explicit, so these imports read only test values.
    import structlog

    from app.config import settings
    from app.core.logging import configure_logging

    configure_logging(settings)

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.database import async_session_factory
    from app.services import cvss_recalculation, task_publication
    from app.services.ticket_convergence_publication import drain_ticket_convergence

    target = cvss_recalculation.validate_target_version(args.target_version)
    task_id = cvss_recalculation.validate_task_id(args.task_id, target_version=target)
    drained = 0

    async def _pausing_drain(session: AsyncSession) -> None:
        nonlocal drained
        await drain_ticket_convergence(session)
        drained += 1
        if drained < pause_after:
            return
        staged = marker.with_suffix(".staged")
        staged.write_text(f"PAUSED {drained}\n")
        os.replace(staged, marker)
        await asyncio.sleep(_ORPHAN_GUARD_SECONDS)
        sys.stdout.flush()
        os._exit(ORPHAN_EXIT_CODE)

    async def _no_publication(task_name: str, **options: Any) -> None:
        return None

    cvss_recalculation.drain_ticket_convergence = _pausing_drain  # type: ignore[attr-defined]
    task_publication.publish_task = _no_publication

    with structlog.contextvars.bound_contextvars(celery_task_id=task_id):
        asyncio.run(
            cvss_recalculation.run_cvss_derived_state_recalculation(
                target, task_id, async_session_factory
            )
        )
    sys.stdout.flush()
    os._exit(RAN_PAST_PAUSE_EXIT_CODE)


if __name__ == "__main__":
    main(sys.argv[1:])
