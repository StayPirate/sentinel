"""Local process system test: SIGTERM and SIGINT end the real IBS RabbitMQ
consumer process during its reconnect backoff with exit code 0.

See docs/features/platform/testing-strategy.md (Local Process System
Testing > IBS RabbitMQ Consumer Signal Handling) and
docs/features/integrations/ibs-rabbitmq-integration.md (Reconnection: a
signal interrupts the backoff wait immediately; Graceful Shutdown: exit
code 0).

The unmodified entry module (`python -m app.ibs_consumer`) runs with the
suite's explicit environment (`system_process_env`: the worker's test
database, no inherited shell or `.env` configuration), a JSON log format,
and `IBS_RABBITMQ_URL` pointing at a local port with no listener, so every
connection attempt is refused at once. The 300-second backoff starts after
the first refusal; the signal arrives during it and the process must exit
0 within a fraction of that wait. Waits are bounded by monotonic deadlines
and a process that outlives its deadline is killed.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

import pytest

pytestmark = pytest.mark.system

_READY_TIMEOUT: Final = 30.0
_EXIT_TIMEOUT: Final = 20.0
_BACKOFF_SECONDS: Final = 300


def _refused_port() -> int:
    """A loopback port with no listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


def _events(log_path: Path) -> list[str]:
    events = []
    for line in log_path.read_text("utf-8", errors="replace").splitlines():
        with contextlib.suppress(ValueError):
            record = json.loads(line)
            if isinstance(record, dict) and str(record.get("event", "")).startswith(
                "ibs_consumer_"
            ):
                events.append(str(record["event"]))
    return events


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT], ids=str)
async def test_signal_during_backoff_exits_zero_promptly(
    signum: signal.Signals,
    system_process_env: dict[str, str],
    tmp_path: Path,
) -> None:
    env = {
        **system_process_env,
        "LOG_FORMAT": "json",
        "IBS_RABBITMQ_URL": f"amqps://example:example@127.0.0.1:{_refused_port()}",
        "IBS_RABBITMQ_RECONNECT_INITIAL": str(_BACKOFF_SECONDS),
        "IBS_RABBITMQ_RECONNECT_MAX": str(_BACKOFF_SECONDS),
    }
    log_path = tmp_path / "ibs-consumer.log"
    with log_path.open("wb") as log:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "app.ibs_consumer",
            cwd=tmp_path,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    try:
        deadline = time.monotonic() + _READY_TIMEOUT
        while "ibs_consumer_reconnect_scheduled" not in _events(log_path):
            code = process.returncode
            assert code is None, f"exited early ({code}):\n{log_path.read_text()}"
            assert time.monotonic() < deadline, log_path.read_text()
            await asyncio.sleep(0.1)

        signalled_at = time.monotonic()
        process.send_signal(signum)
        code = await asyncio.wait_for(process.wait(), _EXIT_TIMEOUT)

        assert code == 0, log_path.read_text()
        assert time.monotonic() - signalled_at < _EXIT_TIMEOUT
        events = _events(log_path)
        assert events[: events.index("ibs_consumer_connection_failed") + 1] == [
            "ibs_consumer_started",
            "ibs_consumer_connection_failed",
        ]
        assert events[-2:] == ["ibs_consumer_shutdown_started", "ibs_consumer_stopped"]
        assert "example:example" not in log_path.read_text()
    finally:
        if process.returncode is None:
            process.kill()
            await asyncio.wait_for(process.wait(), _EXIT_TIMEOUT)
