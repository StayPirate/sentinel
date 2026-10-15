"""Tests for the IBS RabbitMQ consumer entry module (backend/app/ibs_consumer.py).

Owning specification: docs/features/integrations/ibs-rabbitmq-integration.md
(Runtime Independence: `python -m app.ibs_consumer`, one `asyncio.run()`;
Startup steps 1-2: logging is configured before the enabled check, and a
disabled consumer logs one INFO event through the structured pipeline and
exits 0 without connecting anywhere).

The in-process tests replace `configure_logging` and `IBSEventConsumer`:
the enabled test proves the order of the steps, the disabled one that the
consumer is never constructed. The subprocess test runs the unmodified module
with every outbound connection refused, so the disabled event is observed on
the real structured pipeline, which proves that logging is configured before
the enabled check. The consumer lifecycle itself is covered by
`test_services/test_ibs_event_consumer.py`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import pytest
from structlog.testing import capture_logs

from app import ibs_consumer
from app.config import Settings
from app.config import settings as app_settings

pytestmark = pytest.mark.unit

_BACKEND_DIR: Final = Path(__file__).resolve().parents[1]
_INHERITED_OS_ENV_KEYS: Final = ("PATH", "LANG", "LC_ALL", "TZ")
# Fictional JWT secret — never a real credential (AGENTS.md Guardrail 23).
_JWT_SECRET_KEY: Final = "consumer-test-jwt-secret-key-not-for-production"

_DISABLED_PROBE: Final = """\
import runpy
import socket


def _refuse(*args, **kwargs):
    raise AssertionError("a disabled consumer opened a connection")


socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
socket.create_connection = _refuse
runpy.run_module("app.ibs_consumer", run_name="__main__")
"""


@dataclass(eq=False)
class _Recorder:
    calls: list[str] = field(default_factory=list)


@pytest.fixture
def entry(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(
        ibs_consumer, "configure_logging", lambda _s: recorder.calls.append("logging")
    )

    class _Consumer:
        def __init__(self, settings: Settings) -> None:
            recorder.calls.append("consumer")

        async def run(self) -> int:
            recorder.calls.append("run")
            return 7

    monkeypatch.setattr(ibs_consumer, "IBSEventConsumer", _Consumer)
    return recorder


class TestMain:
    def test_disabled_logs_one_event_and_exits_zero_without_a_consumer(
        self, entry: _Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(app_settings, "ibs_rabbitmq_enabled", False)

        with capture_logs() as logs:
            code = ibs_consumer.main()

        assert code == 0
        assert entry.calls == ["logging"]
        assert logs == [{"event": "ibs_consumer_disabled", "log_level": "info"}]

    def test_enabled_runs_the_consumer_in_one_event_loop(
        self, entry: _Recorder, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(app_settings, "ibs_rabbitmq_enabled", True)

        assert ibs_consumer.main() == 7
        assert entry.calls == ["logging", "consumer", "run"]


class TestDisabledProcess:
    def test_disabled_process_logs_one_structured_event_and_exits_zero(
        self, tmp_path: Path
    ) -> None:
        env = {
            key: os.environ[key] for key in _INHERITED_OS_ENV_KEYS if key in os.environ
        }
        env.update(
            HOME=str(tmp_path),
            PYTHONPATH=str(_BACKEND_DIR),
            JWT_SECRET_KEY=_JWT_SECRET_KEY,
            IBS_RABBITMQ_ENABLED="false",
            LOG_FORMAT="json",
        )

        result = subprocess.run(
            [sys.executable, "-c", _DISABLED_PROBE],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )

        assert result.returncode == 0, result.stderr
        records = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(records) == 1, result.stdout
        assert records[0]["event"] == "ibs_consumer_disabled"
        assert records[0]["level"] == "info"
        assert records[0]["logger"] == "app.ibs_consumer"
