"""Behavioral tests for the portable command timeout supervisor."""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_PATH = REPO_ROOT / "scripts" / "run-with-timeout.py"

# Supervisor timeout for cases that expect it to expire. Before it does, a
# Python parent and a Python child must start and install their SIGTERM
# handlers; the bound leaves room for interpreter start-up under the CPU
# contention of parallel test workers.
EXPIRING_TIMEOUT = 3


def _run_supervisor(
    command: list[str], *, timeout: float = 2.0, grace_period: float = 0.5
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--label",
            "unit-test-stage",
            "--timeout",
            str(timeout),
            "--grace-period",
            str(grace_period),
            "--",
            *command,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=8,
    )


def _run_supervisor_arguments(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )


def _process_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for_process_exit(process_id: int) -> bool:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _process_exists(process_id):
            return True
        time.sleep(0.02)
    return not _process_exists(process_id)


def _kill_process_group_from_file(process_id_path: Path) -> None:
    if not process_id_path.exists():
        return
    process_id = int(process_id_path.read_text(encoding="utf-8"))
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process_id, signal.SIGKILL)


@pytest.mark.unit
@pytest.mark.parametrize("exit_code", [0, 37])
def test_supervisor_command_exits_propagates_status(exit_code: int) -> None:
    result = _run_supervisor([sys.executable, "-c", f"raise SystemExit({exit_code})"])

    assert result.returncode == exit_code
    assert result.stderr == ""


@pytest.mark.unit
def test_supervisor_signal_exit_returns_conventional_status() -> None:
    result = _run_supervisor(
        [
            sys.executable,
            "-c",
            "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
        ]
    )

    assert result.returncode == 128 + signal.SIGTERM
    assert result.stderr == ""


@pytest.mark.unit
def test_supervisor_missing_executable_returns_127() -> None:
    result = _run_supervisor(["sentinel-command-that-does-not-exist"])

    assert result.returncode == 127
    assert "Cannot start 'unit-test-stage'" in result.stderr
    assert "sentinel-command-that-does-not-exist" in result.stderr


@pytest.mark.unit
def test_supervisor_rejects_missing_command() -> None:
    result = _run_supervisor_arguments(["--label", "unit-test-stage", "--timeout", "1"])

    assert result.returncode == 2
    assert "a command is required after the options" in result.stderr


@pytest.mark.unit
def test_supervisor_non_executable_command_returns_126(tmp_path: Path) -> None:
    command = tmp_path / "non-executable"
    command.write_text("not executable", encoding="utf-8")

    result = _run_supervisor([str(command)])

    assert result.returncode == 126
    assert "Cannot start 'unit-test-stage'" in result.stderr
    assert str(command) in result.stderr


@pytest.mark.unit
@pytest.mark.parametrize(
    ("option", "value"),
    [
        pytest.param("--timeout", "0", id="zero-timeout"),
        pytest.param("--timeout", "nan", id="nan-timeout"),
        pytest.param("--timeout", "inf", id="infinite-timeout"),
        pytest.param("--grace-period", "-1", id="negative-grace"),
        pytest.param("--grace-period", "nan", id="nan-grace"),
        pytest.param("--grace-period", "inf", id="infinite-grace"),
    ],
)
def test_supervisor_nonfinite_or_out_of_range_bound_rejected(
    option: str, value: str
) -> None:
    result = _run_supervisor_arguments(
        [
            "--label",
            "unit-test-stage",
            "--timeout",
            "1",
            "--grace-period",
            "1",
            option,
            value,
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )

    assert result.returncode == 2
    assert "finite" in result.stderr


@pytest.mark.unit
def test_supervisor_timeout_sends_term_to_group_and_returns_124(
    tmp_path: Path,
) -> None:
    parent_pid_path = tmp_path / "parent.pid"
    child_pid_path = tmp_path / "child.pid"
    parent_term_marker = tmp_path / "parent-term"
    child_term_marker = tmp_path / "child-term"
    child_ready_marker = tmp_path / "child-ready"
    descendant_code = "\n".join(
        [
            "import signal",
            "import sys",
            "import time",
            "from pathlib import Path",
            "term_marker = Path(sys.argv[1])",
            "ready_marker = Path(sys.argv[2])",
            "def handle_term(signum, frame):",
            '    term_marker.write_text("TERM", encoding="utf-8")',
            "    raise SystemExit(0)",
            "signal.signal(signal.SIGTERM, handle_term)",
            'ready_marker.write_text("ready", encoding="utf-8")',
            "time.sleep(30)",
        ]
    )
    parent_code = "\n".join(
        [
            "import os",
            "import signal",
            "import subprocess",
            "import sys",
            "import time",
            "from pathlib import Path",
            "parent_pid_path, child_pid_path = map(Path, sys.argv[1:3])",
            "parent_term_marker = Path(sys.argv[3])",
            "def handle_term(signum, frame):",
            '    parent_term_marker.write_text("TERM", encoding="utf-8")',
            "    raise SystemExit(0)",
            "signal.signal(signal.SIGTERM, handle_term)",
            'parent_pid_path.write_text(str(os.getpid()), encoding="utf-8")',
            "child = subprocess.Popen([sys.executable, '-c', sys.argv[4],",
            "                          *sys.argv[5:]])",
            'child_pid_path.write_text(str(child.pid), encoding="utf-8")',
            "time.sleep(30)",
        ]
    )

    try:
        result = _run_supervisor(
            [
                sys.executable,
                "-c",
                parent_code,
                str(parent_pid_path),
                str(child_pid_path),
                str(parent_term_marker),
                descendant_code,
                str(child_term_marker),
                str(child_ready_marker),
            ],
            timeout=EXPIRING_TIMEOUT,
        )
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        assert child_ready_marker.read_text(encoding="utf-8") == "ready"
        assert result.returncode == 124
        assert parent_term_marker.read_text(encoding="utf-8") == "TERM"
        assert child_term_marker.read_text(encoding="utf-8") == "TERM"
        assert "label='unit-test-stage'" in result.stderr
        assert f"timeout={EXPIRING_TIMEOUT}s" in result.stderr
        assert sys.executable in result.stderr
        assert "Timeout escalation" not in result.stderr
        assert _wait_for_process_exit(child_pid)
    finally:
        _kill_process_group_from_file(parent_pid_path)


@pytest.mark.unit
@pytest.mark.parametrize("interrupt_signal", [signal.SIGINT, signal.SIGTERM])
def test_supervisor_interrupted_terminates_group_without_leaked_child(
    tmp_path: Path, interrupt_signal: signal.Signals
) -> None:
    group_pid_path = tmp_path / "group.pid"
    child_pid_path = tmp_path / "child.pid"
    ready_marker = tmp_path / "ready"
    command_code = "\n".join(
        [
            "import os",
            "import subprocess",
            "import sys",
            "import time",
            "from pathlib import Path",
            'Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")',
            "child = subprocess.Popen([",
            "    sys.executable, '-c', 'import time; time.sleep(30)'",
            "])",
            'Path(sys.argv[2]).write_text(str(child.pid), encoding="utf-8")',
            'Path(sys.argv[3]).write_text("ready", encoding="utf-8")',
            "time.sleep(30)",
        ]
    )
    supervisor = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--label",
            "interrupted-stage",
            "--timeout",
            "30",
            "--grace-period",
            "0.5",
            "--",
            sys.executable,
            "-c",
            command_code,
            str(group_pid_path),
            str(child_pid_path),
            str(ready_marker),
        ],
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 10
        while not ready_marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready_marker.read_text(encoding="utf-8") == "ready"

        supervisor.send_signal(interrupt_signal)
        _, stderr = supervisor.communicate(timeout=5)
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        assert supervisor.returncode == 128 + interrupt_signal
        assert "Interrupted: label='interrupted-stage'" in stderr
        assert f"signal={interrupt_signal}" in stderr
        assert _wait_for_process_exit(child_pid)
    finally:
        with contextlib.suppress(ProcessLookupError):
            supervisor.kill()
        _kill_process_group_from_file(group_pid_path)


@pytest.mark.unit
def test_supervisor_term_resistant_group_escalates_kill_without_leaked_child(
    tmp_path: Path,
) -> None:
    parent_pid_path = tmp_path / "parent.pid"
    child_pid_path = tmp_path / "child.pid"
    child_ready_marker = tmp_path / "child-ready"
    parent_code = "\n".join(
        [
            "import os",
            "import signal",
            "import subprocess",
            "import sys",
            "import time",
            "from pathlib import Path",
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)",
            'Path(sys.argv[1]).write_text(str(os.getpid()), encoding="utf-8")',
            "child = subprocess.Popen([",
            "    sys.executable,",
            '    "-c",',
            '    "import signal, sys, time; from pathlib import Path; "',
            '    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "',
            "    \"Path(sys.argv[1]).write_text('ready', encoding='utf-8'); \"",
            '    "time.sleep(30)",',
            "    sys.argv[3],",
            "])",
            'Path(sys.argv[2]).write_text(str(child.pid), encoding="utf-8")',
            "time.sleep(30)",
        ]
    )

    try:
        result = _run_supervisor(
            [
                sys.executable,
                "-c",
                parent_code,
                str(parent_pid_path),
                str(child_pid_path),
                str(child_ready_marker),
            ],
            timeout=EXPIRING_TIMEOUT,
            grace_period=0.2,
        )
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))

        assert child_ready_marker.read_text(encoding="utf-8") == "ready"
        assert result.returncode == 124
        assert "Timeout escalation" in result.stderr
        assert "grace_period=0.2s" in result.stderr
        assert _wait_for_process_exit(child_pid)
    finally:
        _kill_process_group_from_file(parent_pid_path)
