"""Test-only subprocess entry point for SIGINT/SIGTERM readiness tests.

Not part of the packaged CLI (`app.cli`) — invoked directly via
`subprocess.Popen([sys.executable, <this file>])` from
`test_main.py::test_signal_produces_documented_exit_code`.

Registers a hidden, test-only `_await-signal` command on the real root
group in this process only, then runs the real, unmodified
`app.cli.main()` entry point with that command. The command body prints
an unbuffered readiness marker and then blocks. Because `main()` installs
the `SIGINT`/`SIGTERM` handlers before it dispatches any command, the
marker proves that the production handlers are installed and that a
command is running — the deterministic readiness point required by
`docs/features/platform/testing-strategy.md` (CLI Commands) — without
depending on a database, a network service, or how fast a real command
completes. The bounded sleep only keeps an orphaned probe from lingering
if the parent test dies before signaling it.
"""

from __future__ import annotations

import sys
import time

from app.cli import cli, main

_ORPHAN_EXIT_CODE = 3


@cli.command("_await-signal", hidden=True)
def _await_signal() -> None:
    print("READY", flush=True)
    time.sleep(30)
    sys.exit(_ORPHAN_EXIT_CODE)


sys.argv = ["sentinel", "_await-signal"]
main()
