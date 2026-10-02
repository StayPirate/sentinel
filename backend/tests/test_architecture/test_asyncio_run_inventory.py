"""Structural test: `asyncio.run()` call sites in `backend/app/tasks/`
form an explicitly reviewed, classified inventory.

See `docs/conventions.md` (Cross-loop pooled connection lifecycle) and
`docs/features/platform/testing-strategy.md` (Structural Tests table,
row "`asyncio.run()` boundary inventory") for the rule this test
enforces.

This test does not forbid direct `asyncio.run()` calls — it forces
every call site under `app/tasks/` to be classified here with a
one-line rationale before it is trusted. A synchronous entry point
repeatedly invoked within the same long-lived Celery worker child (a
generic task wrapper such as `run_fetcher` or `cleanup_sessions`) MUST
dispose the shared pooled engine before its `asyncio.run()` loop
closes; a one-shot startup handler is exempt because the process either
never repeats the bridging pattern or exits entirely (`sys.exit(1)`) on
failure. Adding a new call site to `REVIEWED_INVENTORY` with its
classification is the required action when a new one appears — not a
workaround to silence this test.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_TASKS_DIR = Path(__file__).resolve().parents[2] / "app" / "tasks"

# Keyed by (relative file path under app/tasks/, enclosing function
# name). Each value is the reviewed rationale for why this call site's
# event-loop lifecycle is safe.
REVIEWED_INVENTORY: dict[tuple[str, str], str] = {
    ("fetchers.py", "_run_fetcher_sync"): (
        "Repeated per-invocation task wrapper (run_fetcher). Its async "
        "workflow (run_fetcher_async) awaits engine.dispose() in a "
        "finally block before returning control to asyncio.run() — see "
        "docs/conventions.md, Cross-loop pooled connection lifecycle. "
        "This is the single choke point for every fetcher's execute() "
        "and any fetch_single() it calls."
    ),
    ("fetchers.py", "_run_catch_up_sync"): (
        "Repeated per-invocation task wrapper (run_catch_up), including "
        "every Celery retry attempt. Its async workflow "
        "(run_catch_up_async) awaits engine.dispose() exactly once on "
        "every return and exception path before returning control to "
        "asyncio.run() — see docs/conventions.md, Cross-loop pooled "
        "connection lifecycle."
    ),
    ("session_cleanup.py", "_cleanup_sessions_sync"): (
        "Repeated per-invocation task wrapper (cleanup_sessions). Its "
        "async workflow (run_cleanup_sessions) awaits engine.dispose() "
        "in a finally block before returning control to asyncio.run() "
        "— see docs/conventions.md, Cross-loop pooled connection "
        "lifecycle."
    ),
    ("worker_startup.py", "_worker_startup_handler"): (
        "One-shot Celery worker parent-process startup handler. Its "
        "async workflow (worker_async_bootstrap) awaits "
        "engine.dispose() after a successful bootstrap commit so "
        "forked prefork children do not inherit live parent "
        "connections; on failure the process exits via sys.exit(1) "
        "before any task is consumed, so disposal is not required on "
        "that path."
    ),
    ("beat_startup.py", "_beat_startup_handler"): (
        "One-shot Celery Beat startup handler. Its async workflow "
        "(beat_async_bootstrap) bootstraps FetcherConfig, commits, "
        "reconciles the redbeat schedule, then awaits engine.dispose() "
        "before Beat's own synchronous (non-asyncio) tick loop begins; "
        "on failure (lock verification, bootstrap, commit, or "
        "reconciliation) the process exits via sys.exit(1) before "
        "ticking, so disposal is not required on that path."
    ),
}


def _find_asyncio_run_call_sites() -> set[tuple[str, str]]:
    """Every direct `asyncio.run(...)` call site under `app/tasks/`.

    Keyed by (relative file path, enclosing function name). A call
    nested inside an inner function is attributed to the nearest
    enclosing `def`/`async def`. A module-level call (no enclosing
    function) is rejected outright — every current use in this project
    lives inside a named function, and a bare module-level call would
    execute at import time, which is never the intended shape here.
    """
    found: set[tuple[str, str]] = set()

    for path in sorted(_TASKS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel_path = path.relative_to(_TASKS_DIR).as_posix()

        def _visit(
            node: ast.AST, enclosing: str | None, rel_path: str = rel_path
        ) -> None:
            for child in ast.iter_child_nodes(node):
                next_enclosing = enclosing
                if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    next_enclosing = child.name
                if (
                    isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Attribute)
                    and child.func.attr == "run"
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id == "asyncio"
                ):
                    assert enclosing is not None, (
                        f"asyncio.run() call at {rel_path}:{child.lineno} is at "
                        "module level, not inside a function — this inventory "
                        "assumes every call site is attributable to an "
                        "enclosing function"
                    )
                    found.add((rel_path, enclosing))
                _visit(child, next_enclosing)

        _visit(tree, None)

    return found


@pytest.mark.unit
def test_asyncio_run_call_sites_match_reviewed_inventory() -> None:
    discovered = _find_asyncio_run_call_sites()
    expected = set(REVIEWED_INVENTORY)

    unclassified = discovered - expected
    assert not unclassified, (
        "New asyncio.run() call site(s) found in backend/app/tasks/ that are "
        f"not in the reviewed inventory: {sorted(unclassified)}. A Celery "
        "process repeating this call needs an explicit lifecycle "
        "classification — see docs/conventions.md (Cross-loop pooled "
        "connection lifecycle). Add the call site to REVIEWED_INVENTORY in "
        "this test module with its reviewed rationale."
    )

    stale = expected - discovered
    assert not stale, (
        "REVIEWED_INVENTORY entries with no matching call site (stale — "
        f"remove or update): {sorted(stale)}"
    )
