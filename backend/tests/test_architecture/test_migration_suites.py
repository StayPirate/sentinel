"""Structural test: every Alembic revision has a migration suite pinned to
it.

See `docs/features/platform/testing-strategy.md` (Migration Tests, and the
Structural Tests table, row "Migration test suites") for the convention
this test enforces. It checks only the mechanical part: each suite in
`tests/test_migrations/` pins an existing revision in `_REVISION`,
upgrades to it, and never targets `head`, and every revision has such a
suite. Whether a suite seeds representative rows before upgrading needs
judgement and stays with review.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_SUITES_DIR = _BACKEND_DIR / "tests" / "test_migrations"

# Revisions verified as part of a chain by a suite pinned to a later
# revision, keyed by revision with the covering suite as value. The
# identity suite upgrades from the empty database to its `_REVISION` and
# downgrades to `base`, so it exercises each of these revisions. Every
# other revision has its own suite; this list does not grow.
_CHAIN_COVERED_REVISIONS: dict[str, str] = {
    "92bb900c55ff": "test_identity_migrations.py",
    "1327f6343056": "test_identity_migrations.py",
    "81fad13a4b63": "test_identity_migrations.py",
}

# Alembic's symbolic head targets: `head`, `heads`, `<branch>@head`, and
# relative forms such as `head-1`.
_HEAD_TARGET = re.compile(r"(?:[^@\s]+@)?heads?(?:[-+]\d+)?")


@dataclass(frozen=True)
class _Suite:
    name: str
    revision: str | None
    upgrades_to_revision: bool
    head_targets: tuple[str, ...]


def _parse_suite(name: str, source: str) -> _Suite:
    tree = ast.parse(source, filename=name)

    revision: str | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if (
            any(isinstance(t, ast.Name) and t.id == "_REVISION" for t in targets)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        ):
            revision = value.value

    upgrades_to_revision = False
    head_targets: set[str] = set()
    for child in ast.walk(tree):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "upgrade"
            and isinstance(child.func.value, ast.Name)
            and child.func.value.id == "command"
        ):
            target = child.args[1] if len(child.args) > 1 else None
            for keyword in child.keywords:
                if keyword.arg == "revision":
                    target = keyword.value
            if isinstance(target, ast.Name) and target.id == "_REVISION":
                upgrades_to_revision = True
        if (
            isinstance(child, ast.Constant)
            and isinstance(child.value, str)
            and _HEAD_TARGET.fullmatch(child.value)
        ):
            head_targets.add(child.value)

    return _Suite(name, revision, upgrades_to_revision, tuple(sorted(head_targets)))


def _suite_findings(suite: _Suite, revisions: set[str]) -> list[str]:
    findings: list[str] = []
    if suite.revision is None:
        findings.append(f"{suite.name}: no module-level string constant _REVISION")
    elif suite.revision not in revisions:
        findings.append(f"{suite.name}: _REVISION {suite.revision!r} is not a revision")
    if suite.revision is not None and not suite.upgrades_to_revision:
        findings.append(f"{suite.name}: never calls command.upgrade(..., _REVISION)")
    if suite.head_targets:
        findings.append(f"{suite.name}: targets {list(suite.head_targets)}")
    return findings


def _coverage_findings(
    suites: Iterable[_Suite],
    revisions: set[str],
    chain_covered: dict[str, str],
) -> list[str]:
    pinned = {suite.revision for suite in suites if suite.revision is not None}
    findings = [
        f"revision {revision} has no suite pinned to it"
        for revision in sorted(revisions - pinned - chain_covered.keys())
    ]
    findings.extend(
        f"chain-covered revision {revision} is stale: it is not a revision or "
        "it has its own suite"
        for revision in sorted(chain_covered.keys() - (revisions - pinned))
    )
    return findings


def _repository_revisions() -> set[str]:
    # Built from the script directory itself rather than `alembic.ini`:
    # `ScriptDirectory.from_config()` prepends the ini's
    # `prepend_sys_path` to `sys.path`, process-wide state a unit test
    # must not change.
    script = ScriptDirectory(str(_BACKEND_DIR / "alembic"))
    return {revision.revision for revision in script.walk_revisions()}


def _repository_suites() -> list[_Suite]:
    return [
        _parse_suite(path.name, path.read_text(encoding="utf-8"))
        for path in sorted(_SUITES_DIR.glob("test_*.py"))
    ]


@pytest.mark.unit
def test_every_migration_suite_pins_and_upgrades_to_an_existing_revision() -> None:
    revisions = _repository_revisions()
    suites = _repository_suites()

    assert suites, f"no migration suites found in {_SUITES_DIR}"
    findings = [
        finding for suite in suites for finding in _suite_findings(suite, revisions)
    ]
    assert not findings, findings


@pytest.mark.unit
def test_every_revision_has_a_pinned_migration_suite() -> None:
    findings = _coverage_findings(
        _repository_suites(), _repository_revisions(), _CHAIN_COVERED_REVISIONS
    )

    assert not findings, findings


_COMPLIANT_SUITE = '''
"""Upgrade from the previous head to the revision under test."""
_PREVIOUS_HEAD = "aaaa"
_REVISION = "bbbb"


def test_cycle() -> None:
    command.upgrade(cfg, _PREVIOUS_HEAD)
    command.upgrade(cfg, _REVISION)
    command.downgrade(cfg, _PREVIOUS_HEAD)
    command.upgrade(cfg, revision=_REVISION)
'''


@pytest.mark.unit
def test_suite_findings_accept_a_compliant_suite() -> None:
    suite = _parse_suite("test_compliant.py", _COMPLIANT_SUITE)

    assert _suite_findings(suite, {"aaaa", "bbbb"}) == []


@pytest.mark.unit
@pytest.mark.parametrize(
    ("source", "expected"),
    [
        pytest.param(
            'def test_cycle() -> None:\n    command.upgrade(cfg, "bbbb")\n',
            "no module-level string constant _REVISION",
            id="missing-revision",
        ),
        pytest.param(
            '_REVISION = "cccc"\n\n'
            "def test_cycle() -> None:\n    command.upgrade(cfg, _REVISION)\n",
            "_REVISION 'cccc' is not a revision",
            id="unknown-revision",
        ),
        pytest.param(
            '_REVISION = "bbbb"\n\n'
            'def test_cycle() -> None:\n    command.upgrade(cfg, "bbbb")\n',
            "never calls command.upgrade(..., _REVISION)",
            id="revision-not-upgraded",
        ),
        pytest.param(
            '_REVISION = "bbbb"\n\n'
            "def test_cycle() -> None:\n"
            "    command.upgrade(cfg, _REVISION)\n"
            '    command.upgrade(cfg, "head")\n',
            "targets ['head']",
            id="head",
        ),
        pytest.param(
            '_REVISION = "bbbb"\n_TARGET = "heads"\n\n'
            "def test_cycle() -> None:\n    command.upgrade(cfg, _REVISION)\n",
            "targets ['heads']",
            id="heads-through-constant",
        ),
        pytest.param(
            '_REVISION = "bbbb"\n\n'
            "def test_cycle() -> None:\n"
            "    command.upgrade(cfg, _REVISION)\n"
            '    command.downgrade(cfg, "head-1")\n'
            '    command.upgrade(cfg, "main@head")\n',
            "targets ['head-1', 'main@head']",
            id="relative-and-branch-head",
        ),
    ],
)
def test_suite_findings_detect_violation(source: str, expected: str) -> None:
    suite = _parse_suite("test_violating.py", source)

    findings = _suite_findings(suite, {"aaaa", "bbbb"})

    assert findings == [f"test_violating.py: {expected}"]


@pytest.mark.unit
def test_coverage_findings_detect_unpinned_and_stale_revisions() -> None:
    suites = [_Suite("test_b.py", "bbbb", True, ())]
    revisions = {"aaaa", "bbbb", "cccc"}
    chain_covered = {
        "aaaa": "test_b.py",
        "bbbb": "test_b.py",
        "dddd": "test_b.py",
    }

    assert _coverage_findings(suites, revisions, chain_covered) == [
        "revision cccc has no suite pinned to it",
        "chain-covered revision bbbb is stale: it is not a revision or it has "
        "its own suite",
        "chain-covered revision dddd is stale: it is not a revision or it has "
        "its own suite",
    ]
