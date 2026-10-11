"""Cross-source concrete compliance of the eight production CVE fetchers.

See `docs/features/platform/testing-strategy.md` (CVE Fetcher Infrastructure,
Concrete compliance: "NVD and GHSA inline paths construct the token; MITRE and
Kernel return it from `process_item`; Red Hat, OSV, and EPSS preserve
`UpsertResult.action`; KEV remains non-refetchable and preserves its
documented isolated-status deviation. `CompletenessGuardError` remains in the
OSV module"; Parallel Execution), and
`docs/features/platform/cve-fetcher-infrastructure.md` (Class Attributes;
Session Lifecycle for API-based CVE Fetchers, the delegating and inline
`execute()` structures; CVE Source Type Identity, both registry accessors),
`docs/features/platform/fetcher-infrastructure.md` (Per-Ticket Catch-Up,
Registry accessor `get_catch_up_fetchers()`),
`docs/features/platform/git-fetcher-infrastructure.md` (Template Method:
`execute()`), `docs/features/tickets/cve-sync-kev.md` (Conventions, the
isolated-status deviation), and `docs/features/tickets/cve-sync-osv.md`
(`CompletenessGuardError`).

One table pins, per `CVESourceType`, the production class, its capability,
rosters, queue, reference URL pattern, token path, and isolated-status owner,
and names the module and class of the source's own behavioral compliance
tests (typed return, pre-finalization flush, centralized finalization, hard
commit failure, metrics, and status), checked by AST without importing them.
The token path is read from the class's own source: the methods constructing
`CVEFetchResult` and the `self.` calls reaching them from `execute()`.
Every construction passes the `UpsertResult.action` it received.
"""

from __future__ import annotations

import ast
import inspect
import sys
from dataclasses import dataclass
from typing import Final, Literal

import pytest

import app.services.fetcher_discovery  # noqa: F401 — production discovery
from app.core.enums import CVESourceType
from app.services import base_cve_fetcher
from app.services.base_cve_fetcher import (
    BaseCVEFetcher,
    CVEFetchResult,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import get_catch_up_fetchers
from app.services.base_git_fetcher import BaseGitFetcher
from app.services.tickets.sync_cisa_kev import SyncCisaKev
from app.services.tickets.sync_epss_scores import SyncEpssScores
from app.services.tickets.sync_ghsa_advisories import SyncGhsaAdvisories
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from app.services.tickets.sync_nvd_cves import SyncNvdCves
from app.services.tickets.sync_osv_advisories import (
    CompletenessGuardError,
    SyncOsvAdvisories,
)
from app.services.tickets.sync_redhat_cves import SyncRedhatCves
from tests.support.module_imports import APP_ROOT

TokenPath = Literal["inline", "process_item", "fetch_single", "unclassified"]
"""Where the periodic path constructs `CVEFetchResult`: inline in the
`execute()` call graph, in a Git `process_item()`, or in the `fetch_single()`
that `execute()` delegates to."""

IsolatedStatus = Literal["fetcher", "git template", "omitted"]
"""Which code writes isolated source statuses."""

_TESTS: Final = "tests/test_services/test_tickets"


@dataclass(frozen=True)
class _Source:
    fetcher: type[BaseCVEFetcher]
    refetchable: bool
    queue: str | None
    reference_url_pattern: str | None
    token_path: TokenPath
    isolated_status: IsolatedStatus
    compliance_tests: tuple[tuple[str, str], ...]


_SOURCES: Final = {
    CVESourceType.NVD: _Source(
        SyncNvdCves,
        refetchable=True,
        queue=None,
        reference_url_pattern="https://nvd.nist.gov/vuln/detail/{cve_id}",
        token_path="inline",
        isolated_status="fetcher",
        compliance_tests=(
            (f"{_TESTS}/test_sync_nvd_cves_reachability.py", "TestConcreteCompliance"),
        ),
    ),
    CVESourceType.MITRE: _Source(
        SyncMitreCves,
        refetchable=True,
        queue="git",
        reference_url_pattern="https://cve.org/CVERecord?id={cve_id}",
        token_path="process_item",
        isolated_status="git template",
        compliance_tests=(
            (f"{_TESTS}/test_sync_mitre_cves.py", "TestConcreteCompliance"),
        ),
    ),
    CVESourceType.KERNEL: _Source(
        SyncKernelCves,
        refetchable=True,
        queue="git",
        reference_url_pattern=None,
        token_path="process_item",
        isolated_status="git template",
        compliance_tests=(
            (f"{_TESTS}/test_sync_kernel_cves.py", "TestConcreteCompliance"),
        ),
    ),
    CVESourceType.REDHAT: _Source(
        SyncRedhatCves,
        refetchable=True,
        queue=None,
        reference_url_pattern="https://access.redhat.com/security/cve/{cve_id}",
        token_path="fetch_single",
        isolated_status="fetcher",
        compliance_tests=(
            (f"{_TESTS}/test_sync_redhat_cves.py", "TestConcreteCompliance"),
        ),
    ),
    CVESourceType.GHSA: _Source(
        SyncGhsaAdvisories,
        refetchable=True,
        queue=None,
        reference_url_pattern=None,
        token_path="inline",
        isolated_status="fetcher",
        compliance_tests=(
            (
                f"{_TESTS}/test_sync_ghsa_advisories_reachability.py",
                "TestConcreteCompliance",
            ),
        ),
    ),
    CVESourceType.OSV: _Source(
        SyncOsvAdvisories,
        refetchable=True,
        queue=None,
        reference_url_pattern="https://osv.dev/vulnerability/{cve_id}",
        token_path="fetch_single",
        isolated_status="fetcher",
        compliance_tests=(
            (
                f"{_TESTS}/test_sync_osv_advisories_reachability.py",
                "TestRegistrationAndCapability",
            ),
            (f"{_TESTS}/test_sync_osv_advisories_reachability.py", "TestSignalClasses"),
            (f"{_TESTS}/test_sync_osv_advisories_execute.py", "TestFinalization"),
        ),
    ),
    CVESourceType.KEV: _Source(
        SyncCisaKev,
        refetchable=False,
        queue=None,
        reference_url_pattern=(
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            "?field_cve={cve_id}"
        ),
        token_path="inline",
        isolated_status="omitted",
        compliance_tests=(
            (
                f"{_TESTS}/test_sync_cisa_kev_reachability.py",
                "TestRegistrationAndCapability",
            ),
            (f"{_TESTS}/test_sync_cisa_kev_reachability.py", "TestStructuralAbsences"),
            (f"{_TESTS}/test_sync_cisa_kev_execute.py", "TestFinalization"),
        ),
    ),
    CVESourceType.EPSS: _Source(
        SyncEpssScores,
        refetchable=True,
        queue=None,
        reference_url_pattern=None,
        token_path="fetch_single",
        isolated_status="fetcher",
        compliance_tests=(
            (f"{_TESTS}/test_sync_epss_scores.py", "TestConcreteCompliance"),
        ),
    ),
}

_BY_SOURCE: Final = pytest.mark.parametrize(
    "source", list(_SOURCES), ids=[source.value for source in _SOURCES]
)

Method = ast.FunctionDef | ast.AsyncFunctionDef


def _methods(cls: type) -> dict[str, Method]:
    """The methods defined in the class body of `cls`, from its source."""
    (node,) = ast.parse(inspect.getsource(cls)).body
    assert isinstance(node, ast.ClassDef)
    return {m.name: m for m in node.body if isinstance(m, Method)}


def _token_constructions(method: Method) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == CVEFetchResult.__name__
    ]


def _self_calls(method: Method) -> set[str]:
    return {
        node.func.attr
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    }


def _reachable(methods: dict[str, Method], start: str, *, skip: str = "") -> set[str]:
    """Own methods reached from `start` through `self.` calls, never
    entering `skip`."""
    seen: set[str] = set()
    pending = [start]
    while pending:
        name = pending.pop()
        if name in seen or name == skip or name not in methods:
            continue
        seen.add(name)
        pending.extend(_self_calls(methods[name]))
    return seen


def token_path(cls: type) -> TokenPath:
    methods = _methods(cls)
    constructors = {name for name, m in methods.items() if _token_constructions(m)}
    if "execute" not in methods:
        return "process_item" if constructors == {"process_item"} else "unclassified"
    periodic = _reachable(methods, "execute", skip="fetch_single")
    delegates = any("fetch_single" in _self_calls(methods[m]) for m in periodic)
    if constructors & periodic and not delegates:
        return "inline"
    if delegates and not constructors & periodic:
        return "fetch_single"
    return "unclassified"


def _action_argument(call: ast.Call) -> ast.expr | None:
    """The `action` argument of one `CVEFetchResult(...)` construction."""
    if call.args:
        return call.args[0]
    return next((k.value for k in call.keywords if k.arg == "action"), None)


def _referenced_names(cls: type) -> set[str]:
    """Every identifier and attribute name the module of `cls` references."""
    tree = ast.parse(inspect.getsource(sys.modules[cls.__module__]))
    return {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Name | ast.Attribute)
    }


@pytest.mark.unit
class TestCrossSourceCompliance:
    def test_table_covers_exactly_the_cve_source_types(self) -> None:
        assert list(_SOURCES) == list(CVESourceType)
        assert {row.fetcher for row in _SOURCES.values()} == set(
            get_all_cve_source_types().values()
        )

    @_BY_SOURCE
    def test_identity_queue_and_reference_pattern(self, source: CVESourceType) -> None:
        row = _SOURCES[source]

        assert row.fetcher.cve_source_type is source
        assert row.fetcher.queue == row.queue
        assert row.fetcher.source_reference_url_pattern == row.reference_url_pattern

    @_BY_SOURCE
    def test_capability_and_rosters(self, source: CVESourceType) -> None:
        row = _SOURCES[source]
        fetcher = row.fetcher
        fetch_single = get_fetch_single_fetchers()
        catch_up = get_catch_up_fetchers()

        assert fetcher.supports_fetch_single is row.refetchable
        assert fetcher.participates_in_catch_up is row.refetchable
        assert get_all_cve_source_types()[source.value] is fetcher
        assert fetch_single.get(source.value) is (fetcher if row.refetchable else None)
        assert catch_up.get(fetcher.name) is (fetcher if row.refetchable else None)
        if row.refetchable:
            assert fetcher.fetch_single is not BaseCVEFetcher.fetch_single
            returned = inspect.get_annotations(fetcher.fetch_single, eval_str=True)
            assert returned["return"] is CVEFetchResult
        else:
            # The base safety net, never dispatched for this source.
            assert "fetch_single" not in fetcher.__dict__
            assert fetcher.fetch_single is BaseCVEFetcher.fetch_single

    @_BY_SOURCE
    def test_token_path(self, source: CVESourceType) -> None:
        row = _SOURCES[source]
        fetcher = row.fetcher
        methods = _methods(fetcher)

        assert token_path(fetcher) == row.token_path
        if row.token_path == "process_item":
            assert issubclass(fetcher, BaseGitFetcher)
            assert fetcher.execute is BaseGitFetcher.execute
            returned = inspect.get_annotations(fetcher.process_item, eval_str=True)
            assert returned["return"] is CVEFetchResult
        if "fetch_single" in methods:
            on_demand = _reachable(methods, "fetch_single")
            assert any(_token_constructions(methods[m]) for m in on_demand)

    @_BY_SOURCE
    def test_every_token_preserves_the_upsert_action(
        self, source: CVESourceType
    ) -> None:
        calls = [
            call
            for method in _methods(_SOURCES[source].fetcher).values()
            for call in _token_constructions(method)
        ]
        actions = [_action_argument(call) for call in calls]

        assert calls
        assert all(
            isinstance(action, ast.Attribute) and action.attr == "action"
            for action in actions
        ), [ast.unparse(call) for call in calls]

    @_BY_SOURCE
    def test_isolated_status_owner(self, source: CVESourceType) -> None:
        row = _SOURCES[source]
        writes_own = "_isolated_status_commit" in _referenced_names(row.fetcher)

        assert writes_own is (row.isolated_status == "fetcher")
        assert issubclass(row.fetcher, BaseGitFetcher) is (
            row.isolated_status == "git template"
        )

    def test_completeness_guard_error_remains_in_the_osv_module(self) -> None:
        assert CompletenessGuardError.__module__ == SyncOsvAdvisories.__module__
        others = [
            sys.modules[row.fetcher.__module__]
            for source, row in _SOURCES.items()
            if source is not CVESourceType.OSV
        ]
        for module in [*others, base_cve_fetcher]:
            assert not hasattr(module, CompletenessGuardError.__name__), module

    @_BY_SOURCE
    def test_behavioral_compliance_tests_exist(self, source: CVESourceType) -> None:
        for path, class_name in _SOURCES[source].compliance_tests:
            tree = ast.parse((APP_ROOT.parent / path).read_text(encoding="utf-8"))
            classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}

            assert class_name in classes, f"{path}::{class_name}"
