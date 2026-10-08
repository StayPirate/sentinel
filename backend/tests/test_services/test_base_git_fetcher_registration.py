"""Registration, fixed attributes, path construction, utility delegation, and
pure helpers of `BaseGitFetcher` (backend/app/services/base_git_fetcher.py).

Owning specifications:

- docs/features/platform/git-fetcher-infrastructure.md (Worker Affinity;
  BaseGitFetcher Class; Class Attributes; Hook Methods; Inherited Utility
  Methods, `_repo_path()` and `_extract_item_id()`; `_compute_recovery_delta()`;
  Registry Detection Predicate Update).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes,
  `supports_fetch_single` and the `participates_in_catch_up` derivation;
  `__init_subclass__` Validation, rule 4 with the `BaseGitFetcher` case,
  Atomic cross-registry registration, and Test isolation).
- docs/features/platform/fetcher-infrastructure.md (Redbeat Entry
  Structure, the `queue` option).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Atomic registration and isolation, the `BaseGitFetcher` case; Git
  boundaries, `queue = "git"` preserved).

Every test is a pure unit test. Test-only fetcher classes are built with
`type()` inside the test body under `isolated_fetcher_registries`, after the
module's `_unowned_source_types` fixture released every `CVESourceType`
owner, so a failing definition is a single statement inside `pytest.raises`
and teardown restores both registries. The utility-delegation tests replace
the `git_operations` functions through the `GitCalls` spy
(`tests/support/git_fetchers.py`), so no Git process starts. All URLs,
names, and identifiers are fictional.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app import config
from app.core.enums import CVESourceType
from app.models.fetcher_config import FetcherConfig
from app.services import fetcher_schedule
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    get_catch_up_fetchers,
)
from app.services.base_git_fetcher import (
    RECOVERY_BOUNDARY_NOT_FOUND_EVENT,
    BaseGitFetcher,
    is_single_path_component,
    recovery_before_date,
)
from app.services.cve_ingest import UpsertAction
from app.services.git_operations import (
    GitCorruptionError,
    GitFetchError,
    GitFileError,
)
from tests.support.git_fetchers import GitCalls

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("isolated_fetcher_registries")]

REPO_URL = "https://git.example.test/example-cves.git"
DELTA_PREFIX = "delta-cves/"
RECOVERY_PREFIX = "recovery-cves/"
SHA_A = "a" * 40
SHA_B = "b" * 40
REPO = Path("/nonexistent.example/clones/example-clone")
"""A clone path no Git process ever sees (every function is replaced)."""


def _release_source_type_owners() -> None:
    """Unregister every `CVESourceType` owner from both registries, keeping
    them one coherent registration unit."""
    owners = set(_CVE_SOURCE_TYPE_MAP.values())
    _CVE_SOURCE_TYPE_MAP.clear()
    for name in [name for name, cls in FETCHER_REGISTRY.items() if cls in owners]:
        del FETCHER_REGISTRY[name]


@pytest.fixture(autouse=True)
def _unowned_source_types(isolated_fetcher_registries: None) -> None:
    """Every `CVESourceType` member starts unowned, after
    `isolated_fetcher_registries` has snapshotted both registries; teardown
    restores the production owners."""
    _release_source_type_owners()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _process_item_stub(
    self: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
) -> CVEFetchResult:
    return CVEFetchResult(UpsertAction.UNCHANGED, None)


def _candidate_paths_stub(self: BaseGitFetcher, item_id: str) -> list[str]:
    return [f"{DELTA_PREFIX}{item_id}.json"]


async def _execute_stub(self: BaseFetcher, session: AsyncSession) -> None:
    return None


def _unique_name() -> str:
    """A fetcher name matching `^[a-z][a-z0-9_]*$`, unique per call."""
    return f"test_git_fetcher_{uuid4().hex}"


def _define_git(class_name: str, **attrs: Any) -> type[BaseGitFetcher]:
    """Define one `BaseGitFetcher` subclass with valid generic and Git
    attributes and both required hooks.

    `attrs` overrides or extends the defaults; `cve_source_type` is never
    defaulted, so a definition omitting it exercises rule 1. `execute()`
    is never defined: it is the inherited template.
    """
    name = _unique_name()
    namespace: dict[str, Any] = {
        "name": name,
        "description": "Test-only Git CVE fetcher",
        "default_schedule": "0 * * * *",
        "repo_url": REPO_URL,
        "clone_dir_name": name,
        "delta_path_prefix": DELTA_PREFIX,
        "recovery_path_prefix": RECOVERY_PREFIX,
        "process_item": _process_item_stub,
        "_construct_candidate_paths": _candidate_paths_stub,
    }
    namespace.update(attrs)
    return cast(type[BaseGitFetcher], type(class_name, (BaseGitFetcher,), namespace))


def _define_plain(class_name: str, **attrs: Any) -> type[BaseFetcher]:
    """Define one concrete non-CVE `BaseFetcher` subclass."""
    namespace: dict[str, Any] = {
        "name": _unique_name(),
        "description": "Test-only plain fetcher",
        "default_schedule": "0 * * * *",
        "execute": _execute_stub,
    }
    namespace.update(attrs)
    return type(class_name, (BaseFetcher,), namespace)


def _snapshot() -> tuple[dict[str, type[BaseFetcher]], dict[CVESourceType, type]]:
    return dict(FETCHER_REGISTRY), dict(_CVE_SOURCE_TYPE_MAP)


def _assert_rejected_atomically(
    define: Callable[[], object], *, match: str
) -> TypeError:
    """Assert `define()` raises `TypeError` and leaves both registries
    exactly as they were before the attempt."""
    before = _snapshot()
    with pytest.raises(TypeError, match=match) as exc_info:
        define()
    assert _snapshot() == before
    return exc_info.value


class _UntouchedSession:
    """Stands in for a session where no database work may occur."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} must not be used")


UNTOUCHED = cast(AsyncSession, _UntouchedSession())


# ---------------------------------------------------------------------------
# Registration and rule 4 (the inherited `BaseGitFetcher.fetch_single`)
# ---------------------------------------------------------------------------


class TestRegistration:
    @pytest.mark.parametrize(
        "declared",
        [
            pytest.param({}, id="inherited-supports-fetch-single"),
            pytest.param({"supports_fetch_single": True}, id="explicit-true"),
        ],
    )
    def test_inherited_fetch_single_satisfies_rule_4_and_registers_in_both(
        self, declared: dict[str, Any]
    ) -> None:
        """Rule 4: the resolved `fetch_single` is the inherited
        `BaseGitFetcher` implementation, which differs from the
        `BaseCVEFetcher` safety net, so the class registers in both
        registries as one unit."""
        before_fetchers, before_sources = _snapshot()

        concrete = _define_git(
            "InheritedGitFetcher", cve_source_type=CVESourceType.MITRE, **declared
        )

        assert "fetch_single" not in concrete.__dict__
        assert concrete.fetch_single is BaseGitFetcher.fetch_single
        assert concrete.fetch_single is not BaseCVEFetcher.fetch_single
        assert concrete.supports_fetch_single is True
        assert _snapshot() == (
            {**before_fetchers, concrete.name: concrete},
            {**before_sources, CVESourceType.MITRE: concrete},
        )

    def test_joins_both_rosters_with_derived_catch_up_participation(self) -> None:
        """Registry Detection Predicate Update: `BaseGitFetcher` overrides
        neither capability attribute, so `participates_in_catch_up` is
        derived `True` from the inherited `supports_fetch_single`."""
        concrete = _define_git("RosterGitFetcher", cve_source_type=CVESourceType.KERNEL)

        assert "supports_fetch_single" not in BaseGitFetcher.__dict__
        assert "participates_in_catch_up" not in BaseGitFetcher.__dict__
        assert concrete.participates_in_catch_up is True
        assert get_fetch_single_fetchers() == {"kernel": concrete}
        assert get_catch_up_fetchers()[concrete.name] is concrete
        assert concrete.catch_up is BaseCVEFetcher.catch_up

    def test_opting_out_of_fetch_single_derives_no_catch_up_participation(
        self,
    ) -> None:
        concrete = _define_git(
            "OptOutGitFetcher",
            cve_source_type=CVESourceType.KERNEL,
            supports_fetch_single=False,
        )

        assert concrete.participates_in_catch_up is False
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.KERNEL] is concrete
        assert get_fetch_single_fetchers() == {}
        assert concrete.name not in get_catch_up_fetchers()

    def test_base_git_fetcher_is_registered_in_neither_registry(self) -> None:
        assert BaseGitFetcher.__dict__["abstract"] is True
        assert BaseGitFetcher not in FETCHER_REGISTRY.values()
        assert BaseGitFetcher not in _CVE_SOURCE_TYPE_MAP.values()

    def test_abstract_git_intermediate_registers_in_neither_registry(self) -> None:
        before = _snapshot()

        _define_git(
            "AbstractGitIntermediate",
            abstract=True,
            cve_source_type=CVESourceType.MITRE,
        )

        assert _snapshot() == before


class TestAtomicRejection:
    """A validation failure of a `BaseGitFetcher` subclass leaves both
    registries unchanged (no orphan in either)."""

    def test_duplicate_cve_source_type_keeps_the_first_owner(self) -> None:
        first = _define_git("FirstGitFetcher", cve_source_type=CVESourceType.MITRE)

        error = _assert_rejected_atomically(
            lambda: _define_git(
                "SecondGitFetcher", cve_source_type=CVESourceType.MITRE
            ),
            match="already registered by FirstGitFetcher",
        )

        assert "SecondGitFetcher" in str(error)
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.MITRE] is first
        assert FETCHER_REGISTRY[first.name] is first

    @pytest.mark.parametrize("first_kind", ["git", "plain"])
    def test_duplicate_name_leaves_no_orphan_source(self, first_kind: str) -> None:
        first: type[BaseFetcher] = (
            _define_git("FirstNamedFetcher", cve_source_type=CVESourceType.MITRE)
            if first_kind == "git"
            else _define_plain("FirstNamedFetcher")
        )

        _assert_rejected_atomically(
            lambda: _define_git(
                "SameNameGitFetcher",
                name=first.name,
                cve_source_type=CVESourceType.KERNEL,
            ),
            match="already registered by FirstNamedFetcher",
        )

        assert CVESourceType.KERNEL not in _CVE_SOURCE_TYPE_MAP
        assert FETCHER_REGISTRY[first.name] is first

    @pytest.mark.parametrize(
        ("attrs", "match"),
        [
            pytest.param({}, "must declare cve_source_type", id="missing-source-type"),
            pytest.param(
                {"cve_source_type": "mitre"},
                "cve_source_type must be a CVESourceType enum member",
                id="raw-string-source-type",
            ),
            pytest.param(
                {
                    "cve_source_type": CVESourceType.MITRE,
                    "default_schedule": "not a cron",
                },
                "default_schedule",
                id="invalid-schedule",
            ),
            pytest.param(
                {"cve_source_type": CVESourceType.MITRE, "name": "Invalid-Name"},
                "name must match",
                id="invalid-name",
            ),
            pytest.param(
                {
                    "cve_source_type": CVESourceType.MITRE,
                    "supports_fetch_single": False,
                    "participates_in_catch_up": True,
                },
                "does not override catch_up",
                id="rule-5-catch-up-without-fetch-single",
            ),
        ],
    )
    def test_validation_failure_leaves_both_registries_unchanged(
        self, attrs: dict[str, Any], match: str
    ) -> None:
        _assert_rejected_atomically(
            lambda: _define_git("RejectedGitFetcher", **attrs), match=match
        )

        assert CVESourceType.MITRE not in _CVE_SOURCE_TYPE_MAP


# ---------------------------------------------------------------------------
# Fixed and configurable class attributes
# ---------------------------------------------------------------------------


class TestClassAttributes:
    def test_queue_git_is_fixed_on_the_base_and_inherited(self) -> None:
        concrete = _define_git("QueueGitFetcher", cve_source_type=CVESourceType.MITRE)

        assert BaseFetcher.queue is None
        assert BaseGitFetcher.__dict__["queue"] == "git"
        assert concrete.queue == "git"
        assert "queue" not in concrete.__dict__

    def test_base_git_fetcher_defines_no_init_subclass_of_its_own(self) -> None:
        """Registration validation flows through `BaseCVEFetcher`, the
        nearest `__init_subclass__` in the MRO."""
        assert "__init_subclass__" not in BaseGitFetcher.__dict__
        own = BaseCVEFetcher.__dict__["__init_subclass__"]
        assert BaseGitFetcher.__init_subclass__.__func__ is own.__func__  # type: ignore[attr-defined]

    def test_configurable_defaults_and_abstract_flag(self) -> None:
        concrete = _define_git(
            "DefaultsGitFetcher", cve_source_type=CVESourceType.MITRE
        )

        assert BaseGitFetcher.clone_filter is None
        assert BaseGitFetcher.clone_single_branch is True
        assert concrete.clone_filter is None
        assert concrete.clone_single_branch is True
        assert "clone_filter" not in concrete.__dict__
        assert "clone_single_branch" not in concrete.__dict__
        assert "abstract" in BaseGitFetcher.__dict__
        assert "abstract" not in concrete.__dict__

    @pytest.mark.parametrize(
        "attribute",
        ["repo_url", "clone_dir_name", "recovery_path_prefix", "delta_path_prefix"],
    )
    def test_required_attribute_is_only_annotated_on_the_base(
        self, attribute: str
    ) -> None:
        assert attribute in inspect.get_annotations(BaseGitFetcher)
        assert not hasattr(BaseGitFetcher, attribute)

    def test_redbeat_entry_options_carry_the_git_queue(self) -> None:
        """The real RedBeat options builder (fetcher-infrastructure.md,
        Redbeat Entry Structure) includes the inherited queue."""
        concrete = _define_git(
            "ScheduledGitFetcher", cve_source_type=CVESourceType.MITRE
        )
        fetcher_config = FetcherConfig(
            fetcher_name=concrete.name,
            enabled=True,
            schedule_override=None,
            run_timeout=3600,
            request_delay=0.0,
            custom_settings={},
        )

        options = fetcher_schedule._effective_options(concrete, fetcher_config)

        assert options == {"time_limit": 3600, "soft_time_limit": 3420, "queue": "git"}


class TestHooks:
    def test_optional_hooks_default_to_the_unchanged_list(self) -> None:
        concrete = _define_git("HookGitFetcher", cve_source_type=CVESourceType.MITRE)
        fetcher = concrete()
        files = ["cves/b.json", "cves/a.json", "cves/a.json"]

        assert fetcher.filter_delta_files(list(files)) == files
        assert fetcher.deduplicate_items(list(files)) == files

    async def test_required_hooks_raise_not_implemented_on_the_base(self) -> None:
        concrete = _define_git(
            "HooklessGitFetcher",
            cve_source_type=CVESourceType.MITRE,
            process_item=BaseGitFetcher.process_item,
            _construct_candidate_paths=BaseGitFetcher._construct_candidate_paths,
        )
        fetcher = concrete()

        with pytest.raises(NotImplementedError, match="process_item"):
            await fetcher.process_item("cves/CVE-2099-0001.json", b"{}", UNTOUCHED)
        with pytest.raises(NotImplementedError, match="_construct_candidate_paths"):
            fetcher._construct_candidate_paths("CVE-2099-0001")


# ---------------------------------------------------------------------------
# `_repo_path()` and `_extract_item_id()`
# ---------------------------------------------------------------------------


class TestRepoPath:
    def test_joins_the_base_directory_read_at_call_time(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        concrete = _define_git(
            "PathGitFetcher",
            cve_source_type=CVESourceType.MITRE,
            clone_dir_name="example-cves.git",
        )
        fetcher = concrete()
        first, second = tmp_path / "first", tmp_path / "second"

        monkeypatch.setattr(config.settings, "git_clone_base_dir", str(first))
        assert fetcher._repo_path() == first / "example-cves.git"
        monkeypatch.setattr(config.settings, "git_clone_base_dir", str(second))
        assert fetcher._repo_path() == second / "example-cves.git"

    @pytest.mark.parametrize(
        "clone_dir_name",
        [
            pytest.param("", id="empty"),
            pytest.param(".", id="dot"),
            pytest.param("..", id="dot-dot"),
            pytest.param("a/b", id="separator"),
            pytest.param("/abs", id="absolute"),
            pytest.param("x\x00y", id="nul"),
        ],
    )
    async def test_invalid_clone_dir_name_raises_before_any_git_or_filesystem_call(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        clone_dir_name: str,
    ) -> None:
        """No clone, lookup, or deletion can target a path outside
        `GIT_CLONE_BASE_DIR`: `_repo_path()` raises `ValueError` first, so
        neither `fetch_single()` nor `execute()` reaches `git_operations`."""
        base = tmp_path / "clones"
        base.mkdir()
        monkeypatch.setattr(config.settings, "git_clone_base_dir", str(base))
        git_calls = GitCalls(monkeypatch)
        concrete = _define_git(
            "BadPathGitFetcher",
            cve_source_type=CVESourceType.MITRE,
            clone_dir_name=clone_dir_name,
        )
        fetcher = concrete()

        with pytest.raises(ValueError, match="single path component"):
            fetcher._repo_path()
        with pytest.raises(ValueError, match="single path component"):
            await fetcher.fetch_single("CVE-2099-0001", UNTOUCHED)
        with pytest.raises(ValueError, match="single path component"):
            await fetcher.execute(UNTOUCHED)

        assert git_calls.calls == []
        assert list(base.iterdir()) == []


class TestExtractItemId:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("cve/published/2024/CVE-2024-50055.json", "CVE-2024-50055"),
            ("cves/2099/CVE-2099-0001.json", "CVE-2099-0001"),
            ("CVE-2099-0002", "CVE-2099-0002"),
            ("cves/notes/README.md", "README"),
        ],
    )
    def test_default_is_the_file_stem(self, path: str, expected: str) -> None:
        concrete = _define_git("StemGitFetcher", cve_source_type=CVESourceType.MITRE)

        assert concrete()._extract_item_id(path) == expected


# ---------------------------------------------------------------------------
# Inherited utility methods delegate to `git_operations`
# ---------------------------------------------------------------------------


def _returning(value: object) -> Callable[..., Any]:
    """A `GitCalls` replacement returning `value` without running git."""

    async def replacement(real: Any, *args: Any, **kwargs: Any) -> object:
        return value

    return replacement


_DELEGATIONS = [
    pytest.param(
        "_fetch_origin", (REPO,), "fetch_origin", (REPO,), {}, None, id="fetch-origin"
    ),
    pytest.param(
        "_get_head_sha", (REPO,), "get_head_sha", (REPO,), {}, SHA_A, id="head-sha"
    ),
    pytest.param(
        "_get_commit_date",
        (REPO, "HEAD"),
        "get_commit_date",
        (REPO, "HEAD"),
        {},
        "2024-01-10T00:00:00+00:00",
        id="commit-date",
    ),
    pytest.param(
        "_is_clone_valid", (REPO,), "is_clone_valid", (REPO,), {}, True, id="valid"
    ),
    pytest.param(
        "_check_sha_reachable",
        (REPO, SHA_A),
        "check_sha_reachable",
        (REPO, SHA_A),
        {},
        False,
        id="sha-reachable",
    ),
    pytest.param(
        "_compute_delta",
        (REPO, SHA_A, SHA_B),
        "diff_names",
        (REPO, SHA_A, SHA_B),
        {"path_filter": DELTA_PREFIX},
        [f"{DELTA_PREFIX}2099/CVE-2099-0001.json"],
        id="delta-with-delta-prefix",
    ),
    pytest.param(
        "_show_file",
        (REPO, "HEAD", "cves/CVE-2099-0001.json"),
        "show_file",
        (REPO, "HEAD", "cves/CVE-2099-0001.json"),
        {},
        b"{}",
        id="show-file",
    ),
    pytest.param(
        "_delete_if_exists", (REPO,), "delete_clone", (REPO,), {}, None, id="delete"
    ),
]


class TestUtilityDelegation:
    @pytest.mark.parametrize(
        ("method", "args", "function", "expected_args", "expected_kwargs", "value"),
        _DELEGATIONS,
    )
    async def test_delegates_once_and_returns_the_result(
        self,
        monkeypatch: pytest.MonkeyPatch,
        method: str,
        args: tuple[Any, ...],
        function: str,
        expected_args: tuple[Any, ...],
        expected_kwargs: dict[str, Any],
        value: object,
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        git_calls.replacements[function] = _returning(value)
        fetcher = _define_git(
            "DelegatingGitFetcher", cve_source_type=CVESourceType.MITRE
        )()

        result = await getattr(fetcher, method)(*args)

        assert result == value
        assert git_calls.calls == [(function, expected_args, expected_kwargs)]

    @pytest.mark.parametrize(
        ("method", "args", "function", "error"),
        [
            pytest.param(
                "_fetch_origin", (REPO,), "fetch_origin", GitFetchError("x"), id="fetch"
            ),
            pytest.param(
                "_get_head_sha",
                (REPO,),
                "get_head_sha",
                GitCorruptionError("x"),
                id="head",
            ),
            pytest.param(
                "_show_file",
                (REPO, "HEAD", "cves/x.json"),
                "show_file",
                GitFileError("x"),
                id="show",
            ),
            pytest.param(
                "_delete_if_exists",
                (REPO,),
                "delete_clone",
                PermissionError(13, "denied"),
                id="delete",
            ),
        ],
    )
    async def test_propagates_the_git_operations_exception_unchanged(
        self,
        monkeypatch: pytest.MonkeyPatch,
        method: str,
        args: tuple[Any, ...],
        function: str,
        error: Exception,
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        git_calls.errors[function] = error
        fetcher = _define_git(
            "RaisingGitFetcher", cve_source_type=CVESourceType.MITRE
        )()

        with pytest.raises(type(error)) as raised:
            await getattr(fetcher, method)(*args)

        assert raised.value is error

    @pytest.mark.parametrize(
        ("attrs", "expected"),
        [
            pytest.param(
                {}, {"filter_spec": None, "single_branch": True}, id="defaults"
            ),
            pytest.param(
                {"clone_filter": "blob:none", "clone_single_branch": False},
                {"filter_spec": "blob:none", "single_branch": False},
                id="configured",
            ),
        ],
    )
    async def test_clone_passes_the_configured_options(
        self,
        monkeypatch: pytest.MonkeyPatch,
        attrs: dict[str, Any],
        expected: dict[str, Any],
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        git_calls.replacements["clone"] = _returning(None)
        fetcher = _define_git(
            "CloningGitFetcher", cve_source_type=CVESourceType.MITRE, **attrs
        )()

        await fetcher._clone_repo(REPO)

        assert git_calls.calls == [("clone", (REPO_URL, REPO), expected)]


class TestRecoveryDelta:
    async def test_boundary_one_day_earlier_with_the_recovery_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        git_calls.replacements["rev_list_before"] = _returning(SHA_A)
        delta = [f"{RECOVERY_PREFIX}2099/CVE-2099-0001.json"]
        git_calls.replacements["diff_names"] = _returning(delta)
        fetcher = _define_git(
            "RecoveryGitFetcher", cve_source_type=CVESourceType.MITRE
        )()

        result = await fetcher._compute_recovery_delta(
            REPO, SHA_B, "2024-01-10T02:30:45.5+02:00"
        )

        assert result == delta
        assert git_calls.calls == [
            ("rev_list_before", (REPO, "2024-01-09T00:30:45+00:00"), {}),
            ("diff_names", (REPO, SHA_A, SHA_B), {"path_filter": RECOVERY_PREFIX}),
        ]

    async def test_no_boundary_commit_warns_and_returns_an_empty_delta(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        git_calls.replacements["rev_list_before"] = _returning(None)
        concrete = _define_git(
            "NoBoundaryGitFetcher", cve_source_type=CVESourceType.MITRE
        )

        with capture_logs() as logs:
            result = await concrete()._compute_recovery_delta(
                REPO, SHA_B, "2024-01-10T00:00:00+00:00"
            )

        assert result == []
        assert git_calls.names() == ["rev_list_before"]
        assert logs == [
            {
                "event": RECOVERY_BOUNDARY_NOT_FOUND_EVENT,
                "log_level": "warning",
                "fetcher_name": concrete.name,
            }
        ]

    @pytest.mark.parametrize(
        "committed_at", ["2024-01-10T00:00:00", "not a date", "0001-01-01T00:00:00Z"]
    )
    async def test_unusable_committed_at_raises_before_invoking_git(
        self, monkeypatch: pytest.MonkeyPatch, committed_at: str
    ) -> None:
        git_calls = GitCalls(monkeypatch)
        fetcher = _define_git(
            "BadDateGitFetcher", cve_source_type=CVESourceType.MITRE
        )()

        with pytest.raises(ValueError, match="recovery boundary"):
            await fetcher._compute_recovery_delta(REPO, SHA_B, committed_at)

        assert git_calls.calls == []


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


class TestIsSinglePathComponent:
    @pytest.mark.parametrize(
        "name", ["cvelistV5", "vulns.git", ".hidden", "...", "a b", "x-y_z"]
    )
    def test_single_component_is_accepted(self, name: str) -> None:
        assert is_single_path_component(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("", id="empty"),
            pytest.param(".", id="dot"),
            pytest.param("..", id="dot-dot"),
            pytest.param("a/b", id="separator"),
            pytest.param("/abs", id="absolute"),
            pytest.param("trailing/", id="trailing-separator"),
            pytest.param("x\x00y", id="nul"),
            pytest.param(None, id="none"),
            pytest.param(b"bytes", id="bytes"),
            pytest.param(Path("example"), id="path-object"),
            pytest.param(7, id="int"),
        ],
    )
    def test_anything_else_is_rejected(self, name: object) -> None:
        assert is_single_path_component(name) is False


class TestRecoveryBeforeDate:
    @pytest.mark.parametrize(
        ("committed_at", "expected"),
        [
            pytest.param(
                "2024-01-10T00:00:00+00:00", "2024-01-09T00:00:00+00:00", id="utc"
            ),
            pytest.param(
                "2024-01-10T00:00:00Z", "2024-01-09T00:00:00+00:00", id="zulu"
            ),
            pytest.param(
                "2024-01-10T02:30:00+02:00",
                "2024-01-09T00:30:00+00:00",
                id="positive-offset-to-utc",
            ),
            pytest.param(
                "2024-01-09T22:00:00-05:00",
                "2024-01-09T03:00:00+00:00",
                id="negative-offset-to-utc",
            ),
            pytest.param(
                "2024-01-10T00:00:00.999999+00:00",
                "2024-01-09T00:00:00+00:00",
                id="truncated-not-rounded",
            ),
            pytest.param(
                "2024-03-01T00:00:00+00:00", "2024-02-29T00:00:00+00:00", id="leap-day"
            ),
        ],
    )
    def test_usable_value_is_one_day_earlier_in_utc_whole_seconds(
        self, committed_at: str, expected: str
    ) -> None:
        assert recovery_before_date(committed_at) == expected

    @pytest.mark.parametrize(
        "committed_at",
        [
            pytest.param("2024-01-10T00:00:00", id="naive"),
            pytest.param("2024-01-10", id="date-only"),
            pytest.param("", id="empty"),
            pytest.param("yesterday", id="unparseable"),
            pytest.param(None, id="none"),
            pytest.param(1704844800, id="int"),
            pytest.param(datetime(2024, 1, 10, tzinfo=UTC), id="aware-datetime-object"),
            pytest.param("0001-01-01T00:00:00+00:00", id="overflow-minus-one-day"),
            pytest.param("0001-01-01T00:00:00+01:00", id="overflow-to-utc"),
            pytest.param("9999-12-31T23:59:59-01:00", id="overflow-upper-to-utc"),
        ],
    )
    def test_unusable_value_is_none(self, committed_at: object) -> None:
        assert recovery_before_date(committed_at) is None
