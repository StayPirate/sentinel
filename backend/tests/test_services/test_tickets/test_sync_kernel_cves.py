"""Unit tests for the Linux Kernel CNA fetcher class
(backend/app/services/tickets/sync_kernel_cves.py): its delta hooks, its
candidate paths, registration, concrete compliance, and structural
absences.

Owning specifications:

- docs/features/tickets/cve-sync-kernel.md (Fetcher Definition; Algorithm
  steps 1 and 2a; `fetch_single()` Behavior step 1; Work unit and metric
  mapping, pre-scope exclusions).
- docs/features/platform/git-fetcher-infrastructure.md (Class Attributes;
  Template Method: `execute()`; Hook Methods; `filter_delta_files`;
  `deduplicate_items`; `_construct_candidate_paths`, the `ValueError`
  contract; Worker Affinity).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `CVEFetchResult`; CVE Source Type Identity, both registry accessors).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Typed result, Git boundaries, and Concrete compliance, "MITRE and Kernel
  return it from `process_item`").

The ingestion of `process_item()`, the periodic run, and the on-demand and
catch-up wrappers are tested against the real database in
`test_sync_kernel_cves_execute.py` and
`test_sync_kernel_cves_reachability.py`. The repository layout sample is
`tests/support/kernel.py` (`repository_paths()`); every other path and
CVE-ID is fictional. No database, Redis, Git, or network is used.
"""

from __future__ import annotations

import ast
import enum
import inspect
import textwrap
from types import ModuleType
from typing import Final

import pytest
from celery.app.task import Task
from sqlalchemy.orm import DeclarativeBase

import app.services.fetcher_discovery as fetcher_discovery
from app.core.enums import CVESourceType
from app.core.errors import ErrorCode
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    get_catch_up_fetchers,
)
from app.services.base_git_fetcher import BaseGitFetcher
from app.services.tickets import kernel_cve_record
from app.services.tickets import sync_kernel_cves as sync_module
from app.services.tickets.sync_kernel_cves import SyncKernelCves
from tests.support.kernel import RECORD_SOURCES, repository_paths

pytestmark = pytest.mark.unit

NAME: Final = "sync_kernel_cves"
KERNEL: Final = CVESourceType.KERNEL
CVE_ID: Final = "CVE-2099-0001"
PUBLISHED: Final = f"cve/published/2099/{CVE_ID}.json"
REJECTED: Final = f"cve/rejected/2099/{CVE_ID}.json"
OTHER_PUBLISHED: Final = "cve/published/2099/CVE-2099-0002.json"
OTHER_REJECTED: Final = "cve/rejected/2099/CVE-2099-0002.json"
THIRD_PUBLISHED: Final = "cve/published/2098/CVE-2098-0003.json"

SAMPLED_RECORDS: Final = frozenset(
    {
        "cve/published/2019/CVE-2019-25160.json",
        "cve/published/2020/CVE-2020-36791.json",
        "cve/published/2025/CVE-2025-21679.json",
        "cve/published/2026/CVE-2026-43070.json",
        "cve/rejected/2019/CVE-2019-25161.json",
        "cve/rejected/2024/CVE-2024-26701.json",
        "cve/rejected/2025/CVE-2025-68195.json",
    }
)
"""The complete record paths of `repository_paths.txt`, spelled literally."""

EXCLUDED_PATHS: Final = [
    # Every sibling file type of one CVE.
    "cve/published/2099/CVE-2099-0001",
    "cve/published/2099/CVE-2099-0001.sha1",
    "cve/published/2099/CVE-2099-0001.mbox",
    "cve/published/2099/CVE-2099-0001.dyad",
    "cve/published/2099/CVE-2099-0001.vulnerable",
    "cve/published/2099/CVE-2099-0001.reference",
    "cve/published/2099/CVE-2099-0001.cvss",
    "cve/published/2099/CVE-2099-0001.message",
    "cve/rejected/2099/CVE-2099-0001.mbox.rejected",
    "cve/published/2099/.empty",
    "cve/rejected/.empty",
    # Trees outside the two processed directories.
    "cve/reserved/2099/CVE-2099-0001",
    "cve/reserved/2099/x/CVE-2099-100000",
    "cve/reserved/2099/CVE-2099-0001.json",
    "cve/returned/2099/CVE-2099-0001",
    "cve/returned/2099/CVE-2099-0001.json",
    "cve/review/done/gsd/gsd-review.00-fromfile-example",
    "cve/review/proposed/v7.2.9-example",
    "cve/testing/published/2099/CVE-2099-0001.json",
    "cve/testing/rejected/2099/CVE-2099-0001.json",
    # Top-level files.
    "cve/README",
    "cve/schema",
    "cve/vulnerability.txt",
    "cve/CVE_JSON_5.1.1_schema.json",
    "cve/CVE_JSON_5.0_schema.json",
    # A record-shaped path whose year directory or CVE-ID is not canonical.
    "cve/published/2098/CVE-2099-0001.json",
    "cve/published/2099/CVE-2099-001.json",
    "cve/published/2099/CVE-2099-123456789012.json",
    "cve/published/2099/cve-2099-0001.json",
    "cve/published/2099/CVE-2099-0001.JSON",
    "cve/published/2099/CVE-2099-0001.json.orig",
    "cve/published/99/CVE-99-0001.json",
    "cve/published/2099/sub/CVE-2099-0001.json",
    "cve/Published/2099/CVE-2099-0001.json",
    # Non-ASCII digits.
    "cve/published/2099/CVE-2099-\u0661\u0662\u0663\u0664.json",
    "cve/published/\u0662\u0660\u0669\u0669/CVE-\u0662\u0660\u0669\u0669-0001.json",
    # Path syntax variants of a valid record path.
    f"./{PUBLISHED}",
    f"/{PUBLISHED}",
    f"{PUBLISHED}\n",
    f" {PUBLISHED}",
    f"vulns/{PUBLISHED}",
    "",
]


def _fetcher() -> SyncKernelCves:
    return SyncKernelCves()


def _class_body_assignments(cls: type) -> set[str]:
    """The names assigned in `cls`'s own class body (static, from source)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    [class_def] = tree.body
    assert isinstance(class_def, ast.ClassDef)
    names: set[str] = set()
    for node in class_def.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


def _method_names(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if inspect.isfunction(value) or inspect.iscoroutinefunction(value)
    }


def _referenced_names(source: str) -> set[str]:
    """Every identifier and attribute name the source references."""
    tree = ast.parse(textwrap.dedent(source))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


def _imported_modules(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


# ---------------------------------------------------------------------------
# filter_delta_files (Algorithm step 1)
# ---------------------------------------------------------------------------


class TestFilterDeltaFiles:
    def test_sampled_repository_layout_keeps_exactly_the_record_paths(self) -> None:
        sample = repository_paths()

        kept = _fetcher().filter_delta_files(sample)

        assert set(kept) == SAMPLED_RECORDS
        assert kept == [path for path in sample if path in SAMPLED_RECORDS]
        # Every captured record fixture sits at a selected path.
        assert set(RECORD_SOURCES.values()) <= set(kept)

    @pytest.mark.parametrize("path", sorted(set(repository_paths()) - SAMPLED_RECORDS))
    def test_sampled_non_record_path_is_dropped(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == []

    @pytest.mark.parametrize("path", [PUBLISHED, REJECTED, THIRD_PUBLISHED])
    def test_complete_record_path_is_kept(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == [path]

    def test_twenty_character_cve_id_is_the_longest_kept(self) -> None:
        longest = "cve/published/2099/CVE-2099-12345678901.json"
        too_long = "cve/published/2099/CVE-2099-123456789012.json"

        assert _fetcher().filter_delta_files([longest, too_long]) == [longest]

    @pytest.mark.parametrize("path", EXCLUDED_PATHS)
    def test_excluded_path_is_dropped(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == []

    def test_kept_paths_preserve_the_input_order(self) -> None:
        delta = [
            OTHER_REJECTED,
            "cve/published/2099/CVE-2099-0001.sha1",
            THIRD_PUBLISHED,
            "cve/testing/published/2099/CVE-2099-0001.json",
            PUBLISHED,
            OTHER_PUBLISHED,
            REJECTED,
        ]

        kept = _fetcher().filter_delta_files(delta)

        # Both directories of one CVE survive the filter; deduplication is
        # the next hook.
        assert kept == [
            OTHER_REJECTED,
            THIRD_PUBLISHED,
            PUBLISHED,
            OTHER_PUBLISHED,
            REJECTED,
        ]

    def test_empty_delta_stays_empty_and_input_is_not_mutated(self) -> None:
        delta = [PUBLISHED, "cve/README"]

        assert _fetcher().filter_delta_files([]) == []
        assert _fetcher().filter_delta_files(delta) == [PUBLISHED]
        assert delta == [PUBLISHED, "cve/README"]


# ---------------------------------------------------------------------------
# deduplicate_items (Algorithm step 2a)
# ---------------------------------------------------------------------------


class TestDeduplicateItems:
    @pytest.mark.parametrize(
        "delta",
        [[PUBLISHED, REJECTED], [REJECTED, PUBLISHED]],
        ids=["published-first", "rejected-first"],
    )
    def test_rejected_wins_over_published_regardless_of_order(
        self, delta: list[str]
    ) -> None:
        assert _fetcher().deduplicate_items(delta) == [REJECTED]

    def test_distinct_cves_are_untouched_in_their_order(self) -> None:
        delta = [THIRD_PUBLISHED, OTHER_REJECTED, PUBLISHED]

        assert _fetcher().deduplicate_items(delta) == delta

    def test_survivors_keep_their_input_positions(self) -> None:
        delta = [
            PUBLISHED,
            OTHER_PUBLISHED,
            THIRD_PUBLISHED,
            OTHER_REJECTED,
            REJECTED,
        ]

        assert _fetcher().deduplicate_items(delta) == [
            THIRD_PUBLISHED,
            OTHER_REJECTED,
            REJECTED,
        ]

    def test_same_cve_in_different_years_is_not_merged(self) -> None:
        """The CVE-ID, not the file stem position, identifies the unit:
        two CVE-IDs that share a sequence number stay distinct."""
        same_number = "cve/rejected/2098/CVE-2098-0001.json"

        assert _fetcher().deduplicate_items([PUBLISHED, same_number]) == [
            PUBLISHED,
            same_number,
        ]

    def test_is_idempotent(self) -> None:
        delta = [PUBLISHED, OTHER_REJECTED, REJECTED, OTHER_PUBLISHED]
        once = _fetcher().deduplicate_items(delta)

        assert once == [OTHER_REJECTED, REJECTED]
        assert _fetcher().deduplicate_items(once) == once

    def test_empty_list_stays_empty(self) -> None:
        assert _fetcher().deduplicate_items([]) == []

    def test_only_record_paths_are_selected(self) -> None:
        """The hook receives filtered paths only; a non-record path never
        becomes a work unit even when passed directly."""
        delta = ["cve/README", PUBLISHED, "cve/published/2099/CVE-2099-0001.sha1"]

        assert _fetcher().deduplicate_items(delta) == [PUBLISHED]

    def test_composes_with_the_filter_into_one_unit_per_cve(self) -> None:
        fetcher = _fetcher()
        delta = [
            PUBLISHED,
            "cve/published/2099/CVE-2099-0001.mbox",
            REJECTED,
            "cve/rejected/2099/CVE-2099-0001.mbox.rejected",
            OTHER_PUBLISHED,
        ]

        selected = fetcher.deduplicate_items(fetcher.filter_delta_files(delta))

        assert selected == [REJECTED, OTHER_PUBLISHED]


# ---------------------------------------------------------------------------
# _construct_candidate_paths (fetch_single() step 1)
# ---------------------------------------------------------------------------


class TestConstructCandidatePaths:
    @pytest.mark.parametrize(
        ("cve_id", "year"),
        [
            ("CVE-2099-0001", "2099"),
            ("CVE-2024-26701", "2024"),
            ("CVE-2026-12345678901", "2026"),
        ],
    )
    def test_published_then_rejected_for_a_canonical_id(
        self, cve_id: str, year: str
    ) -> None:
        assert _fetcher()._construct_candidate_paths(cve_id) == [
            f"cve/published/{year}/{cve_id}.json",
            f"cve/rejected/{year}/{cve_id}.json",
        ]

    @pytest.mark.parametrize("cve_id", ["CVE-2099-0001", "CVE-2024-26701"])
    def test_candidates_are_selected_record_paths(self, cve_id: str) -> None:
        fetcher = _fetcher()
        candidates = fetcher._construct_candidate_paths(cve_id)

        for path in candidates:
            match = kernel_cve_record.RECORD_PATH_PATTERN.fullmatch(path)
            assert match is not None
            assert match["cve_id"] == cve_id
        assert fetcher.filter_delta_files(candidates) == candidates
        assert fetcher.deduplicate_items(candidates) == [candidates[1]]

    @pytest.mark.parametrize(
        "item_id",
        [
            "",
            "cve-2099-0001",
            "CVE-24-1",
            "CVE-2099-001",
            "CVE-2099-123456789012",
            "CVE-2099-0001/../CVE-2099-0002",
            "../CVE-2099-0001",
            "CVE-2099-0001/",
            "cve/published/2099/CVE-2099-0001.json",
            "CVE-2099-0001\n",
            " CVE-2099-0001",
            "CVE-2099-\u0661\u0662\u0663\u0664",
            "None",
            "null",
            "CVE",
            "CVE-2099",
            "GHSA-xxxx-xxxx-xxxx",
        ],
    )
    def test_malformed_value_raises_value_error(self, item_id: str) -> None:
        with pytest.raises(ValueError, match="canonical CVE-ID") as raised:
            _fetcher()._construct_candidate_paths(item_id)

        assert type(raised.value) is ValueError


# ---------------------------------------------------------------------------
# Discovery, registration, and capability
# ---------------------------------------------------------------------------


class TestRegistrationAndCapability:
    def test_discovery_imports_the_module(self) -> None:
        assert sync_module.__name__ in _imported_modules(fetcher_discovery)
        assert SyncKernelCves.__module__ == "app.services.tickets.sync_kernel_cves"

    def test_properties_match_the_specification(self) -> None:
        assert SyncKernelCves.name == NAME
        assert SyncKernelCves.cve_source_type is KERNEL
        assert SyncKernelCves.cve_source_type.value == "kernel"
        assert SyncKernelCves.description == (
            "Sync CVE data from the Linux Kernel CNA vulnerability repository"
        )
        assert SyncKernelCves.default_schedule == "0 */3 * * *"
        assert SyncKernelCves.default_request_delay == 0
        assert SyncKernelCves.source_reference_url_pattern is None

    def test_git_attributes_match_the_specification(self) -> None:
        assert SyncKernelCves.repo_url == (
            "https://git.kernel.org/pub/scm/linux/security/vulns.git"
        )
        assert SyncKernelCves.clone_dir_name == "vulns.git"
        assert SyncKernelCves.delta_path_prefix == "cve/"
        assert SyncKernelCves.recovery_path_prefix == "cve/"
        assert SyncKernelCves.clone_filter is None
        assert SyncKernelCves.clone_single_branch is True

    def test_class_body_declares_exactly_the_fetcher_definition(self) -> None:
        """No `queue`, `abstract`, `Settings`, `clone_filter`,
        `clone_single_branch`, or capability flag in the class body
        (cve-sync-kernel.md, Fetcher Definition; Custom settings: No)."""
        assert _class_body_assignments(SyncKernelCves) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "source_reference_url_pattern",
            "repo_url",
            "clone_dir_name",
            "delta_path_prefix",
            "recovery_path_prefix",
        }

    def test_queue_and_clone_options_are_inherited(self) -> None:
        assert SyncKernelCves.queue == "git"
        for inherited in (
            "queue",
            "clone_filter",
            "clone_single_branch",
            "Settings",
            "http_client_options",
        ):
            assert inherited not in SyncKernelCves.__dict__, inherited
        assert SyncKernelCves.Settings is None

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncKernelCves.supports_fetch_single is True
        assert SyncKernelCves.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncKernelCves.__dict__
        assert "abstract" not in SyncKernelCves.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncKernelCves.__name__ == "SyncKernelCves"

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncKernelCves
        assert _CVE_SOURCE_TYPE_MAP[KERNEL] is SyncKernelCves
        assert get_all_cve_source_types()["kernel"] is SyncKernelCves

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["kernel"] is SyncKernelCves
        assert get_catch_up_fetchers()[NAME] is SyncKernelCves


# ---------------------------------------------------------------------------
# Concrete compliance (testing-strategy.md, CVE Fetcher Infrastructure)
# ---------------------------------------------------------------------------


class TestConcreteCompliance:
    def test_only_the_four_hooks_are_implemented(self) -> None:
        assert _method_names(SyncKernelCves) == {
            "filter_delta_files",
            "deduplicate_items",
            "_construct_candidate_paths",
            "process_item",
        }

    def test_template_and_finalization_are_inherited(self) -> None:
        assert SyncKernelCves.execute is BaseGitFetcher.execute
        assert SyncKernelCves.fetch_single is BaseGitFetcher.fetch_single
        assert SyncKernelCves.catch_up is BaseCVEFetcher.catch_up
        assert SyncKernelCves.commit_and_dispatch is BaseCVEFetcher.commit_and_dispatch
        assert (
            SyncKernelCves._isolated_status_commit
            is BaseCVEFetcher._isolated_status_commit
        )
        assert SyncKernelCves.run is BaseFetcher.run
        for inherited in (
            "execute",
            "fetch_single",
            "catch_up",
            "commit_and_dispatch",
            "_isolated_status_commit",
            "run",
        ):
            assert inherited not in SyncKernelCves.__dict__, inherited

    def test_process_item_is_async_and_returns_the_typed_token(self) -> None:
        assert inspect.iscoroutinefunction(SyncKernelCves.process_item)
        annotations = inspect.get_annotations(
            SyncKernelCves.process_item, eval_str=True
        )

        assert annotations["return"] is CVEFetchResult

    def test_process_item_returns_the_token_without_finalizing(self) -> None:
        """`process_item()` builds `CVEFetchResult`, never commits, finalizes,
        or records a metric, and never delegates to `fetch_single()`."""
        names = _referenced_names(inspect.getsource(SyncKernelCves.process_item))

        assert {
            "CVEFetchResult",
            "map_record",
            "upsert_cve",
            "upsert_references",
            "build_post_ingest_tasks",
        } <= names
        assert (
            not {
                "commit",
                "rollback",
                "flush",
                "commit_and_dispatch",
                "fetch_single",
                "record_succeeded",
                "record_failed",
                "record_created",
                "record_updated",
                "_isolated_status_commit",
            }
            & names
        )

    def test_hooks_are_synchronous_and_pure(self) -> None:
        for hook in (
            SyncKernelCves.filter_delta_files,
            SyncKernelCves.deduplicate_items,
            SyncKernelCves._construct_candidate_paths,
        ):
            assert not inspect.iscoroutinefunction(hook), hook.__name__

    def test_no_base_class_member_is_added(self) -> None:
        for name in ("_record_cve_id", "_REJECTED_DIRECTORY", "_RECORD_DIRECTORIES"):
            assert not hasattr(BaseGitFetcher, name), name
            assert not hasattr(BaseCVEFetcher, name), name


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


class TestStructuralAbsences:
    def test_defines_no_task_model_or_enum(self) -> None:
        own = [
            value
            for value in vars(sync_module).values()
            if getattr(value, "__module__", None) == sync_module.__name__
        ]

        assert not [
            value for value in vars(sync_module).values() if isinstance(value, Task)
        ]
        assert not [
            value
            for value in own
            if isinstance(value, type)
            and issubclass(value, (DeclarativeBase, enum.Enum))
        ]
        assert [value for value in own if isinstance(value, type)] == [SyncKernelCves]

    def test_touches_no_redis_task_api_or_configuration_layer(self) -> None:
        imported = _imported_modules(sync_module)

        forbidden = {
            name
            for name in imported
            if name in ("app.celery_app", "app.config", "app.database")
            or name.split(".")[0] in ("redis", "httpx", "celery", "subprocess")
            or name.startswith(("app.tasks", "app.api", "app.schemas", "app.models"))
        }
        assert forbidden == set()

    def test_raises_no_api_facing_error(self) -> None:
        names = _referenced_names(inspect.getsource(sync_module))

        assert not {"ErrorCode", "ServiceError", "HTTPException", "logger"} & names
        assert not [name for name in names if name.endswith("ServiceError")]

    def test_no_route_task_or_error_code_names_the_source(self) -> None:
        from app.celery_app import celery_app
        from app.main import app as api

        paths = [getattr(route, "path", "") for route in api.routes]
        assert paths
        assert not [path for path in paths if "kernel" in path.lower()]
        assert not [name for name in celery_app.tasks if "kernel" in name.lower()]
        assert not [
            member
            for member in ErrorCode
            if "KERNEL" in member.name or "VULNS" in member.name
        ]
