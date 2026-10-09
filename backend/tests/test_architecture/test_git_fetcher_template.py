"""Structural test: every production `BaseGitFetcher` subclass follows the
template contract.

See `docs/features/platform/testing-strategy.md` (Structural Tests table,
row "Git fetcher template") and
`docs/features/platform/git-fetcher-infrastructure.md` (Class Attributes;
Template Method: `execute()`; Hook Methods; Inherited Utility Methods,
`_repo_path()`; Concurrency Rules, rule 5).

`BaseGitFetcher` defines no `__init_subclass__` of its own, so registration
does not enforce the template; this test is the enforcement point. After
the production discovery import, every concrete `BaseGitFetcher` subclass
in `FETCHER_REGISTRY` must inherit `execute()` and `queue = "git"`
unchanged, implement `process_item()` and `_construct_candidate_paths()`,
declare `repo_url`, `delta_path_prefix`, and `recovery_path_prefix` as
non-empty strings, and declare `clone_dir_name` as a single path component
that no other production Git fetcher uses.

The checks are a pure function over a list of classes returning the
violations. Applied to production it checks every Git fetcher discovery
imports, so a new production Git fetcher is checked as soon as discovery
imports it. The self-test defines one violating class per check under
`isolated_fetcher_registries` and proves each is detected, and that a
compliant class has no violation. A new exception is a reviewed change to
the contract, not a workaround.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.fetcher_discovery  # noqa: F401 — production discovery
from app.core.enums import CVESourceType
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
)
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.base_git_fetcher import BaseGitFetcher, is_single_path_component
from app.services.cve_ingest import UpsertAction

_NON_EMPTY_STRINGS = ("repo_url", "delta_path_prefix", "recovery_path_prefix")


def git_fetchers(
    registry: Mapping[str, type[BaseFetcher]],
) -> list[type[BaseGitFetcher]]:
    """Every `BaseGitFetcher` subclass in `registry`, ordered by name."""
    return [
        cls
        for _, cls in sorted(registry.items())
        if isinstance(cls, type) and issubclass(cls, BaseGitFetcher)
    ]


def template_violations(classes: Iterable[type[BaseGitFetcher]]) -> list[str]:
    """One message per template rule each class breaks, plus one per
    `clone_dir_name` shared by more than one class."""
    violations: list[str] = []
    by_clone_dir: defaultdict[str, list[str]] = defaultdict(list)
    for cls in classes:
        name = cls.__name__
        if "execute" in cls.__dict__ or cls.execute is not BaseGitFetcher.execute:
            violations.append(f"{name} overrides execute()")
        if "queue" in cls.__dict__ or cls.queue != "git":
            violations.append(f"{name} does not inherit queue = 'git' unchanged")
        if cls.process_item is BaseGitFetcher.process_item:
            violations.append(f"{name} does not implement process_item()")
        if cls._construct_candidate_paths is BaseGitFetcher._construct_candidate_paths:
            violations.append(f"{name} does not implement _construct_candidate_paths()")
        for attribute in _NON_EMPTY_STRINGS:
            value = getattr(cls, attribute, None)
            if not isinstance(value, str) or not value:
                violations.append(f"{name}.{attribute} is not a non-empty string")
        clone_dir_name = getattr(cls, "clone_dir_name", None)
        if is_single_path_component(clone_dir_name):
            by_clone_dir[cast(str, clone_dir_name)].append(name)
        else:
            violations.append(f"{name}.clone_dir_name is not a single path component")
    for clone_dir_name, names in sorted(by_clone_dir.items()):
        if len(names) > 1:
            violations.append(
                f"clone_dir_name {clone_dir_name!r} is shared by {', '.join(names)}"
            )
    return violations


@pytest.mark.unit
class TestProductionGitFetchers:
    def test_every_production_git_fetcher_follows_the_template(self) -> None:
        """Discovery has populated the registry, and every production Git
        fetcher in it follows the template."""
        assert FETCHER_REGISTRY, "production discovery registered no fetcher"

        assert template_violations(git_fetchers(FETCHER_REGISTRY)) == []


# ---------------------------------------------------------------------------
# Self-test: each check detects a violating class
# ---------------------------------------------------------------------------


async def _process_item(
    self: BaseGitFetcher, path: str, content: bytes, session: AsyncSession
) -> CVEFetchResult:
    return CVEFetchResult(UpsertAction.UNCHANGED, None)


def _candidate_paths(self: BaseGitFetcher, item_id: str) -> list[str]:
    return [f"cves/{item_id}.json"]


async def _execute(self: BaseGitFetcher, session: AsyncSession) -> None:
    return None


def _compliant_namespace() -> dict[str, Any]:
    name = f"test_git_template_{uuid4().hex}"
    return {
        "name": name,
        "description": "Test-only Git CVE fetcher",
        "default_schedule": "0 * * * *",
        "repo_url": "https://git.example.test/example-cves.git",
        "clone_dir_name": name,
        "delta_path_prefix": "cves/",
        "recovery_path_prefix": "cves/",
        "process_item": _process_item,
        "_construct_candidate_paths": _candidate_paths,
    }


_ABSENT = object()
"""Marks an attribute removed from the compliant namespace."""


def _define(
    class_name: str,
    source: CVESourceType,
    *,
    base: type[BaseGitFetcher] = BaseGitFetcher,
    **overrides: Any,
) -> type[BaseGitFetcher]:
    """Register one Git fetcher: the compliant namespace with `overrides`
    applied (`_ABSENT` removes an attribute)."""
    namespace = _compliant_namespace()
    namespace["cve_source_type"] = source
    for attribute, value in overrides.items():
        if value is _ABSENT:
            namespace.pop(attribute)
        else:
            namespace[attribute] = value
    return cast(type[BaseGitFetcher], type(class_name, (base,), namespace))


@pytest.fixture
def _unowned_source_types(isolated_fetcher_registries: None) -> None:
    """Every `CVESourceType` starts unowned; teardown restores both
    registries."""
    owners = set(_CVE_SOURCE_TYPE_MAP.values())
    _CVE_SOURCE_TYPE_MAP.clear()
    for name in [name for name, cls in FETCHER_REGISTRY.items() if cls in owners]:
        del FETCHER_REGISTRY[name]


class _ExecuteOverridingIntermediate(BaseGitFetcher):
    abstract = True

    async def execute(self, session: AsyncSession) -> None:
        return None


_VIOLATIONS = [
    pytest.param({"execute": _execute}, "overrides execute()", id="execute-override"),
    pytest.param(
        {"execute": BaseGitFetcher.execute},
        "overrides execute()",
        id="execute-redeclared",
    ),
    pytest.param(
        {"queue": "git"}, "does not inherit queue = 'git'", id="queue-redeclared"
    ),
    pytest.param(
        {"queue": "general"}, "does not inherit queue = 'git'", id="queue-changed"
    ),
    pytest.param(
        {"process_item": _ABSENT}, "does not implement process_item()", id="no-process"
    ),
    pytest.param(
        {"_construct_candidate_paths": _ABSENT},
        "does not implement _construct_candidate_paths()",
        id="no-candidate-paths",
    ),
    pytest.param(
        {"repo_url": _ABSENT}, "repo_url is not a non-empty string", id="no-repo-url"
    ),
    pytest.param(
        {"repo_url": ""}, "repo_url is not a non-empty string", id="empty-repo-url"
    ),
    pytest.param(
        {"delta_path_prefix": ""},
        "delta_path_prefix is not a non-empty string",
        id="empty-delta-prefix",
    ),
    pytest.param(
        {"delta_path_prefix": None},
        "delta_path_prefix is not a non-empty string",
        id="none-delta-prefix",
    ),
    pytest.param(
        {"recovery_path_prefix": _ABSENT},
        "recovery_path_prefix is not a non-empty string",
        id="no-recovery-prefix",
    ),
    pytest.param(
        {"recovery_path_prefix": b"cves/"},
        "recovery_path_prefix is not a non-empty string",
        id="bytes-recovery-prefix",
    ),
    pytest.param(
        {"clone_dir_name": _ABSENT},
        "clone_dir_name is not a single path component",
        id="no-clone-dir",
    ),
    *(
        pytest.param(
            {"clone_dir_name": value},
            "clone_dir_name is not a single path component",
            id=f"clone-dir-{label}",
        )
        for label, value in [
            ("empty", ""),
            ("dot", "."),
            ("dot-dot", ".."),
            ("separator", "a/b"),
            ("absolute", "/abs"),
            ("nul", "x\x00y"),
        ]
    ),
]


@pytest.mark.unit
@pytest.mark.usefixtures("_unowned_source_types")
class TestTemplateChecks:
    def test_compliant_class_has_no_violation_and_is_selected(self) -> None:
        compliant = _define("CompliantGitFetcher", CVESourceType.MITRE)
        plain_cve = cast(
            type[BaseCVEFetcher],
            type(
                "PlainCveFetcher",
                (BaseCVEFetcher,),
                {
                    "name": f"test_git_template_{uuid4().hex}",
                    "description": "Test-only CVE fetcher",
                    "default_schedule": "0 * * * *",
                    "cve_source_type": CVESourceType.NVD,
                    "supports_fetch_single": False,
                    "execute": _execute,
                },
            ),
        )

        selected = git_fetchers(FETCHER_REGISTRY)

        assert compliant in selected
        assert plain_cve not in selected
        assert template_violations([compliant]) == []

    @pytest.mark.parametrize(("overrides", "expected"), _VIOLATIONS)
    def test_each_violation_is_detected(
        self, overrides: dict[str, Any], expected: str
    ) -> None:
        violating = _define("ViolatingGitFetcher", CVESourceType.MITRE, **overrides)

        assert violating in git_fetchers(FETCHER_REGISTRY)
        violations = template_violations([violating])

        assert len(violations) == 1
        assert violations[0].startswith("ViolatingGitFetcher")
        assert expected in violations[0]

    def test_execute_inherited_from_an_overriding_intermediate_is_detected(
        self,
    ) -> None:
        violating = _define(
            "IndirectGitFetcher",
            CVESourceType.MITRE,
            base=_ExecuteOverridingIntermediate,
        )

        assert template_violations([violating]) == [
            "IndirectGitFetcher overrides execute()"
        ]

    def test_shared_clone_dir_name_is_detected(self) -> None:
        first = _define(
            "FirstGitFetcher", CVESourceType.MITRE, clone_dir_name="shared.git"
        )
        second = _define(
            "SecondGitFetcher", CVESourceType.KERNEL, clone_dir_name="shared.git"
        )
        third = _define("ThirdGitFetcher", CVESourceType.GHSA)

        assert template_violations([first, second, third]) == [
            "clone_dir_name 'shared.git' is shared by FirstGitFetcher, SecondGitFetcher"
        ]
        assert template_violations([first, third]) == []
