"""Tests for the BaseCVEFetcher registry core, `CVENotInSource`, and
`CVEFetchResult` (backend/app/services/base_cve_fetcher.py).

See `docs/features/platform/cve-fetcher-infrastructure.md` (BaseCVEFetcher
Class; `CVEFetchResult`; CVE-ID Format Validation Helper;
`__init_subclass__` Validation, including Atomic cross-registry
registration and Test isolation; `CVENotInSource` Signal; CVE Source Type
Identity and both registry accessors; Class Attributes, the
`participates_in_catch_up` auto-derivation and rule 5) for the contract
under test, `docs/features/platform/fetcher-infrastructure.md`
(Import-time validation, rules 7-8), and
`docs/features/platform/testing-strategy.md` (CVE Fetcher Infrastructure —
Atomic registration and isolation).

Every test is a pure unit test: test-only fetcher classes are defined
inside the test body under the shared `isolated_fetcher_registries`
fixture, which snapshots and restores both `FETCHER_REGISTRY` and
`_CVE_SOURCE_TYPE_MAP`. Classes are built with `type()` so each failing
definition is a single statement inside `pytest.raises`.

Out of scope: `commit_and_dispatch()` and `_isolated_status_commit()`
(real PostgreSQL, `tests/test_services/test_cve_fetcher_finalization.py`)
and the default `catch_up()` workflow.
"""

from __future__ import annotations

import dataclasses
import typing
import warnings
from collections.abc import Callable
from enum import StrEnum
from types import MappingProxyType
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

import app.services.base_cve_fetcher as base_cve_fetcher_module
from app.core.enums import CVESourceType
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherError,
    get_catch_up_fetchers,
)
from app.services.cve_ingest import PostIngestTasks, UpsertAction

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("isolated_fetcher_registries")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _execute_stub(self: BaseFetcher, session: AsyncSession) -> None:
    return None


async def _fetch_single_stub(
    self: BaseCVEFetcher, cve_id: str, session: AsyncSession
) -> CVEFetchResult:
    return CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)


def _unique_name() -> str:
    """A fetcher name matching `^[a-z][a-z0-9_]*$`, unique per call."""
    return f"test_cve_fetcher_{uuid4().hex}"


def _define(
    class_name: str, *, base: type[BaseFetcher] = BaseCVEFetcher, **attrs: Any
) -> type[BaseCVEFetcher]:
    """Define one fetcher class with valid generic attributes.

    `attrs` overrides or extends the defaults; `cve_source_type` is never
    defaulted, so a definition omitting it exercises rule 1.
    """
    namespace: dict[str, Any] = {
        "name": _unique_name(),
        "description": "Test-only CVE fetcher",
        "default_schedule": "0 * * * *",
        "execute": _execute_stub,
    }
    namespace.update(attrs)
    return cast(type[BaseCVEFetcher], type(class_name, (base,), namespace))


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


class _ForeignSource(StrEnum):
    """A different Enum whose member value equals a `CVESourceType` value."""

    NVD = "nvd"


# ---------------------------------------------------------------------------
# Rules 1-3: cve_source_type
# ---------------------------------------------------------------------------


class TestCVESourceTypeValidation:
    def test_missing_cve_source_type_raises_exact_message(self) -> None:
        error = _assert_rejected_atomically(
            lambda: _define("MissingSourceFetcher", supports_fetch_single=False),
            match="must declare cve_source_type",
        )

        assert str(error) == (
            "MissingSourceFetcher must declare cve_source_type as a "
            "CVESourceType enum member"
        )

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("nvd", id="raw-string-equal-to-enum-value"),
            pytest.param(1, id="int"),
            pytest.param(None, id="none"),
            pytest.param(_ForeignSource.NVD, id="other-enum-member"),
        ],
    )
    def test_non_member_cve_source_type_raises(self, value: object) -> None:
        _assert_rejected_atomically(
            lambda: _define(
                "NonMemberSourceFetcher",
                cve_source_type=value,
                supports_fetch_single=False,
            ),
            match="cve_source_type must be a CVESourceType enum member",
        )

    def test_duplicate_cve_source_type_raises_and_keeps_first_owner(self) -> None:
        first = _define(
            "FirstNvdFetcher",
            cve_source_type=CVESourceType.NVD,
            supports_fetch_single=False,
        )

        error = _assert_rejected_atomically(
            lambda: _define(
                "SecondNvdFetcher",
                cve_source_type=CVESourceType.NVD,
                supports_fetch_single=False,
            ),
            match="already registered by FirstNvdFetcher",
        )

        assert "SecondNvdFetcher" in str(error)
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.NVD] is first
        assert FETCHER_REGISTRY[first.name] is first


# ---------------------------------------------------------------------------
# Rule 4: fetch_single capability
# ---------------------------------------------------------------------------


class TestFetchSingleCapabilityValidation:
    def test_supports_fetch_single_true_with_base_safety_net_raises(self) -> None:
        _assert_rejected_atomically(
            lambda: _define(
                "SafetyNetFetcher",
                cve_source_type=CVESourceType.MITRE,
                supports_fetch_single=True,
            ),
            match="supports_fetch_single=True but does not implement fetch_single",
        )

    def test_supports_fetch_single_default_with_base_safety_net_raises(
        self,
    ) -> None:
        """The inherited default (`True`) is subject to the same rule."""
        _assert_rejected_atomically(
            lambda: _define(
                "DefaultCapabilityFetcher", cve_source_type=CVESourceType.OSV
            ),
            match="does not implement fetch_single",
        )

    def test_implementation_inherited_from_abstract_intermediate_registers(
        self,
    ) -> None:
        intermediate = _define(
            "TestOnlyIntermediate",
            abstract=True,
            fetch_single=_fetch_single_stub,
        )

        concrete = _define(
            "InheritedImplementationFetcher",
            base=intermediate,
            cve_source_type=CVESourceType.KERNEL,
        )

        assert concrete.supports_fetch_single is True
        assert concrete.fetch_single is not BaseCVEFetcher.fetch_single
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.KERNEL] is concrete
        assert FETCHER_REGISTRY[concrete.name] is concrete

    def test_own_implementation_registers(self) -> None:
        concrete = _define(
            "OwnImplementationFetcher",
            cve_source_type=CVESourceType.GHSA,
            fetch_single=_fetch_single_stub,
        )

        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.GHSA] is concrete

    def test_supports_fetch_single_false_inheriting_safety_net_registers(
        self,
    ) -> None:
        concrete = _define(
            "CatalogFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
        )

        assert concrete.fetch_single is BaseCVEFetcher.fetch_single
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.KEV] is concrete
        assert FETCHER_REGISTRY[concrete.name] is concrete


# ---------------------------------------------------------------------------
# Atomic cross-registry registration
# ---------------------------------------------------------------------------


class TestAtomicRegistration:
    def test_successful_definition_registers_in_both_registries(self) -> None:
        before_fetchers, before_sources = _snapshot()

        concrete = _define(
            "RegisteredFetcher",
            cve_source_type=CVESourceType.EPSS,
            supports_fetch_single=False,
        )

        assert _snapshot() == (
            {**before_fetchers, concrete.name: concrete},
            {**before_sources, CVESourceType.EPSS: concrete},
        )

    def test_abstract_subclass_registers_in_neither_registry(self) -> None:
        before = _snapshot()

        _define(
            "AbstractCveIntermediate",
            abstract=True,
            cve_source_type=CVESourceType.REDHAT,
        )

        assert _snapshot() == before

    def test_base_cve_fetcher_is_registered_in_neither_registry(self) -> None:
        assert BaseCVEFetcher not in FETCHER_REGISTRY.values()
        assert BaseCVEFetcher not in _CVE_SOURCE_TYPE_MAP.values()

    def test_invalid_schedule_leaves_both_registries_unchanged(self) -> None:
        _assert_rejected_atomically(
            lambda: _define(
                "InvalidScheduleFetcher",
                cve_source_type=CVESourceType.NVD,
                supports_fetch_single=False,
                default_schedule="not a cron",
            ),
            match="default_schedule",
        )

    def test_missing_execute_leaves_both_registries_unchanged(self) -> None:
        _assert_rejected_atomically(
            lambda: _define(
                "NoExecuteFetcher",
                cve_source_type=CVESourceType.NVD,
                supports_fetch_single=False,
                execute=BaseFetcher.execute,
            ),
            match="must override execute",
        )

    def test_invalid_name_leaves_both_registries_unchanged(self) -> None:
        _assert_rejected_atomically(
            lambda: _define(
                "InvalidNameFetcher",
                name="Invalid-Name",
                cve_source_type=CVESourceType.NVD,
                supports_fetch_single=False,
            ),
            match="name must match",
        )

    def test_duplicate_name_of_cve_fetcher_leaves_no_orphan_source(self) -> None:
        first = _define(
            "FirstNamedFetcher",
            cve_source_type=CVESourceType.NVD,
            supports_fetch_single=False,
        )

        _assert_rejected_atomically(
            lambda: _define(
                "SameNameFetcher",
                name=first.name,
                cve_source_type=CVESourceType.MITRE,
                supports_fetch_single=False,
            ),
            match="already registered by FirstNamedFetcher",
        )

        assert CVESourceType.MITRE not in _CVE_SOURCE_TYPE_MAP
        assert FETCHER_REGISTRY[first.name] is first

    def test_duplicate_name_of_plain_fetcher_leaves_no_orphan_source(self) -> None:
        plain = _define_plain("PlainNamedFetcher")

        _assert_rejected_atomically(
            lambda: _define(
                "CveSameNameFetcher",
                name=plain.name,
                cve_source_type=CVESourceType.NVD,
                supports_fetch_single=False,
            ),
            match="already registered by PlainNamedFetcher",
        )

        assert CVESourceType.NVD not in _CVE_SOURCE_TYPE_MAP
        assert FETCHER_REGISTRY[plain.name] is plain


# ---------------------------------------------------------------------------
# Registry accessors
# ---------------------------------------------------------------------------


class TestRegistryAccessors:
    def test_accessors_key_by_enum_value_strings_and_map_to_classes(self) -> None:
        _CVE_SOURCE_TYPE_MAP.clear()
        nvd = _define(
            "AccessorNvdFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )

        for accessor in (get_fetch_single_fetchers, get_all_cve_source_types):
            result = accessor()
            assert result == {"nvd": nvd}
            assert all(type(key) is str for key in result)

    def test_accessors_return_fresh_plain_dicts(self) -> None:
        _CVE_SOURCE_TYPE_MAP.clear()
        nvd = _define(
            "FreshDictFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )

        for accessor in (get_fetch_single_fetchers, get_all_cve_source_types):
            first = accessor()
            second = accessor()
            assert type(first) is dict
            assert not isinstance(first, MappingProxyType)
            assert first is not second

            first.clear()
            first["intruder"] = nvd

            assert accessor() == {"nvd": nvd}
            assert dict(_CVE_SOURCE_TYPE_MAP) == {CVESourceType.NVD: nvd}

    def test_fetch_single_fetchers_is_strict_subset_of_all_source_types(
        self,
    ) -> None:
        _CVE_SOURCE_TYPE_MAP.clear()
        nvd = _define(
            "SubsetNvdFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )
        kev = _define(
            "SubsetKevFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
        )

        fetch_single = get_fetch_single_fetchers()
        all_sources = get_all_cve_source_types()

        assert fetch_single == {"nvd": nvd}
        assert all_sources == {"nvd": nvd, "kev": kev}
        assert fetch_single.items() < all_sources.items()

    def test_empty_registry_returns_empty_dicts(self) -> None:
        _CVE_SOURCE_TYPE_MAP.clear()

        assert get_fetch_single_fetchers() == {}
        assert get_all_cve_source_types() == {}


# ---------------------------------------------------------------------------
# Concrete methods
# ---------------------------------------------------------------------------


def _catalog_instance() -> BaseCVEFetcher:
    """An instance of a registered fetcher that inherits the safety net."""
    fetcher_cls = _define(
        "InstanceCatalogFetcher",
        cve_source_type=CVESourceType.KEV,
        supports_fetch_single=False,
    )
    return fetcher_cls()


class TestIsValidCveIdHelper:
    def test_delegates_to_core_predicate_and_passes_result_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fetcher = _catalog_instance()
        calls: list[str] = []

        def _spy(value: object) -> bool:
            calls.append(cast(str, value))
            # Deliberately the opposite of the real predicate for a
            # canonical CVE-ID, proving no logic of the wrapper's own.
            return False

        monkeypatch.setattr(base_cve_fetcher_module, "is_valid_cve_id", _spy)

        assert fetcher._is_valid_cve_id("CVE-2024-12345") is False
        assert calls == ["CVE-2024-12345"]

    @pytest.mark.parametrize(
        ("cve_id", "expected"),
        [
            pytest.param("CVE-2024-1234", True, id="four-digit-sequence"),
            pytest.param("CVE-2024-12345678901", True, id="twenty-characters"),
            pytest.param("CVE-2024-123456789012", False, id="twenty-one-characters"),
            pytest.param("CVE-2024-123", False, id="three-digit-sequence"),
            pytest.param("cve-2024-1234", False, id="lowercase-prefix"),
            pytest.param("CVE-2024-1234\n", False, id="trailing-newline"),
            pytest.param("", False, id="empty"),
        ],
    )
    def test_examples_match_core_predicate(self, cve_id: str, expected: bool) -> None:
        assert _catalog_instance()._is_valid_cve_id(cve_id) is expected


class TestBaseFetchSingle:
    async def test_base_fetch_single_raises_runtime_error(self) -> None:
        fetcher = _catalog_instance()

        with pytest.raises(RuntimeError) as exc_info:
            await fetcher.fetch_single("CVE-2024-1234", cast(AsyncSession, object()))

        assert str(exc_info.value) == (
            "fetch_single() called on a fetcher that does not support it"
        )


async def _custom_catch_up(
    self: BaseCVEFetcher, ticket_id: str, session: AsyncSession
) -> None:
    return None


class TestCatchUpParticipation:
    def test_base_cve_fetcher_declares_participation_true(self) -> None:
        assert BaseCVEFetcher.participates_in_catch_up is True
        assert BaseFetcher.participates_in_catch_up is False

    def test_supports_fetch_single_true_derives_participation_true(self) -> None:
        concrete = _define(
            "DerivedParticipatingFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )

        assert concrete.supports_fetch_single is True
        assert concrete.participates_in_catch_up is True

    def test_supports_fetch_single_false_derives_participation_false(self) -> None:
        concrete = _define(
            "DerivedNonParticipatingFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
        )

        assert concrete.participates_in_catch_up is False

    def test_explicit_true_overrides_derivation_with_custom_catch_up(
        self,
    ) -> None:
        concrete = _define(
            "ExplicitParticipatingFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
            participates_in_catch_up=True,
            catch_up=_custom_catch_up,
        )

        assert concrete.participates_in_catch_up is True
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.KEV] is concrete
        assert FETCHER_REGISTRY[concrete.name] is concrete

    def test_explicit_false_overrides_derivation(self) -> None:
        concrete = _define(
            "ExplicitNonParticipatingFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
            participates_in_catch_up=False,
        )

        assert concrete.supports_fetch_single is True
        assert concrete.participates_in_catch_up is False
        assert concrete.name not in get_catch_up_fetchers()

    def test_derivation_follows_an_inherited_supports_fetch_single(self) -> None:
        """The derivation reads the resolved capability, including one
        inherited from an abstract intermediate class."""
        intermediate = _define(
            "CatalogIntermediate", abstract=True, supports_fetch_single=False
        )

        concrete = _define(
            "InheritedCatalogFetcher",
            base=intermediate,
            cve_source_type=CVESourceType.EPSS,
        )

        assert concrete.participates_in_catch_up is False


class TestCatchUpCapabilityValidation:
    """Rule 5: catch-up participation without fetch-single support needs a
    custom `catch_up()`."""

    def test_participation_without_fetch_single_or_override_raises(self) -> None:
        error = _assert_rejected_atomically(
            lambda: _define(
                "UnsupportedCatchUpFetcher",
                cve_source_type=CVESourceType.KEV,
                supports_fetch_single=False,
                participates_in_catch_up=True,
            ),
            match="does not override catch_up",
        )

        assert str(error) == (
            "UnsupportedCatchUpFetcher sets participates_in_catch_up=True with "
            "supports_fetch_single=False but does not override catch_up()"
        )

    def test_participation_without_fetch_single_with_override_registers(
        self,
    ) -> None:
        before_fetchers, before_sources = _snapshot()

        concrete = _define(
            "CustomCatchUpFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
            participates_in_catch_up=True,
            catch_up=_custom_catch_up,
        )

        assert concrete.catch_up is not BaseCVEFetcher.catch_up
        assert _snapshot() == (
            {**before_fetchers, concrete.name: concrete},
            {**before_sources, CVESourceType.KEV: concrete},
        )

    def test_participating_fetch_single_fetcher_keeps_default_catch_up(
        self,
    ) -> None:
        concrete = _define(
            "DefaultCatchUpFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )

        assert concrete.catch_up is BaseCVEFetcher.catch_up
        assert FETCHER_REGISTRY[concrete.name] is concrete


class TestCatchUpRoster:
    def test_roster_includes_derived_true_and_excludes_derived_false(
        self,
    ) -> None:
        participating = _define(
            "RosterParticipatingFetcher",
            cve_source_type=CVESourceType.NVD,
            fetch_single=_fetch_single_stub,
        )
        catalog = _define(
            "RosterCatalogFetcher",
            cve_source_type=CVESourceType.KEV,
            supports_fetch_single=False,
        )

        roster = get_catch_up_fetchers()

        assert roster[participating.name] is participating
        assert catalog.name not in roster


class TestCatchUpFlagMismatchWarning:
    """Rule 8 is unchanged: it evaluates the derived participation flag."""

    def test_derived_false_with_catch_up_in_body_warns(self) -> None:
        with pytest.warns(UserWarning, match="participates_in_catch_up is False"):
            concrete = _define(
                "SilentlyExcludedFetcher",
                cve_source_type=CVESourceType.KEV,
                supports_fetch_single=False,
                catch_up=_custom_catch_up,
            )

        assert concrete.participates_in_catch_up is False
        assert FETCHER_REGISTRY[concrete.name] is concrete
        assert concrete.name not in get_catch_up_fetchers()

    def test_participating_fetcher_with_custom_catch_up_does_not_warn(
        self,
    ) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            concrete = _define(
                "ParticipatingCustomFetcher",
                cve_source_type=CVESourceType.NVD,
                fetch_single=_fetch_single_stub,
                catch_up=_custom_catch_up,
            )

        assert concrete.participates_in_catch_up is True
        assert get_catch_up_fetchers()[concrete.name] is concrete


# ---------------------------------------------------------------------------
# CVENotInSource and CVEFetchResult
# ---------------------------------------------------------------------------


class TestCVENotInSource:
    def test_constructor_takes_no_parameters(self) -> None:
        assert CVENotInSource().args == ()

        with pytest.raises(TypeError):
            CVENotInSource("CVE-2024-1234")  # type: ignore[call-arg]

    def test_inherits_from_exception_and_not_fetcher_error(self) -> None:
        assert CVENotInSource.__bases__ == (Exception,)
        assert not issubclass(CVENotInSource, FetcherError)


class TestCVEFetchResult:
    def test_declares_action_and_optional_post_ingest(self) -> None:
        assert [field.name for field in dataclasses.fields(CVEFetchResult)] == [
            "action",
            "post_ingest",
        ]
        assert typing.get_type_hints(CVEFetchResult) == {
            "action": UpsertAction,
            "post_ingest": PostIngestTasks | None,
        }

    def test_holds_action_and_post_ingest(self) -> None:
        handoff = PostIngestTasks(
            ticket_id=str(uuid4()),
            cpe_matches=[],
            affected_cpes=[],
            vendor_products=[],
            resolved_packages=["example-package"],
        )

        with_handoff = CVEFetchResult(action=UpsertAction.CREATED, post_ingest=handoff)
        without_handoff = CVEFetchResult(
            action=UpsertAction.UNCHANGED, post_ingest=None
        )

        assert with_handoff.action is UpsertAction.CREATED
        assert with_handoff.post_ingest is handoff
        assert without_handoff.action is UpsertAction.UNCHANGED
        assert without_handoff.post_ingest is None

    def test_fresh_token_is_not_consumed_and_marker_is_not_a_field(self) -> None:
        """The one-shot marker is private state: a fresh token is not
        consumed, and the marker is neither a dataclass field nor part of
        the token's representation or field projection."""
        result = CVEFetchResult(action=UpsertAction.UPDATED, post_ingest=None)

        assert result._consumed is False
        assert len(dataclasses.fields(CVEFetchResult)) == 2
        assert dataclasses.asdict(result) == {
            "action": UpsertAction.UPDATED,
            "post_ingest": None,
        }
        assert "_consumed" not in repr(result)
