"""BaseCVEFetcher registry core, `CVENotInSource`, and `CVEFetchResult`.

See `docs/features/platform/cve-fetcher-infrastructure.md` (BaseCVEFetcher
Class; `CVEFetchResult`; CVE-ID Format Validation Helper;
`__init_subclass__` Validation; `CVENotInSource` Signal; CVE Source Type
Identity) for the contract this module implements.

`BaseCVEFetcher.__init_subclass__` treats `FETCHER_REGISTRY` and
`_CVE_SOURCE_TYPE_MAP` as one registration unit: every CVE-specific
validation completes before `super().__init_subclass__()` performs the
generic validation and registration, and the source map is assigned last,
as the sole remaining operation. A failure therefore never leaves an
orphan in either registry.

Out of scope for this module (owned by later work items): the default
`catch_up()` with the `participates_in_catch_up` auto-derivation and
`__init_subclass__` rule 5, `commit_and_dispatch()` with the
`CVEFetchResult` finalization semantics, and `_isolated_status_commit()`.
`CVEFetchResult` is therefore only the declared shape of the
`fetch_single()` result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType
from app.core.identifiers import is_valid_cve_id
from app.services.base_fetcher import BaseFetcher
from app.services.cve_ingest import PostIngestTasks, UpsertAction

_CVE_SOURCE_TYPE_MAP: dict[CVESourceType, type[BaseCVEFetcher]] = {}
"""Each registered `CVESourceType` member mapped to its owning class."""


class CVENotInSource(Exception):  # noqa: N818 — specified signal name
    """The external source explicitly confirmed the CVE does not exist.

    A signal, not a failure: it maps to the `missing` source status and
    deliberately does not inherit from `FetcherError`. The constructor
    takes no parameters; diagnostic context stays in the caller's scope.
    """

    def __init__(self) -> None:
        super().__init__()


@dataclass
class CVEFetchResult:
    """The one-shot per-CVE finalization token of a successful fetch.

    Carries the effective `UpsertResult.action` and the optional pure
    package-candidate handoff; no ORM object or session. Not a Celery
    payload or result.
    """

    action: UpsertAction
    post_ingest: PostIngestTasks | None


def _validate_cve_source_type(cls: type[BaseCVEFetcher]) -> CVESourceType:
    """Rules 1-3: resolvable, a `CVESourceType` member, and unique."""
    if not hasattr(cls, "cve_source_type"):
        raise TypeError(
            f"{cls.__name__} must declare cve_source_type as a CVESourceType "
            "enum member"
        )
    source_type = cls.cve_source_type
    if not isinstance(source_type, CVESourceType):
        raise TypeError(
            f"{cls.__name__}.cve_source_type must be a CVESourceType enum "
            f"member, got {source_type!r}"
        )
    existing = _CVE_SOURCE_TYPE_MAP.get(source_type)
    if existing is not None and existing is not cls:
        raise TypeError(
            f"cve_source_type {source_type.value!r} is already registered by "
            f"{existing.__name__}; cannot register {cls.__name__}"
        )
    return source_type


def _validate_fetch_single_implementation(cls: type[BaseCVEFetcher]) -> None:
    """Rule 4: a fetch-single capable class resolves to a real method."""
    if cls.supports_fetch_single and cls.fetch_single is BaseCVEFetcher.fetch_single:
        raise TypeError(
            f"{cls.__name__} sets supports_fetch_single=True but does not "
            "implement fetch_single()"
        )


class BaseCVEFetcher(BaseFetcher):
    """Intermediate abstract base class of every CVE fetcher.

    `cve_source_type` is intentionally only annotated here, never
    assigned, so a concrete subclass that omits it fails at import time
    instead of inheriting a default.
    """

    abstract: ClassVar[bool] = True
    cve_source_type: ClassVar[CVESourceType]
    supports_fetch_single: ClassVar[bool] = True
    source_reference_url_pattern: ClassVar[str | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        if cls.__dict__.get("abstract", False):
            super().__init_subclass__(**kwargs)
            return

        source_type = _validate_cve_source_type(cls)
        _validate_fetch_single_implementation(cls)
        super().__init_subclass__(**kwargs)
        _CVE_SOURCE_TYPE_MAP[source_type] = cls

    async def fetch_single(self, cve_id: str, session: AsyncSession) -> CVEFetchResult:
        """Fetch one CVE on demand. Safety net; concrete fetchers override it.

        A fetcher with `supports_fetch_single = True` must resolve to a real
        implementation (enforced at import time); a fetcher with `False`
        may inherit this method, which is never dispatched for it.
        """
        raise RuntimeError(
            "fetch_single() called on a fetcher that does not support it"
        )

    def _is_valid_cve_id(self, cve_id: str) -> bool:
        """Pure delegation to `core.identifiers.is_valid_cve_id()`."""
        return is_valid_cve_id(cve_id)


def get_fetch_single_fetchers() -> dict[str, type[BaseCVEFetcher]]:
    """Registered CVE fetchers with `supports_fetch_single = True`.

    Keyed by `cve_source_type.value`; a fresh plain dict on every call.
    """
    return {
        source_type.value: cls
        for source_type, cls in _CVE_SOURCE_TYPE_MAP.items()
        if cls.supports_fetch_single
    }


def get_all_cve_source_types() -> dict[str, type[BaseCVEFetcher]]:
    """Every registered CVE fetcher, regardless of fetch-single support.

    Keyed by `cve_source_type.value`; a fresh plain dict on every call.
    """
    return {source_type.value: cls for source_type, cls in _CVE_SOURCE_TYPE_MAP.items()}
