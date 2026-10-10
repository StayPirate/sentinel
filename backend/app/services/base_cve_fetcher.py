"""BaseCVEFetcher: registry, per-CVE finalization, and default catch-up.

See `docs/features/platform/cve-fetcher-infrastructure.md` (BaseCVEFetcher
Class; `CVEFetchResult`; Per-CVE Finalization; Default `catch_up()`
implementation; CVE-ID Format Validation Helper; `__init_subclass__`
Validation; Session Lifecycle for API-based CVE Fetchers, Isolated status
commit and Metric placement; `CVENotInSource` Signal; CVE Source Type
Identity; Batch Error Handling, Per-item failure event; Candidate Skip
Event) for the contract this module implements.

`BaseCVEFetcher.__init_subclass__` treats `FETCHER_REGISTRY` and
`_CVE_SOURCE_TYPE_MAP` as one registration unit: the
`participates_in_catch_up` derivation and every CVE-specific validation
(rules 1-5) complete before `super().__init_subclass__()` performs the
generic validation and registration, and the source map is assigned last,
as the sole remaining operation. A failure therefore never leaves an
orphan in either registry.

`commit_and_dispatch()` is the sole per-CVE commit boundary of every CVE
fetcher path (periodic `execute()`, on-demand, and catch-up). It consumes
one `CVEFetchResult`, commits, records the periodic outcome/effect only
under the automatic periodic context of `BaseFetcher.run()`, drains the
transaction's Ticket convergence effects through the automatic adapter,
and then publishes the optional `resolve_ticket_packages` handoff.

`cve_service`, `package_service`, `task_publication`, and
`ticket_convergence_publication` are imported as module objects and
dereferenced at call time: `cve_service` imports this module, so neither
side uses the other while being imported. Tests substitute the broker call
through `task_publication.publish_task`.
"""

from __future__ import annotations

from asyncio import CancelledError
from dataclasses import dataclass
from typing import Any, ClassVar, Final
from uuid import UUID

import structlog
from celery.exceptions import (
    OperationalError,  # kombu.exceptions.OperationalError
    SoftTimeLimitExceeded,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.core.identifiers import is_valid_cve_id
from app.database import async_session_factory
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services import (
    cve_service,
    package_service,
    task_publication,
    ticket_convergence_publication,
)
from app.services.base_fetcher import BaseFetcher
from app.services.cve_ingest import PostIngestTasks, UpsertAction

logger = structlog.get_logger(__name__)

_CVE_SOURCE_TYPE_MAP: dict[CVESourceType, type[BaseCVEFetcher]] = {}
"""Each registered `CVESourceType` member mapped to its owning class."""

HANDOFF_PUBLICATION_FAILED_EVENT: Final = "cve_package_handoff_publication_failed"
"""The bounded ERROR of a best-effort package-handoff broker failure."""

ISOLATED_STATUS_WRITE_FAILED_EVENT: Final = "cve_isolated_status_write_failed"
"""The bounded WARNING of a suppressed isolated status lookup/write/commit."""

ISOLATED_STATUS_CVE_MISSING_EVENT: Final = "cve_isolated_status_cve_missing"
"""The DEBUG of an isolated status write skipped for an absent CVE row."""

CVE_FETCH_ITEM_FAILED_EVENT: Final = "cve_fetch_item_failed"
"""The per-item failure WARNING (Batch Error Handling, Per-item failure
event): canonical CVE-ID when valid, fetcher name, and exception class name
only."""

CVE_FETCH_CANDIDATE_SKIPPED_EVENT: Final = "cve_fetch_candidate_skipped"
"""The candidate skip WARNING (Candidate Skip Event): canonical CVE-ID,
fetcher name, and the emitting fetcher's closed reason."""

_ISOLATED_STATUSES: Final = (
    CVESourceFetchStatus.FAILURE,
    CVESourceFetchStatus.MISSING,
)


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
    payload or result. Tied to the transaction that produced it: the first
    `commit_and_dispatch()` call consumes it, and a consumed token is
    rejected before commit, publication, or metric mutation. The consumed
    marker is private state, not a dataclass field.
    """

    action: UpsertAction
    post_ingest: PostIngestTasks | None

    def __post_init__(self) -> None:
        self._consumed = False


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


def _validate_catch_up_capability(cls: type[BaseCVEFetcher]) -> None:
    """Rule 5: catch-up without fetch-single needs a custom `catch_up()`.

    The default `catch_up()` would call the unsupported base
    `fetch_single()` safety net.
    """
    if (
        cls.participates_in_catch_up
        and not cls.supports_fetch_single
        and cls.catch_up is BaseCVEFetcher.catch_up
    ):
        raise TypeError(
            f"{cls.__name__} sets participates_in_catch_up=True with "
            "supports_fetch_single=False but does not override catch_up()"
        )


class BaseCVEFetcher(BaseFetcher):
    """Intermediate abstract base class of every CVE fetcher.

    `cve_source_type` is intentionally only annotated here, never
    assigned, so a concrete subclass that omits it fails at import time
    instead of inheriting a default. `participates_in_catch_up` is
    auto-derived from `supports_fetch_single` on every concrete subclass
    that does not set it in its own class body.
    """

    abstract: ClassVar[bool] = True
    cve_source_type: ClassVar[CVESourceType]
    supports_fetch_single: ClassVar[bool] = True
    participates_in_catch_up: ClassVar[bool] = True
    source_reference_url_pattern: ClassVar[str | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        if cls.__dict__.get("abstract", False):
            super().__init_subclass__(**kwargs)
            return

        # Derived CVE attribute first, so rule 5 and the generic rules 7-8
        # evaluate the resolved participation flag.
        if "participates_in_catch_up" not in cls.__dict__:
            cls.participates_in_catch_up = cls.supports_fetch_single
        source_type = _validate_cve_source_type(cls)
        _validate_fetch_single_implementation(cls)
        _validate_catch_up_capability(cls)
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

    async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
        """Default CVE catch-up: refetch the Ticket's CVE from this source.

        Category A orchestration over the wrapper-owned `session`.

        Q1: `ticket_id` is the UUID string already validated by
        `run_catch_up`; `session` is the wrapper-owned session.

        Q3: a missing Ticket or a CVE-less Ticket returns silently. Otherwise
        calls `fetch_single()` and flushes every per-CVE write; on success
        `commit_and_dispatch()` (outside the pre-commit handler) owns the
        commit and every post-commit effect, with no periodic metric.
        `CVENotInSource` rolls back and writes an isolated `missing` status.

        Q4: returns `None`.

        Q5: idempotent by delegation to `fetch_single()`.

        Q6: a Ticket referencing an unresolvable CVE row raises a
        non-retryable `RuntimeError`. Every ordinary pre-finalization
        exception (including a flush failure) rolls back, attempts an
        isolated `failure` status write, and propagates unchanged for retry
        classification. Cancellation, `SoftTimeLimitExceeded`, and
        `MemoryError` propagate without status handling. A finalization
        exception propagates without rollback or isolated status.
        """
        ticket = await session.get(Ticket, UUID(ticket_id))
        if ticket is None or ticket.cve_id is None:
            return
        cve = await session.get(CVE, ticket.cve_id)
        if cve is None:
            raise RuntimeError("Ticket references a CVE row that cannot be resolved")
        # Read before any rollback expires the instance.
        cve_id = cve.cve_id
        try:
            result = await self.fetch_single(cve_id, session)
            await session.flush()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise
        except CVENotInSource:
            await session.rollback()
            await self._isolated_status_commit(cve_id, CVESourceFetchStatus.MISSING)
        except Exception:
            await session.rollback()
            await self._isolated_status_commit(cve_id, CVESourceFetchStatus.FAILURE)
            raise
        else:
            # Finalization owns commit and all post-commit effects. An
            # escaping finalization exception must not enter the pre-commit
            # handler above.
            await self.commit_and_dispatch(session, result)

    async def commit_and_dispatch(
        self, session: AsyncSession, result: CVEFetchResult
    ) -> None:
        """Finalize one per-CVE transaction exactly once.

        Category A (commit of the caller's per-CVE transaction, then broker
        I/O only).

        Q1: `session` carries the per-CVE transaction whose every write the
        caller has already flushed; `result` is the token produced by that
        transaction.

        Q2: a consumed `result` raises `RuntimeError` before commit,
        publication, or metric mutation. A fresh `result` is marked consumed
        before any further step, so it stays consumed on every later
        outcome.

        Q3, in order: (1) commits `session` once; (2) only under the
        automatic periodic context of `BaseFetcher.run()`, maps `created` to
        `record_created()` and `updated` to `record_updated()` and always
        calls `record_succeeded()`, before any awaitable post-commit action;
        (3) detaches the committed Ticket convergence effects and attempts
        each once in registered order through the automatic adapter (a
        broker operational failure emits its one Ticket-owned ERROR and is
        absorbed); (4) publishes a non-NULL `post_ingest` as
        `resolve_ticket_packages` with its five primitive arguments.

        Q4: returns `None`.

        Q5: not re-invocable for the same token. The same session may
        finalize later CVEs; consumed or cleared effects are never replayed.

        Q6: a commit exception (including an ambiguous outcome) propagates
        before any metric or publication and terminates the owning run. A
        `kombu.exceptions.OperationalError` from the handoff publication
        logs one sanitized `cve_package_handoff_publication_failed` ERROR
        and returns normally. Every other exception and control signal
        after the commit propagates as a post-commit finalization failure,
        with committed metrics intact and no later step attempted.
        """
        if result._consumed:
            raise RuntimeError("CVEFetchResult has already been finalized")
        result._consumed = True

        await session.commit()

        if self._periodic_context:
            if result.action is UpsertAction.CREATED:
                self.record_created()
            elif result.action is UpsertAction.UPDATED:
                self.record_updated()
            self.record_succeeded()

        await ticket_convergence_publication.drain_ticket_convergence(session)

        if result.post_ingest is not None:
            await self._publish_package_handoff(result.post_ingest)

    async def _publish_package_handoff(self, handoff: PostIngestTasks) -> None:
        """Publish the post-ingest handoff as five primitive task arguments.

        Fresh primitive copies of the `PostIngestTasks` fields are passed;
        the dataclass itself is never a Celery payload. Only the broker
        operational error is best effort.
        """
        kwargs: dict[str, task_publication.JSONValue] = {
            "ticket_id": handoff.ticket_id,
            "cpe_matches": [
                {
                    "criteria": match["criteria"],
                    "vulnerable": match["vulnerable"],
                    "match_criteria_id": match["match_criteria_id"],
                }
                for match in handoff.cpe_matches
            ],
            "affected_cpes": list(handoff.affected_cpes),
            "vendor_products": [list(pair) for pair in handoff.vendor_products],
            "resolved_packages": list(handoff.resolved_packages),
        }
        try:
            await task_publication.publish_task(
                package_service.RESOLVE_TICKET_PACKAGES_TASK, kwargs=kwargs
            )
        except OperationalError as exc:
            logger.error(
                HANDOFF_PUBLICATION_FAILED_EVENT,
                ticket_id=handoff.ticket_id,
                fetcher_name=self.name,
                cause=type(exc).__name__,
            )

    async def _isolated_status_commit(
        self, cve_id: str, status: CVESourceFetchStatus
    ) -> None:
        """Write a `failure`/`missing` source status in its own transaction.

        Category A (one independent short-lived session and transaction).

        Q1: `cve_id` is the canonical CVE-ID; `status` is
        `CVESourceFetchStatus.FAILURE` or `CVESourceFetchStatus.MISSING`.
        Called only after the caller has rolled back its main session.

        Q2: any other value, including an equal raw string, raises
        `ValueError` before database work.

        Q3: looks up the CVE row, writes the status through
        `cve_service.record_source_status()`, and commits directly. A
        missing CVE row is skipped. Never calls `commit_and_dispatch()`;
        publishes no Ticket convergence effect or package task; records no
        `FetcherRun` metric.

        Q4: returns `None`.

        Q6: an ordinary lookup, write, commit, or session failure is logged
        with bounded context and suppressed, preserving the previous latest
        state and any exception the caller is handling. Cancellation,
        `SoftTimeLimitExceeded`, and `MemoryError` propagate.
        """
        if not any(status is allowed for allowed in _ISOLATED_STATUSES):
            raise ValueError(
                "isolated status must be CVESourceFetchStatus.FAILURE or "
                "CVESourceFetchStatus.MISSING"
            )
        try:
            async with async_session_factory() as status_session:
                cve_uuid = await status_session.scalar(
                    select(CVE.id).where(CVE.cve_id == cve_id)
                )
                if cve_uuid is None:
                    logger.debug(
                        ISOLATED_STATUS_CVE_MISSING_EVENT,
                        cve_id=cve_id,
                        source=self.cve_source_type.value,
                        status=status.value,
                    )
                    return
                await cve_service.record_source_status(
                    status_session, cve_uuid, self.cve_source_type, status
                )
                await status_session.commit()
        except CancelledError, SoftTimeLimitExceeded, MemoryError:
            raise
        except Exception as exc:
            logger.warning(
                ISOLATED_STATUS_WRITE_FAILED_EVENT,
                cve_id=cve_id,
                source=self.cve_source_type.value,
                status=status.value,
                fetcher_name=self.name,
                cause=type(exc).__name__,
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
