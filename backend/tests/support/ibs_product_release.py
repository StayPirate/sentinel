"""Shared world, builders, and substitutes for the IBS Product release
reconciliation boundary tests
(backend/app/services/packages/ibs_product_release.py).

- `ReleaseWorld` is a `CommittedWorld` that also deletes the committed
  `ProductRepository` associations of its Products before the inherited
  teardown (their FK to `Product` is `NO ACTION`).
- `Seed` builds CVEs, Tickets, catalog Products with current and historical
  repository associations, and Product occurrences on either a rolled back
  `db_session` or a `ReleaseWorld` session. Every Product is seen in the
  fictional latest catalog snapshot `SNAPSHOT`, far after any real
  `catalog_last_seen_at`, so `MAX(Product.catalog_last_seen_at)` is
  `SNAPSHOT` in every test; historical associations were last seen at
  `EARLIER`.
- `UnitSessions` replaces the boundary's module-level
  `async_session_factory`; `Publish` replaces
  `task_publication.publish_task`, so no test reaches a broker;
  `between_phases()` runs a committed concurrent change after phase 1 (all
  repository I/O) and before phase 2 (the per-occurrence transactions).
- `Outcomes` is the per-outcome hook recorder.

All data is fictional: CVE identifiers `CVE-2099-NNNNNNNN`, packages
`example*`, repositories `SUSE:Updates:SLE-Example:*`, advisories
`SUSE-SU-2024:*`.

Consumers: `tests/test_services/test_packages/test_ibs_product_release.py`
and `tests/test_services/test_packages/test_ibs_product_release_races.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from types import TracebackType
from typing import Any, Final, Literal

import httpx
import pytest
from sqlalchemy import delete, event, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session

from app.core.enums import (
    DeliveryStatus,
    PackageStatus,
    Severity,
    TicketStatus,
    WorkflowType,
)
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.product_repository import ProductRepository
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.services import package_service
from app.services.packages import ibs_product_release
from app.services.packages.ibs_product_download import ProductRepositoryDownloads
from app.services.packages.ibs_product_release import (
    ProductReleaseCandidate,
    ProductReleaseOutcome,
    ProductReleaseSummary,
    reconcile_ibs_product_releases,
)
from app.services.ticket_convergence_publication import (
    PUBLICATION_FAILED_EVENT,
    RUN_TICKET_CONVERGENCE_TASK,
)
from app.services.ticket_convergence_registry import register_ticket_convergence
from tests.support.ibs_download import (
    Artifact,
    DownloadServer,
    advisory,
    artifact,
    updateinfo_document,
    xml_response,
)
from tests.support.suse_cvss import V31_CRITICAL
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import AFTER_EVAL, EventRow, ticket_events_by_id

FETCHER: Final = "detect_ibs_product_releases"

SNAPSHOT: Final = datetime(2090, 1, 1, tzinfo=UTC)
"""The fictional latest complete Product catalog snapshot."""

EARLIER: Final = datetime(2089, 6, 1, tzinfo=UTC)
"""An earlier catalog snapshot: associations last seen then are historical."""

PACKAGE: Final = "example"
SIBLING_PACKAGE: Final = "example-libs"

REPOSITORY: Final = "SUSE:Updates:SLE-Example:15-SP6:x86_64"
OTHER_REPOSITORY: Final = "SUSE:Updates:SLE-Example:15-SP6:aarch64"
HISTORICAL_REPOSITORY: Final = "SUSE:Updates:SLE-Example:15-SP5:x86_64"

IBS_REFERENCE: Final = "SUSE:SLE-15-SP6:Update"
GIT_REFERENCE: Final = "slfo-1.2"

ADVISORY_ID: Final = "SUSE-SU-2024:0001-1"
OTHER_ADVISORY_ID: Final = "SUSE-SU-2024:0002-1"
ISSUED: Final = "1717068854"
ISSUED_AT: Final = datetime(2024, 5, 30, 11, 34, 14, tzinfo=UTC)
ISSUED_Z: Final = "2024-05-30T11:34:14Z"

WAIT: Final = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

PRODUCT_RELEASED: Final = "product_released"

OCCURRENCE_FAILED: Final = "ibs_product_release_occurrence_failed"
OCCURRENCE_STALE: Final = "ibs_product_release_occurrence_stale"
RUN_COMPLETED: Final = "ibs_product_release_run_completed"
REPOSITORY_FAILED: Final = "ibs_product_release_repository_failed"

Exclusion = Literal["package", "track", "product"]


# ---------------------------------------------------------------------------
# Committed world and builders
# ---------------------------------------------------------------------------


class ReleaseWorld(CommittedWorld):
    """`CommittedWorld` that also deletes its Products' repository
    associations before the inherited explicit teardown, and owns one
    reusable read-only probe session (each probe read ends with a
    rollback, so the next read sees the latest committed state)."""

    _probe: AsyncSession | None = None

    async def probe(self) -> AsyncSession:
        if self._probe is None:
            self._probe = await self.open_session()
        return self._probe

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        await self.session.execute(
            delete(ProductRepository).where(
                ProductRepository.product_id.in_(self.product_ids)
            )
        )
        await self.session.commit()
        await super().cleanup()


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One persisted Product occurrence, its semantic locator, the Ticket
    CVE, and its event-time Product subject."""

    id: uuid.UUID
    ticket_id: uuid.UUID
    package_id: uuid.UUID
    track_id: uuid.UUID
    product_id: uuid.UUID
    cve_id: str | None
    package_name: str
    reference: str
    product_name: str
    product_cpe: str

    def candidate(
        self,
        *,
        current: Iterable[str] = (REPOSITORY,),
        historical: Iterable[str] = (),
    ) -> ProductReleaseCandidate:
        assert self.cve_id is not None
        return ProductReleaseCandidate(
            occurrence_id=self.id,
            ticket_id=self.ticket_id,
            package_id=self.package_id,
            track_id=self.track_id,
            product_id=self.product_id,
            cve_id=self.cve_id,
            package_name=self.package_name,
            current_repositories=tuple(current),
            historical_repositories=tuple(historical),
        )

    def released_event(
        self, new_value: str = ISSUED_Z, advisory_id: str = ADVISORY_ID
    ) -> EventRow:
        """The one system `product_released` event of this occurrence."""
        return EventRow(
            PRODUCT_RELEASED,
            None,
            None,
            new_value,
            None,
            {
                "track": self.reference,
                "package": self.package_name,
                "product_name": self.product_name,
                "product_cpe": self.product_cpe,
                "advisory_id": advisory_id,
            },
        )


class Seed:
    """Builds the release-detection data on `session`; when `world` is
    given, records every CVE, Ticket, and Product for its teardown.

    Packages are shared per `(Ticket, package name)` and tracks per
    `(package, reference)`, so several Products may sit below one track.
    """

    def __init__(self, session: AsyncSession, world: CommittedWorld | None = None):
        self.session = session
        self._world = world
        self._cves: dict[uuid.UUID, str | None] = {}
        self._packages: dict[tuple[uuid.UUID, str], TicketPackage] = {}
        self._tracks: dict[tuple[uuid.UUID, str], TicketPackageTrack] = {}

    async def cve(self, *, assessed: bool = False) -> CVE:
        """A CVE; an `assessed` one has severity Critical and one SUSE v3.1
        assessment, so a Ticket gate can reach `Analyzed`/`Resolved`."""
        cve = CVE(
            cve_id=f"CVE-2099-{uuid.uuid4().int % 10**8:08d}",
            severity=Severity.CRITICAL.value if assessed else None,
        )
        self.session.add(cve)
        await self.session.flush()
        if self._world is not None:
            self._world.cve_ids.append(cve.id)
        if assessed:
            self.session.add(
                CVECVSSAssessment(
                    cve_id=cve.id, provider_name="SUSE", **V31_CRITICAL.columns()
                )
            )
            await self.session.flush()
        return cve

    async def ticket(
        self,
        status: TicketStatus = TicketStatus.ANALYSIS,
        *,
        with_cve: bool = True,
        assessed: bool = False,
    ) -> Ticket:
        """A Ticket; a `Duplicated` one points at a fresh CVE-less
        canonical `Analysis` Ticket."""
        cve = await self.cve(assessed=assessed) if with_cve else None
        duplicate_of_id = None
        if status is TicketStatus.DUPLICATED:
            canonical = await self.ticket(TicketStatus.ANALYSIS, with_cve=False)
            duplicate_of_id = canonical.id
        ticket = Ticket(
            status=status.value,
            cve_id=cve.id if cve is not None else None,
            duplicate_of_id=duplicate_of_id,
        )
        self.session.add(ticket)
        await self.session.flush()
        if self._world is not None:
            self._world.ticket_ids.append(ticket.id)
        self._cves[ticket.id] = cve.cve_id if cve is not None else None
        return ticket

    async def product(
        self,
        *,
        current: Iterable[str] = (REPOSITORY,),
        historical: Iterable[str] = (),
        seen_at: datetime = SNAPSHOT,
        general_support_end_date: date = AFTER_EVAL,
    ) -> Product:
        """A catalog Product seen at `seen_at`, with associations seen in
        the latest snapshot (`current`) and earlier (`historical`)."""
        suffix = uuid.uuid4().hex[:10]
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"EP {suffix}",
            cpe=f"cpe:/o:example:product:{suffix}",
            catalog_last_seen_at=seen_at,
            general_support_end_date=general_support_end_date,
        )
        self.session.add(product)
        await self.session.flush()
        if self._world is not None:
            self._world.product_ids.append(product.id)
        for names, last_seen in ((current, SNAPSHOT), (historical, EARLIER)):
            for name in names:
                self.session.add(
                    ProductRepository(
                        product_id=product.id,
                        repo_name=name,
                        catalog_last_seen_at=last_seen,
                    )
                )
        await self.session.flush()
        return product

    async def occurrence(
        self,
        ticket: Ticket,
        product: Product,
        *,
        package_name: str = PACKAGE,
        workflow: WorkflowType = WorkflowType.IBS,
        reference: str | None = None,
        track_status: PackageStatus = PackageStatus.ANALYSIS,
        delivery_status: DeliveryStatus = DeliveryStatus.PENDING,
        eligible: bool = True,
        is_eligible_override: bool = False,
        released_at: datetime | None = None,
        excluded: Exclusion | None = None,
        occurrence_id: uuid.UUID | None = None,
    ) -> Occurrence:
        """One Product occurrence below the (shared) package and track."""
        if reference is None:
            reference = IBS_REFERENCE if workflow is WorkflowType.IBS else GIT_REFERENCE
        excluded_at = datetime(2026, 9, 1, tzinfo=UTC)
        package = self._packages.get((ticket.id, package_name))
        if package is None:
            package = TicketPackage(
                ticket_id=ticket.id,
                package_name=package_name,
                deleted_at=excluded_at if excluded == "package" else None,
            )
            self.session.add(package)
            await self.session.flush()
            self._packages[(ticket.id, package_name)] = package
        track = self._tracks.get((package.id, reference))
        if track is None:
            track = TicketPackageTrack(
                ticket_package_id=package.id,
                workflow_type=workflow.value,
                reference=reference,
                status=track_status.value,
                delivery_status=delivery_status.value,
                deleted_at=excluded_at if excluded == "track" else None,
            )
            self.session.add(track)
            await self.session.flush()
            self._tracks[(package.id, reference)] = track
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=is_eligible_override,
            released_at=released_at,
            deleted_at=excluded_at if excluded == "product" else None,
        )
        if occurrence_id is not None:
            occurrence.id = occurrence_id
        self.session.add(occurrence)
        await self.session.flush()
        return Occurrence(
            id=occurrence.id,
            ticket_id=ticket.id,
            package_id=package.id,
            track_id=track.id,
            product_id=product.id,
            cve_id=self._cves[ticket.id],
            package_name=package_name,
            reference=reference,
            product_name=product.display_name,
            product_cpe=product.cpe,
        )

    async def commit(self) -> None:
        await self.session.commit()


# ---------------------------------------------------------------------------
# Repositories and the boundary invocation
# ---------------------------------------------------------------------------


def matching(
    *cves: str | None,
    sources: Iterable[str] = (PACKAGE,),
    advisory_id: str = ADVISORY_ID,
    issued: str = ISSUED,
) -> str:
    """One stable security advisory naming `cves` and `sources`."""
    return advisory(
        advisory_id,
        cves=[cve for cve in cves if cve is not None],
        sources=sources,
        issued=issued,
    )


def repository(*updates: str) -> Artifact:
    return artifact(updateinfo_document(*updates))


def status_response(status: int) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _: xml_response(b"<html/>", status=status, content_type="text/html")


def recording_client(server: DownloadServer, events: list[str]) -> httpx.AsyncClient:
    """A client over `server` that appends `"http"` to `events` per request."""

    def handle(request: httpx.Request) -> httpx.Response:
        events.append("http")
        return server(request)

    return httpx.AsyncClient(transport=httpx.MockTransport(handle))


async def reconcile_from(
    server: DownloadServer,
    candidates: Iterable[ProductReleaseCandidate],
    hook: Callable[[ProductReleaseOutcome], None] | None = None,
) -> ProductReleaseSummary:
    """One boundary invocation over a client of `server`, with `hook` as
    the per-outcome hook."""
    async with server.client() as client:
        return await reconcile_ibs_product_releases(
            candidates, client=client, fetcher_name=FETCHER, on_outcome=hook
        )


def summary(
    selected: int = 0, updated: int = 0, no_op: int = 0, failed: int = 0
) -> ProductReleaseSummary:
    return ProductReleaseSummary(
        selected=selected, updated=updated, no_op=no_op, failed=failed
    )


@dataclass
class Outcomes:
    """The per-outcome hook: records each outcome and, when `events` is
    set, appends `"hook:<kind>"` to it."""

    received: list[ProductReleaseOutcome] = field(default_factory=list)
    events: list[str] | None = None

    def __call__(self, outcome: ProductReleaseOutcome) -> None:
        self.received.append(outcome)
        if self.events is not None:
            self.events.append(f"hook:{outcome.kind}")

    @property
    def kinds(self) -> list[tuple[uuid.UUID, str]]:
        """`(occurrence ID, kind)` of each received outcome, in order."""
        return [(outcome.occurrence_id, outcome.kind) for outcome in self.received]


# ---------------------------------------------------------------------------
# Substitutes
# ---------------------------------------------------------------------------


class UnitSessions:
    """Replaces the boundary's module-level `async_session_factory`.

    Hands out the `queued` sessions first, then sessions of the real
    factory; records every session it hands out and, in `closed`, every
    completed `close()`; optionally makes the commit of the session at one
    index fail; when `events` is set, appends `"unit"` on each opening and
    `"commit"`/`"close"` after each successful commit and close; when
    `before_commit` is set, calls it with the sync session at the start of
    each commit (before the commit's own flush)."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.sessions: list[AsyncSession] = []
        self.closed: list[AsyncSession] = []
        self.queued: list[AsyncSession] = []
        self.failing_commit: tuple[int, BaseException] | None = None
        self.events: list[str] | None = None
        self.before_commit: Callable[[Session], None] | None = None

    def __call__(self) -> AsyncSession:
        session = self.queued.pop(0) if self.queued else self._factory()
        index = len(self.sessions)
        sync_session = session.sync_session

        def _before_commit(committing: Session) -> None:
            if self.before_commit is not None:
                self.before_commit(committing)
            if self.failing_commit is not None and self.failing_commit[0] == index:
                raise self.failing_commit[1]

        def _after_commit(_committed: Session) -> None:
            if self.events is not None:
                self.events.append("commit")

        event.listen(sync_session, "before_commit", _before_commit)
        event.listen(sync_session, "after_commit", _after_commit)
        close = session.close

        async def _recording_close() -> None:
            await close()
            self.closed.append(session)
            if self.events is not None:
                self.events.append("close")

        session.close = _recording_close  # type: ignore[method-assign]
        if self.events is not None:
            self.events.append("unit")
        self.sessions.append(session)
        return session


def install_units(
    monkeypatch: pytest.MonkeyPatch, factory: async_sessionmaker[AsyncSession]
) -> UnitSessions:
    sessions = UnitSessions(factory)
    monkeypatch.setattr(ibs_product_release, "async_session_factory", sessions)
    return sessions


@dataclass
class Publish:
    """Substitute for `task_publication.publish_task` recording each call.

    `on_call` runs inside the publication attempt, before `error` (if set)
    is raised for a root Ticket convergence publication."""

    error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)
    on_call: Callable[[dict[str, Any]], Awaitable[None]] | None = None

    async def __call__(self, task_name: str, **options: Any) -> None:
        call = {"task_name": task_name, **options}
        self.calls.append(call)
        if self.on_call is not None:
            await self.on_call(call)
        if self.error is not None and task_name == RUN_TICKET_CONVERGENCE_TASK:
            raise self.error


def published(calls: Sequence[Mapping[str, Any]]) -> list[uuid.UUID]:
    """The Ticket UUIDs of the recorded root convergence publications."""
    tickets = []
    for call in calls:
        assert call["task_name"] == RUN_TICKET_CONVERGENCE_TASK
        assert call["kwargs"].keys() == {"ticket_id"}
        tickets.append(uuid.UUID(call["kwargs"]["ticket_id"]))
    return tickets


def register_after_release(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Make every `set_product_released_at()` call also register a Ticket
    convergence effect for its Ticket after the real call (a Product
    release alone never registers one). Returns the registered Tickets."""
    original = package_service.set_product_released_at
    registered: list[uuid.UUID] = []

    async def registering(
        db: AsyncSession, **kwargs: Any
    ) -> package_service.ProductReleasedResult:
        result = await original(db, **kwargs)
        register_ticket_convergence(db, kwargs["ticket_id"])
        registered.append(kwargs["ticket_id"])
        return result

    monkeypatch.setattr(package_service, "set_product_released_at", registering)
    return registered


def between_phases(
    monkeypatch: pytest.MonkeyPatch, action: Callable[[], Awaitable[None]]
) -> None:
    """Run `action` after the download context closed normally (phase 1
    complete) and before the first per-occurrence transaction."""

    class _Downloads(ProductRepositoryDownloads):
        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            await super().__aexit__(exc_type, exc, traceback)
            if exc_type is None:
                await action()

    monkeypatch.setattr(ibs_product_release, "ProductRepositoryDownloads", _Downloads)


# ---------------------------------------------------------------------------
# Committed state and logs
# ---------------------------------------------------------------------------


async def released_at(world: ReleaseWorld, occurrence: Occurrence) -> datetime | None:
    """The committed `released_at`, read through a fresh session."""
    probe = await world.probe()
    value = (
        await probe.execute(
            select(TicketPackageProduct.released_at).where(
                TicketPackageProduct.id == occurrence.id
            )
        )
    ).scalar_one_or_none()
    await probe.rollback()
    return value


async def events_of(world: ReleaseWorld, ticket_id: uuid.UUID) -> list[EventRow]:
    """The committed Ticket audit events in insertion order."""
    probe = await world.probe()
    events = await ticket_events_by_id(probe, ticket_id)
    await probe.rollback()
    return events


async def released_events(world: ReleaseWorld, ticket_id: uuid.UUID) -> list[EventRow]:
    return [
        e for e in await events_of(world, ticket_id) if e.event_type == PRODUCT_RELEASED
    ]


async def ticket_status(world: ReleaseWorld, ticket_id: uuid.UUID) -> str | None:
    probe = await world.probe()
    value = (
        await probe.execute(select(Ticket.status).where(Ticket.id == ticket_id))
    ).scalar_one_or_none()
    await probe.rollback()
    return value


def logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def occurrence_failed(
    occurrence: Occurrence, repository: str, reason_category: str
) -> dict[str, Any]:
    return {
        "event": OCCURRENCE_FAILED,
        "log_level": "warning",
        "ticket_package_product_id": str(occurrence.id),
        "ticket_id": str(occurrence.ticket_id),
        "fetcher_name": FETCHER,
        "repository": repository,
        "reason_category": reason_category,
    }


def occurrence_stale(occurrence: Occurrence, reason_category: str) -> dict[str, Any]:
    return {
        "event": OCCURRENCE_STALE,
        "log_level": "warning",
        "ticket_package_product_id": str(occurrence.id),
        "ticket_id": str(occurrence.ticket_id),
        "reason_category": reason_category,
    }


def run_completed(
    selected: int = 0, updated: int = 0, no_op: int = 0, failed: int = 0
) -> dict[str, Any]:
    return {
        "event": RUN_COMPLETED,
        "log_level": "info",
        "selected": selected,
        "updated": updated,
        "no_op": no_op,
        "failed": failed,
    }


def publication_failed(ticket_id: uuid.UUID) -> dict[str, Any]:
    return {
        "event": PUBLICATION_FAILED_EVENT,
        "log_level": "error",
        "ticket_id": str(ticket_id),
        "cause": "broker_operational_error",
    }
