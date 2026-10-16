"""Shared world, builders, and substitutes for the IBS track release
reconciliation boundary tests
(backend/app/services/packages/ibs_track_release.py).

- `TrackWorld` is a `CommittedWorld` that also deletes the
  `TrackReleaseCheckpoint` rows of its Tickets' tracks before the
  inherited teardown (their FK to `TicketPackageTrack` is `ON DELETE
  RESTRICT`), and owns one reusable read-only probe session (each probe
  read ends with a rollback, so the next read sees the latest committed
  state).
- `Seed` builds CVEs, Tickets, IBS and Git tracks (optionally excluded,
  with a persisted checkpoint), and Product occurrences below a track, on
  either a rolled back `db_session` or a `TrackWorld` session. A seeded
  checkpoint was accepted at the fictional `SEEN_AT`.
- `FakeIBS` serves the targeted source info (per IBS project; one
  scripted entry list per package, so an entry can be missing,
  duplicated, error-bearing, or carry an invalid `srcmd5`) and the
  expanded diffs (keyed by `(project, package, orev, rev)`) through the
  authenticating `IBSServer` of `tests/support/ibs_api.py`, behind a real
  `IBSClient`: the production signature authentication, session cookie,
  transport retry (backoff sleeps recorded, not awaited), parsing, and
  classification all run. It records every served request in order and,
  when `events` is set, appends `"http:source"`/`"http:diff"` to it.
- `TrackUnitSessions` extends `UnitSessions` (which replaces the
  boundary's module-level `async_session_factory`) with a `before_flush`
  hook and an error raised after one unit's commit (an ambiguous commit:
  the database committed, the caller sees an exception).
- `before_local_unit()` runs a committed concurrent change after every
  IBS request of a track's diff and before that track's local unit takes
  the Ticket lock.
- `register_after_fixed()` makes `set_track_status()` also register a
  Ticket convergence effect (a system `FIXED` registers one by itself only
  when it regresses a stale `Resolved` Ticket); `Publish` and `published`
  come from
  `tests/support/ibs_product_release.py`.
- `Outcomes` is the per-outcome hook recorder.

All data is fictional: CVE identifiers `CVE-2099-NNNNNNNN`, packages
`example*`, checksums derived from fictional labels, the account `jdoe`
with a fictional key derived at run time.

Consumers: `tests/test_services/test_packages/test_ibs_track_release.py`,
`tests/test_services/test_packages/test_ibs_track_release_races.py`, and
`tests/test_services/test_packages/test_detect_ibs_track_releases.py`.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any, Final, Literal
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr
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
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.track_release_checkpoint import TrackReleaseCheckpoint
from app.services import http_client, package_service
from app.services.ibs_client import IBSClient
from app.services.packages import ibs_track_release
from app.services.packages.ibs_track_release import (
    TrackReleaseCandidate,
    TrackReleaseOutcome,
    reconcile_ibs_track_releases,
)
from app.services.ticket_convergence_publication import PUBLICATION_FAILED_EVENT
from app.services.ticket_convergence_registry import register_ticket_convergence
from tests.support.ibs_api import (
    FICTIONAL_OREV,
    FICTIONAL_REV,
    LIVE_PROJECT,
    TEST_API_URL,
    IBSServer,
    Responder,
    load_fixture,
    xml_response,
)
from tests.support.ibs_keys import fictional_ed25519_key, fictional_settings_value
from tests.support.ibs_product_release import UnitSessions
from tests.support.suse_cvss import V31_CRITICAL
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import AFTER_EVAL, EventRow, ticket_events_by_id

FETCHER: Final = "detect_ibs_track_releases"

PROJECT: Final = "SUSE:SLE-15-SP6:Update"
OTHER_PROJECT: Final = "SUSE:SLE-15-SP7:Update"
GIT_REFERENCE: Final = "slfo-1.2"

PACKAGE: Final = "example"
SIBLING_PACKAGE: Final = "example-libs"

OTHER_CVE: Final = "CVE-2099-99999999"
"""A canonical CVE ID that no seeded Ticket uses."""

SEEN_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
"""When every seeded checkpoint was accepted."""

WAIT: Final = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""

TRACK_STATUS_CHANGED: Final = "track_status_changed"

SOURCE_INFO_FAILED: Final = "ibs_track_release_source_info_failed"
PACKAGE_SOURCE_INVALID: Final = "ibs_track_release_package_source_invalid"
DIFF_FAILED: Final = "ibs_track_release_diff_failed"
ISSUE_IGNORED: Final = "ibs_track_release_issue_ignored"
HISTORY_UNAVAILABLE: Final = "ibs_track_release_history_unavailable"
TRACK_FAILED: Final = "ibs_track_release_track_failed"
TRACK_STALE: Final = "ibs_track_release_track_stale"

Exclusion = Literal["package", "track"]


def checksum(label: str) -> str:
    """A fictional 32-hex expanded source checksum derived from `label`."""
    return hashlib.md5(label.encode(), usedforsecurity=False).hexdigest()


CHECKPOINT: Final = checksum("fictional-checkpoint")
"""A persisted checkpoint (an earlier expanded source state)."""

CURRENT: Final = checksum("fictional-current")
"""The current expanded `srcmd5` served by source info."""

NEWER: Final = checksum("fictional-newer")
"""A later expanded state accepted by a concurrent handler."""

LINK_SRCMD5: Final = checksum("fictional-lsrcmd5")
"""The local link revision of a linked package; never a checkpoint."""

VERIFY_MD5: Final = checksum("fictional-verifymd5")


# ---------------------------------------------------------------------------
# Committed world and builders
# ---------------------------------------------------------------------------


class TrackWorld(CommittedWorld):
    """`CommittedWorld` that also deletes the checkpoints of its Tickets'
    tracks before the inherited explicit teardown, and owns one reusable
    read-only probe session."""

    _probe: AsyncSession | None = None

    async def probe(self) -> AsyncSession:
        if self._probe is None:
            self._probe = await self.open_session()
        return self._probe

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        await self.session.execute(
            delete(TrackReleaseCheckpoint).where(
                TrackReleaseCheckpoint.ticket_package_track_id.in_(tracks)
            )
        )
        await self.session.commit()
        await super().cleanup()


@dataclass(frozen=True, slots=True)
class Track:
    """One persisted track, its semantic locator, and the snapshot a
    selection would carry (Ticket CVE, package, project, checkpoint)."""

    id: uuid.UUID
    package_id: uuid.UUID
    ticket_id: uuid.UUID
    cve_id: str | None
    package_name: str
    project: str
    checkpoint: str | None

    def candidate(self, **changes: Any) -> TrackReleaseCandidate:
        """The candidate `load_track_release_candidates()` yields for this
        track, with `changes` applied."""
        assert self.cve_id is not None
        candidate = TrackReleaseCandidate(
            track_id=self.id,
            package_id=self.package_id,
            ticket_id=self.ticket_id,
            cve_id=self.cve_id,
            package_name=self.package_name,
            project=self.project,
            checkpoint=self.checkpoint,
        )
        return replace(candidate, **changes)

    def fixed_event(self, old: PackageStatus = PackageStatus.ANALYSIS) -> EventRow:
        """The one system `track_status_changed` event of an effective
        `FIXED` (ibs-track-release-detection.md, Audit and Transaction
        Guarantees)."""
        return EventRow(
            TRACK_STATUS_CHANGED,
            None,
            old.value,
            PackageStatus.FIXED.value,
            None,
            {"track": self.project, "package": self.package_name},
        )


class Seed:
    """Builds the track release data on `session`; when `world` is given,
    records every CVE, Ticket, and Product for its teardown.

    Packages are shared per `(Ticket, package name)`; every `track()` call
    creates a new track."""

    def __init__(self, session: AsyncSession, world: CommittedWorld | None = None):
        self.session = session
        self._world = world
        self._cves: dict[uuid.UUID, str | None] = {}
        self._packages: dict[tuple[uuid.UUID, str], TicketPackage] = {}

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

    async def track(
        self,
        ticket: Ticket,
        *,
        package_name: str = PACKAGE,
        project: str | None = None,
        workflow: WorkflowType = WorkflowType.IBS,
        status: PackageStatus = PackageStatus.ANALYSIS,
        delivery_status: DeliveryStatus = DeliveryStatus.PENDING,
        excluded: Exclusion | None = None,
        checkpoint: str | None = None,
        track_id: uuid.UUID | None = None,
    ) -> Track:
        """One track below the (shared) package, with a checkpoint
        accepted at `SEEN_AT` when `checkpoint` is given."""
        if project is None:
            project = PROJECT if workflow is WorkflowType.IBS else GIT_REFERENCE
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
        track = TicketPackageTrack(
            ticket_package_id=package.id,
            workflow_type=workflow.value,
            reference=project,
            status=status.value,
            delivery_status=delivery_status.value,
            deleted_at=excluded_at if excluded == "track" else None,
        )
        if track_id is not None:
            track.id = track_id
        self.session.add(track)
        await self.session.flush()
        if checkpoint is not None:
            self.session.add(
                TrackReleaseCheckpoint(
                    ticket_package_track_id=track.id,
                    srcmd5=checkpoint,
                    last_seen_at=SEEN_AT,
                )
            )
            await self.session.flush()
        return Track(
            id=track.id,
            package_id=package.id,
            ticket_id=ticket.id,
            cve_id=self._cves[ticket.id],
            package_name=package_name,
            project=project,
            checkpoint=checkpoint,
        )

    async def product(
        self,
        track: Track,
        *,
        eligible: bool = True,
        is_eligible_override: bool = False,
        released_at: datetime | None = None,
        general_support_end_date: date = AFTER_EVAL,
    ) -> uuid.UUID:
        """One Product occurrence below `track` with its own catalog
        Product; returns the occurrence ID."""
        suffix = uuid.uuid4().hex[:10]
        product = Product(
            name=f"Example Product {suffix}",
            version="1",
            display_name=f"EP {suffix}",
            cpe=f"cpe:/o:example:product:{suffix}",
            catalog_last_seen_at=datetime(2090, 1, 1, tzinfo=UTC),
            general_support_end_date=general_support_end_date,
        )
        self.session.add(product)
        await self.session.flush()
        if self._world is not None:
            self._world.product_ids.append(product.id)
        occurrence = TicketPackageProduct(
            ticket_package_track_id=track.id,
            product_id=product.id,
            eligible=eligible,
            is_eligible_override=is_eligible_override,
            released_at=released_at,
        )
        self.session.add(occurrence)
        await self.session.flush()
        return occurrence.id

    async def commit(self) -> None:
        await self.session.commit()


# ---------------------------------------------------------------------------
# Fake IBS API
# ---------------------------------------------------------------------------


def source_entry(
    package: str,
    srcmd5: str,
    *,
    lsrcmd5: str = LINK_SRCMD5,
    error: bool = False,
) -> str:
    """One `sourceinfo` entry of a linked package in the live shape
    (`sourceinfo_single_linked.xml`); `error` adds an upstream `error`
    child while keeping the checksum attributes."""
    inner = f'<linked project="{PROJECT}" package="{package}.12345"/>'
    if error:
        inner += "<error>fictional upstream failure</error>"
    return (
        f'<sourceinfo package="{package}" rev="7" vrev="1" srcmd5="{srcmd5}" '
        f'lsrcmd5="{lsrcmd5}" verifymd5="{VERIFY_MD5}">{inner}</sourceinfo>'
    )


def issue(
    label: str | None,
    *,
    state: str = "added",
    tracker: str = "cve",
    name: str | None = None,
) -> str:
    """One diff `issue` in the live attribute set; `name` defaults to the
    tracker-native form of a CVE label."""
    if name is None and label is not None and label.startswith("CVE-"):
        name = label.removeprefix("CVE-")
    attributes = {"state": state, "tracker": tracker}
    if name is not None:
        attributes["name"] = name
    if label is not None:
        attributes["label"] = label
    attributes["url"] = "https://issues.example.test/fictional"
    rendered = " ".join(f'{key}="{value}"' for key, value in attributes.items())
    return f"<issue {rendered}/>"


def diff_document(*issues: str) -> bytes:
    """An expanded source diff with `issues`; without issues, the live
    empty shape (`diff_empty.xml`: no `issues` element)."""
    body = (
        f'<old project="{PROJECT}" package="{PACKAGE}" rev="1" srcmd5="{CHECKPOINT}"/>'
        f'<new project="{PROJECT}" package="{PACKAGE}" rev="2" srcmd5="{CURRENT}"/>'
        "<files/>"
    )
    if issues:
        body += f"<issues>{''.join(issues)}</issues>"
    return f'<sourcediff key="{VERIFY_MD5}">{body}</sourcediff>'.encode()


def unavailable(
    project: str,
    package: str,
    revision: str,
    *,
    which: Literal["orev", "rev"] = "orev",
) -> Responder:
    """HTTP 400 with the live unavailable-revision status document
    (`diff_error_orev_unavailable.xml` or `diff_error_rev_unavailable.xml`)
    whose summary names `{project}/{package}/{revision}`."""
    name, fictional = (
        ("diff_error_orev_unavailable", FICTIONAL_OREV)
        if which == "orev"
        else ("diff_error_rev_unavailable", FICTIONAL_REV)
    )
    live = load_fixture(name)
    adapted = live.replace(
        f"{LIVE_PROJECT}/sudo/{fictional}".encode(),
        f"{project}/{package}/{revision}".encode(),
    )
    assert adapted != live
    return xml_response(adapted, status=400)


def raising(error: BaseException) -> Responder:
    def respond(_: httpx.Request) -> httpx.Response:
        raise error

    return respond


@dataclass(frozen=True, slots=True)
class Served:
    """One request that passed authentication and reached a responder."""

    kind: Literal["source", "diff"]
    project: str
    packages: tuple[str, ...]
    query: tuple[tuple[str, str], ...]

    @property
    def params(self) -> dict[str, str]:
        return dict(self.query)


class FakeIBS:
    """Scripted IBS source info and expanded diffs behind `server`.

    Source info: `source()` serves one valid entry per package, `entries()`
    any raw entry list (empty for a missing package, two for a duplicate),
    `fail_source()` a responder for the whole project. The response holds
    the scripted entries of the requested packages in request order.
    Diffs: `diff()` serves a responder, `issues()` a document, for one
    `(project, package, orev, rev)`; any other diff is recorded in
    `unscripted` and answered with a valid empty diff. `after_source`,
    when set, runs after each source-info response is built."""

    def __init__(self, server: IBSServer) -> None:
        self.server = server
        self.served: list[Served] = []
        self.unscripted: list[tuple[str, str, str, str]] = []
        self.events: list[str] | None = None
        self.after_source: Callable[[], None] | None = None
        self._entries: dict[str, dict[str, list[str]]] = defaultdict(dict)
        self._source_failures: dict[str, Responder] = {}
        self._diffs: dict[tuple[str, str, str, str], Responder] = {}

    def client(self, *, configured: bool = True) -> IBSClient:
        """A real client of the fictional API; `configured=False` leaves the
        account and key empty."""
        return IBSClient(
            api_url=TEST_API_URL,
            username="jdoe" if configured else "",
            ssh_private_key=SecretStr(fictional_settings_value() if configured else ""),
        )

    def source(self, project: str, package: str, srcmd5: str) -> None:
        self.entries(project, package, source_entry(package, srcmd5))

    def entries(self, project: str, package: str, *entries: str) -> None:
        self._entries[project][package] = list(entries)
        self.server.route("GET", f"/source/{project}", self._serve_source)

    def fail_source(self, project: str, responder: Responder) -> None:
        self._source_failures[project] = responder
        self.server.route("GET", f"/source/{project}", self._serve_source)

    def diff(
        self, project: str, package: str, orev: str, rev: str, responder: Responder
    ) -> None:
        self._diffs[(project, package, orev, rev)] = responder
        self.server.route("POST", f"/source/{project}/{package}", self._serve_diff)

    def issues(
        self, project: str, package: str, orev: str, rev: str, *issues: str
    ) -> None:
        self.diff(project, package, orev, rev, xml_response(diff_document(*issues)))

    def sources(self) -> list[Served]:
        return [served for served in self.served if served.kind == "source"]

    def diffs(self) -> list[tuple[str, str, str, str]]:
        """`(project, package, orev, rev)` of every served diff, in order."""
        return [
            (s.project, s.packages[0], s.params["orev"], s.params["rev"])
            for s in self.served
            if s.kind == "diff"
        ]

    def _record(self, served: Served) -> None:
        self.served.append(served)
        if self.events is not None:
            self.events.append(f"http:{served.kind}")

    def _serve_source(self, request: httpx.Request) -> httpx.Response:
        project = request.url.path.removeprefix("/source/")
        packages = request.url.params.get_list("package")
        self._record(
            Served(
                "source",
                project,
                tuple(packages),
                tuple(request.url.params.multi_items()),
            )
        )
        failure = self._source_failures.get(project)
        if failure is not None:
            response = failure(request)
        else:
            scripted = self._entries[project]
            body = "".join(
                entry for package in packages for entry in scripted.get(package, [])
            )
            response = xml_response(
                f"<sourceinfolist>{body}</sourceinfolist>".encode()
            )(request)
        if self.after_source is not None:
            self.after_source()
        return response

    def _serve_diff(self, request: httpx.Request) -> httpx.Response:
        _, _, project, package = request.url.path.split("/")
        params = request.url.params
        self._record(Served("diff", project, (package,), tuple(params.multi_items())))
        key = (project, package, params["orev"], params["rev"])
        responder = self._diffs.get(key)
        if responder is None:
            # Recorded (and visible in `diffs()`) rather than raised, so an
            # unexpected request fails the test's request assertions
            # instead of aborting the invocation.
            self.unscripted.append(key)
            return xml_response(diff_document())(request)
        return responder(request)


def install_ibs(monkeypatch: pytest.MonkeyPatch) -> FakeIBS:
    """The fake IBS API behind every `IBSClient` the test creates: the
    network transport replaced, retry backoff sleeps recorded."""
    server = IBSServer(public_key=fictional_ed25519_key().public_key())
    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=AsyncMock()))
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: server.transport())
    return FakeIBS(server)


async def reconcile(
    fake: FakeIBS,
    candidates: Iterable[TrackReleaseCandidate],
    hook: Callable[[TrackReleaseOutcome], None] | None = None,
    *,
    configured: bool = True,
    request_delay: float | None = None,
) -> list[TrackReleaseOutcome]:
    """One boundary invocation over a fresh client of `fake`;
    `request_delay` is passed only when given."""
    async with fake.client(configured=configured) as client:
        if request_delay is None:
            return await reconcile_ibs_track_releases(
                candidates, client=client, fetcher_name=FETCHER, on_outcome=hook
            )
        return await reconcile_ibs_track_releases(
            candidates,
            client=client,
            fetcher_name=FETCHER,
            on_outcome=hook,
            request_delay=request_delay,
        )


def kinds(outcomes: Iterable[TrackReleaseOutcome]) -> dict[uuid.UUID, str]:
    """`{track ID: kind}`; the boundary guarantees no ordering."""
    result: dict[uuid.UUID, str] = {}
    for outcome in outcomes:
        assert outcome.track_id not in result, "two outcomes for one track"
        result[outcome.track_id] = outcome.kind
    return result


@dataclass
class Outcomes:
    """The per-outcome hook: records each outcome and, when `events` is
    set, appends `"hook:<kind>"` to it."""

    received: list[TrackReleaseOutcome] = field(default_factory=list)
    events: list[str] | None = None

    def __call__(self, outcome: TrackReleaseOutcome) -> None:
        self.received.append(outcome)
        if self.events is not None:
            self.events.append(f"hook:{outcome.kind}")

    @property
    def kinds(self) -> dict[uuid.UUID, str]:
        return kinds(self.received)


# ---------------------------------------------------------------------------
# Substitutes
# ---------------------------------------------------------------------------


class TrackUnitSessions(UnitSessions):
    """`UnitSessions` that also calls `before_flush` with the sync session
    at the start of every flush, and raises `after_commit_error[1]` after
    the successful commit of the unit at index `after_commit_error[0]`."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        super().__init__(factory)
        self.before_flush: Callable[[Session], None] | None = None
        self.after_commit_error: tuple[int, BaseException] | None = None

    def __call__(self) -> AsyncSession:
        index = len(self.sessions)
        session = super().__call__()

        def _before_flush(flushing: Session, *_: Any) -> None:
            if self.before_flush is not None:
                self.before_flush(flushing)

        def _after_commit(_committed: Session) -> None:
            if self.after_commit_error is not None:
                failing, error = self.after_commit_error
                if failing == index:
                    raise error

        event.listen(session.sync_session, "before_flush", _before_flush)
        event.listen(session.sync_session, "after_commit", _after_commit)
        return session


def install_units(
    monkeypatch: pytest.MonkeyPatch, factory: async_sessionmaker[AsyncSession]
) -> TrackUnitSessions:
    sessions = TrackUnitSessions(factory)
    monkeypatch.setattr(ibs_track_release, "async_session_factory", sessions)
    return sessions


def before_local_unit(
    monkeypatch: pytest.MonkeyPatch,
    action: Callable[[TrackReleaseCandidate], Awaitable[None]],
) -> None:
    """Await `action(track)` inside each track's unit session before its
    first statement (so before the Ticket lock), after the track's diff."""
    original = ibs_track_release._reconcile_track

    async def wrapped(
        db: AsyncSession, track: TrackReleaseCandidate, *, srcmd5: str, evidence: bool
    ) -> Any:
        await action(track)
        return await original(db, track, srcmd5=srcmd5, evidence=evidence)

    monkeypatch.setattr(ibs_track_release, "_reconcile_track", wrapped)


def register_after_fixed(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Make every `set_track_status()` call also register a Ticket
    convergence effect for its Ticket after the real call (a system
    `FIXED` registers one by itself only when it regresses a stale
    `Resolved` Ticket). Returns the registered Tickets."""
    original = package_service.set_track_status
    registered: list[uuid.UUID] = []

    async def registering(
        db: AsyncSession, **kwargs: Any
    ) -> package_service.TrackStatusResult:
        result = await original(db, **kwargs)
        register_ticket_convergence(db, kwargs["ticket_id"])
        registered.append(kwargs["ticket_id"])
        return result

    monkeypatch.setattr(package_service, "set_track_status", registering)
    return registered


# ---------------------------------------------------------------------------
# Committed state and logs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrackRow:
    status: str
    delivery_status: str
    updated_at: datetime


async def track_row(world: TrackWorld, track: Track) -> TrackRow | None:
    """The committed track state, read through the probe session."""
    probe = await world.probe()
    row = (
        await probe.execute(
            select(
                TicketPackageTrack.status,
                TicketPackageTrack.delivery_status,
                TicketPackageTrack.updated_at,
            ).where(TicketPackageTrack.id == track.id)
        )
    ).one_or_none()
    await probe.rollback()
    return None if row is None else TrackRow(*row)


async def track_status(world: TrackWorld, track: Track) -> str | None:
    row = await track_row(world, track)
    return None if row is None else row.status


async def checkpoint_of(world: TrackWorld, track: Track) -> tuple[str, datetime] | None:
    """The committed `(srcmd5, last_seen_at)` of the track's checkpoint."""
    probe = await world.probe()
    row = (
        await probe.execute(
            select(
                TrackReleaseCheckpoint.srcmd5, TrackReleaseCheckpoint.last_seen_at
            ).where(TrackReleaseCheckpoint.ticket_package_track_id == track.id)
        )
    ).one_or_none()
    await probe.rollback()
    return None if row is None else (row.srcmd5, row.last_seen_at)


async def checkpoint_srcmd5(world: TrackWorld, track: Track) -> str | None:
    value = await checkpoint_of(world, track)
    return None if value is None else value[0]


async def events_of(world: TrackWorld, ticket_id: uuid.UUID) -> list[EventRow]:
    """The committed Ticket audit events in insertion order."""
    probe = await world.probe()
    events = await ticket_events_by_id(probe, ticket_id)
    await probe.rollback()
    return events


async def ticket_status(world: TrackWorld, ticket_id: uuid.UUID) -> str | None:
    probe = await world.probe()
    value = (
        await probe.execute(select(Ticket.status).where(Ticket.id == ticket_id))
    ).scalar_one_or_none()
    await probe.rollback()
    return value


def own(logs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """The detector's own events and the convergence publication failures
    (the HTTP client factory may log unrelated TLS diagnostics)."""
    return [
        entry
        for entry in logs
        if entry["event"].startswith("ibs_track_release_")
        or entry["event"] == PUBLICATION_FAILED_EVENT
    ]


def logged(logs: Sequence[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def track_failed(track: Track, reason_category: str) -> dict[str, Any]:
    return {
        "event": TRACK_FAILED,
        "log_level": "warning",
        "codestream": track.project,
        "package_name": track.package_name,
        "track_id": str(track.id),
        "ticket_id": str(track.ticket_id),
        "fetcher_name": FETCHER,
        "reason_category": reason_category,
    }


def track_stale(track: Track) -> dict[str, Any]:
    return {
        "event": TRACK_STALE,
        "log_level": "warning",
        "codestream": track.project,
        "package_name": track.package_name,
        "track_id": str(track.id),
        "ticket_id": str(track.ticket_id),
        "reason_category": "ticket_not_operable",
    }


def source_info_failed(
    project: str, count: int, reason_category: str, http_status: int | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event": SOURCE_INFO_FAILED,
        "log_level": "warning",
        "codestream": project,
        "affected_track_count": count,
        "reason_category": reason_category,
    }
    if http_status is not None:
        entry["http_status"] = http_status
    return entry


def package_source_invalid(
    project: str, package: str, count: int, reason_category: str
) -> dict[str, Any]:
    return {
        "event": PACKAGE_SOURCE_INVALID,
        "log_level": "warning",
        "codestream": project,
        "package_name": package,
        "affected_track_count": count,
        "reason_category": reason_category,
    }


def diff_failed(
    project: str,
    package: str,
    count: int,
    reason_category: str,
    http_status: int | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "event": DIFF_FAILED,
        "log_level": "warning",
        "codestream": project,
        "package_name": package,
        "affected_track_count": count,
        "reason_category": reason_category,
    }
    if http_status is not None:
        entry["http_status"] = http_status
    return entry


def issue_ignored(project: str = PROJECT, package: str = PACKAGE) -> dict[str, Any]:
    return {
        "event": ISSUE_IGNORED,
        "log_level": "warning",
        "codestream": project,
        "package_name": package,
        "reason_category": "invalid_cve_label",
    }


def history_unavailable(track: Track) -> dict[str, Any]:
    return {
        "event": HISTORY_UNAVAILABLE,
        "log_level": "warning",
        "codestream": track.project,
        "package_name": track.package_name,
        "track_id": str(track.id),
        "reason_category": "history_unavailable",
        "http_status": 400,
    }


def publication_failed(ticket_id: uuid.UUID) -> dict[str, Any]:
    return {
        "event": PUBLICATION_FAILED_EVENT,
        "log_level": "error",
        "ticket_id": str(ticket_id),
        "cause": "broker_operational_error",
    }
