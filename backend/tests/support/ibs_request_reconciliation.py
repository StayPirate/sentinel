"""Shared builders, fake IBS API, and world for the IBS request
reconciliation tests (backend/app/services/packages/ibs_request_*.py).

- Document builders render request detail, source history, request action
  diffs, ID searches, and source info in the live shapes of
  `tests/support/ibs_request_api.py` and `tests/support/ibs_api.py`.
  `Action` describes one action; `submission()` and `release()` build the
  usual names (`{package}.{origin}` from a staging project or an incident,
  `{package}.{incident}` in a codestream).
- `FakeRequests` serves them through the authenticating `IBSServer` with
  query-aware routes (`QueryRoutes`), so an unpaged history and an exact
  lookup of one package, or two diffs of one path, have separate routes.
  Every served request is recorded in order; an unrouted one is answered
  with HTTP 404 and recorded in `unrouted`. `quiet()` serves the empty
  open-request searches and current release evidence without the CVE.
- `scope()`, `retained()`, and `snapshot()` build the in-memory scope and
  step-1 snapshot of the observation tests.
- `RequestWorld` is a `TrackWorld` that also deletes the request evidence of
  its request numbers and tracks before the inherited teardown;
  `RequestSeed` adds retained requests, actions, and correlations;
  `install_request_units()` replaces the boundary's module-level
  `async_session_factory`.

All data is fictional: CVE identifiers `CVE-2099-NNNNNNNN`, packages
`example-*`, request numbers from 970001, incidents from 82001, checksums
derived from fictional labels, the account `jdoe` with a fictional key
derived at run time.
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.enums import (
    DeliveryStatus,
    IBSRequestActionType,
    IBSRequestState,
    PackageStatus,
    TicketStatus,
    WorkflowType,
)
from app.models.cve import CVE
from app.models.ibs_request import IBSRequest
from app.models.ibs_request_action import IBSRequestAction
from app.models.ibs_request_action_track import IBSRequestActionTrack
from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from app.services import http_client
from app.services.ibs_client import AcceptInfo, IBSClient, IBSRequestActionDetail
from app.services.ibs_request_evidence import request_action_diff_form
from app.services.packages import ibs_request_reconciliation
from app.services.packages.ibs_request_identity import (
    action_identity,
    detail_action_key,
)
from app.services.packages.ibs_request_observation import (
    IBSRequestScope,
    RetainedAction,
    RetainedRequest,
    ScopeSnapshot,
)
from app.services.packages.ibs_request_reconciliation import (
    IBSRequestOutcome,
    reconcile_ibs_requests,
)
from tests.support.ibs_api import TEST_API_URL, IBSServer, Responder, xml_response
from tests.support.ibs_keys import fictional_ed25519_key, fictional_settings_value
from tests.support.ibs_product_release import UnitSessions
from tests.support.ibs_request_api import (
    load_request_fixture,
    request_fixture_query,
    request_fixture_record,
)
from tests.support.ibs_request_provenance import (
    QueryRoutes,
    load_provenance_fixture,
    provenance_fixture_query,
    provenance_fixture_record,
)
from tests.support.ibs_track_release import TrackWorld, issue

CODESTREAM: Final = "SUSE:SLE-15-SP6:Update"
OTHER_CODESTREAM: Final = "SUSE:SLE-15-SP7:Update"
TICKET_CVE: Final = "CVE-2099-00000001"
OTHER_CVE: Final = "CVE-2099-99999999"
CREATED: Final = "2026-10-01T05:20:43"
WHEN: Final = "2026-10-01T09:16:55"
WHEN_AT: Final = datetime(2026, 10, 1, 9, 16, 55, tzinfo=UTC)
CREATED_AT: Final = datetime(2026, 10, 1, 5, 20, 43, tzinfo=UTC)
OPEN_STATES: Final = "(state/@name='new' or state/@name='review')"

SCOPE_FAILED: Final = "ibs_request_scope_failed"
SCOPE_STALE: Final = "ibs_request_scope_stale"
ISSUE_IGNORED: Final = "ibs_request_issue_ignored"

_numbers = itertools.count(970001)
_incidents = itertools.count(82001)


def next_number() -> int:
    """A fresh fictional request number."""
    return next(_numbers)


def next_incident() -> int:
    """A fresh fictional incident number."""
    return next(_incidents)


def unique_package() -> str:
    """A fresh fictional logical package, so committed evidence of one test
    never shares a retained root with another."""
    return f"example-{uuid.uuid4().hex[:10]}"


def checksum(label: str) -> str:
    """A fictional lowercase 32-hex checksum derived from `label`."""
    return hashlib.md5(label.encode(), usedforsecurity=False).hexdigest()


def origin(codestream: str) -> str:
    """The origin suffix of a maintenance package name."""
    return codestream.replace(":", "_")


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Accept:
    """One `acceptinfo` element; `None` attributes are omitted."""

    rev: str | None = "2"
    srcmd5: str | None = None
    xsrcmd5: str | None = None
    osrcmd5: str | None = None
    oxsrcmd5: str | None = None
    oproject: str | None = None
    opackage: str | None = None

    def xml(self) -> str:
        attributes = {
            name: getattr(self, name)
            for name in (
                "rev",
                "srcmd5",
                "xsrcmd5",
                "osrcmd5",
                "oxsrcmd5",
                "oproject",
                "opackage",
            )
            if getattr(self, name) is not None
        }
        rendered = " ".join(f'{k}="{v}"' for k, v in attributes.items())
        return f"<acceptinfo {rendered}/>"

    def info(self) -> AcceptInfo:
        stored = self.oproject
        if stored is not None and not stored.startswith("SUSE:"):
            stored = "_redacted_"
        return AcceptInfo(
            rev=self.rev,
            srcmd5=self.srcmd5,
            xsrcmd5=self.xsrcmd5,
            osrcmd5=self.osrcmd5,
            oxsrcmd5=self.oxsrcmd5,
            oproject=stored,
            opackage=self.opackage,
        )


def _stored(project: str | None) -> str | None:
    if project is None or project.startswith("SUSE:"):
        return project
    return "_redacted_"


@dataclass(frozen=True, slots=True)
class Action:
    """One request action as served by point detail."""

    type: str
    source_project: str
    source_package: str
    rev: str | None = None
    target_project: str | None = None
    target_package: str | None = None
    release_project: str | None = None
    accept: Accept | None = None

    def xml(self) -> str:
        source = (
            f'<source project="{self.source_project}" package="{self.source_package}"'
        )
        if self.rev is not None:
            source += f' rev="{self.rev}"'
        target_attributes = {
            "project": self.target_project,
            "package": self.target_package,
            "releaseproject": self.release_project,
        }
        target = " ".join(f'{k}="{v}"' for k, v in target_attributes.items() if v)
        body = source + "/>" + (f"<target {target}/>" if target else "")
        if self.accept is not None:
            body += self.accept.xml()
        return f'<action type="{self.type}">{body}</action>'

    def detail(self, request_number: int) -> IBSRequestActionDetail:
        """The parsed action in the stored form."""
        return IBSRequestActionDetail(
            request_number=request_number,
            action_type=IBSRequestActionType(self.type),
            source_project=_stored(self.source_project) or "",
            source_package=self.source_package,
            source_revision=self.rev,
            target_project=_stored(self.target_project),
            target_package=self.target_package,
            target_release_project=_stored(self.release_project),
            acceptinfo=None if self.accept is None else self.accept.info(),
        )

    def accepted(self, accept: Accept, **changes: Any) -> Action:
        return replace(self, accept=accept, **changes)


def submission(
    package: str,
    number: int,
    *,
    codestream: str = CODESTREAM,
    incident: int | None = None,
    accept: Accept | None = None,
    source_package: str | None = None,
    source_project: str | None = None,
    rev: str | None = None,
) -> Action:
    """A `maintenance_incident` action from the staging project of request
    `number`; with `incident`, the accepted target in that incident."""
    physical = source_package or f"{package}.{origin(codestream)}"
    return Action(
        type=IBSRequestActionType.MAINTENANCE_INCIDENT.value,
        source_project=source_project or f"SUSE:Maintenance:REQUEST:{number}",
        source_package=physical,
        rev=rev or checksum(f"sr-source-{number}-{physical}"),
        target_project=f"SUSE:Maintenance:{incident}"
        if incident
        else "SUSE:Maintenance",
        target_package=physical if incident else None,
        release_project=codestream,
        accept=accept,
    )


def release(
    package: str,
    incident: int,
    *,
    codestream: str = CODESTREAM,
    accept: Accept | None = None,
    target_package: str | None = None,
    source_project: str | None = None,
    rev: str | None = None,
) -> Action:
    """A `maintenance_release` action of `package` from incident `incident`
    to `codestream`."""
    return Action(
        type=IBSRequestActionType.MAINTENANCE_RELEASE.value,
        source_project=source_project or f"SUSE:Maintenance:{incident}",
        source_package=f"{package}.{origin(codestream)}",
        rev=rev or checksum(f"rr-source-{incident}-{package}"),
        target_project=codestream,
        target_package=target_package or f"{package}.{incident}",
        accept=accept,
    )


def request_document(
    number: int,
    state: IBSRequestState | str,
    *actions: Action,
    created: str = CREATED,
    when: str = WHEN,
    superseded_by: int | None = None,
    extra_actions: Sequence[str] = (),
) -> bytes:
    """One `<request>` point detail with `actions` (and raw
    `extra_actions`, such as ignored types)."""
    name = state.value if isinstance(state, IBSRequestState) else state
    state_attributes = f'name="{name}" created="{created}" when="{when}"'
    if superseded_by is not None:
        state_attributes += f' superseded_by="{superseded_by}"'
    body = "".join(action.xml() for action in actions) + "".join(extra_actions)
    return (
        f'<request id="{number}">{body}<state {state_attributes}/></request>'.encode()
    )


HistoryEntry = tuple[int, str, int | None]
"""`(revision, srcmd5, request number)`."""


def history_document(
    entries: Iterable[HistoryEntry], *, time: int = 1700000000
) -> bytes:
    revisions = []
    for revision, srcmd5, request in entries:
        inner = f"<srcmd5>{srcmd5}</srcmd5><time>{time + revision}</time>"
        if request is not None:
            inner += f"<requestid>{request}</requestid>"
        revisions.append(f'<revision rev="{revision}">{inner}</revision>')
    return f"<revisionlist>{''.join(revisions)}</revisionlist>".encode()


def diff_document(*issues: str) -> bytes:
    """A request action or source diff with `issues`; without issues, a
    valid diff without an `issues` element."""
    if not issues:
        return b"<sourcediff/>"
    return f"<sourcediff><issues>{''.join(issues)}</issues></sourcediff>".encode()


def cve_issue(label: str | None, *, state: str = "added") -> str:
    return issue(label, state=state)


def search_document(numbers: Iterable[int]) -> bytes:
    ids = list(numbers)
    entries = "".join(f'<request id="{n}"/>' for n in ids)
    return f'<collection matches="{len(ids)}">{entries}</collection>'.encode()


def sourceinfo_document(package: str, srcmd5: str) -> bytes:
    return (
        f'<sourceinfolist><sourceinfo package="{package}" srcmd5="{srcmd5}"/>'
        "</sourceinfolist>"
    ).encode()


def search_predicate(action_type: IBSRequestActionType, package: str) -> str:
    field_path = (
        "source/@package"
        if action_type is IBSRequestActionType.MAINTENANCE_INCIDENT
        else "target/@package"
    )
    return (
        f"action[@type='{action_type.value}' and "
        f"starts-with({field_path},'{package}.')] and {OPEN_STATES}"
    )


# ---------------------------------------------------------------------------
# Fake IBS API
# ---------------------------------------------------------------------------

Served = tuple[str, str, tuple[tuple[str, str], ...]]


class FakeRequests:
    """Scripted IBS request, history, diff, and source-info responses behind
    `server`, with query-aware routes; `served` records every routed request
    in order as `(method, path, query)`."""

    def __init__(self, server: IBSServer) -> None:
        self.server = server
        self.routes = QueryRoutes(server)
        self.served: list[Served] = []

    @property
    def unrouted(self) -> list[Served]:
        return self.routes.unrouted

    def client(self, *, configured: bool = True) -> IBSClient:
        return IBSClient(
            api_url=TEST_API_URL,
            username="jdoe" if configured else "",
            ssh_private_key=SecretStr(fictional_settings_value() if configured else ""),
        )

    def route(
        self, method: str, path: str, query: list[tuple[str, str]], responder: Responder
    ) -> None:
        def recording(request: httpx.Request) -> httpx.Response:
            self.served.append((method, path, tuple(query)))
            return responder(request)

        self.routes.route(method, path, query, recording)

    def respond(
        self, method: str, path: str, query: list[tuple[str, str]], status: int
    ) -> None:
        self.route(method, path, query, lambda _: httpx.Response(status))

    def raw_request(self, number: int, responder: Responder) -> None:
        self.route("GET", f"/request/{number}", [], responder)

    def request(
        self,
        number: int,
        state: IBSRequestState | str,
        *actions: Action,
        **kwargs: Any,
    ) -> None:
        self.raw_request(
            number, xml_response(request_document(number, state, *actions, **kwargs))
        )

    def search(
        self,
        action_type: IBSRequestActionType,
        package: str,
        numbers: Iterable[int] = (),
        *,
        responder: Responder | None = None,
    ) -> None:
        self.route(
            "GET",
            "/search/request/id",
            [("match", search_predicate(action_type, package))],
            responder or xml_response(search_document(numbers)),
        )

    def history(
        self,
        project: str,
        package: str,
        entries: Iterable[HistoryEntry] = (),
        *,
        revision: str | None = None,
        responder: Responder | None = None,
    ) -> None:
        query = [] if revision is None else [("rev", revision)]
        self.route(
            "GET",
            f"/source/{project}/{package}/_history",
            query,
            responder or xml_response(history_document(entries)),
        )

    def action_diff(
        self,
        number: int,
        action: Action,
        *issues: str,
        codestream_package: str,
        responder: Responder | None = None,
    ) -> None:
        form = request_action_diff_form(action.detail(number), codestream_package)
        query = [
            ("cmd", "diff"),
            ("view", "xml"),
            ("withissues", "1"),
            ("onlyissues", "1"),
            *form.params,
        ]
        self.route(
            "POST",
            f"/source/{form.project}/{form.package}",
            query,
            responder or xml_response(diff_document(*issues)),
        )

    def release_evidence(
        self,
        codestream: str,
        package: str,
        *issues: str,
        srcmd5: str | None = None,
        source: Responder | None = None,
        diff: Responder | None = None,
    ) -> None:
        current = srcmd5 or checksum(f"current-{codestream}-{package}")
        self.route(
            "GET",
            f"/source/{codestream}",
            [("view", "info"), ("nofilename", "1"), ("package", package)],
            source or xml_response(sourceinfo_document(package, current)),
        )
        self.route(
            "POST",
            f"/source/{codestream}/{package}",
            [
                ("cmd", "diff"),
                ("view", "xml"),
                ("onlyissues", "1"),
                ("expand", "1"),
                ("orev", "0"),
                ("rev", current),
            ],
            diff or xml_response(diff_document(*issues)),
        )

    def quiet(
        self,
        package: str,
        codestream: str = CODESTREAM,
        *,
        open_submissions: Iterable[int] = (),
        open_releases: Iterable[int] = (),
    ) -> None:
        """The open-request searches (empty unless given) and current
        release evidence without any CVE."""
        self.search(
            IBSRequestActionType.MAINTENANCE_INCIDENT, package, open_submissions
        )
        self.search(IBSRequestActionType.MAINTENANCE_RELEASE, package, open_releases)
        self.release_evidence(codestream, package)

    def paths(self) -> list[str]:
        return [path for _, path, _ in self.served]


def install_fake_requests(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    """The fake IBS API behind every `IBSClient` the test creates: no proxy,
    the network transport replaced, retry backoff sleeps recorded."""
    server = IBSServer(public_key=fictional_ed25519_key().public_key())
    for variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)

    monkeypatch.setattr(http_client, "asyncio", SimpleNamespace(sleep=AsyncMock()))
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: server.transport())
    return FakeRequests(server)


# ---------------------------------------------------------------------------
# In-memory scope and snapshot
# ---------------------------------------------------------------------------


def scope(
    *,
    cve: str | None = TICKET_CVE,
    package: str = "example",
    codestream: str = CODESTREAM,
) -> IBSRequestScope:
    return IBSRequestScope(
        ticket_id=uuid.uuid4(),
        cve_id=cve,
        package_id=uuid.uuid4(),
        package_name=package,
        track_id=uuid.uuid4(),
        codestream=codestream,
    )


def retained(
    number: int,
    state: IBSRequestState,
    action: Action,
    *,
    when: datetime = WHEN_AT,
) -> RetainedAction:
    """The retained row of `action` as the reconciliation persists it."""
    detail = action.detail(number)
    identity = action_identity(detail, accepted=state is IBSRequestState.ACCEPTED)
    assert identity.logical_package is not None
    assert identity.codestream is not None
    request = RetainedRequest(
        id=uuid.uuid4(),
        request_number=number,
        state=state,
        superseded_by_request_number=None,
        upstream_created_at=CREATED_AT,
        upstream_updated_at=when,
        created_at=when,
        updated_at=when,
    )
    accepted = detail.acceptinfo
    return RetainedAction(
        id=uuid.uuid4(),
        request=request,
        action_type=detail.action_type,
        source_project=detail.source_project,
        source_package=detail.source_package,
        target_project=detail.target_project,
        target_package=detail.target_package,
        target_release_project=detail.target_release_project,
        logical_package=identity.logical_package,
        codestream_name=identity.codestream,
        incident_number=identity.incident_number,
        accepted_revision=None if accepted is None else accepted.rev,
        accepted_srcmd5=None if accepted is None else accepted.srcmd5,
        created_at=when,
        updated_at=when,
    )


def snapshot(
    *,
    delivery: DeliveryStatus | None = DeliveryStatus.PENDING,
    correlated: Sequence[RetainedAction] = (),
    in_flight: Sequence[RetainedAction] = (),
) -> ScopeSnapshot:
    return ScopeSnapshot(
        delivery_status=delivery,
        correlated=tuple(correlated),
        in_flight=tuple(in_flight),
        fingerprint=frozenset(),
    )


def key_of(number: int, action: Action) -> object:
    return detail_action_key(action.detail(number))


# ---------------------------------------------------------------------------
# Committed world
# ---------------------------------------------------------------------------


class RequestWorld(TrackWorld):
    """`TrackWorld` that also deletes the correlations of its tracks and the
    requests (with their actions) of `request_numbers` before the inherited
    teardown; every FK of the evidence is `ON DELETE RESTRICT`."""

    request_numbers: set[int]

    def number(self) -> int:
        number = next_number()
        self.numbers().add(number)
        return number

    def numbers(self) -> set[int]:
        if not hasattr(self, "request_numbers"):
            self.request_numbers = set()
        return self.request_numbers

    async def cleanup(self) -> None:
        await self._release()
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        tracks = select(TicketPackageTrack.id).where(
            TicketPackageTrack.ticket_package_id.in_(packages)
        )
        requests = select(IBSRequest.id).where(
            IBSRequest.request_number.in_(sorted(self.numbers()))
        )
        await self.session.execute(
            delete(IBSRequestActionTrack).where(
                IBSRequestActionTrack.ticket_package_track_id.in_(tracks)
            )
        )
        await self.session.execute(
            delete(IBSRequestActionTrack).where(
                IBSRequestActionTrack.ibs_request_action_id.in_(
                    select(IBSRequestAction.id).where(
                        IBSRequestAction.ibs_request_id.in_(requests)
                    )
                )
            )
        )
        await self.session.execute(
            delete(IBSRequestAction).where(
                IBSRequestAction.ibs_request_id.in_(requests)
            )
        )
        await self.session.execute(
            delete(IBSRequest).where(
                IBSRequest.request_number.in_(sorted(self.numbers()))
            )
        )
        await self.session.commit()
        await super().cleanup()


async def seed_evidence(
    session: AsyncSession,
    number: int,
    state: IBSRequestState,
    action: Action,
    *,
    tracks: Iterable[uuid.UUID] = (),
    upstream_updated_at: datetime = WHEN_AT,
    superseded_by: int | None = None,
    retained_action: Mapping[str, Any] | None = None,
) -> uuid.UUID:
    """Persist `action` of request `number` (creating the request when
    absent) and correlate it to `tracks`; returns the action ID.
    `retained_action` overrides persisted action columns."""
    request_id = await session.scalar(
        select(IBSRequest.id).where(IBSRequest.request_number == number)
    )
    if request_id is None:
        request = IBSRequest(
            request_number=number,
            state=state.value,
            superseded_by_request_number=superseded_by,
            upstream_created_at=CREATED_AT,
            upstream_updated_at=upstream_updated_at,
        )
        session.add(request)
        await session.flush()
        request_id = request.id
    detail = action.detail(number)
    identity = action_identity(detail, accepted=state is IBSRequestState.ACCEPTED)
    assert identity.logical_package is not None
    assert identity.codestream is not None
    accepted = detail.acceptinfo
    columns: dict[str, Any] = {
        "ibs_request_id": request_id,
        "action_type": detail.action_type.value,
        "source_project": detail.source_project,
        "source_package": detail.source_package,
        "target_project": detail.target_project,
        "target_package": detail.target_package,
        "target_release_project": detail.target_release_project,
        "logical_package": identity.logical_package,
        "codestream_name": identity.codestream,
        "incident_number": identity.incident_number,
        "accepted_revision": None if accepted is None else accepted.rev,
        "accepted_srcmd5": None if accepted is None else accepted.srcmd5,
    }
    columns.update(retained_action or {})
    row = IBSRequestAction(**columns)
    session.add(row)
    await session.flush()
    for track_id in tracks:
        session.add(
            IBSRequestActionTrack(
                ibs_request_action_id=row.id, ticket_package_track_id=track_id
            )
        )
    await session.flush()
    return row.id


def install_request_units(
    monkeypatch: pytest.MonkeyPatch, factory: async_sessionmaker[AsyncSession]
) -> UnitSessions:
    sessions = UnitSessions(factory)
    monkeypatch.setattr(ibs_request_reconciliation, "async_session_factory", sessions)
    return sessions


async def reconcile(
    fake: FakeRequests,
    scopes: Iterable[IBSRequestScope],
    hook: Any = None,
    *,
    configured: bool = True,
    request_delay: float = 0.0,
) -> list[IBSRequestOutcome]:
    async with fake.client(configured=configured) as client:
        return await reconcile_ibs_requests(
            scopes, client=client, on_outcome=hook, request_delay=request_delay
        )


def kinds(outcomes: Iterable[IBSRequestOutcome]) -> dict[uuid.UUID, str]:
    result: dict[uuid.UUID, str] = {}
    for outcome in outcomes:
        assert outcome.track_id not in result, "two outcomes for one track"
        result[outcome.track_id] = outcome.kind
    return result


@dataclass
class Outcomes:
    """The per-outcome hook recorder."""

    received: list[IBSRequestOutcome] = field(default_factory=list)

    def __call__(self, outcome: IBSRequestOutcome) -> None:
        self.received.append(outcome)


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    request_number: int
    state: str
    superseded_by_request_number: int | None
    action_type: str
    logical_package: str
    codestream_name: str
    incident_number: int | None
    accepted_revision: str | None
    accepted_srcmd5: str | None
    target_project: str | None
    target_package: str | None
    source_project: str | None


async def evidence_of(session: AsyncSession, track_id: uuid.UUID) -> list[EvidenceRow]:
    """The committed actions correlated to `track_id`, ordered by request
    number and action type; the session is rolled back after the read."""
    rows = (
        await session.execute(
            select(
                IBSRequest.request_number,
                IBSRequest.state,
                IBSRequest.superseded_by_request_number,
                IBSRequestAction.action_type,
                IBSRequestAction.logical_package,
                IBSRequestAction.codestream_name,
                IBSRequestAction.incident_number,
                IBSRequestAction.accepted_revision,
                IBSRequestAction.accepted_srcmd5,
                IBSRequestAction.target_project,
                IBSRequestAction.target_package,
                IBSRequestAction.source_project,
            )
            .select_from(IBSRequestActionTrack)
            .join(
                IBSRequestAction,
                IBSRequestAction.id == IBSRequestActionTrack.ibs_request_action_id,
            )
            .join(IBSRequest, IBSRequest.id == IBSRequestAction.ibs_request_id)
            .where(IBSRequestActionTrack.ticket_package_track_id == track_id)
            .order_by(IBSRequest.request_number, IBSRequestAction.action_type)
        )
    ).all()
    await session.rollback()
    return [EvidenceRow(**row._asdict()) for row in rows]


async def request_rows(
    session: AsyncSession, numbers: Iterable[int]
) -> dict[int, tuple[str, int | None, datetime, datetime, datetime]]:
    """`{number: (state, successor, upstream created, upstream updated,
    updated_at)}` of the committed requests; rolled back after the read."""
    rows = (
        await session.execute(
            select(
                IBSRequest.request_number,
                IBSRequest.state,
                IBSRequest.superseded_by_request_number,
                IBSRequest.upstream_created_at,
                IBSRequest.upstream_updated_at,
                IBSRequest.updated_at,
            ).where(IBSRequest.request_number.in_(list(numbers)))
        )
    ).all()
    await session.rollback()
    return {row[0]: tuple(row[1:]) for row in rows}  # type: ignore[misc]


class RequestSeed:
    """Builds Tickets and tracks on a `RequestWorld` session and returns the
    scope `load_ibs_request_scopes()` would yield for each track. Packages
    are shared per `(Ticket, package name)`."""

    def __init__(self, world: RequestWorld) -> None:
        self.world = world
        self.session = world.session
        self._cves: dict[uuid.UUID, str | None] = {}
        self._packages: dict[tuple[uuid.UUID, str], TicketPackage] = {}

    async def ticket(
        self,
        status: TicketStatus = TicketStatus.ANALYSIS,
        *,
        cve_id: str | None = None,
        with_cve: bool = True,
    ) -> Ticket:
        cve: CVE | None = None
        if with_cve:
            cve = CVE(cve_id=cve_id or f"CVE-2099-{uuid.uuid4().int % 10**8:08d}")
            self.session.add(cve)
            await self.session.flush()
            self.world.cve_ids.append(cve.id)
        duplicate_of_id = None
        if status is TicketStatus.DUPLICATED:
            canonical = await self.ticket(TicketStatus.ANALYSIS, with_cve=False)
            duplicate_of_id = canonical.id
        ticket = Ticket(
            status=status.value,
            cve_id=None if cve is None else cve.id,
            duplicate_of_id=duplicate_of_id,
        )
        self.session.add(ticket)
        await self.session.flush()
        self.world.ticket_ids.append(ticket.id)
        self._cves[ticket.id] = None if cve is None else cve.cve_id
        return ticket

    async def track(
        self,
        ticket: Ticket,
        *,
        package: str,
        codestream: str = CODESTREAM,
        workflow: WorkflowType = WorkflowType.IBS,
        status: PackageStatus = PackageStatus.ANALYSIS,
        delivery: DeliveryStatus = DeliveryStatus.PENDING,
        excluded: str | None = None,
    ) -> IBSRequestScope:
        excluded_at = datetime(2026, 9, 1, tzinfo=UTC)
        ticket_package = self._packages.get((ticket.id, package))
        if ticket_package is None:
            ticket_package = TicketPackage(
                ticket_id=ticket.id,
                package_name=package,
                deleted_at=excluded_at if excluded == "package" else None,
            )
            self.session.add(ticket_package)
            await self.session.flush()
            self._packages[(ticket.id, package)] = ticket_package
        track = TicketPackageTrack(
            ticket_package_id=ticket_package.id,
            workflow_type=workflow.value,
            reference=codestream,
            status=status.value,
            delivery_status=delivery.value,
            deleted_at=excluded_at if excluded == "track" else None,
        )
        self.session.add(track)
        await self.session.flush()
        return IBSRequestScope(
            ticket_id=ticket.id,
            cve_id=self._cves[ticket.id],
            package_id=ticket_package.id,
            package_name=package,
            track_id=track.id,
            codestream=codestream,
        )

    async def evidence(
        self,
        number: int,
        state: IBSRequestState,
        action: Action,
        *,
        tracks: Iterable[IBSRequestScope] = (),
        **kwargs: Any,
    ) -> uuid.UUID:
        self.world.numbers().add(number)
        return await seed_evidence(
            self.session,
            number,
            state,
            action,
            tracks=[scope.track_id for scope in tracks],
            **kwargs,
        )

    async def commit(self) -> None:
        await self.session.commit()


async def delivery_of(session: AsyncSession, track_id: uuid.UUID) -> str | None:
    value = await session.scalar(
        select(TicketPackageTrack.delivery_status).where(
            TicketPackageTrack.id == track_id
        )
    )
    await session.rollback()
    return value


def serve_request_group_fixture(fake: FakeRequests, name: str) -> None:
    """Route a fixture of `tests/support/ibs_request_api.py` at its recorded
    method, path, and query."""
    record = request_fixture_record(name)
    fake.route(
        record["method"],
        record["path"],
        request_fixture_query(name),
        xml_response(load_request_fixture(name)),
    )


def serve_provenance(fake: FakeRequests, name: str) -> None:
    """Route a fixture of `tests/support/ibs_request_provenance.py` at its
    recorded method, path, and query."""
    record = provenance_fixture_record(name)
    fake.route(
        record["method"],
        record["path"],
        provenance_fixture_query(name),
        xml_response(load_provenance_fixture(name)),
    )
