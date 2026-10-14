"""Unit tests for the lock-free observation of one IBS request scope
(backend/app/services/packages/ibs_request_observation.py): `observe_scope()`
and the per-invocation `EvidenceCache`.

Owning specifications:

- docs/features/packages/ibs-submission-tracking.md (Request States;
  Package and Codestream Identity; Required Roots, including the in-flight
  SR of root 1, the release proof applied first, and a `RELEASED` track;
  Request Discovery and Detail, including evidence reuse within one
  invocation; Action-Scoped CVE Evidence; Effective SR; Release Discovery;
  Accepted RR Provenance; Observation Outcomes; Delivery Derivation; Shared
  Authoritative Reconciliation > Scope Identity, Algorithm steps 2-3, and
  Structured Logs (`ibs_request_issue_ignored`); Fetcher > Request Delay;
  Testing Requirements).
- docs/features/integrations/ibs-integration.md (Request ID Search; Request
  Point Detail; Request Action Diff; Package Source History; Service Layer
  > IBSClient escaping outcomes).

Every test drives a real `IBSClient` over the authenticating fake IBS API of
`tests/support/ibs_request_reconciliation.py` (`FakeRequests`): routes are
query-aware, `served` records each request that reached a responder, and an
unrouted query is answered with HTTP 404. No database or Redis is used.
Unless a test states otherwise, the scope is the Ticket CVE `TICKET_CVE` of
a fresh fictional logical package in `CODESTREAM`, with a `PENDING`
baseline and no retained evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, Final
from unittest.mock import AsyncMock, call

import httpx
import pytest
from structlog.testing import capture_logs

from app.core.enums import DeliveryStatus, IBSRequestActionType, IBSRequestState
from app.services.packages import ibs_request_observation
from app.services.packages.ibs_request_identity import (
    action_identity,
    detail_action_key,
)
from app.services.packages.ibs_request_observation import (
    NO_MATCH,
    ActionWrite,
    EvidenceCache,
    IBSRequestScope,
    Observation,
    RequestWrite,
    ScopeSnapshot,
    UnusableObservation,
    observe_scope,
)
from tests.support.ibs_api import Responder, status_response, xml_response
from tests.support.ibs_request_reconciliation import (
    CODESTREAM,
    CREATED_AT,
    ISSUE_IGNORED,
    OTHER_CODESTREAM,
    OTHER_CVE,
    TICKET_CVE,
    WHEN_AT,
    Accept,
    Action,
    FakeRequests,
    HistoryEntry,
    checksum,
    cve_issue,
    install_fake_requests,
    next_incident,
    next_number,
    origin,
    release,
    retained,
    scope,
    snapshot,
    sourceinfo_document,
    submission,
    unique_package,
)
from tests.support.ibs_track_release import issue, raising

pytestmark = pytest.mark.unit

MI: Final = IBSRequestActionType.MAINTENANCE_INCIDENT
MR: Final = IBSRequestActionType.MAINTENANCE_RELEASE
NEW: Final = IBSRequestState.NEW
REVIEW: Final = IBSRequestState.REVIEW
ACCEPTED: Final = IBSRequestState.ACCEPTED
DECLINED: Final = IBSRequestState.DECLINED
SUPERSEDED: Final = IBSRequestState.SUPERSEDED

INTEGER_MAX: Final = 2_147_483_647
RELEASE_REV: Final = "3"
"""The acceptinfo `rev` of every accepted release action built here."""
SEARCH_PATH: Final = "/search/request/id"


@pytest.fixture(autouse=True)
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeRequests:
    return install_fake_requests(monkeypatch)


@pytest.fixture
def package() -> str:
    return unique_package()


# ---------------------------------------------------------------------------
# Invocation helpers
# ---------------------------------------------------------------------------


async def observe(
    fake: FakeRequests,
    target: IBSRequestScope,
    state: ScopeSnapshot | None = None,
    *,
    configured: bool = True,
) -> Observation:
    """Observe one scope with its own client and evidence cache."""
    async with fake.client(configured=configured) as client:
        return await observe_scope(
            target, state or snapshot(), EvidenceCache(client, request_delay=0.0)
        )


async def unusable(
    fake: FakeRequests,
    target: IBSRequestScope,
    state: ScopeSnapshot | None = None,
    *,
    configured: bool = True,
) -> UnusableObservation:
    with pytest.raises(UnusableObservation) as raised:
        await observe(fake, target, state, configured=configured)
    return raised.value


async def observe_together(
    fake: FakeRequests,
    targets: list[tuple[IBSRequestScope, ScopeSnapshot]],
    *,
    delay: float = 0.0,
) -> list[Observation | UnusableObservation]:
    """Observe several scopes in order through one shared evidence cache."""
    results: list[Observation | UnusableObservation] = []
    async with fake.client() as client:
        cache = EvidenceCache(client, request_delay=delay)
        for target, state in targets:
            try:
                results.append(await observe_scope(target, state, cache))
            except UnusableObservation as exc:
                results.append(exc)
    return results


# ---------------------------------------------------------------------------
# Expected writes and served-request views
# ---------------------------------------------------------------------------


def request_write(
    number: int, state: IBSRequestState, *, superseded_by: int | None = None
) -> RequestWrite:
    return RequestWrite(
        request_number=number,
        state=state,
        superseded_by_request_number=superseded_by,
        upstream_created_at=CREATED_AT,
        upstream_updated_at=WHEN_AT,
    )


def action_write(
    number: int,
    action: Action,
    *,
    package: str,
    state: IBSRequestState,
    codestream: str = CODESTREAM,
) -> ActionWrite:
    """The stored form of `action` as Package and Codestream Identity and
    the IBSRequestAction columns define it."""
    detail = action.detail(number)
    accepted = detail.acceptinfo
    return ActionWrite(
        key=detail_action_key(detail),
        request_number=number,
        action_type=detail.action_type,
        source_project=detail.source_project,
        source_package=detail.source_package,
        target_project=detail.target_project,
        target_package=detail.target_package,
        target_release_project=detail.target_release_project,
        logical_package=package,
        codestream_name=codestream,
        incident_number=action_identity(
            detail, accepted=state is ACCEPTED
        ).incident_number,
        accepted_revision=None if accepted is None else accepted.rev,
        accepted_srcmd5=None if accepted is None else accepted.srcmd5,
    )


def detail_numbers(fake: FakeRequests) -> list[int]:
    """The request numbers point-fetched, in order."""
    return [
        int(path.removeprefix("/request/"))
        for method, path, _ in fake.served
        if method == "GET" and path.startswith("/request/")
    ]


def action_diff_paths(fake: FakeRequests) -> list[str]:
    """The paths of the request action diffs requested, in order."""
    return [
        path
        for method, path, query in fake.served
        if method == "POST" and ("withissues", "1") in query
    ]


def history_requests(
    fake: FakeRequests,
) -> list[tuple[str, tuple[tuple[str, str], ...]]]:
    return [
        (path, query) for _, path, query in fake.served if path.endswith("/_history")
    ]


def searched(fake: FakeRequests) -> bool:
    return SEARCH_PATH in fake.paths()


def source_info_requested(fake: FakeRequests, codestream: str = CODESTREAM) -> bool:
    return ("GET", f"/source/{codestream}") in {(m, p) for m, p, _ in fake.served}


def issue_logs(logs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == ISSUE_IGNORED]


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


def serve_searches(
    fake: FakeRequests,
    package: str,
    *,
    submissions: tuple[int, ...] = (),
    releases: tuple[int, ...] = (),
) -> None:
    fake.search(MI, package, submissions)
    fake.search(MR, package, releases)


def open_submission(
    fake: FakeRequests,
    package: str,
    *issues: str,
    state: IBSRequestState | str = REVIEW,
    diff: bool = True,
) -> tuple[int, Action]:
    """Route the detail of an SR with one matching `maintenance_incident`
    action and, with `diff`, that action's not-accepted diff."""
    number = next_number()
    action = submission(package, number)
    fake.request(number, state, action)
    if diff:
        fake.action_diff(number, action, *issues, codestream_package=package)
    return number, action


@dataclass(frozen=True, slots=True)
class AcceptedSubmission:
    """An accepted SR action into incident `incident`; history `srcmd5` is
    the unexpanded `srcmd5`, `xsrcmd5` the different expanded checksum."""

    number: int
    incident: int
    action: Action
    srcmd5: str
    xsrcmd5: str

    @property
    def project(self) -> str:
        return f"SUSE:Maintenance:{self.incident}"

    @property
    def physical(self) -> str:
        assert self.action.target_package is not None
        return self.action.target_package

    def open_form(self, package: str) -> Action:
        """The action as retained while the SR was open."""
        return submission(package, self.number)


def accepted_submission(
    package: str, *, incident: int | None = None, acceptinfo: bool = True
) -> AcceptedSubmission:
    number = next_number()
    srcmd5 = checksum(f"sr-commit-{number}")
    xsrcmd5 = checksum(f"sr-expanded-{number}")
    accept = Accept(rev="2", srcmd5=srcmd5, xsrcmd5=xsrcmd5) if acceptinfo else None
    incident = incident or next_incident()
    return AcceptedSubmission(
        number=number,
        incident=incident,
        action=submission(package, number, incident=incident, accept=accept),
        srcmd5=srcmd5,
        xsrcmd5=xsrcmd5,
    )


def correlated_open_form(package: str, sr: AcceptedSubmission) -> ScopeSnapshot:
    """A snapshot whose track is correlated to `sr` as retained while it was
    open, so its current accepted detail is point-fetched."""
    return snapshot(correlated=[retained(sr.number, REVIEW, sr.open_form(package))])


def incident_history(*revisions: tuple[str, int | None]) -> list[HistoryEntry]:
    """A complete unpaged history from revision 1."""
    return [
        (index, srcmd5, request)
        for index, (srcmd5, request) in enumerate(revisions, start=1)
    ]


@dataclass(frozen=True, slots=True)
class AcceptedRelease:
    number: int
    incident: int
    action: Action
    srcmd5: str

    @property
    def target_package(self) -> str:
        assert self.action.target_package is not None
        return self.action.target_package


def accepted_release(
    package: str, *, accept: Accept | None = None, acceptinfo: bool = True
) -> AcceptedRelease:
    number, incident = next_number(), next_incident()
    srcmd5 = checksum(f"rr-target-{number}")
    if acceptinfo and accept is None:
        accept = Accept(rev=RELEASE_REV, srcmd5=srcmd5)
    return AcceptedRelease(
        number=number,
        incident=incident,
        action=release(package, incident, accept=accept),
        srcmd5=srcmd5,
    )


def serve_release(
    fake: FakeRequests,
    package: str,
    rr: AcceptedRelease,
    *issues: str,
    lookup: bool = True,
    state: IBSRequestState = ACCEPTED,
) -> None:
    """Route the detail, the release diff, and the exact lookup that proves
    `rr` (its own target package at the acceptinfo `rev`)."""
    fake.request(rr.number, state, rr.action)
    fake.action_diff(rr.number, rr.action, *issues, codestream_package=package)
    if lookup:
        fake.history(
            CODESTREAM,
            rr.target_package,
            [(int(RELEASE_REV), rr.srcmd5, rr.number)],
            revision=RELEASE_REV,
        )


def codestream_history(fake: FakeRequests, package: str, *requests: int | None) -> None:
    """The unpaged codestream history of `package`, oldest first; each
    revision carries the link-update checksum."""
    fake.history(
        CODESTREAM,
        package,
        [
            (index, checksum(f"link-{package}-{index}"), request)
            for index, request in enumerate(requests, start=1)
        ],
    )


def proven(package: str, rr: AcceptedRelease) -> Observation:
    return Observation(
        DeliveryStatus.RELEASED,
        (request_write(rr.number, ACCEPTED),),
        (action_write(rr.number, rr.action, package=package, state=ACCEPTED),),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestObservationWithoutRequests:
    """Scope Identity and Required Roots: outcomes decided before any IBS
    request."""

    async def test_observe_scope_cve_less_scope_returns_no_match_without_requests(
        self, fake: FakeRequests, package: str
    ) -> None:
        assert await observe(fake, scope(cve=None, package=package)) == NO_MATCH
        assert fake.server.requests == []

    async def test_observe_scope_track_absent_at_step_1_returns_no_match(
        self, fake: FakeRequests, package: str
    ) -> None:
        observation = await observe(
            fake, scope(package=package), snapshot(delivery=None)
        )

        assert observation == NO_MATCH
        assert fake.server.requests == []

    @pytest.mark.parametrize(
        ("package_name", "codestream"),
        [
            pytest.param("bad name", CODESTREAM, id="package-not-an-ibs-name"),
            pytest.param("p" * 255, CODESTREAM, id="search-prefix-too-long"),
            pytest.param("example", "SUSE:SLE 15:Update", id="codestream-not-a-name"),
        ],
    )
    async def test_observe_scope_invalid_identity_is_incomplete_without_requests(
        self, fake: FakeRequests, package_name: str, codestream: str
    ) -> None:
        exc = await unusable(fake, scope(package=package_name, codestream=codestream))

        assert (exc.reason_category, exc.failed) == ("invalid_identity", False)
        assert fake.server.requests == []

    async def test_observe_scope_codestream_outside_suse_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        target = scope(package=package, codestream="openSUSE:Leap:15.6:Update")

        exc = await unusable(fake, target)

        assert (exc.reason_category, exc.failed) == ("outside_suse_namespace", False)
        assert fake.server.requests == []


class TestRequestStates:
    """Request States, Delivery Derivation, and Action-Scoped CVE Evidence
    for the request state of a matching action."""

    @pytest.mark.parametrize("state", [NEW, REVIEW])
    async def test_open_submission_positive_diff_is_in_progress_with_upstream_times(
        self, fake: FakeRequests, package: str, state: IBSRequestState
    ) -> None:
        number = next_number()
        action = submission(package, number)
        fake.request(
            number,
            state,
            action,
            created="2026-09-30T22:05:01",
            when="2026-10-02T07:45:12",
        )
        fake.action_diff(
            number, action, cve_issue(TICKET_CVE), codestream_package=package
        )
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        source_package = f"{package}.{origin(CODESTREAM)}"
        source_project = f"SUSE:Maintenance:REQUEST:{number}"
        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (
                RequestWrite(
                    request_number=number,
                    state=state,
                    superseded_by_request_number=None,
                    upstream_created_at=datetime(2026, 9, 30, 22, 5, 1, tzinfo=UTC),
                    upstream_updated_at=datetime(2026, 10, 2, 7, 45, 12, tzinfo=UTC),
                ),
            ),
            (
                ActionWrite(
                    key=(number, MI, source_project, source_package, CODESTREAM),
                    request_number=number,
                    action_type=MI,
                    source_project=source_project,
                    source_package=source_package,
                    target_project="SUSE:Maintenance",
                    target_package=None,
                    target_release_project=CODESTREAM,
                    logical_package=package,
                    codestream_name=CODESTREAM,
                    incident_number=None,
                    accepted_revision=None,
                    accepted_srcmd5=None,
                ),
            ),
        )
        assert fake.unrouted == []

    @pytest.mark.parametrize(
        "state",
        [DECLINED, IBSRequestState.REVOKED, IBSRequestState.DELETED],
    )
    async def test_closed_request_matching_action_needs_no_diff_and_is_pending(
        self, fake: FakeRequests, package: str, state: IBSRequestState
    ) -> None:
        number, _ = open_submission(fake, package, state=state, diff=False)
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert action_diff_paths(fake) == []
        assert fake.unrouted == []

    async def test_superseded_request_without_relevant_successor_is_pending(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, successor = next_number(), next_number()
        fake.request(
            number, SUPERSEDED, submission(package, number), superseded_by=successor
        )
        fake.request(successor, IBSRequestState.REVOKED, submission(package, successor))
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert detail_numbers(fake) == [number, successor]
        assert action_diff_paths(fake) == []

    async def test_correlated_submission_now_declined_refreshes_request_only(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, action = open_submission(fake, package, state=DECLINED, diff=False)
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(number, REVIEW, action)]),
        )

        assert observation == Observation(
            DeliveryStatus.PENDING, (request_write(number, DECLINED),), ()
        )
        assert action_diff_paths(fake) == []

    async def test_declined_request_returning_to_review_is_in_progress(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, action = open_submission(fake, package, state=REVIEW, diff=False)
        fake.quiet(package, open_submissions=[number])

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(number, DECLINED, action)]),
        )

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(number, REVIEW),),
            (action_write(number, action, package=package, state=REVIEW),),
        )
        assert action_diff_paths(fake) == []

    async def test_correlated_request_detail_404_is_incomplete_not_deleted(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        fake.respond("GET", f"/request/{number}", [], 404)
        fake.quiet(package)
        state = snapshot(
            correlated=[retained(number, REVIEW, submission(package, number))]
        )

        exc = await unusable(fake, scope(package=package), state)

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            "not_found",
            number,
            False,
        )

    async def test_unknown_request_state_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, _ = open_submission(fake, package, state="frozen", diff=False)
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == ("invalid_state", number)


class TestSupersession:
    """Required Roots root 3 and Request Discovery and Detail: the closure of
    every `superseded_by_request_number`."""

    async def test_successor_open_with_positive_diff_is_in_progress(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, successor = next_number(), next_number()
        fake.request(
            number, SUPERSEDED, submission(package, number), superseded_by=successor
        )
        successor_action = submission(package, successor)
        fake.request(successor, REVIEW, successor_action)
        fake.action_diff(
            successor,
            successor_action,
            cve_issue(TICKET_CVE),
            codestream_package=package,
        )
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(successor, REVIEW),),
            (action_write(successor, successor_action, package=package, state=REVIEW),),
        )
        assert detail_numbers(fake) == [number, successor]
        assert len(action_diff_paths(fake)) == 1

    async def test_supersession_cycle_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        first, second = next_number(), next_number()
        fake.request(
            first, SUPERSEDED, submission(package, first), superseded_by=second
        )
        fake.request(
            second, SUPERSEDED, submission(package, second), superseded_by=first
        )
        fake.quiet(package, open_submissions=[first])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "supersession_cycle",
            second,
        )
        assert detail_numbers(fake) == [first, second]

    async def test_missing_successor_is_not_found(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, successor = next_number(), next_number()
        fake.request(
            number, SUPERSEDED, submission(package, number), superseded_by=successor
        )
        fake.respond("GET", f"/request/{successor}", [], 404)
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == ("not_found", successor)

    async def test_unknown_successor_state_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, successor = next_number(), next_number()
        fake.request(
            number, SUPERSEDED, submission(package, number), superseded_by=successor
        )
        fake.request(successor, "frozen", submission(package, successor))
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "invalid_state",
            successor,
        )
        assert detail_numbers(fake) == [number, successor]


class TestActionScopedEvidence:
    """Action-Scoped CVE Evidence, Package and Codestream Identity, and the
    `ibs_request_issue_ignored` log of Structured Logs."""

    @pytest.mark.parametrize("issue_state", ["added", "changed"])
    async def test_cve_issue_added_or_changed_is_positive(
        self, fake: FakeRequests, package: str, issue_state: str
    ) -> None:
        number, _ = open_submission(
            fake, package, cve_issue(TICKET_CVE, state=issue_state)
        )
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation.derived is DeliveryStatus.IN_PROGRESS
        assert [write.request_number for write in observation.actions] == [number]

    @pytest.mark.parametrize(
        "evidence",
        [
            pytest.param(cve_issue(TICKET_CVE, state="deleted"), id="deleted"),
            pytest.param(issue(TICKET_CVE, tracker="bnc"), id="bnc-tracker"),
            pytest.param(issue(TICKET_CVE, tracker="jsc"), id="other-tracker"),
            pytest.param(cve_issue(OTHER_CVE), id="other-cve"),
            pytest.param(issue(None, name=TICKET_CVE), id="name-only"),
            pytest.param(issue(None), id="label-less"),
            pytest.param(issue(TICKET_CVE.lower()), id="non-canonical-label"),
        ],
    )
    async def test_non_qualifying_issue_is_a_no_match(
        self, fake: FakeRequests, package: str, evidence: str
    ) -> None:
        number, _ = open_submission(fake, package, evidence)
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert len(action_diff_paths(fake)) == 1

    async def test_invalid_cve_labels_log_once_per_diff_with_bounded_fields(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, _ = open_submission(
            fake,
            package,
            issue(None),
            issue("cve-2099-00000002", state="changed"),
            cve_issue(TICKET_CVE),
        )
        fake.quiet(package, open_submissions=[number])

        with capture_logs() as logs:
            observation = await observe(fake, scope(package=package))

        assert observation.derived is DeliveryStatus.IN_PROGRESS
        assert issue_logs(logs) == [
            {
                "event": ISSUE_IGNORED,
                "log_level": "warning",
                "package_name": package,
                "codestream": CODESTREAM,
                "request_number": number,
                "reason_category": "invalid_cve_label",
            }
        ]

    @pytest.mark.parametrize(
        "evidence",
        [
            pytest.param(cve_issue(OTHER_CVE), id="valid-other-label"),
            pytest.param(issue(None, state="deleted"), id="label-less-deleted"),
            pytest.param(issue(None, tracker="bnc"), id="label-less-bnc"),
        ],
    )
    async def test_issue_outside_cve_evidence_states_logs_nothing(
        self, fake: FakeRequests, package: str, evidence: str
    ) -> None:
        number, _ = open_submission(fake, package, evidence)
        fake.quiet(package, open_submissions=[number])

        with capture_logs() as logs:
            await observe(fake, scope(package=package))

        assert issue_logs(logs) == []

    async def test_release_evidence_invalid_label_logs_without_request_number(
        self, fake: FakeRequests, package: str
    ) -> None:
        serve_searches(fake, package)
        fake.release_evidence(CODESTREAM, package, issue(None), issue(None))

        with capture_logs() as logs:
            observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert issue_logs(logs) == [
            {
                "event": ISSUE_IGNORED,
                "log_level": "warning",
                "package_name": package,
                "codestream": CODESTREAM,
                "reason_category": "invalid_cve_label",
            }
        ]

    async def test_issue_ignored_log_omits_codestream_outside_suse(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, incident = next_number(), next_incident()
        action = Action(
            type=MI.value,
            source_project=f"SUSE:Maintenance:REQUEST:{number}",
            source_package=f"{package}.openSUSE_Leap_15.6_Update",
            target_project=f"SUSE:Maintenance:{incident}",
            target_package=f"{package}.openSUSE_Leap_15.6_Update",
            release_project="openSUSE:Leap:15.6:Update",
            accept=Accept(rev="2", srcmd5=checksum(f"sr-commit-{number}")),
        )
        fake.action_diff(number, action, issue(None), codestream_package=package)

        with capture_logs() as logs:
            async with fake.client() as client:
                labels = await EvidenceCache(client).action_labels(
                    action.detail(number), package
                )

        assert labels == frozenset()
        assert issue_logs(logs) == [
            {
                "event": ISSUE_IGNORED,
                "log_level": "warning",
                "package_name": package,
                "request_number": number,
                "reason_category": "invalid_cve_label",
            }
        ]
        assert "openSUSE" not in repr(logs)
        assert "_redacted_" not in repr(logs)

    @pytest.mark.parametrize(
        ("responder", "reason"),
        [
            pytest.param(
                xml_response(b"<sourcediff><issues>"), "malformed_xml", id="malformed"
            ),
            pytest.param(
                xml_response(b"<status/>"), "invalid_document", id="other-root"
            ),
            pytest.param(status_response(400), "rejected", id="http-400"),
            pytest.param(status_response(404), "not_found", id="http-404"),
        ],
    )
    async def test_unusable_action_diff_is_incomplete(
        self,
        fake: FakeRequests,
        package: str,
        responder: Responder,
        reason: str,
    ) -> None:
        number = next_number()
        action = submission(package, number)
        fake.request(number, REVIEW, action)
        fake.action_diff(
            number, action, codestream_package=package, responder=responder
        )
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            reason,
            number,
            False,
        )

    async def test_valid_diff_without_issues_is_a_no_match(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, _ = open_submission(fake, package)
        fake.quiet(package, open_submissions=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())

    async def test_open_submission_from_outside_suse_is_incomplete_without_diff(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        fake.request(
            number,
            REVIEW,
            submission(package, number, source_project="home:example-user:branches"),
        )
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "outside_suse_namespace",
            number,
        )
        assert action_diff_paths(fake) == []
        assert all("home:" not in str(request.url) for request in fake.server.requests)

    async def test_multi_action_request_plans_only_the_matching_action(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, incident = next_number(), next_incident()
        matching = release(package, incident)
        patchinfo = Action(
            type=MR.value,
            source_project=f"SUSE:Maintenance:{incident}",
            source_package="patchinfo",
            rev=checksum(f"patchinfo-{incident}"),
            target_project=CODESTREAM,
            target_package=f"patchinfo.{incident}",
        )
        other_codestream = release(package, incident, codestream=OTHER_CODESTREAM)
        submit = (
            f'<action type="submit"><source project="SUSE:Maintenance:{incident}" '
            f'package="{package}-channel"/></action>'
        )
        fake.request(
            number,
            REVIEW,
            patchinfo,
            matching,
            other_codestream,
            extra_actions=[submit],
        )
        fake.action_diff(
            number, matching, cve_issue(TICKET_CVE), codestream_package=package
        )
        fake.quiet(package, open_releases=[number])

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(number, REVIEW),),
            (action_write(number, matching, package=package, state=REVIEW),),
        )
        assert action_diff_paths(fake) == [
            f"/source/SUSE:Maintenance:{incident}/{package}.{origin(CODESTREAM)}"
        ]

    async def test_one_request_matching_two_codestreams_correlates_per_scope(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        first = submission(package, number)
        second = submission(package, number, codestream=OTHER_CODESTREAM)
        fake.request(number, REVIEW, first, second)
        fake.action_diff(
            number, first, cve_issue(TICKET_CVE), codestream_package=package
        )
        fake.action_diff(
            number, second, cve_issue(OTHER_CVE), codestream_package=package
        )
        serve_searches(fake, package, submissions=(number,))
        fake.release_evidence(CODESTREAM, package)
        fake.release_evidence(OTHER_CODESTREAM, package)

        results = await observe_together(
            fake,
            [
                (scope(package=package), snapshot()),
                (
                    scope(cve=OTHER_CVE, package=package, codestream=OTHER_CODESTREAM),
                    snapshot(),
                ),
            ],
        )

        assert results == [
            Observation(
                DeliveryStatus.IN_PROGRESS,
                (request_write(number, REVIEW),),
                (action_write(number, first, package=package, state=REVIEW),),
            ),
            Observation(
                DeliveryStatus.IN_PROGRESS,
                (request_write(number, REVIEW),),
                (
                    action_write(
                        number,
                        second,
                        package=package,
                        state=REVIEW,
                        codestream=OTHER_CODESTREAM,
                    ),
                ),
            ),
        ]
        assert detail_numbers(fake) == [number]

    async def test_correlated_open_action_is_not_diffed_again(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, action = open_submission(fake, package, diff=False)
        fake.quiet(package, open_submissions=[number])

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(number, REVIEW, action)]),
        )

        assert observation.derived is DeliveryStatus.IN_PROGRESS
        assert action_diff_paths(fake) == []
        assert detail_numbers(fake) == [number]

    @pytest.mark.parametrize(
        ("source_project", "suffix"),
        [
            pytest.param("SUSE:Maintenance:REQUEST:1", 0, id="non-incident-source"),
            pytest.param(None, 1, id="other-incident-suffix"),
        ],
    )
    async def test_unresolved_release_action_is_incomplete(
        self,
        fake: FakeRequests,
        package: str,
        source_project: str | None,
        suffix: int,
    ) -> None:
        number, incident = next_number(), next_incident()
        action = release(
            package,
            incident,
            source_project=source_project,
            target_package=f"{package}.{incident + suffix}",
        )
        fake.request(number, REVIEW, action)
        fake.quiet(package, open_releases=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "unresolved_action",
            number,
        )
        assert action_diff_paths(fake) == []


class TestEffectiveSubmission:
    """Effective SR and Required Roots root 7 for an accepted matching
    `maintenance_incident` action."""

    async def test_effective_by_request_number_and_unexpanded_srcmd5(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.history(
            sr.project,
            sr.physical,
            incident_history((checksum("branch"), None), (sr.srcmd5, sr.number)),
        )
        fake.quiet(package)

        observation = await observe(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(sr.number, ACCEPTED),),
            (
                ActionWrite(
                    key=(
                        sr.number,
                        MI,
                        f"SUSE:Maintenance:REQUEST:{sr.number}",
                        sr.physical,
                        CODESTREAM,
                    ),
                    request_number=sr.number,
                    action_type=MI,
                    source_project=f"SUSE:Maintenance:REQUEST:{sr.number}",
                    source_package=sr.physical,
                    target_project=sr.project,
                    target_package=sr.physical,
                    target_release_project=CODESTREAM,
                    logical_package=package,
                    codestream_name=CODESTREAM,
                    incident_number=sr.incident,
                    accepted_revision="2",
                    accepted_srcmd5=sr.srcmd5,
                ),
            ),
        )
        assert action_diff_paths(fake) == []

    async def test_history_carrying_expanded_checksum_is_missing_provenance(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.history(
            sr.project,
            sr.physical,
            incident_history((checksum("branch"), None), (sr.xsrcmd5, sr.number)),
        )
        fake.quiet(package)

        exc = await unusable(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert (exc.reason_category, exc.request_number) == (
            "missing_provenance",
            sr.number,
        )

    async def test_branch_commit_and_release_revisions_do_not_end_the_sr(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        rr_number = next_number()
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.request(
            rr_number,
            ACCEPTED,
            release(
                package, sr.incident, accept=Accept(rev="1", srcmd5=checksum("rr"))
            ),
        )
        fake.history(
            sr.project,
            sr.physical,
            incident_history(
                (checksum("branch"), None),
                (sr.srcmd5, sr.number),
                (checksum("direct"), None),
                (checksum("release"), rr_number),
            ),
        )
        fake.quiet(package)

        observation = await observe(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert observation.derived is DeliveryStatus.IN_PROGRESS
        assert detail_numbers(fake) == [sr.number, rr_number]

    @pytest.mark.parametrize(
        ("later_issues", "derived"),
        [
            pytest.param(
                (cve_issue(TICKET_CVE, state="changed"),),
                DeliveryStatus.IN_PROGRESS,
                id="with-cve",
            ),
            pytest.param(
                (cve_issue(OTHER_CVE),), DeliveryStatus.PENDING, id="without-cve"
            ),
        ],
    )
    async def test_later_sr_replacing_incident_contents_decides_progress(
        self,
        fake: FakeRequests,
        package: str,
        later_issues: tuple[str, ...],
        derived: DeliveryStatus,
    ) -> None:
        sr = accepted_submission(package)
        later = accepted_submission(package, incident=sr.incident)
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.request(later.number, ACCEPTED, later.action)
        fake.action_diff(
            later.number, later.action, *later_issues, codestream_package=package
        )
        fake.history(
            sr.project,
            sr.physical,
            incident_history(
                (checksum("branch"), None),
                (sr.srcmd5, sr.number),
                (checksum("branch-2"), None),
                (later.srcmd5, later.number),
            ),
        )
        fake.quiet(package)

        observation = await observe(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        planned = [(sr.number, sr.action)]
        if derived is DeliveryStatus.IN_PROGRESS:
            planned.append((later.number, later.action))
        assert observation == Observation(
            derived,
            tuple(request_write(number, ACCEPTED) for number, _ in planned),
            tuple(
                action_write(number, action, package=package, state=ACCEPTED)
                for number, action in planned
            ),
        )
        assert len(history_requests(fake)) == 1

    @pytest.mark.parametrize(
        ("history", "reason"),
        [
            pytest.param(None, "not_found", id="http-404"),
            pytest.param(((2, "sr"),), "history_unavailable", id="not-from-revision-1"),
            pytest.param(((1, "branch"), (3, "sr")), "history_unavailable", id="gap"),
        ],
    )
    async def test_unavailable_incident_history_is_incomplete(
        self,
        fake: FakeRequests,
        package: str,
        history: tuple[tuple[int, str], ...] | None,
        reason: str,
    ) -> None:
        sr = accepted_submission(package)
        fake.request(sr.number, ACCEPTED, sr.action)
        if history is None:
            fake.history(sr.project, sr.physical, responder=status_response(404))
        else:
            fake.history(
                sr.project,
                sr.physical,
                [
                    (
                        revision,
                        sr.srcmd5 if label == "sr" else checksum(label),
                        sr.number,
                    )
                    for revision, label in history
                ],
            )
        fake.quiet(package)

        exc = await unusable(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert (exc.reason_category, exc.request_number) == (reason, sr.number)

    @pytest.mark.parametrize(
        "entries",
        [
            pytest.param(((checksum("branch"), None),), id="no-request-revision"),
            pytest.param(((checksum("other"), "own"),), id="other-srcmd5"),
            pytest.param(((None, "other"),), id="other-request"),
        ],
    )
    async def test_history_without_the_action_revision_is_missing_provenance(
        self,
        fake: FakeRequests,
        package: str,
        entries: tuple[tuple[str | None, str | None], ...],
    ) -> None:
        sr = accepted_submission(package)
        other = next_number()
        requests = {None: None, "own": sr.number, "other": other}
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.history(
            sr.project,
            sr.physical,
            incident_history(
                *(
                    (srcmd5 or sr.srcmd5, requests[request])
                    for srcmd5, request in entries
                )
            ),
        )
        fake.quiet(package)

        exc = await unusable(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert (exc.reason_category, exc.request_number) == (
            "missing_provenance",
            sr.number,
        )

    async def test_accepted_action_without_acceptinfo_is_missing_provenance(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package, acceptinfo=False)
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.quiet(package)

        exc = await unusable(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert (exc.reason_category, exc.request_number) == (
            "missing_provenance",
            sr.number,
        )
        assert history_requests(fake) == []

    async def test_unavailable_detail_of_later_request_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        later = next_number()
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.respond("GET", f"/request/{later}", [], 404)
        fake.history(
            sr.project,
            sr.physical,
            incident_history((sr.srcmd5, sr.number), (checksum("later"), later)),
        )
        fake.quiet(package)

        exc = await unusable(
            fake, scope(package=package), correlated_open_form(package, sr)
        )

        assert (exc.reason_category, exc.request_number) == ("not_found", later)

    async def test_retained_accepted_sr_uses_retained_provenance_without_detail(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        fake.history(
            sr.project,
            sr.physical,
            incident_history((checksum("branch"), None), (sr.srcmd5, sr.number)),
        )
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(sr.number, ACCEPTED, sr.action)]),
        )

        assert observation == Observation(DeliveryStatus.IN_PROGRESS, (), ())
        assert detail_numbers(fake) == []
        assert action_diff_paths(fake) == []

    async def test_accepted_sr_never_observed_while_open_is_not_discovered(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        fake.request(sr.number, ACCEPTED, sr.action)
        fake.quiet(package)

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert detail_numbers(fake) == []


class TestCurrentReleaseEvidence:
    """Release Discovery step 1 and Required Roots root 5."""

    async def test_evidence_without_cve_requires_no_scan(
        self, fake: FakeRequests, package: str
    ) -> None:
        fake.quiet(package)

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert [(method, path) for method, path, _ in fake.served] == [
            ("GET", f"/source/{CODESTREAM}"),
            ("POST", f"/source/{CODESTREAM}/{package}"),
            ("GET", SEARCH_PATH),
            ("GET", SEARCH_PATH),
        ]

    async def test_evidence_with_cve_scans_the_codestream_history(
        self, fake: FakeRequests, package: str
    ) -> None:
        fake.release_evidence(
            CODESTREAM, package, cve_issue(TICKET_CVE, state="changed")
        )
        codestream_history(fake, package, None)
        serve_searches(fake, package)

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert history_requests(fake) == [
            (f"/source/{CODESTREAM}/{package}/_history", ())
        ]

    @pytest.mark.parametrize(
        ("document", "reason"),
        [
            pytest.param(b"<sourceinfolist/>", "missing", id="missing"),
            pytest.param(
                sourceinfo_document("PKG", "not-a-checksum"),
                "invalid_srcmd5",
                id="srcmd5",
            ),
            pytest.param(
                b'<sourceinfolist><sourceinfo package="PKG"><error>x</error>'
                b"</sourceinfo></sourceinfolist>",
                "upstream_error",
                id="error-entry",
            ),
            pytest.param(b"<sourceinfolist", "malformed_xml", id="malformed"),
            pytest.param(b"<collection/>", "invalid_document", id="other-root"),
        ],
    )
    async def test_unusable_source_info_is_incomplete(
        self, fake: FakeRequests, package: str, document: bytes, reason: str
    ) -> None:
        fake.release_evidence(
            CODESTREAM,
            package,
            source=xml_response(document.replace(b"PKG", package.encode())),
        )

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            reason,
            None,
            False,
        )
        assert not searched(fake)

    @pytest.mark.parametrize(
        ("document", "reason"),
        [
            pytest.param(b"<sourcediff><issues>", "malformed_xml", id="malformed"),
            pytest.param(
                b'<sourcediff><issues><issue tracker="cve" state="open"/></issues>'
                b"</sourcediff>",
                "invalid_issue",
                id="invalid-issue",
            ),
        ],
    )
    async def test_unusable_source_diff_is_incomplete(
        self, fake: FakeRequests, package: str, document: bytes, reason: str
    ) -> None:
        fake.release_evidence(CODESTREAM, package, diff=xml_response(document))

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.failed) == (reason, False)

    @pytest.mark.parametrize("operation", ["source", "diff"])
    @pytest.mark.parametrize(
        ("responder", "reason", "status"),
        [
            pytest.param(status_response(500), "http_status", 500, id="http-500"),
            pytest.param(
                raising(httpx.ConnectError("fictional connection failure")),
                "transport",
                None,
                id="transport",
            ),
        ],
    )
    async def test_release_evidence_request_failure_fails_the_scope(
        self,
        fake: FakeRequests,
        package: str,
        operation: str,
        responder: Responder,
        reason: str,
        status: int | None,
    ) -> None:
        if operation == "source":
            fake.release_evidence(CODESTREAM, package, source=responder)
        else:
            fake.release_evidence(CODESTREAM, package, diff=responder)

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.http_status, exc.failed) == (
            reason,
            status,
            True,
        )
        assert not searched(fake)


class TestReleaseScan:
    """Release Discovery step 2 and Accepted RR Provenance through the
    newest-first scan of the codestream history."""

    async def test_release_proven_at_the_newest_entry_ends_the_observation(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, None, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE))

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(
            DeliveryStatus.RELEASED,
            (request_write(rr.number, ACCEPTED),),
            (
                ActionWrite(
                    key=(rr.number, MR, CODESTREAM, f"{package}.{rr.incident}"),
                    request_number=rr.number,
                    action_type=MR,
                    source_project=f"SUSE:Maintenance:{rr.incident}",
                    source_package=f"{package}.{origin(CODESTREAM)}",
                    target_project=CODESTREAM,
                    target_package=f"{package}.{rr.incident}",
                    target_release_project=None,
                    logical_package=package,
                    codestream_name=CODESTREAM,
                    incident_number=rr.incident,
                    accepted_revision=RELEASE_REV,
                    accepted_srcmd5=rr.srcmd5,
                ),
            ),
        )
        assert not searched(fake)
        assert fake.unrouted == []

    async def test_release_proven_at_an_older_entry_after_a_diff_without_cve(
        self, fake: FakeRequests, package: str
    ) -> None:
        older, newer = accepted_release(package), accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, older.number, newer.number)
        serve_release(fake, package, older, cve_issue(TICKET_CVE))
        serve_release(fake, package, newer, cve_issue(OTHER_CVE), lookup=False)

        observation = await observe(fake, scope(package=package))

        assert observation == proven(package, older)
        assert detail_numbers(fake) == [newer.number, older.number]
        assert history_requests(fake)[1:] == [
            (
                f"/source/{CODESTREAM}/{older.target_package}/_history",
                (("rev", RELEASE_REV),),
            )
        ]

    async def test_entries_without_request_or_matching_action_are_skipped(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        unrelated = next_number()
        fake.request(
            unrelated,
            ACCEPTED,
            release(
                package,
                next_incident(),
                codestream=OTHER_CODESTREAM,
                accept=Accept(rev="1", srcmd5=checksum("inherited")),
            ),
        )
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number, None, unrelated, None)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE))

        observation = await observe(fake, scope(package=package))

        assert observation == proven(package, rr)
        assert detail_numbers(fake) == [unrelated, rr.number]
        assert action_diff_paths(fake) == [f"/source/{CODESTREAM}/{rr.target_package}"]

    async def test_matching_action_without_acceptinfo_stops_the_scan(
        self, fake: FakeRequests, package: str
    ) -> None:
        older = accepted_release(package)
        unrecorded = accepted_release(package, acceptinfo=False)
        fake.request(unrecorded.number, ACCEPTED, unrecorded.action)
        serve_release(fake, package, older, cve_issue(TICKET_CVE))
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, older.number, unrecorded.number)
        sr_number, sr_action = open_submission(fake, package, cve_issue(TICKET_CVE))
        serve_searches(fake, package, submissions=(sr_number,))

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(sr_number, REVIEW),),
            (action_write(sr_number, sr_action, package=package, state=REVIEW),),
        )
        assert detail_numbers(fake) == [unrecorded.number, sr_number]

    async def test_exhausted_history_completes_without_a_proof(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, None, rr.number, None)
        serve_release(fake, package, rr, cve_issue(OTHER_CVE), lookup=False)
        serve_searches(fake, package)

        observation = await observe(fake, scope(package=package))

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert searched(fake)

    async def test_unavailable_entry_detail_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        fake.respond("GET", f"/request/{number}", [], 404)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, number)

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == ("not_found", number)
        assert not searched(fake)

    @pytest.mark.parametrize(
        ("lookup", "reason"),
        [
            pytest.param("other-srcmd5", "release_proof_failed", id="other-srcmd5"),
            pytest.param("other-request", "release_proof_failed", id="other-request"),
            pytest.param("other-revision", "invalid_entry", id="other-revision"),
            pytest.param("unavailable", "not_found", id="unavailable"),
        ],
    )
    async def test_failed_release_proof_is_incomplete(
        self, fake: FakeRequests, package: str, lookup: str, reason: str
    ) -> None:
        rr = accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE), lookup=False)
        entries: dict[str, list[HistoryEntry]] = {
            "other-srcmd5": [(3, checksum("link-update"), rr.number)],
            "other-request": [(3, rr.srcmd5, next_number())],
            "other-revision": [(4, rr.srcmd5, rr.number)],
        }
        if lookup == "unavailable":
            fake.history(
                CODESTREAM,
                rr.target_package,
                revision=RELEASE_REV,
                responder=status_response(404),
            )
        else:
            fake.history(
                CODESTREAM, rr.target_package, entries[lookup], revision=RELEASE_REV
            )

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            reason,
            rr.number,
            False,
        )

    async def test_matching_action_of_open_request_is_contradictory(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package, acceptinfo=False)
        fake.request(rr.number, REVIEW, rr.action)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number)

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "contradictory_evidence",
            rr.number,
        )
        assert action_diff_paths(fake) == []

    @pytest.mark.parametrize(
        "accept",
        [
            pytest.param(
                Accept(rev=None, srcmd5=checksum("released")), id="without-rev"
            ),
            pytest.param(
                Accept(rev=RELEASE_REV, srcmd5=None, xsrcmd5=checksum("expanded")),
                id="without-srcmd5",
            ),
        ],
    )
    async def test_acceptinfo_without_rev_or_srcmd5_is_missing_provenance(
        self, fake: FakeRequests, package: str, accept: Accept
    ) -> None:
        rr = accepted_release(package, accept=accept)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE), lookup=False)

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "missing_provenance",
            rr.number,
        )
        assert history_requests(fake) == [
            (f"/source/{CODESTREAM}/{package}/_history", ())
        ]

    async def test_logical_codestream_package_is_never_the_proof_target(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, None, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE), lookup=False)
        fake.history(
            CODESTREAM,
            rr.target_package,
            revision=RELEASE_REV,
            responder=status_response(404),
        )
        fake.history(
            CODESTREAM,
            package,
            [(int(RELEASE_REV), rr.srcmd5, rr.number)],
            revision=RELEASE_REV,
        )

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == ("not_found", rr.number)
        assert (
            f"/source/{CODESTREAM}/{package}/_history",
            (("rev", RELEASE_REV),),
        ) not in (history_requests(fake))

    async def test_proven_release_skips_remaining_roots_even_when_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE))
        fake.search(MI, package, responder=status_response(404))
        fake.search(MR, package, responder=status_response(404))
        in_flight = accepted_submission(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(
                in_flight=[retained(in_flight.number, ACCEPTED, in_flight.action)]
            ),
        )

        assert observation == proven(package, rr)
        assert not searched(fake)
        assert in_flight.number not in detail_numbers(fake)


class TestReleaseProofFirst:
    """Required Roots and Accepted RR Provenance: the proof applied first to
    the accepted release actions correlated to the track."""

    async def test_correlated_release_proven_in_chain_order_without_scan(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE))

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(rr.number, ACCEPTED, rr.action)]),
        )

        assert observation == proven(package, rr)
        assert [(method, path) for method, path, _ in fake.served] == [
            ("GET", f"/request/{rr.number}"),
            ("GET", f"/source/{CODESTREAM}/{rr.target_package}/_history"),
            ("POST", f"/source/{CODESTREAM}/{rr.target_package}"),
        ]

    async def test_incomplete_correlated_proof_then_scan_proof_is_released(
        self, fake: FakeRequests, package: str
    ) -> None:
        stale, rr = accepted_release(package), accepted_release(package)
        serve_release(fake, package, stale, cve_issue(TICKET_CVE), lookup=False)
        fake.history(
            CODESTREAM,
            stale.target_package,
            revision=RELEASE_REV,
            responder=status_response(404),
        )
        fake.release_evidence(CODESTREAM, package, cve_issue(TICKET_CVE))
        codestream_history(fake, package, rr.number)
        serve_release(fake, package, rr, cve_issue(TICKET_CVE))

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(stale.number, ACCEPTED, stale.action)]),
        )

        assert observation == proven(package, rr)

    async def test_incomplete_correlated_proof_without_other_proof_is_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        stale = accepted_release(package)
        serve_release(fake, package, stale, cve_issue(TICKET_CVE), lookup=False)
        fake.history(
            CODESTREAM,
            stale.target_package,
            revision=RELEASE_REV,
            responder=status_response(404),
        )
        fake.quiet(package)

        exc = await unusable(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(stale.number, ACCEPTED, stale.action)]),
        )

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            "not_found",
            stale.number,
            False,
        )
        assert source_info_requested(fake)
        assert not searched(fake)

    async def test_correlated_release_without_acceptinfo_is_no_evidence(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package, acceptinfo=False)
        fake.request(rr.number, ACCEPTED, rr.action)
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(rr.number, ACCEPTED, rr.action)]),
        )

        assert observation == Observation(DeliveryStatus.PENDING, (), ())
        assert action_diff_paths(fake) == []
        assert history_requests(fake) == []

    async def test_correlated_open_release_is_in_progress_without_proof(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package, acceptinfo=False)
        fake.request(rr.number, REVIEW, rr.action)
        fake.quiet(package, open_releases=[rr.number])

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(correlated=[retained(rr.number, REVIEW, rr.action)]),
        )

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(rr.number, REVIEW),),
            (action_write(rr.number, rr.action, package=package, state=REVIEW),),
        )
        assert detail_numbers(fake) == [rr.number]
        assert action_diff_paths(fake) == []

    async def test_retained_accepted_request_fetched_only_for_release_proof_diff(
        self, fake: FakeRequests, package: str
    ) -> None:
        sr = accepted_submission(package)
        rr = accepted_release(package)
        serve_release(fake, package, rr, cve_issue(OTHER_CVE))
        fake.history(
            sr.project,
            sr.physical,
            incident_history((checksum("branch"), None), (sr.srcmd5, sr.number)),
        )
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(
                correlated=[
                    retained(sr.number, ACCEPTED, sr.action),
                    retained(rr.number, ACCEPTED, rr.action),
                ]
            ),
        )

        assert observation == Observation(DeliveryStatus.IN_PROGRESS, (), ())
        assert detail_numbers(fake) == [rr.number]
        assert action_diff_paths(fake) == [f"/source/{CODESTREAM}/{rr.target_package}"]


class TestReleasedBaseline:
    """Required Roots: a `RELEASED` track without the release proof, roots 5,
    6, and 7, and the in-flight SRs of root 1."""

    async def test_released_baseline_refreshes_roots_1_to_4_only(
        self, fake: FakeRequests, package: str
    ) -> None:
        rr = accepted_release(package)
        sr = accepted_submission(package)
        flight = accepted_submission(package)
        fake.request(sr.number, ACCEPTED, sr.action)
        open_number, open_action = open_submission(fake, package, cve_issue(TICKET_CVE))
        serve_searches(fake, package, submissions=(open_number,))
        state = snapshot(
            delivery=DeliveryStatus.RELEASED,
            correlated=[
                retained(rr.number, ACCEPTED, rr.action),
                retained(sr.number, REVIEW, sr.open_form(package)),
            ],
            in_flight=[retained(flight.number, ACCEPTED, flight.action)],
        )

        observation = await observe(fake, scope(package=package), state)

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(sr.number, ACCEPTED), request_write(open_number, REVIEW)),
            (
                action_write(sr.number, sr.action, package=package, state=ACCEPTED),
                action_write(open_number, open_action, package=package, state=REVIEW),
            ),
        )
        assert detail_numbers(fake) == [sr.number, open_number]
        assert history_requests(fake) == []
        assert not source_info_requested(fake)
        assert fake.unrouted == []


class TestInFlightSubmission:
    """Required Roots root 1: an uncorrelated in-flight accepted SR."""

    async def test_positive_and_effective_in_flight_sr_is_correlated(
        self, fake: FakeRequests, package: str
    ) -> None:
        flight = accepted_submission(package)
        fake.request(flight.number, ACCEPTED, flight.action)
        fake.action_diff(
            flight.number,
            flight.action,
            cve_issue(TICKET_CVE),
            codestream_package=package,
        )
        fake.history(
            flight.project,
            flight.physical,
            incident_history(
                (checksum("branch"), None), (flight.srcmd5, flight.number)
            ),
        )
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(in_flight=[retained(flight.number, ACCEPTED, flight.action)]),
        )

        assert observation == Observation(
            DeliveryStatus.IN_PROGRESS,
            (request_write(flight.number, ACCEPTED),),
            (
                action_write(
                    flight.number, flight.action, package=package, state=ACCEPTED
                ),
            ),
        )

    @pytest.mark.parametrize(
        "unavailable",
        ["detail", "diff", "history", "history-incomplete", "negative-diff"],
    )
    async def test_unavailable_in_flight_evidence_is_not_evidence(
        self, fake: FakeRequests, package: str, unavailable: str
    ) -> None:
        flight = accepted_submission(package)
        if unavailable == "detail":
            fake.respond("GET", f"/request/{flight.number}", [], 404)
        else:
            fake.request(flight.number, ACCEPTED, flight.action)
        fake.action_diff(
            flight.number,
            flight.action,
            cve_issue(OTHER_CVE if unavailable == "negative-diff" else TICKET_CVE),
            codestream_package=package,
            responder=status_response(404) if unavailable == "diff" else None,
        )
        if unavailable == "history":
            fake.history(
                flight.project, flight.physical, responder=status_response(404)
            )
        else:
            first = 2 if unavailable == "history-incomplete" else 1
            fake.history(
                flight.project, flight.physical, [(first, flight.srcmd5, flight.number)]
            )
        fake.quiet(package)

        observation = await observe(
            fake,
            scope(package=package),
            snapshot(in_flight=[retained(flight.number, ACCEPTED, flight.action)]),
        )

        assert observation == Observation(DeliveryStatus.PENDING, (), ())

    async def test_in_flight_transport_failure_fails_the_scope(
        self, fake: FakeRequests, package: str
    ) -> None:
        flight = accepted_submission(package)
        fake.request(flight.number, ACCEPTED, flight.action)
        fake.action_diff(
            flight.number,
            flight.action,
            codestream_package=package,
            responder=raising(httpx.ConnectError("fictional connection failure")),
        )
        fake.quiet(package)

        exc = await unusable(
            fake,
            scope(package=package),
            snapshot(in_flight=[retained(flight.number, ACCEPTED, flight.action)]),
        )

        assert (exc.reason_category, exc.request_number, exc.failed) == (
            "transport",
            flight.number,
            True,
        )


def shared_evidence(fake: FakeRequests, package: str) -> tuple[int, Action]:
    """Current release evidence naming both CVEs, a scanned release without
    either, and an open SR whose diff names only `TICKET_CVE`: nine
    distinct artifacts."""
    rr = accepted_release(package)
    fake.release_evidence(
        CODESTREAM, package, cve_issue(TICKET_CVE), cve_issue(OTHER_CVE)
    )
    codestream_history(fake, package, rr.number)
    serve_release(fake, package, rr, lookup=False)
    number, action = open_submission(fake, package, cve_issue(TICKET_CVE))
    serve_searches(fake, package, submissions=(number,))
    return number, action


class TestEvidenceReuse:
    """Request Discovery and Detail: each artifact obtained at most once per
    invocation and reused without merging scope outcomes."""

    async def test_two_scopes_obtain_each_artifact_once_without_merging(
        self, fake: FakeRequests, package: str
    ) -> None:
        number, action = shared_evidence(fake, package)

        results = await observe_together(
            fake,
            [
                (scope(package=package), snapshot()),
                (scope(cve=OTHER_CVE, package=package), snapshot()),
            ],
        )

        assert results == [
            Observation(
                DeliveryStatus.IN_PROGRESS,
                (request_write(number, REVIEW),),
                (action_write(number, action, package=package, state=REVIEW),),
            ),
            Observation(DeliveryStatus.PENDING, (), ()),
        ]
        assert len(fake.served) == 9
        assert len(set(fake.served)) == 9

    async def test_incomplete_shared_artifact_makes_every_scope_incomplete(
        self, fake: FakeRequests, package: str
    ) -> None:
        fake.release_evidence(CODESTREAM, package)
        fake.search(MI, package, responder=status_response(404))
        fake.search(MR, package)

        results = await observe_together(
            fake,
            [
                (scope(package=package), snapshot()),
                (scope(cve=OTHER_CVE, package=package), snapshot()),
            ],
        )

        assert [
            (result.reason_category, result.failed)
            for result in results
            if isinstance(result, UnusableObservation)
        ] == [("not_found", False), ("not_found", False)]
        assert fake.paths().count(SEARCH_PATH) == 1


class TestRequestDelay:
    """Fetcher > Request Delay as applied by `EvidenceCache`."""

    async def test_delay_precedes_every_later_request_across_scopes(
        self, fake: FakeRequests, package: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        waits: list[int] = []
        recorder = AsyncMock(side_effect=lambda _: waits.append(len(fake.served)))
        monkeypatch.setattr(
            ibs_request_observation, "asyncio", SimpleNamespace(sleep=recorder)
        )
        shared_evidence(fake, package)

        await observe_together(
            fake,
            [
                (scope(package=package), snapshot()),
                (scope(cve=OTHER_CVE, package=package), snapshot()),
            ],
            delay=0.25,
        )

        assert len(fake.served) == 9
        assert waits == list(range(1, 9))
        assert recorder.await_args_list == [call(0.25)] * 8

    async def test_zero_delay_never_waits(
        self, fake: FakeRequests, package: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = AsyncMock()
        monkeypatch.setattr(
            ibs_request_observation, "asyncio", SimpleNamespace(sleep=recorder)
        )
        shared_evidence(fake, package)

        await observe_together(fake, [(scope(package=package), snapshot())])

        assert len(fake.served) == 9
        recorder.assert_not_awaited()


class TestRequestFailures:
    """Structured Logs reason categories of failed IBS operations."""

    async def test_credentials_not_configured_fail_before_any_request(
        self, fake: FakeRequests, package: str
    ) -> None:
        fake.quiet(package)

        exc = await unusable(fake, scope(package=package), configured=False)

        assert (exc.reason_category, exc.failed) == ("credentials_not_configured", True)
        assert fake.server.requests == []

    async def test_rejected_signature_fails_with_its_reason(
        self, fake: FakeRequests, package: str
    ) -> None:
        fake.quiet(package)
        fake.server.reject_signatures = True

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.failed) == ("signature_rejected", True)
        assert fake.served == []

    async def test_detail_403_fails_with_http_status(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        fake.respond("GET", f"/request/{number}", [], 403)
        fake.quiet(package)
        state = snapshot(
            correlated=[retained(number, REVIEW, submission(package, number))]
        )

        exc = await unusable(fake, scope(package=package), state)

        assert (
            exc.reason_category,
            exc.http_status,
            exc.request_number,
            exc.failed,
        ) == ("http_status", 403, number, True)


class TestValueOutOfRange:
    """Observation Outcomes: a value to be persisted that exceeds its
    column."""

    async def test_request_number_above_integer_range_is_out_of_range(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = INTEGER_MAX + 1
        action = submission(package, number)
        fake.request(number, REVIEW, action)
        fake.action_diff(
            number, action, cve_issue(TICKET_CVE), codestream_package=package
        )
        fake.quiet(package, open_submissions=[number])

        exc = await unusable(fake, scope(package=package))

        assert (exc.reason_category, exc.request_number) == (
            "value_out_of_range",
            number,
        )

    async def test_successor_above_integer_range_is_out_of_range(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        fake.request(
            number,
            SUPERSEDED,
            submission(package, number),
            superseded_by=INTEGER_MAX + 1,
        )
        fake.quiet(package)
        state = snapshot(
            correlated=[retained(number, REVIEW, submission(package, number))]
        )

        exc = await unusable(fake, scope(package=package), state)

        assert (exc.reason_category, exc.request_number) == (
            "value_out_of_range",
            number,
        )

    @pytest.mark.parametrize(
        ("incident", "rev"),
        [
            pytest.param(INTEGER_MAX + 1, "2", id="incident-number"),
            pytest.param(None, "9" * 256, id="acceptinfo-rev-of-256-digits"),
        ],
    )
    async def test_accepted_value_above_column_is_out_of_range(
        self, fake: FakeRequests, package: str, incident: int | None, rev: str
    ) -> None:
        number = next_number()
        accepted = submission(
            package,
            number,
            incident=incident or next_incident(),
            accept=Accept(rev=rev, srcmd5=checksum(f"sr-commit-{number}")),
        )
        fake.request(number, ACCEPTED, accepted)
        fake.quiet(package)
        state = snapshot(
            correlated=[retained(number, REVIEW, submission(package, number))]
        )

        exc = await unusable(fake, scope(package=package), state)

        assert (exc.reason_category, exc.request_number) == (
            "value_out_of_range",
            number,
        )

    async def test_acceptinfo_rev_of_255_characters_is_in_range(
        self, fake: FakeRequests, package: str
    ) -> None:
        number = next_number()
        accepted = submission(
            package,
            number,
            incident=next_incident(),
            accept=Accept(rev="9" * 255, srcmd5=checksum(f"sr-commit-{number}")),
        )
        fake.request(number, ACCEPTED, accepted)
        assert accepted.target_project is not None
        assert accepted.target_package is not None
        fake.history(
            accepted.target_project,
            accepted.target_package,
            incident_history((checksum(f"sr-commit-{number}"), number)),
        )
        fake.quiet(package)
        state = snapshot(
            correlated=[retained(number, REVIEW, submission(package, number))]
        )

        observation = await observe(fake, scope(package=package), state)

        assert [write.accepted_revision for write in observation.actions] == ["9" * 255]
