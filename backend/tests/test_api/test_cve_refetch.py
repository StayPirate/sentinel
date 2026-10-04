"""End-to-end tests for Re-fetch CVE Data
(`POST /api/v1/cves/{cve_id}/refetch`, `backend/app/api/v1/cves.py`).

Owning specifications:

- docs/features/tickets/cve-tracking.md (Re-fetch Endpoint: the source
  semantics, the four result lists, the error table, Access check behavior,
  Behavior; Security);
- docs/api-spec.md (Authorization Chain Evaluation Order; Query Parameter
  Length Limit; NUL Characters in Request Input; Response Format; Global
  Responses; CVE Accessibility Check with the refetch exception and outcome
  matrix; Manual-Zone Mutability Guard; CVE Identifier Resolution);
- docs/features/identity/rbac.md (Endpoint Permission Map row
  `POST /api/v1/cves/{cve_id}/refetch` -> `triage_ticket`; Predefined
  Roles; Authorization Chain Evaluation Order, CVE refetch paragraph);
- docs/features/tickets/cve-service.md (Fetch Orchestration: Transactional
  Preparation, Database-Free Publication, `FetchDispatchResult`, Callers and
  Ordering);
- docs/features/tickets/ticket-audit-log.md (CVE refetch creates no event);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch;
  Mandatory Test Scenarios > API Endpoints; Ticket Accessibility).

The service matrix, the lock order, commit/close/lock release before
publication, commit failures, and the locked-current accessibility races
are proven by `tests/test_services/test_cve_refetch.py`; these tests cover
the HTTP contract. The handler has no `DatabaseSession`: its service opens
one short session from the overridable `get_cve_refetch_session_factory`,
pointed here at sessions joined to the `db_session` connection in
`create_savepoint` mode (the per-test rollback discards everything).

Every test except the production-reachability class empties both fetcher
registries under `isolated_fetcher_registries` and defines its own test-only
CVE fetchers. The broker is never reached (`task_publication.publish_task`
is a recorder) and the pending-marker client is either `ScriptedRedis` or
forbidden; "zero Redis commands" refers to that client (authentication's
session cache is a separate Redis boundary isolated by `redis_client`).

Capability premise (rbac.md, Predefined Roles): `vulnerability_analyst`
(scope `all`) and `restricted_analyst` (scope `non_confidential`) hold
`triage_ticket`; `admin` does not.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
import pytest_asyncio
import redis.asyncio as redis_asyncio
from celery.exceptions import OperationalError as BrokerOperationalError
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.api.v1 import cves as route
from app.core.enums import (
    Capability,
    CVESourceType,
    Role,
    SessionCreationReason,
    TicketStatus,
)
from app.core.permissions import get_capabilities
from app.main import app
from app.models.cve import CVE
from app.models.fetcher_config import FetcherConfig
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import base_cve_fetcher, task_publication
from app.services.session_service import create_session
from tests.support.cve_catch_up import Publications, define_cve_fetcher
from tests.support.cve_source_status import clear_fetcher_registries
from tests.support.fetch_single_cve import (
    TASK,
    ScriptedRedis,
    assert_private_logs,
    events_named,
    fictional_cve_id,
    forbid_redis,
    pending_key,
)
from tests.support.ticket_mutations import StatementRecorder

Factory = Callable[..., Awaitable[Any]]

_PATH = "/api/v1/cves/{cve_id}/refetch"
_NOT_FOUND = b'{"code":"CVE_NOT_FOUND","detail":"CVE not found."}'
_UNAUTHENTICATED = {
    "code": "AUTH_NOT_AUTHENTICATED",
    "detail": "Authentication required",
}
_FORBIDDEN = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}
_CELERY_UNAVAILABLE = {
    "code": "CELERY_UNAVAILABLE",
    "detail": "CVE refetch could not be dispatched to the task broker",
}
_NUL_ERROR = {"msg": "Value error, must not contain U+0000", "type": "value_error"}

UNCONFIRMED = "cve_fetch_publication_unconfirmed"
"""The WARNING of a non-empty `sources_failed` (issue #800, D4)."""

SECRET = "amqp://refetch-user:fictional-secret@broker.example.test:5672//"
"""A fictional credential-bearing broker detail carried by injected errors."""

NVD = CVESourceType.NVD
MITRE = CVESourceType.MITRE
KERNEL = CVESourceType.KERNEL
REDHAT = CVESourceType.REDHAT
GHSA = CVESourceType.GHSA
OSV = CVESourceType.OSV
EPSS = CVESourceType.EPSS

# A statement reading or writing a CVE- or Ticket-domain table.
_DOMAIN_TABLE = re.compile(r'\b(?:FROM|INTO|UPDATE|JOIN)\s+"?(?:ticket|cve)\w*"?\b')


def _url(cve_id: str) -> str:
    return _PATH.format(cve_id=cve_id)


def _result(
    enqueued: list[str],
    pending: list[str],
    disabled: list[str],
    failed: list[str],
) -> dict[str, Any]:
    """The exact 202 body (cve-tracking.md, Success response)."""
    return {
        "data": {
            "sources_enqueued": enqueued,
            "sources_already_pending": pending,
            "sources_disabled": disabled,
            "sources_failed": failed,
        }
    }


def _failing_for(sources: set[str], error: Exception) -> Any:
    """A `Publications.before` hook raising `error` for `sources`."""

    async def before(call_options: dict[str, Any]) -> None:
        if call_options["kwargs"]["source"] in sources:
            raise error

    return before


def _assert_error_envelope(response: httpx.Response, status: int, code: str) -> None:
    """The standard error envelope only: `code` and `detail`, no `data`
    (cve-tracking.md: "All errors use the standard error envelope and
    return no partial `data` payload")."""
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"code", "detail"}
    assert body["code"] == code
    assert isinstance(body["detail"], str)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _registries(
    request: pytest.FixtureRequest, isolated_fetcher_registries: None
) -> None:
    """Both registries empty, except for the production-reachability tests,
    which keep the production registration state.
    `isolated_fetcher_registries` restores both registries."""
    if "production_registry" not in request.fixturenames:
        clear_fetcher_registries()


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> Publications:
    recorder = Publications()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


class _CountingFactory:
    """The refetch `session_factory`: sessions joined to the test
    connection, counting how many were opened."""

    def __init__(self, inner: async_sessionmaker[AsyncSession]) -> None:
        self._inner = inner
        self.calls = 0

    def __call__(self) -> AsyncSession:
        self.calls += 1
        return self._inner()


@dataclass
class _Api:
    client: AsyncClient
    db: AsyncSession
    sessions: _CountingFactory
    published: Publications
    user_factory: Factory
    user_role_factory: Factory

    async def headers(self, *roles: Role) -> dict[str, str]:
        """A Bearer credential of a new committed-to-savepoint User holding
        `roles`."""
        suffix = uuid.uuid4().hex[:10]
        user = await self.user_factory(
            username=f"erin.refetch.{suffix}",
            email=f"erin.refetch.{suffix}@example.com",
        )
        for role in roles:
            await self.user_role_factory(user_id=user.id, role=role.value)
        created = await create_session(
            self.db,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        return {"Authorization": f"Bearer {created.token}"}

    async def refetch(
        self,
        cve_id: str,
        headers: dict[str, str],
        *,
        source: str | None = None,
    ) -> httpx.Response:
        params = {"source": source} if source is not None else None
        return await self.client.post(_url(cve_id), headers=headers, params=params)

    async def fetcher(
        self,
        source: CVESourceType,
        *,
        enabled: bool = True,
        refetchable: bool = True,
        queue: str | None = None,
    ) -> str:
        """Register a test-only CVE fetcher owning `source` and flush its
        `FetcherConfig`."""
        probe = define_cve_fetcher(
            source=source, supports=refetchable, fetcher_queue=queue
        )
        self.db.add(FetcherConfig(fetcher_name=probe.name, enabled=enabled))
        await self.db.flush()
        return probe.name

    async def cve(self) -> CVE:
        cve = CVE(cve_id=fictional_cve_id())
        self.db.add(cve)
        await self.db.flush()
        return cve

    async def ticket(
        self,
        cve: CVE,
        *,
        status: TicketStatus = TicketStatus.ANALYSIS,
        confidential: bool = False,
    ) -> Ticket:
        target_id: uuid.UUID | None = None
        if status is TicketStatus.DUPLICATED:
            target = Ticket(status=TicketStatus.ANALYSIS.value)
            self.db.add(target)
            await self.db.flush()
            target_id = target.id
        ticket = Ticket(
            status=status.value,
            cve_id=cve.id,
            is_confidential=confidential,
            duplicate_of_id=target_id,
        )
        self.db.add(ticket)
        await self.db.flush()
        return ticket

    async def ticket_events(self) -> int:
        return int(
            await self.db.scalar(select(func.count()).select_from(TicketAuditEvent))
            or 0
        )


@pytest_asyncio.fixture
async def api(
    client: AsyncClient,
    db_session: AsyncSession,
    user_factory: Factory,
    user_role_factory: Factory,
    redis_client: redis_asyncio.Redis,
    published: Publications,
) -> AsyncGenerator[_Api]:
    """The shared `client` (its `get_db` yields `db_session`) and the
    refetch session factory joined to the same connection. `redis_client`
    isolates the session liveness cache used by authentication."""
    assert isinstance(db_session.bind, AsyncConnection)
    sessions = _CountingFactory(
        async_sessionmaker(
            bind=db_session.bind,
            class_=AsyncSession,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )
    )
    app.dependency_overrides[route.get_cve_refetch_session_factory] = lambda: sessions
    try:
        yield _Api(
            client, db_session, sessions, published, user_factory, user_role_factory
        )
    finally:
        app.dependency_overrides.pop(route.get_cve_refetch_session_factory, None)


def _assert_no_dispatch(attempts: Callable[[], int], published: Publications) -> None:
    """Zero pending-marker Redis commands and zero publication attempts
    (cve-tracking.md, Behavior step 4)."""
    assert attempts() == 0
    assert published.calls == []


# ---------------------------------------------------------------------------
# A1: authentication and capability before any lookup
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAuthenticationAndCapability:
    @pytest.mark.parametrize(
        "headers",
        [
            pytest.param({}, id="missing"),
            pytest.param({"Authorization": "Bearer invalid-token"}, id="invalid"),
        ],
    )
    async def test_credential_failure_is_401_before_any_lookup(
        self,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        headers: dict[str, str],
    ) -> None:
        """api-spec.md, Global Responses: the fixed 401 body; the capability
        and the CVE lookup are never reached (cve-tracking.md, Access check
        behavior step 1)."""
        await api.fetcher(NVD)
        cve = await api.cve()
        attempts = forbid_redis(monkeypatch)

        for target in (cve.cve_id, fictional_cve_id(), "not-a-cve"):
            response = await api.refetch(target, headers)
            assert response.status_code == 401, target
            assert response.json() == _UNAUTHENTICATED, target

        assert api.sessions.calls == 0
        _assert_no_dispatch(attempts, api.published)

    @pytest.mark.parametrize(
        "roles",
        [pytest.param((), id="no-roles"), pytest.param((Role.ADMIN,), id="admin")],
    )
    async def test_caller_without_triage_ticket_gets_the_identical_403_before_lookup(
        self,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        roles: tuple[Role, ...],
    ) -> None:
        """`triage_ticket` is checked before any CVE lookup: a visible, an
        inaccessible, a missing, and a malformed CVE all return the same
        generic 403, with no CVE- or Ticket-domain statement and no refetch
        session (rbac.md, Authorization Chain Evaluation Order; api-spec.md,
        flow 3 step 1)."""
        assert Capability.TRIAGE_TICKET not in get_capabilities(roles)
        await api.fetcher(NVD)
        visible = await api.cve()
        hidden = await api.cve()
        await api.ticket(hidden, confidential=True)
        headers = await api.headers(*roles)
        attempts = forbid_redis(monkeypatch)

        bodies: list[bytes] = []
        with StatementRecorder(api.db) as recorder:
            for target in (visible.cve_id, hidden.cve_id, fictional_cve_id(), "cve-1"):
                response = await api.refetch(target, headers)
                assert response.status_code == 403, target
                assert response.json() == _FORBIDDEN, target
                bodies.append(response.content)

        assert len(set(bodies)) == 1
        assert [s for s in recorder.statements if _DOMAIN_TABLE.search(s)] == []
        assert api.sessions.calls == 0
        _assert_no_dispatch(attempts, api.published)
        assert await api.ticket_events() == 0

    @pytest.mark.parametrize(
        "role", [Role.VULNERABILITY_ANALYST, Role.RESTRICTED_ANALYST], ids=str
    )
    async def test_either_triage_role_alone_is_accepted(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch, role: Role
    ) -> None:
        """rbac.md, Endpoint Permission Map and Predefined Roles: each role
        holding `triage_ticket` refetches a ticketless (public) CVE."""
        assert Capability.TRIAGE_TICKET in get_capabilities([role])
        await api.fetcher(NVD)
        cve = await api.cve()
        ScriptedRedis().install(monkeypatch)

        response = await api.refetch(cve.cve_id, await api.headers(role))

        assert response.status_code == 202, response.text
        assert response.json() == _result(["nvd"], [], [], [])


# ---------------------------------------------------------------------------
# A2: malformed, missing, and inaccessible CVE are the identical 404
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestCVENotFound:
    async def test_every_not_found_cause_is_byte_identical_for_a_restricted_caller(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """api-spec.md, CVE Identifier Resolution and CVE Accessibility
        Check; cve-tracking.md, Access check behavior step 3: a malformed
        locator (including the CVE's internal UUID), a missing CVE, and a
        CVE of a confidential Ticket without a visibility path are
        indistinguishable, even though an enabled source exists."""
        await api.fetcher(NVD)
        visible = await api.cve()
        hidden = await api.cve()
        await api.ticket(hidden, confidential=True)
        headers = await api.headers(Role.RESTRICTED_ANALYST)
        attempts = forbid_redis(monkeypatch)
        targets = [
            "not-a-cve",
            visible.cve_id.lower(),
            "%20" + visible.cve_id,
            "CVE-2099-" + "1" * 12,
            str(visible.id),
            fictional_cve_id(),
            hidden.cve_id,
        ]

        for target in targets:
            response = await api.refetch(target, headers)
            assert response.status_code == 404, target
            assert response.content == _NOT_FOUND, target

        _assert_no_dispatch(attempts, api.published)
        assert await api.ticket_events() == 0

    async def test_scope_all_caller_gets_the_identical_404_and_sees_a_confidential_cve(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """For a scope-`all` caller the malformed and missing causes remain
        identical, while the confidential Ticket's CVE is accessible
        (rbac.md, Scope and Confidential Ticket Visibility)."""
        await api.fetcher(NVD)
        hidden = await api.cve()
        await api.ticket(hidden, confidential=True)
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        attempts = forbid_redis(monkeypatch)

        missing = await api.refetch(fictional_cve_id(), headers)
        malformed = await api.refetch("cve-2099-0001", headers)
        _assert_no_dispatch(attempts, api.published)
        ScriptedRedis().install(monkeypatch)
        accessible = await api.refetch(hidden.cve_id, headers)

        assert missing.status_code == malformed.status_code == 404
        assert missing.content == malformed.content == _NOT_FOUND
        assert accessible.status_code == 202
        assert accessible.json() == _result(["nvd"], [], [], [])


# ---------------------------------------------------------------------------
# A3: shared request-input constraints (global 422 VALIDATION_ERROR)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequestInputConstraints:
    @pytest.mark.parametrize(
        "roles",
        [pytest.param(None, id="unauthenticated"), pytest.param((), id="no-roles")],
    )
    @pytest.mark.parametrize("where", ["path", "query"])
    async def test_nul_is_the_global_422_before_authentication(
        self,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        roles: tuple[Role, ...] | None,
        where: str,
    ) -> None:
        """api-spec.md, NUL Characters in Request Input: a percent-encoded
        `%00` in `{cve_id}` or a U+0000 in `source` is rejected before
        authentication, authorization, and CVE resolution, located at the
        string and never echoed."""
        cve = await api.cve()
        headers = {} if roles is None else await api.headers(*roles)
        attempts = forbid_redis(monkeypatch)

        if where == "path":
            response = await api.client.post(_url(f"{cve.cve_id}%00"), headers=headers)
            loc = ["path", "cve_id"]
        else:
            response = await api.client.post(
                _url(cve.cve_id), headers=headers, params={"source": "nv\x00d"}
            )
            loc = ["query", "source"]

        assert response.status_code == 422
        assert response.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [{"loc": loc, **_NUL_ERROR}],
        }
        assert api.sessions.calls == 0
        _assert_no_dispatch(attempts, api.published)

    async def test_source_over_500_characters_is_the_global_validation_error(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """api-spec.md, Query Parameter Length Limit: a 501-character
        `source` is the global `422 VALIDATION_ERROR`, not
        `CVE_INVALID_SOURCE`; exactly 500 characters reach the service and
        are an invalid source."""
        await api.fetcher(NVD)
        cve = await api.cve()
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        attempts = forbid_redis(monkeypatch)

        over = await api.refetch(cve.cve_id, headers, source="s" * 501)
        assert api.sessions.calls == 0
        at_limit = await api.refetch(cve.cve_id, headers, source="s" * 500)

        assert over.status_code == 422
        assert over.json() == {
            "code": "VALIDATION_ERROR",
            "detail": "Request validation failed",
            "errors": [
                {
                    "loc": ["query", "source"],
                    "msg": "String should have at most 500 characters",
                    "type": "string_too_long",
                }
            ],
        }
        _assert_error_envelope(at_limit, 422, "CVE_INVALID_SOURCE")
        _assert_no_dispatch(attempts, api.published)


# ---------------------------------------------------------------------------
# A4 / A8 / A11: the source matrix with zero dispatch and no audit event
# ---------------------------------------------------------------------------


_ROSTERS: dict[str, list[tuple[CVESourceType, bool, bool]]] = {
    "standard": [(NVD, True, True), (GHSA, False, True), (EPSS, True, False)],
    "all-disabled": [(NVD, False, True), (GHSA, False, True), (EPSS, True, False)],
    "empty": [],
}
"""`(source, enabled, refetchable)` of the registered test-only fetchers;
`osv` is a valid `CVESourceType` value that no fetcher registers."""

_SOURCE_CASES = [
    pytest.param(
        "standard", "fictional_source", 422, "CVE_INVALID_SOURCE", id="unknown"
    ),
    pytest.param("standard", "osv", 422, "CVE_INVALID_SOURCE", id="deregistered"),
    pytest.param("standard", "epss", 422, "CVE_INVALID_SOURCE", id="not-refetchable"),
    pytest.param("standard", "ghsa", 409, "FETCHER_DISABLED", id="explicit-disabled"),
    pytest.param("all-disabled", None, 503, "CVE_FETCH_FAILED", id="none-enabled"),
    pytest.param("empty", None, 503, "CVE_FETCH_FAILED", id="empty-registry"),
]


@pytest.mark.e2e
class TestSourceMatrix:
    @pytest.mark.parametrize(("roster", "source", "status", "code"), _SOURCE_CASES)
    async def test_source_outcome_uses_the_error_envelope_without_dispatch(
        self,
        api: _Api,
        monkeypatch: pytest.MonkeyPatch,
        roster: str,
        source: str | None,
        status: int,
        code: str,
    ) -> None:
        """cve-tracking.md, Re-fetch Endpoint error table; api-spec.md, CVE
        refetch outcome matrix: unknown, deregistered, and non-refetchable
        explicit sources are `422 CVE_INVALID_SOURCE`, an explicit disabled
        source is `409 FETCHER_DISABLED`, and a broadcast with no enabled
        refetchable source (including an empty fetch-single registry) is
        `503 CVE_FETCH_FAILED`. No partial `data`, zero Redis and Celery
        I/O, and no Ticket audit event (ticket-audit-log.md)."""
        for fetcher_source, enabled, refetchable in _ROSTERS[roster]:
            await api.fetcher(fetcher_source, enabled=enabled, refetchable=refetchable)
        cve = await api.cve()
        await api.ticket(cve)
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        attempts = forbid_redis(monkeypatch)

        response = await api.refetch(cve.cve_id, headers, source=source)

        _assert_error_envelope(response, status, code)
        _assert_no_dispatch(attempts, api.published)
        assert await api.ticket_events() == 0


# ---------------------------------------------------------------------------
# A5: every attempted publication unconfirmed
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestEveryPublicationUnconfirmed:
    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                BrokerOperationalError(f"connection refused {SECRET}"), id="broker"
            ),
            pytest.param(RuntimeError(f"fictional failure {SECRET}"), id="runtime"),
        ],
    )
    async def test_all_unconfirmed_is_the_fixed_celery_unavailable(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch, error: Exception
    ) -> None:
        """cve-tracking.md, Behavior step 5; api-spec.md, CVE refetch
        outcome matrix and Infrastructure Dependency Errors: with no source
        enqueued or already pending, the fixed `503 CELERY_UNAVAILABLE`
        body, with no exception text; exactly one sanitized
        `cve_fetch_publication_unconfirmed` WARNING (issue #800, D4)."""
        await api.fetcher(NVD)
        await api.fetcher(MITRE, queue="git")
        cve = await api.cve()
        await api.ticket(cve)
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        redis = ScriptedRedis()
        redis.install(monkeypatch)
        api.published.before = _failing_for({"nvd", "mitre"}, error)

        with capture_logs() as logs:
            response = await api.refetch(cve.cve_id, headers)

        assert response.status_code == 503
        assert response.json() == _CELERY_UNAVAILABLE
        for fragment in (
            "fictional-secret",
            "refetch-user",
            "broker.example.test",
            "5672",
            "amqp",
            "refused",
            "Traceback",
        ):
            assert fragment not in response.text
        assert [c["kwargs"]["source"] for c in api.published.calls] == ["mitre", "nvd"]
        warnings = events_named(logs, UNCONFIRMED)
        assert warnings == [
            {
                "event": UNCONFIRMED,
                "log_level": "warning",
                "cve_id": cve.cve_id,
                "sources_failed": ["mitre", "nvd"],
                "trigger": "refetch",
            }
        ]
        tokens = [str(token) for token in redis.values("set")]
        assert_private_logs(warnings, *tokens, "fictional-secret", "amqp")
        assert await api.ticket_events() == 0


# ---------------------------------------------------------------------------
# A6 / A7 / A11: 202 with the complete four-list result
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestAccepted:
    async def test_partial_result_returns_202_with_the_exact_four_lists(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cve-tracking.md, Success response: the standard `data` envelope
        with exactly the four disjoint lists in canonical source order,
        including disabled and unconfirmed sources beside enqueued and
        already-pending ones; a non-refetchable source is in no list. The
        refetch creates no Ticket audit event."""
        for source in (REDHAT, OSV, NVD):
            await api.fetcher(source)
        await api.fetcher(MITRE, queue="git")
        await api.fetcher(KERNEL, queue="git")
        await api.fetcher(GHSA, enabled=False)
        await api.fetcher(EPSS, enabled=False)
        await api.fetcher(CVESourceType.KEV, refetchable=False)
        cve = await api.cve()
        await api.ticket(cve, confidential=True)
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        ScriptedRedis(set_results={pending_key(cve.cve_id, "mitre"): None}).install(
            monkeypatch
        )
        api.published.before = _failing_for(
            {"kernel", "redhat"}, BrokerOperationalError(SECRET)
        )

        with capture_logs() as logs:
            response = await api.refetch(cve.cve_id, headers)

        assert response.status_code == 202, response.text
        assert response.json() == _result(
            ["nvd", "osv"], ["mitre"], ["epss", "ghsa"], ["kernel", "redhat"]
        )
        assert SECRET not in response.text
        assert [
            entry["sources_failed"] for entry in events_named(logs, UNCONFIRMED)
        ] == [["kernel", "redhat"]]
        assert await api.ticket_events() == 0

    @pytest.mark.parametrize(
        "failing", [False, True], ids=["pending-only", "pending-and-failed"]
    )
    async def test_already_pending_without_enqueued_is_202(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch, failing: bool
    ) -> None:
        """A non-empty `sources_already_pending` alone is accepted, even when
        every attempted publication is unconfirmed (api-spec.md, CVE
        refetch outcome matrix: `CELERY_UNAVAILABLE` requires that no
        source is already pending)."""
        await api.fetcher(NVD)
        if failing:
            await api.fetcher(GHSA)
        cve = await api.cve()
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        ScriptedRedis(set_results={pending_key(cve.cve_id, "nvd"): None}).install(
            monkeypatch
        )
        api.published.before = _failing_for({"ghsa"}, RuntimeError("fictional"))

        response = await api.refetch(cve.cve_id, headers)

        assert response.status_code == 202, response.text
        assert response.json() == _result([], ["nvd"], [], ["ghsa"] if failing else [])
        assert [c["kwargs"]["source"] for c in api.published.calls] == (
            ["ghsa"] if failing else []
        )

    @pytest.mark.parametrize("pending", [False, True], ids=["new", "pending"])
    async def test_explicit_source_success_is_in_exactly_one_accepted_list(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch, pending: bool
    ) -> None:
        """cve-tracking.md, Success response: with an explicit `source`,
        success contains that one source in exactly one of
        `sources_enqueued` and `sources_already_pending`; other enabled and
        disabled sources appear in no list."""
        mitre = await api.fetcher(MITRE, queue="git")
        await api.fetcher(NVD)
        await api.fetcher(GHSA, enabled=False)
        cve = await api.cve()
        headers = await api.headers(Role.RESTRICTED_ANALYST)
        redis = ScriptedRedis(
            set_results={pending_key(cve.cve_id, "mitre"): None} if pending else {}
        )
        redis.install(monkeypatch)

        response = await api.refetch(cve.cve_id, headers, source="mitre")

        assert response.status_code == 202, response.text
        if pending:
            assert response.json() == _result([], ["mitre"], [], [])
            assert api.published.calls == []
        else:
            assert response.json() == _result(["mitre"], [], [], [])
            assert api.published.calls == [
                {
                    "task_name": TASK,
                    "kwargs": {
                        "fetcher_name": mitre,
                        "cve_id": cve.cve_id,
                        "source": "mitre",
                        "token": redis.values("set")[0],
                    },
                    "queue": "git",
                }
            ]

    @pytest.mark.parametrize(
        "status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED], ids=str
    )
    async def test_manual_zone_ticket_is_accepted_never_not_mutable(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch, status: TicketStatus
    ) -> None:
        """api-spec.md, Manual-Zone Mutability Guard (CVE on-demand refetch
        exception) and CVE Accessibility Check: dispatch-only refetch of an
        accessible CVE whose Ticket is `Ignored` or `Duplicated` is 202,
        never `409 TICKET_NOT_MUTABLE`, and creates no audit event."""
        await api.fetcher(NVD)
        cve = await api.cve()
        await api.ticket(cve, status=status)
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        ScriptedRedis().install(monkeypatch)

        response = await api.refetch(cve.cve_id, headers)

        assert response.status_code == 202, response.text
        assert response.json() == _result(["nvd"], [], [], [])
        assert await api.ticket_events() == 0


# ---------------------------------------------------------------------------
# A10: production reachability (production registration state)
# ---------------------------------------------------------------------------


@pytest.fixture
def production_registry() -> None:
    """Premise: the production build registers no fetch-single CVE source
    yet, so every refetch must take the empty-registry branch."""
    assert base_cve_fetcher.get_fetch_single_fetchers() == {}


@pytest.mark.e2e
@pytest.mark.usefixtures("production_registry")
class TestProductionReachability:
    async def test_empty_production_registry_outcomes(
        self, api: _Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With the production (empty) fetch-single registry: broadcast is
        `503 CVE_FETCH_FAILED`, explicit `nvd` is `422 CVE_INVALID_SOURCE`,
        and a missing CVE is still the identical 404, each without dispatch
        (cve-tracking.md, error table; api-spec.md, CVE refetch outcome
        matrix)."""
        cve = await api.cve()
        headers = await api.headers(Role.VULNERABILITY_ANALYST)
        attempts = forbid_redis(monkeypatch)

        broadcast = await api.refetch(cve.cve_id, headers)
        explicit = await api.refetch(cve.cve_id, headers, source="nvd")
        missing = await api.refetch(fictional_cve_id(), headers)

        _assert_error_envelope(broadcast, 503, "CVE_FETCH_FAILED")
        _assert_error_envelope(explicit, 422, "CVE_INVALID_SOURCE")
        assert missing.status_code == 404
        assert missing.content == _NOT_FOUND
        _assert_no_dispatch(attempts, api.published)


# ---------------------------------------------------------------------------
# A9: OpenAPI contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenApiContract:
    @staticmethod
    def _operation() -> dict[str, Any]:
        operation: dict[str, Any] = app.openapi()["paths"][_PATH]["post"]
        return operation

    @staticmethod
    def _ref_name(response: dict[str, Any]) -> str:
        ref: str = response["content"]["application/json"]["schema"]["$ref"]
        return ref.rsplit("/", 1)[-1]

    def test_operation_has_summary_description_and_no_request_body(self) -> None:
        operation = self._operation()

        assert operation["tags"] == ["CVEs"]
        assert operation["summary"]
        assert operation["description"]
        assert "triage_ticket" in operation["description"]
        assert "requestBody" not in operation

    def test_parameters_are_the_path_cve_id_and_an_optional_string_source(
        self,
    ) -> None:
        parameters = {p["name"]: p for p in self._operation()["parameters"]}

        assert set(parameters) == {"cve_id", "source"}
        assert parameters["cve_id"]["in"] == "path"
        assert parameters["cve_id"]["schema"]["type"] == "string"
        source = parameters["source"]
        assert source["in"] == "query"
        assert source["required"] is False
        assert {"type": "string"} in source["schema"]["anyOf"]
        assert source["description"]

    def test_responses_declare_202_and_the_error_envelopes(self) -> None:
        responses = self._operation()["responses"]

        assert "200" not in responses
        assert self._ref_name(responses["202"]) == "CVERefetchResponse"
        for code, errors in (
            ("404", ["CVE_NOT_FOUND"]),
            ("409", ["FETCHER_DISABLED"]),
            ("422", ["CVE_INVALID_SOURCE"]),
            ("503", ["CVE_FETCH_FAILED", "CELERY_UNAVAILABLE"]),
        ):
            assert self._ref_name(responses[code]) == "ErrorResponse"
            for error in errors:
                assert error in responses[code]["description"]
        assert "TICKET_NOT_MUTABLE" not in str(responses)

    def test_result_schema_has_exactly_four_required_string_arrays(self) -> None:
        schemas = app.openapi()["components"]["schemas"]
        envelope = schemas["CVERefetchResponse"]
        body = schemas["CVERefetchResult"]
        names = [
            "sources_enqueued",
            "sources_already_pending",
            "sources_disabled",
            "sources_failed",
        ]

        assert envelope["required"] == ["data"]
        assert envelope["properties"]["data"]["$ref"].endswith("/CVERefetchResult")
        assert set(body["properties"]) == set(names)
        assert sorted(body["required"]) == sorted(names)
        for name in names:
            assert body["properties"][name]["type"] == "array"
            assert body["properties"][name]["items"] == {"type": "string"}


@pytest.mark.unit
def test_session_factory_provider_returns_the_production_factory() -> None:
    """Without an override the refetch uses the production session factory
    (no I/O at resolution)."""
    from app.database import async_session_factory

    assert route.get_cve_refetch_session_factory() is async_session_factory
