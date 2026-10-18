"""Unit and end-to-end tests for shared authentication and authorization
FastAPI dependencies (backend/app/api/dependencies.py).

See docs/features/identity/authentication.md (Authenticated Principal,
Authentication Dependencies, API key validation, Session-Only
Authentication Dependency) and docs/features/identity/rbac.md
(require_capability() Dependency) for the contract under test.

A minimal standalone FastAPI app (`_build_test_app()`) exercises the real
dependencies through the actual ASGI/HTTP layer without touching the
production `app`'s route table.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
import uuid
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import FrozenInstanceError, dataclass, fields
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, cast
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis_asyncio
from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import dependencies
from app.api.dependencies import (
    SESSION_COOKIE_NAME,
    AuthenticatedPrincipal,
    AuthenticatedTicketCaller,
    CurrentUser,
    KeyedWarningLimiter,
    LastUsedDebouncer,
    OptionalCurrentUser,
    OptionalTicketCaller,
    require_accessible_ticket,
    require_any_capability,
    require_capability,
    require_session_authentication,
)
from app.config import settings
from app.core.enums import (
    ApiKeyRejectionReason,
    Capability,
    CredentialKind,
    Role,
    SessionCreationReason,
)
from app.core.errors import AppError, ErrorCode
from app.core.identifiers import format_ticket_id
from app.core.jwt import issue_token
from app.database import get_db
from app.models.api_key import ApiKey
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.user import User
from app.models.user_role import UserRole
from app.services import api_key_service, ticket_service, user_service
from app.services.session_service import create_session
from app.services.ticket_service import ResolvedTicket
from app.services.ticket_visibility import TicketCaller

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _dependency_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Join only log records emitted by `app.api.dependencies`.

    Scoping to this module's own records avoids false negatives/positives
    from unrelated propagated records (mirrors the identical helper in
    test_services/test_api_key_service.py and test_session_service.py).
    """
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.api.dependencies"
    )


def _dependency_events(
    caplog: pytest.LogCaptureFixture, event: str
) -> list[dict[str, Any]]:
    """The structured event dicts named `event` among the records of
    `app.api.dependencies`."""
    return [
        record.msg
        for record in caplog.records
        if record.name == "app.api.dependencies"
        and isinstance(record.msg, dict)
        and record.msg.get("event") == event
    ]


def _app_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured application (`app.*`) record."""
    return [record for record in caplog.records if record.name.startswith("app.")]


def _make_api_key_credential() -> tuple[str, str]:
    """Return `(plaintext_token, sha256_hex_digest)` for a synthetic key."""
    token = "stl_ak_" + secrets.token_hex(16)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, digest


# A fictional ASGI peer address (RFC 5737 documentation range).
_FICTIONAL_PEER = "198.51.100.23"


# Matched-key rejection cases and the `reason` each must log
# (authentication.md, API key validation, Rejected-key warning).
_REJECTED_KEY_REASONS = {
    "revoked": "revoked",
    "expired": "expired",
    "revoked_and_expired": "revoked",
    "inactive_owner": "owner_inactive",
    "missing_owner": "owner_inactive",
}


@dataclass(frozen=True)
class _RejectedKey:
    """A presented key matching a stored key that must be rejected, with
    the values its `api_key_rejected` record must and must not carry."""

    token: str
    digest: str
    key_id: str
    owner_id: str
    reason: str
    identifying_values: tuple[str, ...]


async def _arrange_rejected_key(
    case: str,
    user_factory: Callable[..., Awaitable[User]],
    api_key_factory: Callable[..., Awaitable[ApiKey]],
    monkeypatch: pytest.MonkeyPatch,
) -> _RejectedKey:
    """Create the key of `case` (a `_REJECTED_KEY_REASONS` key). A missing
    owner is simulated by making the owner lookup return None, the
    defensive guard for an `ApiKey.user_id` referencing no User row."""
    now = datetime.now(UTC)
    owner = await user_factory(active=case != "inactive_owner")
    token, digest = _make_api_key_credential()
    overrides: dict[str, Any] = {}
    if case in {"revoked", "revoked_and_expired"}:
        overrides["revoked_at"] = now
    if case in {"expired", "revoked_and_expired"}:
        overrides["expires_at"] = now - timedelta(days=1)
    key = await api_key_factory(user_id=owner.id, key_hash=digest, **overrides)
    monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())
    if case == "missing_owner":
        monkeypatch.setattr(
            user_service, "get_user_by_id", AsyncMock(return_value=None)
        )
    return _RejectedKey(
        token=token,
        digest=digest,
        key_id=str(key.id),
        owner_id=str(owner.id),
        reason=_REJECTED_KEY_REASONS[case],
        identifying_values=(key.prefix, key.name, owner.username, owner.email),
    )


def _assert_single_rejected_key_warning(
    caplog: pytest.LogCaptureFixture, rejected: _RejectedKey
) -> None:
    """Exactly one `api_key_rejected` with the key's internal identifiers
    and `reason`, no `api_key_validation_failed`, and none of the
    presented key, its digest, the key prefix or name, the owner's
    username or email, or the ASGI peer address in this module's logs."""
    records = _dependency_events(caplog, "api_key_rejected")
    assert len(records) == 1
    assert (
        records[0]["key_id"],
        records[0]["user_id"],
        records[0]["reason"],
        records[0]["suppressed_count"],
    ) == (rejected.key_id, rejected.owner_id, rejected.reason, 0)
    assert _dependency_events(caplog, "api_key_validation_failed") == []
    text = _dependency_log_text(caplog)
    for value in (
        rejected.token,
        rejected.digest,
        "stl_ak_",
        _FICTIONAL_PEER,
        *rejected.identifying_values,
    ):
        assert value not in text, f"forbidden value in log: {value!r}"


@pytest.fixture(autouse=True)
def _reset_authentication_state() -> None:
    """Reset the module-level limiter/debouncer singletons before each
    test — mirrors `session_service._redis_outage_active`'s per-test
    reset (docs/features/platform/testing-strategy.md, Test
    Independence). Autouse is scoped to this test module only.
    """
    dependencies._unknown_key_limiter = KeyedWarningLimiter()
    dependencies._rejected_key_limiter = KeyedWarningLimiter()
    dependencies._last_used_debouncer = LastUsedDebouncer()


def _build_test_app() -> FastAPI:
    test_app = FastAPI()

    @test_app.exception_handler(AppError)
    async def _app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code.value, "detail": exc.detail},
            headers=exc.headers,
        )

    @test_app.get("/whoami")
    async def whoami(principal: CurrentUser) -> dict[str, str]:
        return {
            "user_id": str(principal.user.id),
            "credential_kind": principal.credential_kind.value,
        }

    @test_app.get("/optional-whoami")
    async def optional_whoami(
        principal: OptionalCurrentUser,
    ) -> dict[str, str | None]:
        if principal is None:
            return {"user_id": None, "credential_kind": None}
        return {
            "user_id": str(principal.user.id),
            "credential_kind": principal.credential_kind.value,
        }

    @test_app.get("/capability-protected")
    async def capability_protected(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.MANAGE_USERS)),
        ],
    ) -> dict[str, str]:
        return {"user_id": str(principal.user.id)}

    def _caller_body(caller: TicketCaller) -> dict[str, str | None]:
        return {
            "user_id": None if caller.user_id is None else str(caller.user_id),
            "scope": None if caller.scope is None else caller.scope.value,
        }

    @test_app.get("/ticket-caller")
    async def ticket_caller(caller: AuthenticatedTicketCaller) -> dict[str, str | None]:
        return _caller_body(caller)

    @test_app.get("/optional-ticket-caller")
    async def optional_ticket_caller(
        caller: OptionalTicketCaller,
    ) -> dict[str, str | None]:
        return _caller_body(caller)

    @test_app.get("/tickets/{ticket_id}/accessible")
    async def accessible_ticket(
        caller: AuthenticatedTicketCaller,
        ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
    ) -> dict[str, int | str | None]:
        return {"sequence_id": ticket.sequence_id, **_caller_body(caller)}

    @test_app.get("/triage-caller")
    async def triage_caller(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.TRIAGE_TICKET)),
        ],
        caller: AuthenticatedTicketCaller,
    ) -> dict[str, str | None]:
        return _caller_body(caller)

    @test_app.get("/tickets/{ticket_id}/triage")
    async def triage_accessible_ticket(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(require_capability(Capability.TRIAGE_TICKET)),
        ],
        caller: AuthenticatedTicketCaller,
        ticket: Annotated[ResolvedTicket, Depends(require_accessible_ticket)],
    ) -> dict[str, int | str | None]:
        return {"sequence_id": ticket.sequence_id, **_caller_body(caller)}

    @test_app.get("/session-only")
    async def session_only(
        principal: Annotated[
            AuthenticatedPrincipal, Depends(require_session_authentication)
        ],
    ) -> dict[str, str]:
        return {"user_id": str(principal.user.id)}

    return test_app


@pytest.fixture
def test_app() -> FastAPI:
    return _build_test_app()


@pytest.fixture
async def dep_client(
    test_app: FastAPI, db_session: AsyncSession
) -> AsyncGenerator[AsyncClient]:
    """An `AsyncClient` bound to the standalone dependency test app,
    sharing the test transaction. Mirrors `tests/test_api/test_auth.py`'s
    `auth_client` fixture: `db_session`'s savepoint-based rollback does
    not by itself execute `get_db`'s post-yield commit, but sliding
    refresh cookie assertions and role-change-on-next-request scenarios
    need real request/response round trips through the ASGI layer.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    test_app.dependency_overrides[get_db] = _override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=test_app), base_url="http://test"
    ) as client:
        yield client


@pytest.fixture
async def peer_client(
    test_app: FastAPI, dep_client: AsyncClient
) -> AsyncGenerator[AsyncClient]:
    """`dep_client` (whose fixture installs the database override) seen
    from the fictional ASGI peer address `_FICTIONAL_PEER`, so a test can
    prove that address absent from a log record."""
    async with AsyncClient(
        transport=ASGITransport(app=test_app, client=(_FICTIONAL_PEER, 50123)),
        base_url="http://test",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# AuthenticatedPrincipal
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAuthenticatedPrincipal:
    def test_carries_exactly_user_and_credential_kind(self) -> None:
        assert {f.name for f in fields(AuthenticatedPrincipal)} == {
            "user",
            "credential_kind",
        }

    def test_is_frozen(self) -> None:
        principal = AuthenticatedPrincipal(
            user=User(username="jdoe", email="jdoe@example.com"),
            credential_kind=CredentialKind.JWT,
        )
        with pytest.raises(FrozenInstanceError):
            principal.credential_kind = CredentialKind.API_KEY  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Error factories
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestErrorFactories:
    def test_unauthenticated_error_shape(self) -> None:
        error = dependencies.unauthenticated_error()
        assert error.status_code == 401
        assert error.code == ErrorCode.AUTH_NOT_AUTHENTICATED
        assert error.detail == "Authentication required"

    def test_unauthenticated_error_returns_fresh_instance(self) -> None:
        first = dependencies.unauthenticated_error()
        second = dependencies.unauthenticated_error()
        assert first is not second

    def test_user_not_found_error_shape(self) -> None:
        error = dependencies.user_not_found_error()
        assert error.status_code == 404
        assert error.code == ErrorCode.USER_NOT_FOUND
        assert error.detail == "User not found."

    def test_ticket_not_found_error_shape(self) -> None:
        error = dependencies.ticket_not_found_error()
        assert error.status_code == 404
        assert error.code == ErrorCode.TICKET_NOT_FOUND
        assert error.detail == "Ticket not found."
        assert error.headers is None

    def test_cve_not_found_error_shape(self) -> None:
        error = dependencies.cve_not_found_error()
        assert error.status_code == 404
        assert error.code == ErrorCode.CVE_NOT_FOUND
        assert error.detail == "CVE not found."
        assert error.headers is None

    def test_cve_not_found_error_returns_fresh_instance(self) -> None:
        assert dependencies.cve_not_found_error() is not (
            dependencies.cve_not_found_error()
        )

    def test_ticket_not_mutable_error_shape(self) -> None:
        """See docs/api-spec.md (Manual-Zone Mutability Guard)."""
        error = dependencies.ticket_not_mutable_error()
        assert error.status_code == 409
        assert error.code == ErrorCode.TICKET_NOT_MUTABLE
        assert error.detail == "Ticket is not mutable."
        assert error.headers is None

    def test_ticket_not_mutable_error_returns_fresh_instance(self) -> None:
        assert dependencies.ticket_not_mutable_error() is not (
            dependencies.ticket_not_mutable_error()
        )


# ---------------------------------------------------------------------------
# KeyedWarningLimiter
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestKeyedWarningLimiter:
    """The shared per-key limiter of both API key warnings, exercised
    with peer-address keys (the unknown-key granularity); the
    rejected-key granularity is covered by
    `TestRecordRejectedKeyAttempt`."""

    def test_first_attempt_returns_zero_suppressed(self) -> None:
        limiter = KeyedWarningLimiter()
        assert limiter.record("203.0.113.5", datetime.now(UTC)) == 0

    def test_within_window_suppresses_and_accumulates(self) -> None:
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("203.0.113.5", now + timedelta(seconds=10)) is None
        assert limiter.record("203.0.113.5", now + timedelta(seconds=20)) is None

    def test_after_window_elapses_emits_with_suppressed_count(self) -> None:
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)
        limiter.record("203.0.113.5", now + timedelta(seconds=10))
        limiter.record("203.0.113.5", now + timedelta(seconds=20))

        emitted = limiter.record("203.0.113.5", now + timedelta(seconds=61))

        assert emitted == 2

    def test_window_boundary_at_exactly_60_seconds_emits(self) -> None:
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("203.0.113.5", now + timedelta(seconds=60)) == 0

    def test_distinct_peers_are_independent(self) -> None:
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        assert limiter.record("198.51.100.7", now) == 0

    def test_inactivity_eviction_resets_state(self) -> None:
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("203.0.113.5", now)

        later = now + timedelta(seconds=301)
        assert limiter.record("203.0.113.5", later) == 0

    def test_lru_eviction_when_max_entries_exceeded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(dependencies, "_LIMITER_MAX_ENTRIES", 2)
        limiter = KeyedWarningLimiter()
        now = datetime.now(UTC)
        limiter.record("peer-a", now)
        limiter.record("peer-b", now)
        limiter.record("peer-c", now)  # evicts peer-a (least-recently-seen)

        assert "peer-a" not in limiter._entries
        assert "peer-b" in limiter._entries
        assert "peer-c" in limiter._entries


@pytest.mark.unit
class TestRecordUnknownKeyAttempt:
    """`_record_unknown_key_attempt()` peer extraction — isolated from
    the HTTP layer via a minimal duck-typed request."""

    class _FakeClient:
        def __init__(self, host: str) -> None:
            self.host = host

    class _FakeRequest:
        def __init__(self, client: Any) -> None:
            self.client = client

    def test_uses_asgi_peer_host(self, caplog: pytest.LogCaptureFixture) -> None:
        request = self._FakeRequest(client=self._FakeClient(host="203.0.113.5"))

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(
                cast(Request, request), datetime.now(UTC)
            )

        text = _dependency_log_text(caplog)
        assert "api_key_validation_failed" in text
        assert "203.0.113.5" in text

    def test_none_client_uses_unknown_sentinel(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        request = self._FakeRequest(client=None)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(
                cast(Request, request), datetime.now(UTC)
            )

        assert "unknown" in _dependency_log_text(caplog)

    def test_second_attempt_within_window_is_not_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        request = self._FakeRequest(client=self._FakeClient(host="203.0.113.5"))
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            dependencies._record_unknown_key_attempt(cast(Request, request), now)
            caplog.clear()
            dependencies._record_unknown_key_attempt(
                cast(Request, request), now + timedelta(seconds=10)
            )

        assert _dependency_log_text(caplog) == ""


@pytest.mark.unit
class TestRecordRejectedKeyAttempt:
    """`_record_rejected_key_attempt()` — the rate-limited
    `api_key_rejected` WARNING (authentication.md, API key validation,
    Rejected-key warning), driven with a controlled `now` and a transient
    `ApiKey`, without HTTP."""

    @staticmethod
    def _key() -> ApiKey:
        return ApiKey(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            key_hash=f"{7:064x}",
            prefix="stl_ak_0a1b2",
            name="build-pipeline",
        )

    @staticmethod
    def _record(key: ApiKey, reason: ApiKeyRejectionReason, now: datetime) -> None:
        dependencies._record_rejected_key_attempt(key, reason, now)

    def test_emits_exactly_the_documented_fields(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        key = self._key()

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            self._record(key, ApiKeyRejectionReason.REVOKED, datetime.now(UTC))

        records = _dependency_events(caplog, "api_key_rejected")
        assert len(records) == 1
        event_dict = records[0]
        assert event_dict["level"] == "warning"
        # Pipeline keys aside (`_build_test_app()` binds no `request_id`),
        # the record carries exactly the documented fields.
        assert set(event_dict) == {
            "event",
            "key_id",
            "user_id",
            "reason",
            "suppressed_count",
            "logger",
            "level",
            "timestamp",
            "app",
        }
        assert (
            event_dict["key_id"],
            event_dict["user_id"],
            event_dict["reason"],
            event_dict["suppressed_count"],
        ) == (str(key.id), str(key.user_id), "revoked", 0)

    def test_second_attempt_within_window_is_not_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        key = self._key()
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            self._record(key, ApiKeyRejectionReason.EXPIRED, now)
            caplog.clear()
            self._record(
                key, ApiKeyRejectionReason.EXPIRED, now + timedelta(seconds=59)
            )

        assert _dependency_events(caplog, "api_key_rejected") == []

    def test_after_window_reports_suppressed_count(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        key = self._key()
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            for offset in (0, 10, 20, 60):
                self._record(
                    key,
                    ApiKeyRejectionReason.OWNER_INACTIVE,
                    now + timedelta(seconds=offset),
                )

        assert [
            record["suppressed_count"]
            for record in _dependency_events(caplog, "api_key_rejected")
        ] == [0, 2]

    def test_suppressed_count_aggregates_reasons_and_record_carries_emitting_reason(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Every rejection of the key counts toward its window whatever
        the reason; the emitted record carries the reason of the call
        that emits it."""
        key = self._key()
        now = datetime.now(UTC)
        attempts = [
            (0, ApiKeyRejectionReason.REVOKED),
            (10, ApiKeyRejectionReason.EXPIRED),
            (20, ApiKeyRejectionReason.OWNER_INACTIVE),
            (61, ApiKeyRejectionReason.EXPIRED),
        ]

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            for offset, reason in attempts:
                self._record(key, reason, now + timedelta(seconds=offset))

        assert [
            (record["reason"], record["suppressed_count"])
            for record in _dependency_events(caplog, "api_key_rejected")
        ] == [("revoked", 0), ("expired", 2)]

    def test_distinct_keys_are_independent(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        first, second = self._key(), self._key()
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            self._record(first, ApiKeyRejectionReason.REVOKED, now)
            self._record(second, ApiKeyRejectionReason.REVOKED, now)

        assert [
            record["key_id"]
            for record in _dependency_events(caplog, "api_key_rejected")
        ] == [str(first.id), str(second.id)]

    def test_unknown_key_peers_cannot_evict_a_rejected_key_entry(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The two limiters keep independent state: with room for a single
        entry, lookup misses from new peer addresses do not evict the
        rejected key's entry, so its second rejection inside the window
        stays suppressed."""
        monkeypatch.setattr(dependencies, "_LIMITER_MAX_ENTRIES", 1)
        key = self._key()
        now = datetime.now(UTC)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            self._record(key, ApiKeyRejectionReason.REVOKED, now)
            for host in ("203.0.113.5", "203.0.113.6"):
                request = TestRecordUnknownKeyAttempt._FakeRequest(
                    client=TestRecordUnknownKeyAttempt._FakeClient(host=host)
                )
                dependencies._record_unknown_key_attempt(cast(Request, request), now)
            self._record(key, ApiKeyRejectionReason.REVOKED, now + timedelta(seconds=1))

        assert len(_dependency_events(caplog, "api_key_validation_failed")) == 2
        assert len(_dependency_events(caplog, "api_key_rejected")) == 1


# ---------------------------------------------------------------------------
# LastUsedDebouncer (isolated — no real database)
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True


@pytest.mark.unit
class TestLastUsedDebouncer:
    def _patch_factory(
        self, monkeypatch: pytest.MonkeyPatch, session: _FakeSession
    ) -> None:
        monkeypatch.setattr(
            dependencies, "get_last_used_session_factory", lambda: lambda: session
        )

    async def test_first_touch_writes_and_commits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        calls: list[tuple[uuid.UUID, datetime]] = []

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            calls.append((key_id, used_at))
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await debouncer.touch(key_id, now)

        assert calls == [(key_id, now)]
        assert session.committed is True
        assert session.rolled_back is False

    async def test_second_touch_within_window_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)
        await debouncer.touch(key_id, now)

        await debouncer.touch(key_id, now + timedelta(seconds=30))

        assert call_count == 1

    async def test_touch_after_window_writes_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)
        await debouncer.touch(key_id, now)

        await debouncer.touch(key_id, now + timedelta(seconds=61))

        assert call_count == 2

    async def test_failure_rolls_back_and_does_not_advance_debounce(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)

        async def _fake_update_fails(
            s: Any, key_id: uuid.UUID, used_at: datetime
        ) -> bool:
            raise RuntimeError("simulated database failure")

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update_fails)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await debouncer.touch(key_id, now)  # must not raise

        assert session.rolled_back is True
        assert session.committed is False
        assert key_id not in debouncer._last_write_at

    async def test_concurrent_touches_for_same_key_write_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession()
        self._patch_factory(monkeypatch, session)
        call_count = 0

        async def _fake_update(s: Any, key_id: uuid.UUID, used_at: datetime) -> bool:
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)
            return True

        monkeypatch.setattr(api_key_service, "update_last_used_at", _fake_update)
        debouncer = LastUsedDebouncer()
        key_id = uuid.uuid4()
        now = datetime.now(UTC)

        await asyncio.gather(
            debouncer.touch(key_id, now),
            debouncer.touch(key_id, now),
        )

        assert call_count == 1


@pytest.mark.integration
class TestLastUsedDebouncerIntegration:
    async def test_touch_persists_last_used_at_through_real_session(
        self,
        db_session: AsyncSession,
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exercise the full path: ``get_last_used_session_factory()`` →
        real session → ``update_last_used_at()`` → commit, verifying
        that the dedicated transaction actually persists the write.

        Uses the savepoint-nested ``db_session`` as the backing session
        so the outer transaction rollback at teardown cleans up the
        write — no leaked state.
        """
        key = await api_key_factory(last_used_at=None)

        @contextlib.asynccontextmanager
        async def _session_cm() -> AsyncGenerator[AsyncSession]:
            yield db_session

        monkeypatch.setattr(
            dependencies,
            "get_last_used_session_factory",
            lambda: _session_cm,
        )
        debouncer = LastUsedDebouncer()
        now = datetime.now(UTC)

        await debouncer.touch(key.id, now)

        await db_session.refresh(key)
        assert key.last_used_at == now


# ---------------------------------------------------------------------------
# get_current_user — JWT path (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCurrentUserJwt:
    async def test_valid_jwt_cookie_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get("/whoami")

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "jwt"

    async def test_bearer_takes_precedence_over_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        bearer_user = await user_factory()
        bearer_created = await create_session(
            db_session,
            bearer_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert bearer_created is not None
        cookie_user = await user_factory()
        cookie_created = await create_session(
            db_session,
            cookie_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert cookie_created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, cookie_created.token)

        response = await dep_client.get(
            "/whoami",
            headers={"Authorization": f"Bearer {bearer_created.token}"},
        )

        assert response.json()["user_id"] == str(bearer_user.id)

    async def test_missing_credential_returns_generic_401(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get("/whoami")

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }


@pytest.mark.e2e
class TestSlidingRefresh:
    async def test_refresh_sets_new_cookie_after_threshold(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")
        assert issued.token not in response.headers["set-cookie"]

    async def test_no_refresh_before_threshold(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        recent_iat = datetime.now(UTC) - timedelta(
            hours=settings.jwt_expiry_hours * 0.1
        )
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=recent_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" not in response.headers

    async def test_api_key_never_refreshes(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" not in response.headers

    async def test_cookie_attachment_failure_does_not_fail_request(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """If `Response.set_cookie()` raises for any reason, the request
        still succeeds with the old JWT — see authentication.md, Token
        refresh notes."""
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        def _raise(*args: Any, **kwargs: Any) -> None:
            raise RuntimeError("simulated cookie attachment failure")

        monkeypatch.setattr(dependencies, "set_session_cookie", _raise)

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {issued.token}"}
            )

        assert response.status_code == 200
        assert "session_cookie_refresh_failed" in _dependency_log_text(caplog)


# ---------------------------------------------------------------------------
# get_current_user — API key path (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestGetCurrentUserApiKey:
    async def test_valid_key_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "api_key"
        # A valid key emits neither API key warning.
        assert _dependency_events(caplog, "api_key_rejected") == []
        assert _dependency_events(caplog, "api_key_validation_failed") == []

    async def test_successful_auth_touches_last_used(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await dep_client.get(
            "/whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id

    async def test_unknown_key_returns_generic_401_with_warning(
        self,
        dep_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        token = "stl_ak_" + "0" * 32
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        text = _dependency_log_text(caplog)
        assert "api_key_validation_failed" in text
        # A lookup miss never emits the matched-key warning.
        assert _dependency_events(caplog, "api_key_rejected") == []

        # Complete secrets/PII exclusion contract (authentication.md, API
        # key validation, step 2): the log MUST NOT include the presented
        # key, its SHA-256 digest, the key prefix alone, a key name, a
        # username, or an email — nothing beyond the documented safe
        # fields (`event`, `source_ip`, `suppressed_count`).
        assert token not in text
        assert digest not in text
        assert "stl_ak_" not in text
        assert "key_name" not in text
        assert "username" not in text
        assert "email" not in text

        records = [
            record
            for record in caplog.records
            if record.name == "app.api.dependencies"
            and isinstance(record.msg, dict)
            and record.msg.get("event") == "api_key_validation_failed"
        ]
        assert len(records) == 1
        event_dict = records[0].msg
        # This exact field set reflects `_build_test_app()` (no
        # `CorrelationIdMiddleware`, hence no `request_id`), not a claim
        # that production emits nothing beyond these fields — the
        # negative assertions above (absence of token/digest/prefix)
        # are what the secrets/PII contract actually requires and hold
        # regardless of which non-sensitive fields the pipeline adds.
        assert set(event_dict) == {
            "event",
            "source_ip",
            "suppressed_count",
            "logger",
            "level",
            "timestamp",
            "app",
        }

    @pytest.mark.parametrize("case", list(_REJECTED_KEY_REASONS))
    async def test_rejected_key_returns_generic_401_with_rejected_key_warning(
        self,
        peer_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        case: str,
    ) -> None:
        """A matched key that is revoked (also when its expiration has
        passed), expired, or owned by an inactive or missing user (the
        defensive guard for an `ApiKey.user_id` referencing no User row)
        returns the generic 401 and emits one `api_key_rejected` — never
        `api_key_validation_failed` — with only internal identifiers
        (authentication.md, API key validation, Rejected-key warning)."""
        rejected = await _arrange_rejected_key(
            case, user_factory, api_key_factory, monkeypatch
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await peer_client.get(
                "/whoami", headers={"Authorization": f"Bearer {rejected.token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        _assert_single_rejected_key_warning(caplog, rejected)

    async def test_repeated_rejection_within_window_logs_once_and_always_401(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Denial is never rate-limited — only the log emission is. The
        fixture rows are committed to the test savepoint first, so the
        rollback of each failed request cannot undo them (see
        `tests/test_api/test_auth.py`, `auth_client`)."""
        rejected = await _arrange_rejected_key(
            "revoked", user_factory, api_key_factory, monkeypatch
        )
        await db_session.commit()

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            responses = [
                await dep_client.get(
                    "/whoami", headers={"Authorization": f"Bearer {rejected.token}"}
                )
                for _ in range(3)
            ]

        assert [response.status_code for response in responses] == [401, 401, 401]
        assert len(_dependency_events(caplog, "api_key_rejected")) == 1
        assert _dependency_events(caplog, "api_key_validation_failed") == []


@pytest.mark.integration
class TestAuthenticateApiKeyExpirationBoundary:
    """`_authenticate_api_key()` called directly with a controlled `now`."""

    async def test_expiration_equal_to_now_is_rejected_as_expired(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Step 4 rejects when `expires_at <= now`, so a key at exactly its
        expiration instant reports `expired`."""
        owner = await user_factory()
        token, digest = _make_api_key_credential()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        key = await api_key_factory(
            user_id=owner.id, key_hash=digest, expires_at=expires_at
        )

        with (
            caplog.at_level(logging.WARNING, logger="app.api.dependencies"),
            pytest.raises(AppError) as exc_info,
        ):
            await dependencies._authenticate_api_key(
                db_session, cast(Request, None), token, expires_at
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.code == ErrorCode.AUTH_NOT_AUTHENTICATED
        records = _dependency_events(caplog, "api_key_rejected")
        assert [(r["key_id"], r["reason"]) for r in records] == [
            (str(key.id), "expired")
        ]


# ---------------------------------------------------------------------------
# get_optional_current_user (e2e)
# ---------------------------------------------------------------------------
#
# See docs/features/identity/authentication.md (get_optional_current_user)
# and docs/features/platform/testing-strategy.md (Optional authentication
# mandatory scenarios). `get_current_user` and `get_optional_current_user`
# share the same `_resolve_principal()` selection/validation path — the
# rejection-matrix scenarios below are the optional-path counterparts of
# `TestGetCurrentUserJwt`/`TestGetCurrentUserApiKey` above and prove the two
# dependencies never diverge on a selected credential. The rejected-JWT
# matrix (malformed, expired, inactive session, inactive or missing user)
# runs against both dependencies in `TestRejectedJwtIsNotLogged`.


@pytest.mark.e2e
class TestGetOptionalCurrentUserAnonymous:
    """No credential selected — returns `None` with no authentication
    work at all."""

    async def test_no_credential_returns_anonymous(
        self, dep_client: AsyncClient
    ) -> None:
        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "credential_kind": None}
        assert "set-cookie" not in response.headers

    async def test_empty_cookie_returns_anonymous(
        self, dep_client: AsyncClient
    ) -> None:
        dep_client.cookies.set(SESSION_COOKIE_NAME, "")

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "credential_kind": None}

    async def test_no_credential_performs_no_authentication_work(
        self,
        dep_client: AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Absence of a credential must short-circuit before any user
        lookup, `last_used_at` touch, or API key warning — each side
        effect is made to fail loudly if invoked."""

        async def _fail_get_user_by_id(*args: Any, **kwargs: Any) -> User:
            raise AssertionError("user lookup must not occur when anonymous")

        def _fail_record_unknown_key(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("unknown-key warning must not occur when anonymous")

        def _fail_record_rejected_key(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("rejected-key warning must not occur when anonymous")

        monkeypatch.setattr(user_service, "get_user_by_id", _fail_get_user_by_id)
        monkeypatch.setattr(
            dependencies._last_used_debouncer,
            "touch",
            AsyncMock(side_effect=AssertionError("touch must not occur")),
        )
        monkeypatch.setattr(
            dependencies, "_record_unknown_key_attempt", _fail_record_unknown_key
        )
        monkeypatch.setattr(
            dependencies, "_record_rejected_key_attempt", _fail_record_rejected_key
        )

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200


@pytest.mark.unit
class TestResolvePrincipalWhitespaceCookie:
    """A whitespace-only cookie *value* reaching `_resolve_principal()`
    is a selected, invalid credential — not anonymous access (see
    authentication.md, Shared Credential Resolution step 2).

    Exercised by calling `_resolve_principal()` directly with a
    duck-typed request: Starlette's own `Cookie` header parser
    (`starlette.requests.cookie_parser`) unconditionally `.strip()`s
    cookie values before application code ever sees them, so a
    whitespace-only *raw* cookie cannot reach this function through a
    real HTTP round trip (verified separately — Starlette normalizes it
    to an empty string). This test proves the documented behavior of
    the shared resolver itself, independent of that framework-level
    normalization.
    """

    async def test_whitespace_only_cookie_value_is_selected_and_rejected(
        self,
    ) -> None:
        class _FakeHeaders:
            def get(self, key: str) -> str | None:
                return None

        class _FakeCookies:
            def get(self, key: str) -> str | None:
                return "   "

        class _FakeRequest:
            headers = _FakeHeaders()
            cookies = _FakeCookies()

        with pytest.raises(AppError) as exc_info:
            await dependencies._resolve_principal(
                cast(Request, _FakeRequest()),
                Response(),
                cast(AsyncSession, None),
            )

        assert exc_info.value.status_code == 401
        assert exc_info.value.code == ErrorCode.AUTH_NOT_AUTHENTICATED


@pytest.mark.e2e
class TestGetOptionalCurrentUserValidCredential:
    """A selected valid credential authenticates exactly as under
    mandatory authentication, including sliding refresh and API-key
    operational effects."""

    async def test_valid_jwt_cookie_returns_principal(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get("/optional-whoami")

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "jwt"

    async def test_bearer_takes_precedence_over_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        bearer_user = await user_factory()
        bearer_created = await create_session(
            db_session,
            bearer_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert bearer_created is not None
        cookie_user = await user_factory()
        cookie_created = await create_session(
            db_session,
            cookie_user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert cookie_created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, cookie_created.token)

        response = await dep_client.get(
            "/optional-whoami",
            headers={"Authorization": f"Bearer {bearer_created.token}"},
        )

        assert response.json()["user_id"] == str(bearer_user.id)

    async def test_empty_bearer_header_falls_back_to_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": "Bearer   "}
        )

        assert response.status_code == 200
        assert response.json()["user_id"] == str(user.id)

    async def test_eligible_jwt_refreshes_cookie(
        self,
        dep_client: AsyncClient,
        session_factory: Callable[..., Awaitable[Session]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        session = await session_factory()
        old_iat = datetime.now(UTC) - timedelta(hours=settings.jwt_expiry_hours * 0.6)
        issued = issue_token(
            user_id=session.user_id,
            session_id=session.id,
            issued_at=old_iat,
            session_deadline=session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        )

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {issued.token}"}
        )

        assert response.status_code == 200
        assert "set-cookie" in response.headers
        assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE_NAME}=")

    async def test_valid_api_key_returns_principal_and_touches_last_used(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        key = await api_key_factory(user_id=user.id, key_hash=digest)
        touch_mock = AsyncMock()
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", touch_mock)

        response = await dep_client.get(
            "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["user_id"] == str(user.id)
        assert body["credential_kind"] == "api_key"
        touch_mock.assert_awaited_once()
        assert touch_mock.await_args is not None
        assert touch_mock.await_args.args[0] == key.id


@pytest.mark.e2e
class TestGetOptionalCurrentUserRejection:
    """A selected credential that fails validation returns the same
    generic 401 as mandatory authentication rather than degrading to
    anonymous access — see authentication.md,
    `get_optional_current_user`."""

    async def test_invalid_non_empty_bearer_does_not_fall_back_to_valid_cookie(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        dep_client.cookies.set(SESSION_COOKIE_NAME, created.token)

        response = await dep_client.get(
            "/optional-whoami",
            headers={"Authorization": "Bearer not-a-real-token"},
        )

        assert response.status_code == 401

    async def test_unknown_api_key_returns_generic_401_with_warning(
        self,
        dep_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        token = "stl_ak_" + "1" * 32

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/optional-whoami", headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        assert "api_key_validation_failed" in _dependency_log_text(caplog)
        assert _dependency_events(caplog, "api_key_rejected") == []

    @pytest.mark.parametrize("case", ["revoked", "expired", "inactive_owner"])
    async def test_rejected_api_key_returns_generic_401_with_rejected_key_warning(
        self,
        peer_client: AsyncClient,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        case: str,
    ) -> None:
        """The same `api_key_rejected` path as mandatory authentication
        (authentication.md, `get_optional_current_user`)."""
        rejected = await _arrange_rejected_key(
            case, user_factory, api_key_factory, monkeypatch
        )

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await peer_client.get(
                "/optional-whoami",
                headers={"Authorization": f"Bearer {rejected.token}"},
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        _assert_single_rejected_key_warning(caplog, rejected)

    async def test_database_failure_propagates_rather_than_anonymous(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unexpected infrastructure failure must propagate — never
        be converted into an anonymous optional-authentication result
        — see authentication.md, Shared Credential Resolution: "Database
        failures and other infrastructure or unexpected exceptions
        propagate through normal error handling; neither dependency
        converts them to anonymous access"."""
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        async def _fail_get_user_by_id(*args: Any, **kwargs: Any) -> User:
            raise RuntimeError("simulated database failure")

        monkeypatch.setattr(user_service, "get_user_by_id", _fail_get_user_by_id)

        with pytest.raises(RuntimeError, match="simulated database failure"):
            await dep_client.get(
                "/optional-whoami",
                headers={"Authorization": f"Bearer {created.token}"},
            )


@pytest.mark.e2e
class TestRejectedJwtIsNotLogged:
    """A rejected JWT emits no log record of its own under mandatory or
    optional authentication — token expiry and `JWT_SECRET_KEY` rotation
    make such rejections routine (authentication.md, JWT validation;
    `get_optional_current_user`). Redis is available, so the liveness
    check's outage warning cannot appear either."""

    @staticmethod
    async def _rejected_token(
        kind: str,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> str:
        if kind == "malformed":
            return "not-a-real-token"
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        if kind == "inactive_session":
            created.session.is_active = False
        elif kind == "inactive_user":
            user.active = False
        await db_session.flush()
        if kind in {"inactive_session", "inactive_user"}:
            return created.token
        issued_at = datetime.now(UTC)
        user_id = user.id
        if kind == "expired":
            issued_at -= timedelta(hours=settings.jwt_expiry_hours + 1)
        else:
            assert kind == "missing_user"
            user_id = uuid.uuid4()
        return issue_token(
            user_id=user_id,
            session_id=created.session.id,
            issued_at=issued_at,
            session_deadline=created.session.expires_at,
            jwt_expiry_hours=settings.jwt_expiry_hours,
            secret_key=settings.jwt_secret_key.get_secret_value(),
        ).token

    @pytest.mark.parametrize("path", ["/whoami", "/optional-whoami"])
    @pytest.mark.parametrize(
        "kind",
        ["malformed", "expired", "inactive_session", "inactive_user", "missing_user"],
    )
    async def test_rejected_jwt_returns_401_without_log_record(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
        kind: str,
        path: str,
    ) -> None:
        token = await self._rejected_token(kind, db_session, user_factory)

        with caplog.at_level(logging.DEBUG):
            caplog.clear()
            response = await dep_client.get(
                path, headers={"Authorization": f"Bearer {token}"}
            )

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        assert _app_records(caplog) == []


# ---------------------------------------------------------------------------
# require_capability (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestRequireCapability:
    async def test_denies_without_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 403
        assert response.json() == {
            "code": "AUTH_INSUFFICIENT_PERMISSION",
            "detail": "Insufficient permissions",
        }

    async def test_allows_with_matching_role(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 200

    async def test_admin_does_not_inherit_va_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/capability-protected",
            headers={"Authorization": f"Bearer {created.token}"},
        )

        assert response.status_code == 403

    async def test_role_added_takes_effect_on_next_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        headers = {"Authorization": f"Bearer {created.token}"}
        # Capture the UUID before the failing request below: a rollback
        # (even a partial ROLLBACK TO SAVEPOINT) expires all tracked ORM
        # objects regardless of `expire_on_commit`, and a later
        # synchronous `user.id` access would raise `MissingGreenlet`.
        user_id = user.id
        # Checkpoint the fixture data via a savepoint commit: the first
        # request below is expected to fail (403), and the dep_client
        # override's rollback-on-exception would otherwise undo this
        # uncommitted user/session data too (see dep_client docstring).
        await db_session.commit()

        first = await dep_client.get("/capability-protected", headers=headers)
        assert first.status_code == 403

        await user_role_factory(user_id=user_id, role=Role.ADMIN.value)

        second = await dep_client.get("/capability-protected", headers=headers)
        assert second.status_code == 200

    async def test_role_removed_takes_effect_on_next_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        role = await user_role_factory(user_id=user.id, role=Role.ADMIN.value)
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None
        headers = {"Authorization": f"Bearer {created.token}"}

        first = await dep_client.get("/capability-protected", headers=headers)
        assert first.status_code == 200

        await db_session.delete(role)
        await db_session.flush()

        second = await dep_client.get("/capability-protected", headers=headers)
        assert second.status_code == 403

    async def test_denial_does_not_disclose_capability(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        with caplog.at_level(logging.WARNING, logger="app.api.dependencies"):
            response = await dep_client.get(
                "/capability-protected",
                headers={"Authorization": f"Bearer {created.token}"},
            )

        assert "manage_users" not in response.text.lower()
        assert "manage_users" not in _dependency_log_text(caplog).lower()


# ---------------------------------------------------------------------------
# require_session_authentication (e2e)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequireAnyCapabilityDeclaration:
    """`require_any_capability()` declares a union of alternatives; a single
    capability uses `require_capability()` (docs/api-spec.md,
    Authorization, `Capability: <a> OR <b>`)."""

    @pytest.mark.parametrize(
        "capabilities",
        [
            pytest.param((), id="none"),
            pytest.param((Capability.MANAGE_PACKAGES,), id="one"),
            pytest.param(
                (Capability.MANAGE_PACKAGES, Capability.MANAGE_PACKAGES),
                id="duplicate",
            ),
        ],
    )
    def test_fewer_than_two_distinct_alternatives_are_rejected(
        self, capabilities: tuple[Capability, ...]
    ) -> None:
        with pytest.raises(ValueError, match="at least two capabilities"):
            require_any_capability(*capabilities)


@pytest.mark.e2e
class TestRequireSessionAuthentication:
    async def test_jwt_principal_passes_through(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        created = await create_session(
            db_session,
            user,
            SessionCreationReason.LOCAL_LOGIN,
            expected_password_hash=None,
        )
        assert created is not None

        response = await dep_client.get(
            "/session-only", headers={"Authorization": f"Bearer {created.token}"}
        )

        assert response.status_code == 200
        assert response.json()["user_id"] == str(user.id)

    async def test_api_key_principal_is_rejected(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        api_key_factory: Callable[..., Awaitable[ApiKey]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        token, digest = _make_api_key_credential()
        await api_key_factory(user_id=user.id, key_hash=digest)
        monkeypatch.setattr(dependencies._last_used_debouncer, "touch", AsyncMock())

        response = await dep_client.get(
            "/session-only", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 403
        assert response.json() == {
            "code": "AUTH_SESSION_REQUIRED",
            "detail": "This operation requires session authentication.",
        }


# ---------------------------------------------------------------------------
# Ticket caller information and require_accessible_ticket (e2e)
# ---------------------------------------------------------------------------


async def _bearer(db_session: AsyncSession, user: User) -> dict[str, str]:
    created = await create_session(
        db_session,
        user,
        SessionCreationReason.LOCAL_LOGIN,
        expected_password_hash=None,
    )
    assert created is not None
    return {"Authorization": f"Bearer {created.token}"}


def _count_role_lookups(monkeypatch: pytest.MonkeyPatch) -> list[uuid.UUID]:
    """Record every `user_service.get_user_roles()` call made by the
    dependencies while still delegating to the real implementation."""
    calls: list[uuid.UUID] = []
    original = user_service.get_user_roles

    async def _spy(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
        calls.append(user_id)
        return await original(session, user_id)

    monkeypatch.setattr(user_service, "get_user_roles", _spy)
    return calls


@pytest.mark.e2e
class TestTicketCallerDependencies:
    async def test_optional_caller_without_credential_is_anonymous(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get("/optional-ticket-caller")

        assert response.status_code == 200
        assert response.json() == {"user_id": None, "scope": None}
        assert calls == []

    async def test_optional_caller_with_invalid_credential_returns_401(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get(
            "/optional-ticket-caller", headers={"Authorization": "Bearer invalid"}
        )

        assert response.status_code == 401
        assert response.json()["code"] == "AUTH_NOT_AUTHENTICATED"
        assert calls == []

    @pytest.mark.parametrize(
        ("roles", "scope"),
        [
            ([], "non_confidential"),
            ([Role.RESTRICTED_ANALYST], "non_confidential"),
            ([Role.VULNERABILITY_ANALYST], "all"),
            ([Role.RESTRICTED_ANALYST, Role.ADMIN], "all"),
        ],
    )
    @pytest.mark.parametrize("path", ["/ticket-caller", "/optional-ticket-caller"])
    async def test_authenticated_caller_carries_the_effective_scope(
        self,
        path: str,
        roles: list[Role],
        scope: str,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        for role in roles:
            await user_role_factory(user_id=user.id, role=role.value)
        headers = await _bearer(db_session, user)

        response = await dep_client.get(path, headers=headers)

        assert response.status_code == 200
        assert response.json() == {"user_id": str(user.id), "scope": scope}

    async def test_authenticated_caller_requires_a_credential(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get("/ticket-caller")

        assert response.status_code == 401
        assert calls == []

    async def test_caller_is_resolved_once_per_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        ticket = await ticket_factory()
        headers = await _bearer(db_session, user)
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get(
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/accessible",
            headers=headers,
        )

        assert response.status_code == 200
        assert calls == [user.id]


@pytest.mark.e2e
class TestRequireAccessibleTicket:
    async def test_accessible_ticket_resolves(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_access_grant_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        headers = await _bearer(db_session, user)

        response = await dep_client.get(
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/accessible",
            headers=headers,
        )

        assert response.status_code == 200
        assert response.json()["sequence_id"] == ticket.sequence_id

    async def test_every_denial_cause_returns_the_identical_404(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
    ) -> None:
        user = await user_factory()
        visible = await ticket_factory()
        hidden = await ticket_factory(is_confidential=True)
        headers = await _bearer(db_session, user)
        locators = [
            format_ticket_id(visible.sequence_id).lower(),
            f"SNTL-0{visible.sequence_id}",
            "SNTL-2147483648",
            str(visible.id),
            "SNTL-2147483647",
            format_ticket_id(hidden.sequence_id),
        ]
        # Checkpoint the fixtures: each 404 rolls back the request's work.
        await db_session.commit()

        bodies = []
        for locator in locators:
            response = await dep_client.get(
                f"/tickets/{locator}/accessible", headers=headers
            )
            assert response.status_code == 404, locator
            bodies.append(response.content)

        assert set(bodies) == {
            b'{"code":"TICKET_NOT_FOUND","detail":"Ticket not found."}'
        }

    async def test_missing_credential_returns_401_before_lookup(
        self, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resolver = AsyncMock()
        monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)

        response = await dep_client.get("/tickets/SNTL-1/accessible")

        assert response.status_code == 401
        resolver.assert_not_awaited()


# ---------------------------------------------------------------------------
# Single role resolution per request (require_capability + Ticket caller)
# ---------------------------------------------------------------------------


_FORBIDDEN_BODY = {
    "code": "AUTH_INSUFFICIENT_PERMISSION",
    "detail": "Insufficient permissions",
}


def _change_roles_after_load(
    monkeypatch: pytest.MonkeyPatch,
    change: Callable[[AsyncSession, uuid.UUID], Awaitable[None]],
) -> list[uuid.UUID]:
    """Spy on `user_service.get_user_roles()` that applies `change` to the
    user's roles right after each load has completed.

    Deterministically simulates a role change landing between the
    request's single role load and the rest of its dependencies and
    handler: any later reload in the same request would observe it.
    """
    calls: list[uuid.UUID] = []
    original = user_service.get_user_roles

    async def _spy(session: AsyncSession, user_id: uuid.UUID) -> list[Role]:
        calls.append(user_id)
        roles = await original(session, user_id)
        await change(session, user_id)
        return roles

    monkeypatch.setattr(user_service, "get_user_roles", _spy)
    return calls


def _spy_resolver(monkeypatch: pytest.MonkeyPatch) -> list[TicketCaller]:
    """Record the caller handed to `ticket_service.resolve_ticket_locator()`
    while delegating to the real implementation."""
    callers: list[TicketCaller] = []
    original = ticket_service.resolve_ticket_locator

    async def _spy(
        session: AsyncSession, ticket_id: str, caller: TicketCaller
    ) -> ResolvedTicket:
        callers.append(caller)
        return await original(session, ticket_id, caller)

    monkeypatch.setattr(ticket_service, "resolve_ticket_locator", _spy)
    return callers


@pytest.mark.e2e
class TestSingleRoleResolution:
    """`require_capability()` and the Ticket caller share one role load per
    request (docs/features/identity/rbac.md, Optional Principal to Caller
    Context, Permission Checking; docs/api-spec.md, Authorization Chain
    Evaluation Order; testing-strategy.md, Ticket Accessibility)."""

    @pytest.mark.parametrize(
        ("roles", "scope"),
        [
            ([Role.VULNERABILITY_ANALYST], "all"),
            ([Role.RESTRICTED_ANALYST], "non_confidential"),
            ([Role.RESTRICTED_ANALYST, Role.ADMIN], "all"),
        ],
    )
    async def test_capability_and_caller_scope_come_from_one_role_load(
        self,
        roles: list[Role],
        scope: str,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        for role in roles:
            await user_role_factory(user_id=user.id, role=role.value)
        headers = await _bearer(db_session, user)
        calls = _count_role_lookups(monkeypatch)

        response = await dep_client.get("/triage-caller", headers=headers)

        assert response.status_code == 200
        assert response.json() == {"user_id": str(user.id), "scope": scope}
        assert calls == [user.id]

    @pytest.mark.parametrize(
        ("role", "granted", "scope"),
        [
            (Role.VULNERABILITY_ANALYST, False, "all"),
            (Role.RESTRICTED_ANALYST, True, "non_confidential"),
        ],
    )
    async def test_accessible_ticket_route_loads_roles_once(
        self,
        role: Role,
        granted: bool,
        scope: str,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        ticket_access_grant_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=role.value)
        ticket = await ticket_factory(is_confidential=True)
        if granted:
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        headers = await _bearer(db_session, user)
        calls = _count_role_lookups(monkeypatch)
        callers = _spy_resolver(monkeypatch)

        response = await dep_client.get(
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/triage", headers=headers
        )

        assert response.status_code == 200
        assert response.json() == {
            "sequence_id": ticket.sequence_id,
            "user_id": str(user.id),
            "scope": scope,
        }
        assert calls == [user.id]
        assert [(c.user_id, c.scope and c.scope.value) for c in callers] == [
            (user.id, scope)
        ]

    @pytest.mark.parametrize(
        "roles",
        [pytest.param([], id="no-roles"), pytest.param([Role.ADMIN], id="admin")],
    )
    async def test_missing_capability_is_403_after_one_load_and_before_lookup(
        self,
        roles: list[Role],
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        user = await user_factory()
        for role in roles:
            await user_role_factory(user_id=user.id, role=role.value)
        ticket = await ticket_factory()
        headers = await _bearer(db_session, user)
        user_id = user.id
        paths = [
            "/triage-caller",
            f"/tickets/{format_ticket_id(ticket.sequence_id)}/triage",
            "/tickets/SNTL-2147483647/triage",
            "/tickets/not-a-ticket/triage",
        ]
        # Checkpoint the fixtures: each 403 rolls back the request's work.
        await db_session.commit()
        resolver = AsyncMock()
        monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)

        for path in paths:
            calls = _count_role_lookups(monkeypatch)
            response = await dep_client.get(path, headers=headers)
            assert response.status_code == 403, path
            assert response.json() == _FORBIDDEN_BODY, path
            assert calls == [user_id], path

        resolver.assert_not_awaited()

    @pytest.mark.parametrize(
        "path", ["/triage-caller", "/tickets/SNTL-1/triage", "/tickets/bad/triage"]
    )
    async def test_missing_credential_is_401_without_any_role_load(
        self, path: str, dep_client: AsyncClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _count_role_lookups(monkeypatch)
        resolver = AsyncMock()
        monkeypatch.setattr(ticket_service, "resolve_ticket_locator", resolver)

        response = await dep_client.get(path)

        assert response.status_code == 401
        assert response.json() == {
            "code": "AUTH_NOT_AUTHENTICATED",
            "detail": "Authentication required",
        }
        assert calls == []
        resolver.assert_not_awaited()

    async def test_role_removed_after_the_load_keeps_the_in_flight_authorization(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        ticket_factory: Callable[..., Awaitable[Ticket]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The VA role disappears right after the single load. The in-flight
        request keeps both the capability and the `all` scope that lets it
        see a confidential Ticket without a grant; a reload would see no
        role and deny. The committed removal applies to the next request."""
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value)
        ticket = await ticket_factory(is_confidential=True)
        headers = await _bearer(db_session, user)
        user_id = user.id
        path = f"/tickets/{format_ticket_id(ticket.sequence_id)}/triage"
        await db_session.commit()

        async def _remove_roles(session: AsyncSession, target: uuid.UUID) -> None:
            await session.execute(delete(UserRole).where(UserRole.user_id == target))

        original = user_service.get_user_roles
        calls = _change_roles_after_load(monkeypatch, _remove_roles)
        callers = _spy_resolver(monkeypatch)

        in_flight = await dep_client.get(path, headers=headers)

        assert in_flight.status_code == 200
        assert in_flight.json()["scope"] == "all"
        assert calls == [user_id]
        assert [c.scope and c.scope.value for c in callers] == ["all"]

        monkeypatch.setattr(user_service, "get_user_roles", original)
        next_calls = _count_role_lookups(monkeypatch)
        next_request = await dep_client.get(path, headers=headers)

        assert next_request.status_code == 403
        assert next_request.json() == _FORBIDDEN_BODY
        assert next_calls == [user_id]
        assert len(callers) == 1

    async def test_role_added_after_the_load_applies_to_the_next_request(
        self,
        dep_client: AsyncClient,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        user_role_factory: Callable[..., Awaitable[Any]],
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A restricted analyst gains the VA role right after the single
        load: the in-flight caller keeps `non_confidential`, the next
        request resolves `all`."""
        user = await user_factory()
        await user_role_factory(user_id=user.id, role=Role.RESTRICTED_ANALYST.value)
        headers = await _bearer(db_session, user)
        user_id = user.id

        async def _add_va(session: AsyncSession, target: uuid.UUID) -> None:
            session.add(UserRole(user_id=target, role=Role.VULNERABILITY_ANALYST.value))
            await session.flush()

        original = user_service.get_user_roles
        calls = _change_roles_after_load(monkeypatch, _add_va)
        in_flight = await dep_client.get("/triage-caller", headers=headers)
        monkeypatch.setattr(user_service, "get_user_roles", original)
        next_calls = _count_role_lookups(monkeypatch)
        next_request = await dep_client.get("/triage-caller", headers=headers)

        assert in_flight.status_code == 200
        assert in_flight.json() == {
            "user_id": str(user_id),
            "scope": "non_confidential",
        }
        assert calls == [user_id]
        assert next_request.status_code == 200
        assert next_request.json() == {"user_id": str(user_id), "scope": "all"}
        assert next_calls == [user_id]
