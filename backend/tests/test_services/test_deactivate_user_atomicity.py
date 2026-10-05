"""Independent-session tests for `deactivate_user()`
(backend/app/services/user_service.py) against its identity-local
counterparts.

Owning specifications:

- docs/features/identity/user-service.md (`deactivate_user()`, Concurrency
  and Re-invocation; `reset_password()`, Concurrency; `update_roles()`,
  Concurrency; Concurrency Considerations: Concurrent deactivation from
  multiple entry points, Concurrent role removal and deactivation, Session
  creation concurrent with deactivation, Redis operations and lock scope).
- docs/features/identity/authentication.md (Session creation: Deactivation
  serialization).
- docs/features/identity/local-authentication.md (Login Endpoint, Login
  step 11).
- docs/features/identity/api-key-service.md (`create_key()`,
  `revoke_all_user_keys()`).
- docs/features/identity/identity-audit-log.md (Event types; detail JSONB
  Schema Contract) and docs/features/tickets/ticket-audit-log.md (Canonical
  Automatic Comment Vocabulary).
- docs/features/platform/testing-strategy.md (Concurrency Testing,
  Lock-Wait Observation; Authentication and Session: Lockout concurrency;
  User Lifecycle and Management: Concurrency and endpoint behavior,
  Deactivation concurrency; API Key Management).

The single-session behavior of `deactivate_user()` is covered by
`tests/test_services/test_deactivate_user.py`; this module adds only what
needs independent sessions. Each race holds the first writer's uncommitted
transaction in session A, proves with `assert_lock_wait()` that the second
writer in session B waits on A's User lock with that lock as its only
statement so far, commits A, and lets B classify from the locked-current
state. The final rows are read through a fresh session. The races with
Ticket assignment and access-grant creation are covered by their own
modules.

Committed rows are deleted explicitly at teardown (testing-strategy.md,
Concurrency Testing). Expected values are transcribed from the
specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import functools
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import redis.asyncio as redis_asyncio
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import Role, SessionCreationReason, TicketStatus
from app.core.exceptions import InactiveUserError
from app.core.passwords import hash_password, verify_password
from app.models.api_key import ApiKey
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.user import User
from app.services import local_auth_service, session_service, user_service
from app.services.api_key_service import create_key
from app.services.local_auth_service import (
    LoginInvalidCredentials,
    LoginSuccess,
    authenticate_local_user,
)
from app.services.session_service import create_session
from app.services.user_service import reset_password
from tests.support.database import assert_lock_wait
from tests.support.identity_lifecycle_races import (
    USER_DEACTIVATED,
    VA_ROLE_REMOVED,
    IdentityEventRow,
    IdentityWorld,
    deactivate,
    identity_events,
    origins,
    remove_roles,
    role_removed,
    user_deactivated,
)
from tests.support.suse_cvss_races import SessionStatementRecorder
from tests.support.ticket_mutations import (
    EventRow,
    ticket_events_by_id,
    unassigned_event,
)

Factory = Callable[[], Awaitable[AsyncSession]]
Writer = Callable[[AsyncSession], Awaitable[Any]]
Timeline = list[tuple[str, str]]

_REASON = "fictional offboarding"
_OTHER_REASON = "fictional duplicate offboarding"
_KEY_NAME = "fictional-ci"
# Within the documented 16-128 character range (user-service.md,
# `reset_password()` step 1).
_NEW_PASSWORD = "fictional-new-passphrase-42"
_LOGIN_PASSWORD = "fictional correct horse login 7"


@functools.cache
def _login_password_hash() -> str:
    """A real bcrypt hash of `_LOGIN_PASSWORD`, computed once on first use
    so that the login workflow can verify it."""
    return hash_password(_LOGIN_PASSWORD)


@pytest.fixture
async def identity_world(db_session_factory: Factory) -> AsyncIterator[IdentityWorld]:
    world = IdentityWorld(db_session_factory, await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _TimelineRecorder(SessionStatementRecorder):
    """`SessionStatementRecorder` that also appends each statement of its
    session, labelled, to a timeline shared with other recorders and with
    test instrumentation."""

    def __init__(self, db: AsyncSession, timeline: Timeline, label: str) -> None:
        super().__init__(db)
        self._timeline = timeline
        self._label = label

    def _record(self, *args: Any) -> None:
        super()._record(*args)
        self._timeline.append((self._label, args[2]))


@dataclass(frozen=True, slots=True)
class _Race:
    first: Any
    second: Any
    # B's statements when its lock wait was observed.
    waiting: list[str]
    second_writes: list[str]
    timeline: Timeline


async def _race(
    world: IdentityWorld,
    first: Writer,
    second: Writer,
    *,
    raises: type[Exception] | None = None,
    timeline: Timeline | None = None,
) -> _Race:
    """Run `first` uncommitted in session A, start `second` in session B,
    prove that B waits on A, commit A, then let B finish. B commits, or
    rolls back after raising `raises`, which then becomes `second`.

    Statements of A (`"first"`) and B (`"second"`) are appended to
    `timeline`, which the caller may share with its own instrumentation."""
    shared: Timeline = [] if timeline is None else timeline
    a = await world.open_session()
    b = await world.open_session()
    with (
        _TimelineRecorder(a, shared, "first"),
        _TimelineRecorder(b, shared, "second") as recorder,
    ):
        first_result = await first(a)
        task = world.start(b, second(b))
        await assert_lock_wait(task, waiter=b, blocked_by=a)
        waiting = list(recorder.statements)
        await a.commit()
        second_result: Any
        if raises is None:
            second_result = await asyncio.wait_for(task, timeout=5)
            await b.commit()
        else:
            with pytest.raises(raises) as raised:
                await asyncio.wait_for(task, timeout=5)
            second_result = raised.value
            await b.rollback()
    return _Race(first_result, second_result, waiting, recorder.writes(), shared)


def _is_user_lock(statement: str, mode: str) -> bool:
    """A `SELECT ... FROM "user" ... FOR <mode>` statement."""
    return 'FROM "user"' in statement and statement.rstrip().endswith(f"FOR {mode}")


def _assert_waits_on_user_lock(race: _Race, mode: str = "NO KEY UPDATE") -> None:
    """B's only statement while waiting is its User lock: the documented
    first database operation of every racing writer."""
    assert len(race.waiting) == 1
    assert _is_user_lock(race.waiting[0], mode)


@dataclass(frozen=True, slots=True)
class _Committed:
    active: bool
    password_hash: str | None
    last_login_at: datetime | None
    sessions: dict[uuid.UUID, bool]
    # key id -> (revoked, revoked_by)
    keys: dict[uuid.UUID, tuple[bool, uuid.UUID | None]]
    origins: set[tuple[str, str]]
    identity: list[IdentityEventRow]
    tickets: dict[uuid.UUID, tuple[str, uuid.UUID | None]]
    ticket_events: dict[uuid.UUID, list[EventRow]]


async def _committed(
    world: IdentityWorld, user: User, tickets: tuple[Ticket, ...] = ()
) -> _Committed:
    """The committed state of `user`, its Sessions, API keys, role origins,
    and Identity events, and of each Ticket, read through a fresh
    independent session."""
    probe = await world.open_session()
    row = (
        await probe.execute(
            select(User.active, User.password_hash, User.last_login_at).where(
                User.id == user.id
            )
        )
    ).one()
    sessions = (
        await probe.execute(
            select(Session.id, Session.is_active).where(Session.user_id == user.id)
        )
    ).all()
    keys = (
        await probe.execute(
            select(ApiKey.id, ApiKey.revoked_at, ApiKey.revoked_by).where(
                ApiKey.user_id == user.id
            )
        )
    ).all()
    ticket_rows = (
        await probe.execute(
            select(Ticket.id, Ticket.status, Ticket.assignee_id).where(
                Ticket.id.in_([t.id for t in tickets])
            )
        )
    ).all()
    committed = _Committed(
        active=row.active,
        password_hash=row.password_hash,
        last_login_at=row.last_login_at,
        sessions={s.id: s.is_active for s in sessions},
        keys={k.id: (k.revoked_at is not None, k.revoked_by) for k in keys},
        origins=await origins(probe, user.id),
        identity=await identity_events(probe, user.id),
        tickets={t.id: (t.status, t.assignee_id) for t in ticket_rows},
        ticket_events={t.id: await ticket_events_by_id(probe, t.id) for t in tickets},
    )
    await probe.rollback()
    return committed


def _actor(world: IdentityWorld) -> Awaitable[User]:
    return world.identity_user(prefix="alice.admin")


def _target(world: IdentityWorld) -> Awaitable[User]:
    """An active local User with one manual VA origin."""
    return world.identity_user(manual=[Role.VULNERABILITY_ANALYST])


async def _active_session(world: IdentityWorld, user: User) -> uuid.UUID:
    """One committed active Session of `user`."""
    session = Session(
        user_id=user.id, expires_at=datetime.now(UTC) + timedelta(days=30)
    )
    world.session.add(session)
    await world.session.commit()
    return session.id


async def _api_key(world: IdentityWorld, user: User, name: str) -> uuid.UUID:
    """One committed non-revoked API key of `user`."""
    # Fictional 64-character hex digest, never a real key hash.
    digest = uuid.uuid4().hex * 2
    key = ApiKey(
        user_id=user.id, key_hash=digest, prefix=f"stl_ak_{digest[:5]}", name=name
    )
    world.session.add(key)
    await world.session.commit()
    return key.id


def _api_key_created(owner: User, key_id: uuid.UUID, name: str) -> IdentityEventRow:
    """api-key-service.md, `create_key()` step 8."""
    return ("api_key_created", owner.id, owner.id, None, name, {"key_id": str(key_id)})


def _api_key_revoked(
    actor: User, owner: User, key_id: uuid.UUID, name: str
) -> IdentityEventRow:
    """api-key-service.md, `revoke_all_user_keys()` step 4."""
    return (
        "api_key_revoked",
        actor.id,
        owner.id,
        name,
        None,
        {"key_id": str(key_id), "reason": "user_deactivated"},
    )


def _password_reset(actor: User, target: User) -> IdentityEventRow:
    """identity-audit-log.md, Event types: `password_reset`."""
    return ("password_reset", actor.id, target.id, None, None, None)


def _login_at(created: Any) -> datetime:
    """The `login_at` snapshot of a created Session: `Session.expires_at` is
    `login_at + SESSION_MAX_LIFETIME_DAYS` (authentication.md, Session
    creation step 3)."""
    expires_at: datetime = created.session.expires_at
    return expires_at - timedelta(days=settings.session_max_lifetime_days)


def _local_auth_log_text(caplog: pytest.LogCaptureFixture) -> str:
    """Only the records of `app.services.local_auth_service`."""
    return "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "app.services.local_auth_service"
    )


# ---------------------------------------------------------------------------
# a. Deactivation / deactivation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConcurrentDeactivation:
    async def test_the_loser_is_a_no_op_with_no_duplicate_effect(
        self, identity_world: IdentityWorld
    ) -> None:
        """user-service.md, Concurrent deactivation from multiple entry
        points: exactly one caller performs the transition with its complete
        audit sequence; the waiting caller observes the committed inactive
        state and returns `deactivated = false` with no mutation or event."""
        actor_a = await _actor(identity_world)
        actor_b = await _actor(identity_world)
        target = await _target(identity_world)
        ticket = await identity_world.ticket(cve_id=None, assignee_id=target.id)
        key_id = await _api_key(identity_world, target, _KEY_NAME)
        session_id = await _active_session(identity_world, target)

        race = await _race(
            identity_world,
            lambda s: deactivate(s, target, _REASON, actor_a),
            lambda s: deactivate(s, target, _OTHER_REASON, actor_b),
        )

        _assert_waits_on_user_lock(race)
        assert race.first.deactivated is True
        assert race.first.invalidated_session_ids == [session_id]
        assert race.second.deactivated is False
        assert race.second.invalidated_session_ids == []
        assert race.second_writes == []
        committed = await _committed(identity_world, target, (ticket,))
        assert committed.active is False
        assert committed.sessions == {session_id: False}
        assert committed.keys == {key_id: (True, actor_a.id)}
        assert committed.origins == {("Vulnerability Analyst", "_manual")}
        assert committed.identity == [
            _api_key_revoked(actor_a, target, key_id, _KEY_NAME),
            user_deactivated(actor_a, target, _REASON),
        ]
        assert committed.tickets == {ticket.id: (TicketStatus.ANALYSIS, None)}
        assert committed.ticket_events == {
            ticket.id: [unassigned_event(target.username, USER_DEACTIVATED)]
        }


# ---------------------------------------------------------------------------
# b. Deactivation / API-key creation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivationAndApiKeyCreation:
    """user-service.md, `deactivate_user()` Concurrency (deactivation /
    API-key creation) and api-key-service.md, `create_key()` step 1: both
    lock the User `FOR NO KEY UPDATE`; whichever acquires it second observes
    the first caller's committed state."""

    async def test_deactivation_first_rejects_the_creation(
        self, identity_world: IdentityWorld
    ) -> None:
        actor = await _actor(identity_world)
        target = await _target(identity_world)

        race = await _race(
            identity_world,
            lambda s: deactivate(s, target, _REASON, actor),
            lambda s: create_key(s, target.id, _KEY_NAME, None),
            raises=InactiveUserError,
        )

        _assert_waits_on_user_lock(race)
        assert race.first.deactivated is True
        assert isinstance(race.second, InactiveUserError)
        assert race.second_writes == []
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.keys == {}
        assert committed.identity == [user_deactivated(actor, target, _REASON)]

    async def test_creation_first_key_is_revoked_by_the_deactivation(
        self, identity_world: IdentityWorld
    ) -> None:
        actor = await _actor(identity_world)
        target = await _target(identity_world)

        race = await _race(
            identity_world,
            lambda s: create_key(s, target.id, _KEY_NAME, None),
            lambda s: deactivate(s, target, _REASON, actor),
        )

        _assert_waits_on_user_lock(race)
        key_id = race.first.api_key.id
        assert race.second.deactivated is True
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.keys == {key_id: (True, actor.id)}
        assert committed.identity == [
            _api_key_created(target, key_id, _KEY_NAME),
            _api_key_revoked(actor, target, key_id, _KEY_NAME),
            user_deactivated(actor, target, _REASON),
        ]


# ---------------------------------------------------------------------------
# c. Deactivation / Session creation
# ---------------------------------------------------------------------------


_PROVIDERS = pytest.mark.parametrize(
    ("reason", "checks_password"),
    [
        (SessionCreationReason.LOCAL_LOGIN, True),
        (SessionCreationReason.SSO_LOGIN, False),
    ],
    ids=["local", "sso"],
)


@pytest.mark.integration
class TestDeactivationAndSessionCreation:
    """authentication.md, Session creation (Deactivation serialization) and
    user-service.md, Session creation concurrent with deactivation: local
    and SSO Session creation revalidate the locked-current active status
    under the conflicting User lock."""

    @_PROVIDERS
    async def test_deactivation_first_creates_no_session(
        self,
        identity_world: IdentityWorld,
        reason: SessionCreationReason,
        checks_password: bool,
    ) -> None:
        actor = await _actor(identity_world)
        target = await _target(identity_world)
        expected_hash = target.password_hash if checks_password else None

        race = await _race(
            identity_world,
            lambda s: deactivate(s, target, _REASON, actor),
            lambda s: create_session(
                s, target, reason, expected_password_hash=expected_hash
            ),
        )

        _assert_waits_on_user_lock(race)
        assert race.first.deactivated is True
        assert race.first.invalidated_session_ids == []
        assert race.second is None
        assert race.second_writes == []
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.sessions == {}
        assert committed.last_login_at is None
        assert committed.identity == [user_deactivated(actor, target, _REASON)]

    @_PROVIDERS
    async def test_session_first_is_invalidated_by_the_deactivation(
        self,
        identity_world: IdentityWorld,
        reason: SessionCreationReason,
        checks_password: bool,
    ) -> None:
        actor = await _actor(identity_world)
        target = await _target(identity_world)
        expected_hash = target.password_hash if checks_password else None

        race = await _race(
            identity_world,
            lambda s: create_session(
                s, target, reason, expected_password_hash=expected_hash
            ),
            lambda s: deactivate(s, target, _REASON, actor),
        )

        _assert_waits_on_user_lock(race)
        created = race.first
        assert created is not None
        assert race.second.deactivated is True
        assert race.second.invalidated_session_ids == [created.session.id]
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.sessions == {created.session.id: False}
        assert committed.last_login_at == _login_at(created)
        assert committed.identity == [user_deactivated(actor, target, _REASON)]


# ---------------------------------------------------------------------------
# d. Local login end to end
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLocalLoginAndDeactivation:
    """local-authentication.md, Login step 11, with the real login workflow
    (`authenticate_local_user()`, the service of the login endpoint) and the
    real `deactivate_user()` in an independent session."""

    @staticmethod
    async def _login_target(world: IdentityWorld) -> User:
        """`_target()` with a verifiable stored password hash."""
        target = await _target(world)
        await world.session.execute(
            update(User)
            .where(User.id == target.id)
            .values(password_hash=_login_password_hash())
        )
        await world.session.commit()
        return target

    @pytest.mark.parametrize(
        ("max_attempts", "transitions"),
        [(1, 1), (5, 0)],
        ids=["at-threshold", "below-threshold"],
    )
    async def test_deactivation_after_the_pre_check_yields_generic_failure(
        self,
        identity_world: IdentityWorld,
        redis_client: redis_asyncio.Redis,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        max_attempts: int,
        transitions: int,
    ) -> None:
        """The deactivation starts after the step-7 pre-check and the step-8
        verification and holds the User lock while the login's locked Session
        creation waits on it; it commits, and the login observes the inactive
        User: the generic invalid-credentials outcome, no Session, no
        `last_login_at`, the step-4 counter retained, and the lockout
        transition exactly when that counter equals `LOGIN_MAX_ATTEMPTS`
        (testing-strategy.md, Lockout concurrency)."""
        monkeypatch.setattr(settings, "login_max_attempts", max_attempts)
        actor = await _actor(identity_world)
        target = await self._login_target(identity_world)
        login = await identity_world.open_session()
        holder = await identity_world.open_session()
        real_create = session_service.create_session
        deactivations: list[Any] = []

        async def _create_after_deactivation(
            db: AsyncSession,
            user: User,
            reason: SessionCreationReason,
            *,
            expected_password_hash: str | None,
        ) -> Any:
            deactivations.append(await deactivate(holder, target, _REASON, actor))
            task = identity_world.start(
                db,
                real_create(
                    db, user, reason, expected_password_hash=expected_password_hash
                ),
            )
            await assert_lock_wait(task, waiter=db, blocked_by=holder)
            await holder.commit()
            return await asyncio.wait_for(task, timeout=5)

        monkeypatch.setattr(
            local_auth_service, "create_session", _create_after_deactivation
        )

        with caplog.at_level("INFO"):
            result = await authenticate_local_user(
                login, target.username, _LOGIN_PASSWORD
            )
        await login.rollback()

        assert result == LoginInvalidCredentials()
        assert len(deactivations) == 1
        assert deactivations[0].deactivated is True
        assert deactivations[0].invalidated_session_ids == []
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.sessions == {}
        assert committed.last_login_at is None
        assert committed.identity == [user_deactivated(actor, target, _REASON)]
        assert await redis_client.get(f"login_attempts:{target.username}") == "1"
        log_text = _local_auth_log_text(caplog)
        assert log_text.count("login_lockout_triggered") == transitions
        assert (str(target.id) in log_text) is bool(transitions)

    async def test_session_first_is_invalidated_by_the_deactivation(
        self,
        identity_world: IdentityWorld,
        redis_client: redis_asyncio.Redis,
    ) -> None:
        """The opposite order: the login's Session and `last_login_at`
        commit first while the deactivation waits on the login's User lock;
        the deactivation then invalidates that Session and returns its id."""
        actor = await _actor(identity_world)
        target = await self._login_target(identity_world)
        login = await identity_world.open_session()
        holder = await identity_world.open_session()

        result = await authenticate_local_user(login, target.username, _LOGIN_PASSWORD)
        assert isinstance(result, LoginSuccess)
        created = result.created_session
        task = identity_world.start(holder, deactivate(holder, target, _REASON, actor))
        await assert_lock_wait(task, waiter=holder, blocked_by=login)
        await login.commit()
        deactivation = await asyncio.wait_for(task, timeout=5)
        await holder.commit()

        assert deactivation.deactivated is True
        assert deactivation.invalidated_session_ids == [created.session.id]
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.sessions == {created.session.id: False}
        assert committed.last_login_at == _login_at(created)
        assert committed.identity == [user_deactivated(actor, target, _REASON)]


# ---------------------------------------------------------------------------
# e. Deactivation / password reset
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivationAndPasswordReset:
    """user-service.md, `reset_password()` Concurrency: deactivation cannot
    interleave its database mutations with a reset because both lock the
    same User row (`FOR NO KEY UPDATE` and `FOR UPDATE` conflict). No bcrypt
    work or Redis I/O occurs while a writer holds its User lock
    (testing-strategy.md, User Lifecycle and Management: Concurrency and
    endpoint behavior).

    Technique: constructing any Redis client fails the test for the whole
    race, so neither writer performs Redis I/O at all. `hash_password` is
    wrapped to append a `bcrypt` entry to the race timeline when hashing
    completes; the timeline also holds every statement of both sessions, so
    the single bcrypt entry must precede the reset session's first
    statement, its User lock."""

    @staticmethod
    def _instrument(monkeypatch: pytest.MonkeyPatch) -> Timeline:
        timeline: Timeline = []

        def _recorded_hash(password: str) -> str:
            hashed = hash_password(password)
            timeline.append(("bcrypt", ""))
            return hashed

        def _forbid_redis(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("no Redis client may be constructed in this race")

        monkeypatch.setattr(user_service, "hash_password", _recorded_hash)
        monkeypatch.setattr(redis_asyncio.Redis, "from_url", _forbid_redis)
        return timeline

    @staticmethod
    def _assert_hashed_before_locking(timeline: Timeline, reset_label: str) -> None:
        labels = [label for label, _ in timeline]
        assert labels.count("bcrypt") == 1
        first_reset_statement = labels.index(reset_label)
        assert labels.index("bcrypt") < first_reset_statement
        assert _is_user_lock(timeline[first_reset_statement][1], "UPDATE")

    async def test_reset_first_then_deactivation_finds_no_session(
        self, identity_world: IdentityWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        resetter = await _actor(identity_world)
        deactivator = await _actor(identity_world)
        target = await _target(identity_world)
        session_id = await _active_session(identity_world, target)
        timeline = self._instrument(monkeypatch)

        race = await _race(
            identity_world,
            lambda s: reset_password(
                s, target.id, _NEW_PASSWORD, acting_user_id=resetter.id
            ),
            lambda s: deactivate(s, target, _REASON, deactivator),
            timeline=timeline,
        )

        _assert_waits_on_user_lock(race)
        self._assert_hashed_before_locking(race.timeline, "first")
        assert race.first.invalidated_session_ids == [session_id]
        assert race.second.deactivated is True
        assert race.second.invalidated_session_ids == []
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.password_hash is not None
        assert verify_password(_NEW_PASSWORD, committed.password_hash)
        assert committed.sessions == {session_id: False}
        assert committed.identity == [
            _password_reset(resetter, target),
            user_deactivated(deactivator, target, _REASON),
        ]

    async def test_deactivation_first_then_reset_stores_the_hash(
        self, identity_world: IdentityWorld, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reset hashes before requesting its lock, then waits on the
        deactivation's User lock with that lock as its only statement, and
        stores its hash on the inactive User without reactivating it or
        invalidating a further Session."""
        deactivator = await _actor(identity_world)
        resetter = await _actor(identity_world)
        target = await _target(identity_world)
        session_id = await _active_session(identity_world, target)
        timeline = self._instrument(monkeypatch)

        race = await _race(
            identity_world,
            lambda s: deactivate(s, target, _REASON, deactivator),
            lambda s: reset_password(
                s, target.id, _NEW_PASSWORD, acting_user_id=resetter.id
            ),
            timeline=timeline,
        )

        _assert_waits_on_user_lock(race, "UPDATE")
        self._assert_hashed_before_locking(race.timeline, "second")
        assert race.first.deactivated is True
        assert race.first.invalidated_session_ids == [session_id]
        assert race.second.invalidated_session_ids == []
        committed = await _committed(identity_world, target)
        assert committed.active is False
        assert committed.password_hash is not None
        assert verify_password(_NEW_PASSWORD, committed.password_hash)
        assert committed.sessions == {session_id: False}
        assert committed.identity == [
            user_deactivated(deactivator, target, _REASON),
            _password_reset(resetter, target),
        ]


# ---------------------------------------------------------------------------
# f. Deactivation / manual final VA-origin loss
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDeactivationAndManualRoleLoss:
    """user-service.md, Concurrent role removal and deactivation: both
    serialize on the User lock; the first to commit performs the Ticket
    unassignment with its own reason, and the second finds no assigned
    Ticket and creates no duplicate `assignment` event."""

    async def test_deactivation_first_unassigns_once(
        self, identity_world: IdentityWorld
    ) -> None:
        deactivator = await _actor(identity_world)
        remover = await _actor(identity_world)
        target = await _target(identity_world)
        ticket = await identity_world.ticket(cve_id=None, assignee_id=target.id)

        race = await _race(
            identity_world,
            lambda s: deactivate(s, target, _REASON, deactivator),
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], remover),
        )

        _assert_waits_on_user_lock(race)
        assert race.first.deactivated is True
        assert race.second.removed_roles == [Role.VULNERABILITY_ANALYST]
        committed = await _committed(identity_world, target, (ticket,))
        assert committed.active is False
        assert committed.origins == set()
        assert committed.identity == [
            user_deactivated(deactivator, target, _REASON),
            role_removed(remover, target, "vulnerability_analyst"),
        ]
        assert committed.tickets == {ticket.id: (TicketStatus.ANALYSIS, None)}
        assert committed.ticket_events == {
            ticket.id: [unassigned_event(target.username, USER_DEACTIVATED)]
        }

    async def test_role_loss_first_unassigns_once(
        self, identity_world: IdentityWorld
    ) -> None:
        remover = await _actor(identity_world)
        deactivator = await _actor(identity_world)
        target = await _target(identity_world)
        ticket = await identity_world.ticket(cve_id=None, assignee_id=target.id)

        race = await _race(
            identity_world,
            lambda s: remove_roles(s, target, [Role.VULNERABILITY_ANALYST], remover),
            lambda s: deactivate(s, target, _REASON, deactivator),
        )

        _assert_waits_on_user_lock(race)
        assert race.first.removed_roles == [Role.VULNERABILITY_ANALYST]
        assert race.second.deactivated is True
        committed = await _committed(identity_world, target, (ticket,))
        assert committed.active is False
        assert committed.origins == set()
        assert committed.identity == [
            role_removed(remover, target, "vulnerability_analyst"),
            user_deactivated(deactivator, target, _REASON),
        ]
        assert committed.tickets == {ticket.id: (TicketStatus.ANALYSIS, None)}
        assert committed.ticket_events == {
            ticket.id: [unassigned_event(target.username, VA_ROLE_REMOVED)]
        }
