"""Tests for `sentinel manage-user deactivate`.

See docs/features/identity/user-management.md (`sentinel manage-user
deactivate`: Behavior steps 1-12, Stale preview, Interruption, Idempotency,
Exit codes, Output channels) for the contract exercised here, and
docs/features/platform/cli-infrastructure.md (Database Session Management,
Error Handling & Exit Code Mapping, Signal Handling, Interactive Input
Helpers) for the shared mechanisms the command composes.
docs/features/platform/testing-strategy.md (Deactivation CLI, CLI Commands,
Sync Entry-Point Tests) defines the required coverage; the preview and the
action themselves are covered by the service tests.

Every test invoking the command is a synchronous `def`. Unit tests replace
the session factory and the composed services with in-memory doubles and
pin the flow: ordering, rendering, delegation, and transaction control.
Integration tests run against the real PostgreSQL test database through
`cli_session_factory`; rows are committed directly through that factory and
removed by `cleanup_users_by_username` plus the module-local `ticket_ids`
fixture. Interactive outcomes that `CliRunner` cannot reproduce — EOF
reaching the shared mapper, answers delivered line by line, and signals at
the prompt — run through the real `main()` with `terminal_stdin()`.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import click
import pytest
import redis.asyncio as redis_asyncio
from click.testing import CliRunner, Result
from redis.exceptions import RedisError
from sqlalchemy import delete, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.cli as cli_package
import app.cli.manage_user as manage_user_module
from app.cli import cli, main
from app.core.enums import IdentityAuditEventType, TicketStatus
from app.core.exceptions import UserNotFoundError
from app.models.api_key import ApiKey
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.session import Session
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.services import session_service
from app.services import user_service as user_service_module
from app.services.user_service import DeactivationImpact, DeactivationResult
from tests.support.redis import redis_url_from_client
from tests.support.terminal import TerminalEntry, terminal_stdin

# Literal transcriptions from user-management.md (`manage-user deactivate`).
_REASON = "deactivated via CLI (manage-user deactivate)"
_EXTERNAL_ERROR = "Error: Cannot deactivate external users."
_TTY_ERROR = (
    "Error: This command requires an interactive terminal (confirmation required)."
)
_LAST_ADMIN_WARNING = (
    "Warning: this is the last active user with Admin role.\n"
    "After deactivation, assign Admin to another user via:\n"
    "  sentinel manage-user update --username <user> --add-role admin\n"
)
_PROMPT = "Proceed? [y/N]: "
_RETRY_FEEDBACK = "Error: invalid input\n"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _username(tag: str) -> str:
    """A unique, format-valid username so parallel workers never collide."""
    return f"{tag}.{uuid4().hex[:10]}"


def _letter_leading_uuid() -> UUID:
    """A random UUID whose canonical text starts with a letter, so it is
    also a format-valid username (docs/conventions.md, Username Format)."""
    return UUID("a" + uuid4().hex[1:])


def _summary(username: str, keys: int, sessions: int, tickets: int) -> str:
    return (
        f"About to deactivate user '{username}':\n"
        f"  - {keys} non-revoked API keys will be revoked\n"
        f"  - {sessions} active sessions will be invalidated\n"
        f"  - {tickets} active tickets will be unassigned\n"
    )


def _not_found(username: str) -> str:
    return f"Error: User '{username}' not found.\n"


def _noop(username: str) -> str:
    return f"User '{username}' is already inactive.\n"


def _deactivated(username: str) -> str:
    return f"Deactivated user '{username}'.\n"


def _invoke(username: str, input: str | bytes | None = None, **extra: Any) -> Result:
    """Invoke the command through the raw `cli` group with
    `standalone_mode=False`, mirroring how production's `main()` invokes
    it. `CliRunner` echoes each visible answer after its prompt."""
    return CliRunner().invoke(
        cli,
        ["manage-user", "deactivate", "--username", username],
        input=input,
        standalone_mode=False,
        **extra,
    )


def _inject_session_factory(monkeypatch: pytest.MonkeyPatch, factory: object) -> None:
    monkeypatch.setattr(manage_user_module, "get_session_factory", lambda: factory)


def _allow_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", lambda: True)


def _forbid(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make each named module-level helper of the command fail if called."""

    def _fail(*args: object, **kwargs: object) -> Any:
        raise AssertionError("must not be reached on this path")

    for name in names:
        monkeypatch.setattr(manage_user_module, name, _fail)


def _forbidden_session_factory() -> None:
    raise AssertionError("the command must not access the database")


class _CountingSessionFactory:
    """Delegates to a real session factory, counting opened sessions."""

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = factory
        self.calls = 0

    def __call__(self) -> AsyncSession:
        self.calls += 1
        return self._factory()


def _count_commits(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Count every `AsyncSession.commit()` from this point on; install only
    after the test's own setup commits."""
    counter = {"n": 0}
    original_commit = AsyncSession.commit

    async def _counting_commit(self: AsyncSession) -> None:
        counter["n"] += 1
        await original_commit(self)

    monkeypatch.setattr(AsyncSession, "commit", _counting_commit)
    return counter


def _spy_asyncio_run(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the command module's `asyncio` with a namespace whose `run`
    delegates to the real `asyncio.run`, counting calls."""
    spy = MagicMock(side_effect=asyncio.run)
    monkeypatch.setattr(manage_user_module, "asyncio", SimpleNamespace(run=spy))
    return spy


@contextmanager
def _restored_signal_handlers() -> Iterator[None]:
    previous = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    try:
        yield
    finally:
        for signum, handler in previous.items():
            if handler is not None:
                signal.signal(signum, handler)


def _run_main(monkeypatch: pytest.MonkeyPatch, username: str) -> int:
    """Run the real `main()` (signal handlers and shared exception mapper)
    and return the process exit code. `main()` returns normally on
    success."""
    monkeypatch.setattr(
        sys, "argv", ["sentinel", "manage-user", "deactivate", "--username", username]
    )
    with _restored_signal_handlers():
        try:
            main()
        except SystemExit as exc:
            code = exc.code
        else:
            code = 0
    assert isinstance(code, int)
    return code


def _run_main_at_terminal(
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    *entries: TerminalEntry,
    errors: str = "strict",
) -> int:
    """`_run_main()` with an interactive terminal delivering `entries` one
    line per read (`tests.support.terminal`)."""
    _allow_tty(monkeypatch)
    monkeypatch.setattr(sys, "stdin", terminal_stdin(*entries, errors=errors))
    return _run_main(monkeypatch, username)


# ---------------------------------------------------------------------------
# Unit doubles: fake session factory and composed services
# ---------------------------------------------------------------------------


_FAKE_USER_ID = UUID("01900000-0000-7000-8000-000000000002")
_FAKE_SESSION_IDS = [
    UUID("01900000-0000-7000-8000-0000000000a1"),
    UUID("01900000-0000-7000-8000-0000000000a2"),
]


class _FakeSession:
    """Records transaction control and any query issued by the command.

    The composed services are replaced by doubles in unit tests, so every
    entry in `queries` would be a statement issued by the command itself —
    the command must perform no API-key, Session, Ticket, or UserRole query
    of its own (user-management.md, Behavior step 4)."""

    def __init__(self, events: list[str], index: int) -> None:
        self._events = events
        self._index = index
        self.queries: list[str] = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def _record_query(self, name: str) -> Callable[..., Any]:
        async def _query(*args: object, **kwargs: object) -> None:
            self.queries.append(name)

        return _query

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name in {"execute", "scalar", "scalars", "get", "stream", "stream_scalars"}:
            return self._record_query(name)
        raise AttributeError(name)

    async def commit(self) -> None:
        self.commits += 1
        self._events.append(f"commit:{self._index}")

    async def rollback(self) -> None:
        self.rollbacks += 1
        self._events.append(f"rollback:{self._index}")


class _FakeSessionContext:
    def __init__(self, session: _FakeSession, events: list[str], index: int) -> None:
        self._session = session
        self._events = events
        self._index = index

    async def __aenter__(self) -> _FakeSession:
        self._events.append(f"open:{self._index}")
        return self._session

    async def __aexit__(self, *exc_info: object) -> bool:
        self._session.closed = True
        self._events.append(f"close:{self._index}")
        return False


class _FakeSessionFactory:
    def __init__(self) -> None:
        self.sessions: list[_FakeSession] = []
        self.events: list[str] = []

    def __call__(self) -> _FakeSessionContext:
        index = len(self.sessions)
        session = _FakeSession(self.events, index)
        self.sessions.append(session)
        return _FakeSessionContext(session, self.events, index)


def _impact(
    *,
    keys: int = 7,
    sessions: int = 5,
    tickets: int = 3,
    last_admin: bool = False,
    already_inactive: bool = False,
) -> DeactivationImpact:
    return DeactivationImpact(
        already_inactive=already_inactive,
        is_last_active_admin=last_admin,
        api_keys_count=keys,
        sessions_count=sessions,
        tickets_count=tickets,
    )


def _result(*, deactivated: bool = True) -> DeactivationResult:
    return DeactivationResult(
        user=User(username="alice.example", email="alice.example@example.com"),
        deactivated=deactivated,
        invalidated_session_ids=list(_FAKE_SESSION_IDS) if deactivated else [],
    )


@pytest.fixture
def fake_factory(monkeypatch: pytest.MonkeyPatch) -> _FakeSessionFactory:
    factory = _FakeSessionFactory()
    _inject_session_factory(monkeypatch, factory)
    return factory


@pytest.fixture
def fake_services(
    monkeypatch: pytest.MonkeyPatch, fake_factory: _FakeSessionFactory
) -> SimpleNamespace:
    """Replace the lookup, the preview, the action, and the cache purge;
    each double appends to the factory's event log."""
    events = fake_factory.events

    def _recording(name: str, return_value: object) -> AsyncMock:
        async def _record(*args: object, **kwargs: object) -> object:
            events.append(name)
            return mock.return_value

        mock = AsyncMock(side_effect=_record, return_value=return_value)
        return mock

    services = SimpleNamespace(
        get_user_by_username=_recording(
            "lookup", SimpleNamespace(id=_FAKE_USER_ID, external_id=None)
        ),
        get_deactivation_impact=_recording("preview", _impact()),
        deactivate_user=_recording("deactivate", _result()),
        purge_session_cache=_recording("purge", None),
    )
    for name in ("get_user_by_username", "get_deactivation_impact", "deactivate_user"):
        monkeypatch.setattr(user_service_module, name, getattr(services, name))
    monkeypatch.setattr(
        session_service, "purge_session_cache", services.purge_session_cache
    )
    return services


def _assert_no_command_queries(factory: _FakeSessionFactory) -> None:
    for session in factory.sessions:
        assert session.queries == []


def _assert_declined_without_mutation(
    factory: _FakeSessionFactory, services: SimpleNamespace
) -> None:
    assert len(factory.sessions) == 1
    assert factory.sessions[0].commits == 0
    services.deactivate_user.assert_not_awaited()
    services.purge_session_cache.assert_not_awaited()
    _assert_no_command_queries(factory)


# ---------------------------------------------------------------------------
# Unit: flow, rendering, and delegation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_summary_renders_exactly_the_preview_counts(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    """The three documented lines carry the preview's own values, and no
    grant or maintainership line is rendered."""
    _allow_tty(monkeypatch)

    result = _invoke("alice.example", input="n\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == (
        _summary("alice.example", 7, 5, 3) + f"{_PROMPT}n\nAborted.\n"
    )
    assert result.stderr == ""
    for absent in ("grant", "maintain"):
        assert absent not in result.output.lower()
    _assert_declined_without_mutation(fake_factory, fake_services)


@pytest.mark.unit
@pytest.mark.parametrize("last_admin", [True, False])
def test_last_active_admin_warning_goes_to_stderr_only_when_reported(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
    last_admin: bool,
) -> None:
    _allow_tty(monkeypatch)
    fake_services.get_deactivation_impact.return_value = _impact(last_admin=last_admin)

    result = _invoke("alice.example", input="n\n")

    assert result.exit_code == 0, result.output
    assert result.stderr == (_LAST_ADMIN_WARNING if last_admin else "")
    assert "Warning" not in result.stdout
    assert result.stdout.startswith(_summary("alice.example", 7, 5, 3))


@pytest.mark.unit
def test_read_only_session_is_closed_before_tty_check_and_prompt(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    def _tty() -> bool:
        assert all(session.closed for session in fake_factory.sessions)
        fake_factory.events.append("tty")
        return True

    def _confirm(text: str, *, default: bool) -> bool:
        assert (text, default) == ("Proceed?", False)
        assert all(session.closed for session in fake_factory.sessions)
        fake_factory.events.append("prompt")
        return True

    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", _tty)
    monkeypatch.setattr(manage_user_module, "confirm", _confirm)

    result = _invoke("alice.example")

    assert result.exit_code == 0, result.output
    assert fake_factory.events == [
        "open:0",
        "lookup",
        "preview",
        "close:0",
        "tty",
        "prompt",
        "open:1",
        "deactivate",
        "commit:1",
        "close:1",
        "purge",
    ]


@pytest.mark.unit
def test_affirmative_answer_delegates_in_fresh_session_and_commits_once(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    """The raw `--username` is trimmed and lowercased before the lookup,
    and the preview runs in the same read-only session with a NULL actor."""
    _allow_tty(monkeypatch)

    result = _invoke("  Alice.Example  ", input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == (
        _summary("alice.example", 7, 5, 3)
        + f"{_PROMPT}y\n"
        + _deactivated("alice.example")
    )
    assert result.stderr == ""
    assert len(fake_factory.sessions) == 2
    read_only, mutating = fake_factory.sessions
    fake_services.get_user_by_username.assert_awaited_once_with(
        read_only, "alice.example"
    )
    fake_services.get_deactivation_impact.assert_awaited_once_with(
        read_only, _FAKE_USER_ID, acting_user_id=None
    )
    assert (read_only.commits, mutating.commits, mutating.rollbacks) == (0, 1, 0)
    fake_services.deactivate_user.assert_awaited_once_with(
        mutating, _FAKE_USER_ID, acting_user_id=None, reason=_REASON
    )
    fake_services.purge_session_cache.assert_awaited_once_with(_FAKE_SESSION_IDS)
    _assert_no_command_queries(fake_factory)


@pytest.mark.unit
def test_confirmed_noop_result_reports_already_inactive_not_the_preview(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    """The preview observed an active target; the outcome derives only
    from `DeactivationResult.deactivated` (Behavior step 12)."""
    _allow_tty(monkeypatch)
    fake_services.deactivate_user.return_value = _result(deactivated=False)

    result = _invoke("alice.example", input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout.endswith(f"{_PROMPT}y\n" + _noop("alice.example"))
    assert "Deactivated" not in result.stdout
    assert fake_factory.sessions[1].commits == 1
    fake_services.purge_session_cache.assert_awaited_once_with([])


@pytest.mark.unit
@pytest.mark.parametrize("answer", ["n", ""], ids=["n", "enter-default"])
def test_negative_answer_or_enter_aborts_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
    answer: str,
) -> None:
    _allow_tty(monkeypatch)

    result = _invoke("alice.example", input=f"{answer}\n")

    assert result.exit_code == 0, result.output
    assert result.stdout.endswith(f"{_PROMPT}{answer}\nAborted.\n")
    assert result.stderr == ""
    _assert_declined_without_mutation(fake_factory, fake_services)


@pytest.mark.unit
def test_unrecognized_answer_reprompts_with_feedback_on_stdout(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    _allow_tty(monkeypatch)

    result = _invoke("alice.example", input="maybe\nn\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == (
        _summary("alice.example", 7, 5, 3)
        + f"{_PROMPT}maybe\n{_RETRY_FEEDBACK}{_PROMPT}n\nAborted.\n"
    )
    assert result.stderr == ""
    _assert_declined_without_mutation(fake_factory, fake_services)


@pytest.mark.unit
def test_eof_at_prompt_reaches_shared_mapper_as_aborted(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    """Through the real `main()` with `CliRunner`'s scripted stdin: EOF
    raises `click.Abort`, which the shared mapper reports as `Aborted.`
    with exit 0, without reaching the mapper's catch-all logger."""
    _allow_tty(monkeypatch)
    mapper_logger = MagicMock()
    monkeypatch.setattr(cli_package, "logger", mapper_logger)

    with CliRunner().isolation(input=b"") as outstreams:
        code = _run_main(monkeypatch, "alice.example")
        sys.stdout.flush()
        sys.stderr.flush()
        stdout = outstreams[0].getvalue()
        stderr = outstreams[1].getvalue()

    assert code == 0
    assert (
        stdout == (_summary("alice.example", 7, 5, 3) + _PROMPT + "Aborted.\n").encode()
    )
    assert stderr == b""
    mapper_logger.error.assert_not_called()
    _assert_declined_without_mutation(fake_factory, fake_services)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("failure", "expected_exit", "expected_stderr"),
    [
        pytest.param(UserNotFoundError(), 1, _not_found("alice.example"), id="mapped"),
        pytest.param(RuntimeError("injected failure"), 1, "", id="unexpected"),
    ],
)
def test_pre_commit_failure_rolls_back_and_commits_zero_times(
    monkeypatch: pytest.MonkeyPatch,
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
    failure: Exception,
    expected_exit: int,
    expected_stderr: str,
) -> None:
    """A `UserNotFoundError` from the action maps to the not-found error
    (defensive; users are never deleted); any other failure propagates to
    the shared mapper. Both roll back and skip the purge."""
    _allow_tty(monkeypatch)
    fake_services.deactivate_user.side_effect = failure

    result = _invoke("alice.example", input="y\n")

    assert result.exit_code == expected_exit
    assert result.stderr == expected_stderr
    assert "Deactivated" not in result.stdout
    assert [s.commits for s in fake_factory.sessions] == [0, 0]
    assert fake_factory.sessions[1].rollbacks == 1
    fake_services.purge_session_cache.assert_not_awaited()


@pytest.mark.unit
def test_database_unreachable_exits_two_through_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fake_factory: _FakeSessionFactory,
    fake_services: SimpleNamespace,
) -> None:
    fake_services.get_user_by_username.side_effect = OperationalError(
        "SELECT 1", {}, Exception("connection refused")
    )

    assert _run_main(monkeypatch, "alice.example") == 2

    captured = capsys.readouterr()
    assert captured.err.startswith("Error: ")
    assert captured.out == ""


# ---------------------------------------------------------------------------
# Integration fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def ticket_ids(
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> Iterator[list[UUID]]:
    """Collect committed Ticket IDs and delete them, with their audit
    events, grants, packages, and maintainer rows, at teardown.

    Depends on `cleanup_users_by_username` so this teardown runs before the
    user cleanup: these rows reference the users."""
    tracked: list[UUID] = []
    yield tracked
    if not tracked:
        return

    async def _cleanup() -> None:
        async with cli_session_factory() as db:
            packages = select(TicketPackage.id).where(
                TicketPackage.ticket_id.in_(tracked)
            )
            await db.execute(
                delete(TicketPackageMaintainer).where(
                    TicketPackageMaintainer.ticket_package_id.in_(packages)
                )
            )
            await db.execute(
                delete(TicketPackage).where(TicketPackage.ticket_id.in_(tracked))
            )
            await db.execute(
                delete(TicketAccessGrant).where(
                    TicketAccessGrant.ticket_id.in_(tracked)
                )
            )
            await db.execute(
                delete(TicketAuditEvent).where(TicketAuditEvent.ticket_id.in_(tracked))
            )
            await db.execute(delete(Ticket).where(Ticket.id.in_(tracked)))
            await db.commit()

    asyncio.run(_cleanup())


async def _create_user(
    factory: async_sessionmaker[AsyncSession],
    *,
    username: str,
    active: bool = True,
    external: bool = False,
    user_id: UUID | None = None,
) -> User:
    """Insert and commit a `User`, bypassing `user_service` (setup only)."""
    async with factory() as db:
        user = User(
            username=username,
            email=f"{username}@example.com",
            active=active,
            external_id=uuid4() if external else None,
            password_hash=None if external else "$2b$12$" + "a" * 53,
        )
        if user_id is not None:
            user.id = user_id
        db.add(user)
        await db.commit()
        return user


async def _add_keys_and_sessions(
    factory: async_sessionmaker[AsyncSession],
    user_id: UUID,
    *,
    keys: int,
    sessions: int,
    revoked_by: UUID | None = None,
) -> tuple[list[UUID], list[UUID]]:
    """Commit `keys` non-revoked API keys (the first one expired) and
    `sessions` active Sessions; with `revoked_by`, also one revoked key and
    one inactive Session that no count includes."""
    now = datetime.now(UTC)
    async with factory() as db:
        api_keys = []
        for index in range(keys):
            # Fictional 64-character hex digest, never a real key hash.
            digest = uuid4().hex * 2
            api_keys.append(
                ApiKey(
                    user_id=user_id,
                    key_hash=digest,
                    prefix=f"stl_ak_{digest[:5]}",
                    name=f"example-key-{index}",
                    expires_at=now - timedelta(days=1) if index == 0 else None,
                )
            )
        live_sessions = [
            Session(user_id=user_id, expires_at=now + timedelta(days=30))
            for _ in range(sessions)
        ]
        db.add_all([*api_keys, *live_sessions])
        if revoked_by is not None:
            digest = uuid4().hex * 2
            db.add(
                ApiKey(
                    user_id=user_id,
                    key_hash=digest,
                    prefix=f"stl_ak_{digest[:5]}",
                    name="example-key-revoked",
                    revoked_at=now - timedelta(days=2),
                    revoked_by=revoked_by,
                )
            )
            db.add(
                Session(
                    user_id=user_id,
                    expires_at=now + timedelta(days=30),
                    is_active=False,
                )
            )
        await db.commit()
        return [k.id for k in api_keys], [s.id for s in live_sessions]


async def _create_ticket(
    factory: async_sessionmaker[AsyncSession],
    tracked: list[UUID],
    *,
    status: TicketStatus,
    assignee_id: UUID | None,
    is_confidential: bool = False,
) -> UUID:
    async with factory() as db:
        ticket = Ticket(
            status=status.value,
            cve_id=None,
            is_confidential=is_confidential,
            assignee_id=assignee_id,
        )
        db.add(ticket)
        await db.flush()
        tracked.append(ticket.id)
        await db.commit()
        return ticket.id


async def _add_grant_and_maintainer(
    factory: async_sessionmaker[AsyncSession],
    tracked: list[UUID],
    *,
    user_id: UUID,
    granted_by: UUID,
) -> None:
    """Commit an explicit access grant and a package-maintainer row for
    `user_id`; deactivation retains both and the preview counts neither."""
    confidential = await _create_ticket(
        factory,
        tracked,
        status=TicketStatus.NEW,
        assignee_id=None,
        is_confidential=True,
    )
    async with factory() as db:
        db.add(
            TicketAccessGrant(
                ticket_id=confidential, user_id=user_id, granted_by_id=granted_by
            )
        )
        package = TicketPackage(ticket_id=confidential, package_name="example-package")
        db.add(package)
        await db.flush()
        db.add(TicketPackageMaintainer(ticket_package_id=package.id, user_id=user_id))
        await db.commit()


async def _fetch_user(factory: async_sessionmaker[AsyncSession], user_id: UUID) -> User:
    async with factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        return user


async def _fetch_identity_events(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> list[IdentityAuditEvent]:
    async with factory() as db:
        rows = await db.scalars(
            select(IdentityAuditEvent)
            .where(IdentityAuditEvent.target_user_id == user_id)
            .order_by(IdentityAuditEvent.id)
        )
        return list(rows)


async def _fetch_ticket_events(
    factory: async_sessionmaker[AsyncSession], ticket_ids: list[UUID]
) -> list[TicketAuditEvent]:
    async with factory() as db:
        rows = await db.scalars(
            select(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id.in_(ticket_ids))
            .order_by(TicketAuditEvent.id)
        )
        return list(rows)


@dataclass(frozen=True)
class _PersistedState:
    """Every persisted value a deactivation may change for one user."""

    active: bool
    keys: list[tuple[UUID, datetime | None, UUID | None]]
    sessions: list[tuple[UUID, bool]]
    tickets: list[tuple[UUID, UUID | None, str]]
    grant: UUID | None
    maintainer: UUID | None
    identity_events: list[UUID]


async def _state(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> _PersistedState:
    async with factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        keys = await db.execute(
            select(ApiKey.id, ApiKey.revoked_at, ApiKey.revoked_by)
            .where(ApiKey.user_id == user_id)
            .order_by(ApiKey.id)
        )
        sessions = await db.execute(
            select(Session.id, Session.is_active)
            .where(Session.user_id == user_id)
            .order_by(Session.id)
        )
        tickets = await db.execute(
            select(Ticket.id, Ticket.assignee_id, Ticket.status)
            .where(Ticket.assignee_id == user_id)
            .order_by(Ticket.id)
        )
        grant = await db.scalar(
            select(TicketAccessGrant.ticket_id).where(
                TicketAccessGrant.user_id == user_id
            )
        )
        maintainer = await db.scalar(
            select(TicketPackageMaintainer.id).where(
                TicketPackageMaintainer.user_id == user_id
            )
        )
        events = await db.scalars(
            select(IdentityAuditEvent.id).where(
                IdentityAuditEvent.target_user_id == user_id
            )
        )
        return _PersistedState(
            active=user.active,
            keys=[(k, at, by) for k, at, by in keys],
            sessions=[(sid, is_active) for sid, is_active in sessions],
            tickets=[(tid, assignee, status) for tid, assignee, status in tickets],
            grant=grant,
            maintainer=maintainer,
            identity_events=list(events),
        )


def _snapshot(
    factory: async_sessionmaker[AsyncSession], user_id: UUID
) -> _PersistedState:
    return asyncio.run(_state(factory, user_id))


async def _redis_set(url: str, keys: list[str]) -> None:
    client = redis_asyncio.Redis.from_url(url, decode_responses=True)
    try:
        for key in keys:
            await client.set(key, "1")
    finally:
        await client.aclose()


async def _redis_existing(url: str, keys: list[str]) -> list[str]:
    client = redis_asyncio.Redis.from_url(url, decode_responses=True)
    try:
        return [key for key in keys if await client.exists(key)]
    finally:
        await client.aclose()


def _liveness_key(session_id: UUID) -> str:
    return f"session_liveness:{session_id}"


class _FailingRedisClient:
    """A Redis client double whose `delete` always raises `RedisError`."""

    async def delete(self, key: str) -> None:
        raise RedisError("simulated outage")

    async def aclose(self) -> None:
        return None


def _interrupt_after(original: Callable[..., Any]) -> Callable[..., Any]:
    async def _run_then_interrupt(*args: Any, **kwargs: Any) -> Any:
        await original(*args, **kwargs)
        raise KeyboardInterrupt()

    return _run_then_interrupt


def _invoke_interrupted(username: str) -> None:
    # Click's own `main()` converts a raw `KeyboardInterrupt` escaping the
    # command into `click.Abort` regardless of `standalone_mode`; the
    # workflow's own rollback (before commit) has already run by then.
    with pytest.raises(click.Abort):
        _invoke(username, input="y\n", catch_exceptions=False)


# ---------------------------------------------------------------------------
# Integration: username validation and resolution
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_invalid_username_rejected_before_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _inject_session_factory(monkeypatch, _forbidden_session_factory)
    run_spy = _spy_asyncio_run(monkeypatch)

    result = _invoke("  9BAD ")

    assert result.exit_code == 1
    assert result.stderr == (
        "Error: Invalid username '9bad'. Username must be 1-64 characters, "
        "start with a letter, and contain only lowercase letters, numbers, "
        "dots, hyphens, and underscores.\n"
    )
    assert result.stdout == ""
    assert run_spy.call_count == 0


@pytest.mark.integration
def test_unknown_user_reports_not_found(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _forbid(monkeypatch, "is_interactive_terminal", "confirm")
    username = _username("nobody")

    result = _invoke(f"  {username.upper()} ")

    assert result.exit_code == 1
    assert result.stderr == _not_found(username)
    assert result.stdout == ""
    assert factory.calls == 1


@pytest.mark.integration
def test_uuid_shaped_username_resolves_by_username_not_by_id(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """docs/conventions.md (Command Design — Username normalization and
    resolution): the value is both one user's username and another user's
    ID, and only the username owner is deactivated."""
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    shared = _letter_leading_uuid()
    username_owner = str(shared)
    id_owner = _username("alice.idowner")
    cleanup_users_by_username(username_owner, id_owner)
    other = asyncio.run(
        _create_user(cli_session_factory, username=id_owner, user_id=shared)
    )
    target = asyncio.run(_create_user(cli_session_factory, username=username_owner))

    result = _invoke(username_owner, input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout.endswith(_deactivated(username_owner))
    assert asyncio.run(_fetch_user(cli_session_factory, target.id)).active is False
    assert asyncio.run(_fetch_user(cli_session_factory, other.id)).active is True


@pytest.mark.integration
def test_existing_user_uuid_is_reported_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.byuuid")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory, username=username, user_id=_letter_leading_uuid()
        )
    )
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _forbid(monkeypatch, "is_interactive_terminal", "confirm")

    result = _invoke(str(user.id))

    assert result.exit_code == 1
    assert result.stderr == _not_found(str(user.id))
    assert result.stdout == ""
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before


# ---------------------------------------------------------------------------
# Integration: classifications before the prompt
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("external", [False, True], ids=["local", "external"])
def test_already_inactive_user_is_noop_without_prompt_or_mutating_session(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    external: bool,
) -> None:
    """The no-op precedes the external guard and TTY detection: it works
    without a terminal, shows no prompt, and opens no second session."""
    username = _username("alice.inactive")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(
            cli_session_factory, username=username, active=False, external=external
        )
    )
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _forbid(monkeypatch, "is_interactive_terminal", "confirm")
    commits = _count_commits(monkeypatch)

    result = _invoke(username)

    assert result.exit_code == 0, result.output
    assert result.stdout == _noop(username)
    assert result.stderr == ""
    assert factory.calls == 1
    assert commits["n"] == 0
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []


@pytest.mark.integration
def test_preview_noop_then_concurrent_reactivation_still_reports_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """Stale preview: the observed no-op is reported even though another
    caller reactivates the target before the command exits; a new
    invocation observes the reactivated state."""
    username = _username("alice.reactivated")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, active=False)
    )
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    original_preview = user_service_module.get_deactivation_impact

    async def _preview_then_concurrent_reactivation(
        *args: Any, **kwargs: Any
    ) -> DeactivationImpact:
        impact = await original_preview(*args, **kwargs)
        async with cli_session_factory() as other:
            await other.execute(
                update(User).where(User.id == user.id).values(active=True)
            )
            await other.commit()
        return impact

    monkeypatch.setattr(
        user_service_module,
        "get_deactivation_impact",
        _preview_then_concurrent_reactivation,
    )
    _forbid(monkeypatch, "is_interactive_terminal", "confirm")

    result = _invoke(username)

    assert result.exit_code == 0, result.output
    assert result.stdout == _noop(username)
    assert factory.calls == 1
    assert asyncio.run(_fetch_user(cli_session_factory, user.id)).active is True
    assert asyncio.run(_fetch_identity_events(cli_session_factory, user.id)) == []

    monkeypatch.setattr(
        user_service_module, "get_deactivation_impact", original_preview
    )
    _allow_tty(monkeypatch)
    monkeypatch.setattr(manage_user_module, "confirm", lambda text, *, default: False)

    again = _invoke(username)

    assert again.exit_code == 0, again.output
    assert again.stdout == _summary(username, 0, 0, 0) + "Aborted.\n"
    assert asyncio.run(_fetch_user(cli_session_factory, user.id)).active is True


@pytest.mark.integration
def test_active_external_user_rejected_before_impact_display(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.external")
    cleanup_users_by_username(username)
    user = asyncio.run(
        _create_user(cli_session_factory, username=username, external=True)
    )
    asyncio.run(
        _add_keys_and_sessions(cli_session_factory, user.id, keys=1, sessions=1)
    )
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _forbid(monkeypatch, "is_interactive_terminal", "confirm")

    result = _invoke(username)

    assert result.exit_code == 1
    assert result.stderr == f"{_EXTERNAL_ERROR}\n"
    assert result.stdout == ""
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before


@pytest.mark.integration
def test_non_tty_rejected_after_summary_without_prompt_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.nontty")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    monkeypatch.setattr(manage_user_module, "is_interactive_terminal", lambda: False)
    _forbid(monkeypatch, "confirm")

    result = _invoke(username, input="y\n")

    assert result.exit_code == 1
    assert result.stdout == _summary(username, 0, 0, 0)
    assert result.stderr == f"{_TTY_ERROR}\n"
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before


@pytest.mark.integration
def test_zero_summary_and_decline_commit_nothing(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.decline")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _allow_tty(monkeypatch)
    commits = _count_commits(monkeypatch)

    result = _invoke(username, input="n\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == _summary(username, 0, 0, 0) + f"{_PROMPT}n\nAborted.\n"
    assert result.stderr == ""
    assert factory.calls == 1
    assert commits["n"] == 0
    assert asyncio.run(_fetch_user(cli_session_factory, user.id)).active is True


# ---------------------------------------------------------------------------
# Integration: confirmed deactivation
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_confirmed_deactivation_applies_every_effect_and_purges_after_commit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    ticket_ids: list[UUID],
    redis_client: redis_asyncio.Redis,
) -> None:
    """Behavior steps 6 and 10-12: the summary renders the preview counts
    (no grant or maintainership line though both rows exist), the action
    runs in a second session with the CLI reason and a NULL actor, commits
    once, and the purge receives exactly the invalidated Session IDs after
    the commit."""
    username = _username("alice.deactivate")
    granter = _username("bob.granter")
    cleanup_users_by_username(username, granter)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    granter_user = asyncio.run(_create_user(cli_session_factory, username=granter))
    key_ids, session_ids = asyncio.run(
        _add_keys_and_sessions(
            cli_session_factory, user.id, keys=2, sessions=2, revoked_by=granter_user.id
        )
    )
    active_tickets = [
        asyncio.run(
            _create_ticket(
                cli_session_factory, ticket_ids, status=status, assignee_id=user.id
            )
        )
        for status in (TicketStatus.NEW, TicketStatus.ANALYSIS, TicketStatus.ANALYZED)
    ]
    resolved = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.RESOLVED,
            assignee_id=user.id,
        )
    )
    asyncio.run(
        _add_grant_and_maintainer(
            cli_session_factory, ticket_ids, user_id=user.id, granted_by=granter_user.id
        )
    )
    redis_url = redis_url_from_client(redis_client)
    unrelated_key = _liveness_key(uuid4())
    liveness_keys = [_liveness_key(sid) for sid in session_ids]
    asyncio.run(_redis_set(redis_url, [*liveness_keys, unrelated_key]))

    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    _allow_tty(monkeypatch)
    original_purge = session_service.purge_session_cache
    purges: list[tuple[list[UUID], bool]] = []

    async def _observing_purge(ids: list[UUID]) -> None:
        committed = await _fetch_user(cli_session_factory, user.id)
        purges.append((sorted(ids), committed.active))
        await original_purge(ids)

    monkeypatch.setattr(session_service, "purge_session_cache", _observing_purge)
    commits = _count_commits(monkeypatch)

    result = _invoke(username, input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == (
        _summary(username, 2, 2, 3) + f"{_PROMPT}y\n" + _deactivated(username)
    )
    assert result.stderr == ""
    assert factory.calls == 2
    assert commits["n"] == 1
    assert purges == [(sorted(session_ids), False)]
    assert asyncio.run(_redis_existing(redis_url, [*liveness_keys, unrelated_key])) == [
        unrelated_key
    ]

    state = asyncio.run(_state(cli_session_factory, user.id))
    assert state.active is False
    revoked = {key_id: (at, by) for key_id, at, by in state.keys}
    for key_id in key_ids:
        assert revoked[key_id][0] is not None
        assert revoked[key_id][1] is None
    assert all(not is_active for _, is_active in state.sessions)
    assert state.tickets == [(resolved, user.id, TicketStatus.RESOLVED.value)]
    assert state.grant is not None
    assert state.maintainer is not None

    ticket_events = asyncio.run(_fetch_ticket_events(cli_session_factory, ticket_ids))
    assert sorted(
        (e.ticket_id, e.event_type, e.user_id, e.old_value, e.new_value, e.comment)
        for e in ticket_events
    ) == sorted(
        (
            ticket_id,
            "assignment",
            None,
            username,
            None,
            f"Unassigned from {username}: user deactivated",
        )
        for ticket_id in active_tickets
    )

    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    revoked_event = IdentityAuditEventType.API_KEY_REVOKED.value
    revocations = [e for e in events if e.event_type == revoked_event]
    assert sorted(e.detail["key_id"] for e in revocations if e.detail) == sorted(
        str(key_id) for key_id in key_ids
    )
    assert all(e.user_id is None for e in revocations)
    lifecycle = [e for e in events if e.event_type != revoked_event]
    assert [
        (e.event_type, e.user_id, e.old_value, e.new_value, e.detail) for e in lifecycle
    ] == [
        (
            IdentityAuditEventType.USER_DEACTIVATED.value,
            None,
            "active",
            "inactive",
            {"reason": _REASON},
        )
    ]


@pytest.mark.integration
def test_stale_preview_with_concurrent_deactivation_reports_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """Another caller deactivates the target between the preview and the
    action: the result's `deactivated = false` drives the no-op message and
    no duplicate event is created."""
    username = _username("alice.stale")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    original_deactivate = user_service_module.deactivate_user

    async def _concurrent_deactivation_then_delegate(
        *args: Any, **kwargs: Any
    ) -> DeactivationResult:
        async with cli_session_factory() as other:
            await original_deactivate(
                other, user.id, acting_user_id=None, reason="fictional offboarding"
            )
            await other.commit()
        return await original_deactivate(*args, **kwargs)

    monkeypatch.setattr(
        user_service_module, "deactivate_user", _concurrent_deactivation_then_delegate
    )

    result = _invoke(username, input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout == (
        _summary(username, 0, 0, 0) + f"{_PROMPT}y\n" + _noop(username)
    )
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert [(e.event_type, e.detail) for e in events] == [
        (
            IdentityAuditEventType.USER_DEACTIVATED.value,
            {"reason": "fictional offboarding"},
        )
    ]


# ---------------------------------------------------------------------------
# Integration: interruption, Redis failure, and the sync boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_interruption_before_commit_rolls_back_every_effect(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    ticket_ids: list[UUID],
) -> None:
    username = _username("alice.intbefore")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    asyncio.run(
        _add_keys_and_sessions(cli_session_factory, user.id, keys=2, sessions=1)
    )
    ticket_id = asyncio.run(
        _create_ticket(
            cli_session_factory,
            ticket_ids,
            status=TicketStatus.ANALYSIS,
            assignee_id=user.id,
        )
    )
    before = _snapshot(cli_session_factory, user.id)
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    monkeypatch.setattr(
        user_service_module,
        "deactivate_user",
        _interrupt_after(user_service_module.deactivate_user),
    )
    purge = AsyncMock()
    monkeypatch.setattr(session_service, "purge_session_cache", purge)

    _invoke_interrupted(username)

    assert _snapshot(cli_session_factory, user.id) == before
    assert asyncio.run(_fetch_ticket_events(cli_session_factory, [ticket_id])) == []
    purge.assert_not_awaited()


@pytest.mark.integration
def test_interruption_after_commit_is_durable_and_rerun_is_noop(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    """An interruption during the post-commit purge omits the success
    message; the deactivation stays committed and a repeated invocation
    prints the preview's no-op."""
    username = _username("alice.intafter")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    asyncio.run(
        _add_keys_and_sessions(cli_session_factory, user.id, keys=1, sessions=1)
    )
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    monkeypatch.setattr(
        session_service, "purge_session_cache", AsyncMock(side_effect=KeyboardInterrupt)
    )

    _invoke_interrupted(username)

    state = asyncio.run(_state(cli_session_factory, user.id))
    assert state.active is False
    assert [is_active for _, is_active in state.sessions] == [False]
    events = asyncio.run(_fetch_identity_events(cli_session_factory, user.id))
    assert [e.event_type for e in events] == [
        IdentityAuditEventType.API_KEY_REVOKED.value,
        IdentityAuditEventType.USER_DEACTIVATED.value,
    ]

    _forbid(monkeypatch, "is_interactive_terminal", "confirm")
    again = _invoke(username)

    assert again.exit_code == 0, again.output
    assert again.stdout == _noop(username)
    assert len(asyncio.run(_fetch_identity_events(cli_session_factory, user.id))) == 2


@pytest.mark.integration
def test_redis_purge_failure_keeps_success_message_and_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
) -> None:
    username = _username("alice.redisfail")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    asyncio.run(
        _add_keys_and_sessions(cli_session_factory, user.id, keys=0, sessions=2)
    )
    _inject_session_factory(monkeypatch, cli_session_factory)
    _allow_tty(monkeypatch)
    failing = MagicMock(side_effect=_FailingRedisClient)
    monkeypatch.setattr(session_service, "_new_redis_client", failing)

    result = _invoke(username, input="y\n")

    assert result.exit_code == 0, result.output
    assert result.stdout.endswith(f"{_PROMPT}y\n" + _deactivated(username))
    # Only the purge's own outage warning log may reach stderr.
    assert "Error" not in result.stderr
    assert failing.call_count == 1
    assert asyncio.run(_fetch_user(cli_session_factory, user.id)).active is False


@pytest.mark.integration
@pytest.mark.parametrize(
    ("setup", "answer", "expected_exit"),
    [
        pytest.param("active", "y", 0, id="success"),
        pytest.param("inactive", None, 0, id="noop"),
        pytest.param("missing", None, 1, id="not-found"),
    ],
)
def test_exactly_one_asyncio_run_per_invocation(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    setup: str,
    answer: str | None,
    expected_exit: int,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    username = _username("alice.asyncrun")
    cleanup_users_by_username(username)
    if setup != "missing":
        asyncio.run(
            _create_user(
                cli_session_factory,
                username=username,
                active=setup != "inactive",
            )
        )
    _allow_tty(monkeypatch)
    run_spy = _spy_asyncio_run(monkeypatch)

    result = _invoke(username, input=f"{answer}\n" if answer else None)

    assert result.exit_code == expected_exit, result.output
    assert run_spy.call_count == 1


# ---------------------------------------------------------------------------
# Integration through `main()`: terminal input encoding and signals
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("errors", ["strict", "surrogateescape"])
def test_repeated_invalid_utf8_answers_then_eof_abort_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    errors: str,
) -> None:
    """Each invalid answer re-prompts with the retry feedback, without
    echoing, logging, or mapping it; EOF ends with the mapper's
    `Aborted.` and exit 0."""
    username = _username("alice.badbytes")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)
    mapper_logger = MagicMock()
    monkeypatch.setattr(cli_package, "logger", mapper_logger)

    code = _run_main_at_terminal(
        monkeypatch, username, b"\xe9\n", b"y\xe9s\n", errors=errors
    )

    assert code == 0
    captured = capsys.readouterr()
    assert captured.out == (
        _summary(username, 0, 0, 0)
        + f"{_PROMPT}{_RETRY_FEEDBACK}" * 2
        + _PROMPT
        + "Aborted.\n"
    )
    assert captured.err == ""
    mapper_logger.error.assert_not_called()
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before


@pytest.mark.integration
@pytest.mark.parametrize(
    ("signum", "expected_exit"),
    [(signal.SIGINT, 130), (signal.SIGTERM, 143)],
    ids=["SIGINT", "SIGTERM"],
)
def test_signal_at_prompt_exits_with_documented_code_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_users_by_username: Callable[..., None],
    signum: signal.Signals,
    expected_exit: int,
) -> None:
    """The handlers installed by `main()` turn the signal raised while the
    prompt waits into exit 130/143 (cli-infrastructure.md, Signal
    Handling); nothing was opened for mutation, so nothing persists."""
    username = _username("alice.signal")
    cleanup_users_by_username(username)
    user = asyncio.run(_create_user(cli_session_factory, username=username))
    asyncio.run(
        _add_keys_and_sessions(cli_session_factory, user.id, keys=1, sessions=1)
    )
    before = _snapshot(cli_session_factory, user.id)
    factory = _CountingSessionFactory(cli_session_factory)
    _inject_session_factory(monkeypatch, factory)

    code = _run_main_at_terminal(monkeypatch, username, signum)

    assert code == expected_exit
    captured = capsys.readouterr()
    assert captured.out == _summary(username, 1, 1, 0) + _PROMPT
    assert "Aborted." not in captured.out
    assert factory.calls == 1
    assert _snapshot(cli_session_factory, user.id) == before
