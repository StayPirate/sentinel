"""Regression tests for database engine construction (app/database.py).

`app/database.py` is excluded from the coverage gate (module-level
side-effecting engine construction — see pyproject.toml), but these
structural assertions guard two real regressions:

1. `DEBUG` must never re-couple to SQLAlchemy's `echo` parameter (see
   docs/features/platform/logging.md, "Relationship with DEBUG").
2. `hide_parameters=True` must remain set so bound SQL parameters
   (which may include credential material) never leak into an
   unhandled `StatementError`'s traceback/message, independent of
   `LOG_LEVEL` (see docs/conventions.md, Secrets and PII Discipline).

Also covers the post-commit callback mechanism (`get_db()`,
`register_post_commit_callback()`) used by API workflows that need a
best-effort side effect (e.g. a Redis cache purge) to run strictly
after the request's transaction commits — see docs/conventions.md
(Transaction Hygiene Rules). A minimal standalone FastAPI app with a
fake session (rather than a real database) isolates the ordering
behavior under test from any real I/O. `detach_post_commit_callbacks()`,
which lets a workflow owner that commits its own session (rather than
`get_db()`) take the registered callbacks and run them itself after its
commit and session close (docs/conventions.md, Caller-Owned Service
Transactions), is covered on the same fake session.

Also covers the `scope="function"` requirement itself
(docs/conventions.md, API Transaction Dependency Scope): the tests
above and `httpx.ASGITransport` both wait for the entire ASGI
application coroutine to finish (including a `yield` dependency's
post-yield teardown) before handing control back to the test, so they
cannot observe whether a real ASGI server would have already
transmitted the response to the client at that point — which is
exactly the ordering issue-#161 identified. `TestFunctionScopeOrdering`
below drives the app via the raw ASGI protocol with a custom `send`
callable instead, recording the exact interleaving of `get_db()`'s
commit and the `http.response.start`/`http.response.body` messages —
the same signal a real ASGI server (uvicorn) would act on.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Callable, MutableMapping
from typing import Annotated, Any, cast

import pytest
from fastapi import Depends, FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import database
from app.database import (
    detach_post_commit_callbacks,
    engine,
    get_db,
    register_post_commit_callback,
)


class _FakeSession:
    """Minimal double standing in for `AsyncSession`: only the surface
    `get_db()` touches (`commit`, `rollback`, `info`)."""

    def __init__(self, order: list[str]) -> None:
        self._order = order
        self.info: dict[str, Any] = {}

    async def commit(self) -> None:
        self._order.append("commit")

    async def rollback(self) -> None:
        self._order.append("rollback")


class _FakeSessionCM:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


_Db = Annotated[Any, Depends(get_db)]


def _build_app(order: list[str]) -> FastAPI:
    """A minimal FastAPI app wired only with the real `get_db`."""
    app = FastAPI()

    @app.get("/ok")
    async def ok_endpoint(db: _Db, fail: bool = False) -> dict[str, bool]:
        if fail:
            raise HTTPException(status_code=500, detail="boom")
        return {"ok": True}

    @app.get("/with-callback")
    async def with_callback_endpoint(db: _Db) -> dict[str, bool]:
        async def _callback() -> None:
            order.append("callback")

        register_post_commit_callback(db, _callback)
        return {"ok": True}

    @app.get("/with-failing-callback")
    async def with_failing_callback_endpoint(db: _Db) -> dict[str, bool]:
        async def _callback() -> None:
            raise RuntimeError("callback boom")

        register_post_commit_callback(db, _callback)
        return {"ok": True}

    @app.get("/with-multiple-callbacks")
    async def with_multiple_callbacks_endpoint(db: _Db) -> dict[str, bool]:
        async def _first() -> None:
            order.append("first")

        async def _second() -> None:
            order.append("second")

        register_post_commit_callback(db, _first)
        register_post_commit_callback(db, _second)
        return {"ok": True}

    @app.get("/with-failing-then-ok-callback")
    async def with_failing_then_ok_callback_endpoint(db: _Db) -> dict[str, bool]:
        async def _failing() -> None:
            raise RuntimeError("callback boom")

        async def _second() -> None:
            order.append("second")

        register_post_commit_callback(db, _failing)
        register_post_commit_callback(db, _second)
        return {"ok": True}

    @app.get("/failing-with-callback")
    async def failing_with_callback_endpoint(db: _Db) -> dict[str, bool]:
        async def _callback() -> None:
            order.append("callback")

        register_post_commit_callback(db, _callback)
        raise HTTPException(status_code=500, detail="boom")

    return app


@pytest.mark.unit
class TestEngineConstruction:
    """Structural regression guards on the module-level `engine`."""

    def test_hide_parameters_is_enabled(self) -> None:
        """Bound SQL parameters must never leak via exception messages,
        regardless of LOG_LEVEL — see security discipline in
        docs/conventions.md."""
        assert engine.sync_engine.hide_parameters is True

    def test_echo_is_not_enabled_by_default(self) -> None:
        """DEBUG must not control SQLAlchemy echo; echo must remain
        unset (falsy) regardless of the DEBUG setting."""
        assert not engine.sync_engine.echo


@pytest.fixture
def order() -> list[str]:
    return []


@pytest.fixture
def fake_session_factory(
    order: list[str], monkeypatch: pytest.MonkeyPatch
) -> Callable[[], _FakeSessionCM]:
    session = _FakeSession(order)

    def factory() -> _FakeSessionCM:
        return _FakeSessionCM(session)

    monkeypatch.setattr(database, "async_session_factory", factory)
    return factory


@pytest.fixture
async def fake_client(
    order: list[str], fake_session_factory: Callable[[], _FakeSessionCM]
) -> AsyncGenerator[AsyncClient]:
    app = _build_app(order)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.unit
class TestPostCommitCallbacks:
    """`get_db()` + `register_post_commit_callback()` ordering contract."""

    async def test_no_callback_registered_just_commits(
        self, fake_client: AsyncClient, order: list[str]
    ) -> None:
        response = await fake_client.get("/ok")
        assert response.status_code == 200
        assert order == ["commit"]

    async def test_callback_runs_after_commit(
        self, fake_client: AsyncClient, order: list[str]
    ) -> None:
        response = await fake_client.get("/with-callback")
        assert response.status_code == 200
        assert order == ["commit", "callback"]

    async def test_multiple_callbacks_all_run_in_order(
        self, fake_client: AsyncClient, order: list[str]
    ) -> None:
        response = await fake_client.get("/with-multiple-callbacks")
        assert response.status_code == 200
        assert order == ["commit", "first", "second"]

    async def test_callback_not_invoked_when_handler_raises(
        self, fake_client: AsyncClient, order: list[str]
    ) -> None:
        response = await fake_client.get("/failing-with-callback")
        assert response.status_code == 500
        assert order == ["rollback"]

    async def test_failing_callback_is_logged_and_swallowed(
        self,
        fake_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level("ERROR"):
            response = await fake_client.get("/with-failing-callback")
        assert response.status_code == 200
        assert "post_commit_callback_failed" in caplog.text

    async def test_failing_callback_does_not_block_next_callback(
        self,
        fake_client: AsyncClient,
        order: list[str],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """One failing callback must not prevent subsequent registered
        callbacks from running — see `register_post_commit_callback()`
        docstring: "each independently caught and logged so one failing
        best-effort side effect never blocks the others."""
        with caplog.at_level("ERROR"):
            response = await fake_client.get("/with-failing-then-ok-callback")
        assert response.status_code == 200
        assert order == ["commit", "second"]
        assert "post_commit_callback_failed" in caplog.text

    async def test_exception_path_still_rolls_back(
        self, fake_client: AsyncClient, order: list[str]
    ) -> None:
        response = await fake_client.get("/ok", params={"fail": "true"})
        assert response.status_code == 500
        assert order == ["rollback"]


@pytest.mark.unit
class TestDetachPostCommitCallbacks:
    """`detach_post_commit_callbacks()` hands the registered callbacks to a
    workflow owner that commits its own session: it returns and removes
    them without running them, so each runs at most once."""

    @staticmethod
    def _session(order: list[str]) -> AsyncSession:
        return cast(AsyncSession, _FakeSession(order))

    async def test_returns_the_callbacks_in_registration_order_and_removes_them(
        self, order: list[str]
    ) -> None:
        session = self._session(order)

        async def _first() -> None:
            order.append("first")

        async def _second() -> None:
            order.append("second")

        register_post_commit_callback(session, _first)
        register_post_commit_callback(session, _second)

        detached = detach_post_commit_callbacks(session)

        assert detached == [_first, _second]
        assert order == []
        assert detach_post_commit_callbacks(session) == []
        for callback in detached:
            await callback()
        assert order == ["first", "second"]

    def test_without_a_registered_callback_returns_an_empty_list(
        self, order: list[str]
    ) -> None:
        session = self._session(order)

        assert detach_post_commit_callbacks(session) == []
        assert detach_post_commit_callbacks(session) == []
        assert order == []


class _FailingCommitFakeSession(_FakeSession):
    """A fake session whose `commit()` always raises — simulates a
    database commit failure (e.g. a constraint violation surfacing only
    at commit time, or a connection loss) after the handler has already
    produced a success value."""

    async def commit(self) -> None:
        self._order.append("commit_attempted")
        raise RuntimeError("commit boom")


# Module-level (not function-local): FastAPI resolves parameter
# annotations via `typing.get_type_hints()` against the endpoint
# function's `__globals__`. With `from __future__ import annotations`
# active in this module, a type alias defined *inside*
# `_build_scope_comparison_app()` would not be a resolvable global,
# causing FastAPI to silently fail to inject `get_db` at all (observed
# as an unrelated 422 response) rather than the intended dependency.
_DbRequestScoped = Annotated[Any, Depends(get_db)]
_DbFunctionScoped = Annotated[Any, Depends(get_db, scope="function")]


def _build_scope_comparison_app(order: list[str]) -> FastAPI:
    """A minimal app exposing the same `get_db` dependency declared
    with each of the two possible scopes, so a single raw-ASGI drive
    can compare their observable ordering directly."""
    app = FastAPI()

    @app.get("/request-scope")
    async def request_scope_endpoint(db: _DbRequestScoped) -> dict[str, bool]:
        return {"ok": True}

    @app.get("/function-scope")
    async def function_scope_endpoint(db: _DbFunctionScoped) -> dict[str, bool]:
        return {"ok": True}

    return app


def _build_function_scope_app_with_callback(order: list[str]) -> FastAPI:
    """A minimal `scope="function"` app whose single endpoint registers
    a post-commit callback — used to prove the callback never runs when
    the commit itself fails (as opposed to `TestPostCommitCallbacks
    .test_callback_not_invoked_when_handler_raises`, which covers the
    handler raising *before* commit is even attempted)."""
    app = FastAPI()

    @app.get("/function-scope-with-callback")
    async def endpoint(db: _DbFunctionScoped) -> dict[str, bool]:
        async def _callback() -> None:
            order.append("callback")

        register_post_commit_callback(db, _callback)
        return {"ok": True}

    return app


async def _drive_raw_asgi(app: FastAPI, path: str, order: list[str]) -> None:
    """Send one GET request to `app` via the raw ASGI protocol.

    Unlike `httpx.ASGITransport` (used by `fake_client` above), which
    awaits the entire ASGI application coroutine — including a `yield`
    dependency's post-yield teardown — before constructing its
    `Response`, this drives the protocol with a bare `send` callable
    that records each ASGI message the instant the application emits
    it. This is the same signal a real ASGI server (uvicorn) acts on:
    it may write `http.response.start`/`http.response.body` to the
    socket as soon as they are sent, independent of whether the
    application coroutine has finished its post-response teardown.
    Any exception that escapes the application (e.g. re-raised by
    Starlette's error-handling wrapper after already having sent an
    error response) is recorded rather than propagated, so the test can
    assert on the full observable sequence.
    """

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: MutableMapping[str, Any]) -> None:
        status = message.get("status")
        suffix = f":{status}" if status is not None else ""
        order.append(f"asgi:{message['type']}{suffix}")

    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "headers": [],
        "query_string": b"",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "scheme": "http",
        "client": ("testclient", 123),
        "server": ("testserver", 80),
        "root_path": "",
    }
    try:
        await app(scope, receive, send)
    except Exception as exc:
        order.append(f"exception:{type(exc).__name__}")


@pytest.mark.unit
class TestFunctionScopeOrdering:
    """The exact regression proven for issue #161: whether `get_db()`'s
    commit (and its failure) completes before or after the response is
    transmitted, as a real ASGI server would observe it — see
    `docs/conventions.md` (API Transaction Dependency Scope).
    """

    async def test_function_scope_commits_before_response_is_sent(
        self, order: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FakeSession(order)
        monkeypatch.setattr(
            database, "async_session_factory", lambda: _FakeSessionCM(session)
        )
        app = _build_scope_comparison_app(order)

        await _drive_raw_asgi(app, "/function-scope", order)

        assert order == [
            "commit",
            "asgi:http.response.start:200",
            "asgi:http.response.body",
        ]

    async def test_request_scope_sends_response_before_commit(
        self, order: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Characterizes the exact bug fixed for issue #161: FastAPI's
        default `scope="request"` for an unscoped `yield` dependency
        sends the response *before* running `get_db()`'s post-yield
        commit. This is why every route dependency that supplies the
        API transaction session must declare `scope="function"`
        explicitly (the `DatabaseSession` alias) instead of relying on
        this default — see `backend/tests/test_api_conventions.py`
        (`TestTransactionDependencyScope`), which enforces that no
        registered production route does.
        """
        session = _FakeSession(order)
        monkeypatch.setattr(
            database, "async_session_factory", lambda: _FakeSessionCM(session)
        )
        app = _build_scope_comparison_app(order)

        await _drive_raw_asgi(app, "/request-scope", order)

        assert order == [
            "asgi:http.response.start:200",
            "asgi:http.response.body",
            "commit",
        ]

    async def test_function_scope_commit_failure_surfaces_as_error_response(
        self, order: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A commit failure must become a real error response, not an
        already-decided success one — see docs/conventions.md
        (Caller-Owned Service Transactions): the dependency "rolls back
        exactly once when an exception escapes ... before the response
        is transmitted to the client."""
        session = _FailingCommitFakeSession(order)
        monkeypatch.setattr(
            database, "async_session_factory", lambda: _FakeSessionCM(session)
        )
        app = _build_scope_comparison_app(order)

        await _drive_raw_asgi(app, "/function-scope", order)

        assert order[0] == "commit_attempted"
        assert "rollback" in order
        response_start = next(
            e for e in order if e.startswith("asgi:http.response.start")
        )
        assert response_start == "asgi:http.response.start:500"

    async def test_request_scope_commit_failure_still_sends_success_response(
        self, order: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Characterizes the dangerous case that motivated issue #161:
        under the default `scope="request"`, a commit failure occurs
        *after* the success response has already been transmitted — the
        client observes 200 even though the transaction was rolled
        back. This is precisely what `scope="function"` prevents (see
        the sibling test above)."""
        session = _FailingCommitFakeSession(order)
        monkeypatch.setattr(
            database, "async_session_factory", lambda: _FakeSessionCM(session)
        )
        app = _build_scope_comparison_app(order)

        await _drive_raw_asgi(app, "/request-scope", order)

        response_start = next(
            e for e in order if e.startswith("asgi:http.response.start")
        )
        assert response_start == "asgi:http.response.start:200"
        assert order.index(response_start) < order.index("commit_attempted")
        assert "rollback" in order


@pytest.mark.unit
class TestCommitFailureWithPostCommitCallback:
    """Proves the interaction between a failed commit and a registered
    post-commit callback: the callback must never execute when the
    commit itself fails (distinct from
    `TestPostCommitCallbacks.test_callback_not_invoked_when_handler_raises`,
    which covers the handler raising *before* commit is even
    attempted), and the rollback must complete before the error
    response is transmitted — the real ASGI ordering `_drive_raw_asgi`
    observes, not merely completion order within the test process.
    """

    async def test_callback_never_runs_after_a_failed_commit(
        self, order: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        session = _FailingCommitFakeSession(order)
        monkeypatch.setattr(
            database, "async_session_factory", lambda: _FakeSessionCM(session)
        )
        app = _build_function_scope_app_with_callback(order)

        await _drive_raw_asgi(app, "/function-scope-with-callback", order)

        assert "callback" not in order
        assert order[0] == "commit_attempted"
        assert "rollback" in order

        response_start = next(
            e for e in order if e.startswith("asgi:http.response.start")
        )
        assert response_start == "asgi:http.response.start:500"
        # Rollback (and the decision to skip the callback) completes
        # strictly before the error response is transmitted.
        assert order.index("rollback") < order.index(response_start)
