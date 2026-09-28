"""HTTP-level tests for the application entry point (`app/main.py`).

Covers the production generic exception handler
(`_unhandled_exception_handler`, registered via
`@app.exception_handler(Exception)`): any exception that escapes route
or dependency code must render as the standard `500 INTERNAL_ERROR`
envelope (`docs/api-spec.md`, Global Responses), never leak the
exception's own message to the client, and be logged at ERROR with the
traceback for operator diagnosis. See issue #185. Also covers the
production `AppError` handler (`_app_error_handler`): the standard
`{"code", "detail"}` envelope plus the top-level fields of
`AppError.extra` (`existing_ticket_id` of `TICKET_CVE_CONFLICT`,
`docs/api-spec.md`, Response Format), with `code` and `detail` always
taken from the exception.

A minimal standalone FastAPI app registers the real, imported handler
function (not a re-implementation) plus one route that deliberately
raises — mirroring the established pattern in
`tests/test_api/test_dependencies.py` (`_build_test_app()`) and
`tests/test_database.py` (`_build_app()`): exercising real
application code through an actual ASGI/HTTP round trip without
mutating the production `app`'s shared route table.

Also covers the FastAPI `lifespan` (system-settings bootstrap ordering
and failure — `docs/features/platform/system-settings.md`, FastAPI
Lifespan Ordering and Failure — and the fetcher config bootstrap added
alongside it — `docs/features/platform/fetcher-infrastructure.md`,
FetcherConfig). These tests call `main_module.lifespan` directly (not
via an ASGI round trip, since `ASGITransport` does not invoke
`lifespan`), with `main_module.async_session_factory` monkeypatched to
`real_session_factory` so the lifespan's own session targets the test
database instead of the production `settings.database_url` connection.
`real_session_factory`-created sessions are not covered by the
per-test savepoint rollback, so every test that leaves a committed row
cleans it up explicitly (see
`docs/features/platform/testing-strategy.md`, Fixture Catalog).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.main as main_module
from app.core.errors import AppError, ErrorCode
from app.main import _app_error_handler, _unhandled_exception_handler
from app.models.fetcher_config import FetcherConfig
from app.models.setting_audit_event import SettingAuditEvent
from app.models.system_setting import SystemSetting
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.settings import get_default_cvss_version

_SENSITIVE_DETAIL = "sensitive: password=hunter2 host=db.internal.example"
_DEFAULT_KEY = "default_cvss_version"


def _build_test_app() -> FastAPI:
    test_app = FastAPI()
    test_app.add_exception_handler(Exception, _unhandled_exception_handler)

    @test_app.get("/boom")
    async def boom() -> None:
        raise RuntimeError(_SENSITIVE_DETAIL)

    return test_app


@pytest.fixture
async def error_client() -> AsyncGenerator[AsyncClient]:
    # `raise_app_exceptions=False`: Starlette's `ServerErrorMiddleware`
    # always re-raises the original exception after sending the custom
    # handler's response ("This allows servers to log the error, or
    # allows test clients to optionally raise the error within the test
    # case" — see `starlette.middleware.errors`). This test wants the
    # transmitted response, not the propagated exception — exactly the
    # "optional" case that flag controls.
    async with AsyncClient(
        transport=ASGITransport(app=_build_test_app(), raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.unit
class TestUnhandledExceptionHandler:
    """HTTP-level contract for the production generic exception handler."""

    async def test_returns_500_with_the_generic_envelope(
        self, error_client: AsyncClient
    ) -> None:
        response = await error_client.get("/boom")

        assert response.status_code == 500
        assert response.json() == {
            "code": ErrorCode.INTERNAL_ERROR.value,
            "detail": "An unexpected error occurred.",
        }

    async def test_does_not_leak_the_exception_message_to_the_client(
        self, error_client: AsyncClient
    ) -> None:
        response = await error_client.get("/boom")

        assert _SENSITIVE_DETAIL not in response.text

    async def test_logs_the_failure_at_error_level(
        self,
        error_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with caplog.at_level("ERROR"):
            response = await error_client.get("/boom")

        assert response.status_code == 500
        assert "unhandled_exception" in caplog.text

    async def test_logged_record_carries_the_original_traceback(
        self,
        error_client: AsyncClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # `logger.error(..., exc_info=exc)` must attach the real
        # traceback so operators can diagnose the failure — verified by
        # asserting the raised exception's own type and message appear
        # in the captured record (structlog's `format_exc_info`
        # processor renders `exc_info` into the record's text).
        with caplog.at_level("ERROR"):
            await error_client.get("/boom")

        assert "RuntimeError" in caplog.text


def _build_app_error_app() -> FastAPI:
    """A standalone app registering the real `_app_error_handler`."""
    test_app = FastAPI()
    test_app.exception_handler(AppError)(_app_error_handler)

    @test_app.get("/plain")
    async def plain() -> None:
        raise AppError(
            status_code=404, code=ErrorCode.TICKET_NOT_FOUND, detail="Ticket not found."
        )

    @test_app.get("/extra")
    async def extra() -> None:
        raise AppError(
            status_code=409,
            code=ErrorCode.TICKET_CVE_CONFLICT,
            detail="CVE is already associated with another Ticket.",
            headers={"X-Example": "1"},
            extra={"existing_ticket_id": "SNTL-42"},
        )

    @test_app.get("/tampered")
    async def tampered() -> None:
        error = AppError(
            status_code=409, code=ErrorCode.TICKET_CVE_CONFLICT, detail="real detail"
        )
        # Bypasses the constructor guard to prove the handler's own
        # precedence: `code` and `detail` always come from the exception.
        error.extra = {
            "code": "FORGED",
            "detail": "forged detail",
            "existing_ticket_id": "SNTL-7",
        }
        raise error

    return test_app


@pytest.fixture
async def app_error_client() -> AsyncGenerator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=_build_app_error_app()),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.unit
class TestAppErrorHandler:
    """`_app_error_handler` renders the standard envelope and merges the
    contract-defined top-level fields of `AppError.extra`
    (`docs/api-spec.md`, Response Format)."""

    async def test_renders_exactly_code_and_detail_without_extra(
        self, app_error_client: AsyncClient
    ) -> None:
        response = await app_error_client.get("/plain")

        assert response.status_code == 404
        assert response.json() == {
            "code": "TICKET_NOT_FOUND",
            "detail": "Ticket not found.",
        }

    async def test_merges_extra_fields_at_the_top_level(
        self, app_error_client: AsyncClient
    ) -> None:
        response = await app_error_client.get("/extra")

        assert response.status_code == 409
        assert response.json() == {
            "code": "TICKET_CVE_CONFLICT",
            "detail": "CVE is already associated with another Ticket.",
            "existing_ticket_id": "SNTL-42",
        }
        assert response.headers["X-Example"] == "1"

    async def test_code_and_detail_always_come_from_the_exception(
        self, app_error_client: AsyncClient
    ) -> None:
        response = await app_error_client.get("/tampered")

        assert response.status_code == 409
        assert response.json() == {
            "code": "TICKET_CVE_CONFLICT",
            "detail": "real detail",
            "existing_ticket_id": "SNTL-7",
        }


async def _delete_default_cvss_version_setting(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Explicit cleanup for a `default_cvss_version` row committed
    through `real_session_factory` — not covered by the per-test
    savepoint rollback (see module docstring)."""
    async with session_factory() as session:
        await session.execute(
            delete(SystemSetting).where(SystemSetting.key == _DEFAULT_KEY)
        )
        await session.commit()


class _StubBootstrapFetcher:
    """Minimal `FETCHER_REGISTRY` entry stub — exposes only the two
    class attributes `bootstrap_fetcher_configs()` reads."""

    name = "test_lifespan_bootstrap_fetcher"
    default_request_delay = 1.25


@pytest.fixture
def _registered_stub_fetcher() -> Generator[None]:
    """Register `_StubBootstrapFetcher` in `FETCHER_REGISTRY` for the
    duration of a test, restoring the original registry afterward —
    mirrors `tests/test_services/test_base_fetcher.py` (Test
    Independence)."""
    original = dict(FETCHER_REGISTRY)
    FETCHER_REGISTRY[_StubBootstrapFetcher.name] = _StubBootstrapFetcher  # type: ignore[assignment]
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


async def _delete_fetcher_config(
    session_factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> None:
    """Explicit cleanup for a `FetcherConfig` row committed through
    `real_session_factory` — not covered by the per-test savepoint
    rollback (see module docstring)."""
    async with session_factory() as session:
        await session.execute(
            delete(FetcherConfig).where(FetcherConfig.fetcher_name == fetcher_name)
        )
        await session.commit()


@pytest.mark.integration
class TestLifespanBootstrap:
    """Contract under test:
    `docs/features/platform/system-settings.md` (FastAPI Lifespan
    Ordering and Failure) — bootstrap runs before the API begins
    serving requests, self-heals a missing row, preserves an existing
    custom value, and any database/bootstrap/commit failure aborts
    startup by letting the exception escape the lifespan.
    """

    async def test_creates_the_missing_row_before_serving_requests(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        try:
            async with main_module.lifespan(main_module.app):
                pass

            async with real_session_factory() as session:
                assert await get_default_cvss_version(session) == "3.1"
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)

    async def test_preserves_an_existing_custom_value(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        async with real_session_factory() as setup_session:
            setup_session.add(SystemSetting(key=_DEFAULT_KEY, value="4.0"))
            await setup_session.commit()

        try:
            async with main_module.lifespan(main_module.app):
                pass

            async with real_session_factory() as session:
                assert await get_default_cvss_version(session) == "4.0"
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)

    async def test_creates_no_audit_event(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        try:
            async with main_module.lifespan(main_module.app):
                pass

            async with real_session_factory() as session:
                rows = (
                    (await session.execute(select(SettingAuditEvent))).scalars().all()
                )
                assert rows == []
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)

    async def test_bootstrap_failure_propagates_and_aborts_startup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        async def _boom(session: AsyncSession) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(main_module, "bootstrap_system_settings", _boom)

        with pytest.raises(OperationalError):
            async with main_module.lifespan(main_module.app):
                pass

        # No degraded startup: the row was never created because the
        # failure happened before any insert was attempted.
        async with real_session_factory() as session:
            assert await session.get(SystemSetting, _DEFAULT_KEY) is None

    async def test_commit_failure_propagates_and_aborts_startup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        async def _boom_commit(self: AsyncSession) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(AsyncSession, "commit", _boom_commit)

        try:
            with pytest.raises(OperationalError):
                async with main_module.lifespan(main_module.app):
                    pass

            # No degraded startup: the transaction was rolled back, so
            # the flushed-but-uncommitted row never persisted.
            async with real_session_factory() as session:
                assert await session.get(SystemSetting, _DEFAULT_KEY) is None
        finally:
            monkeypatch.undo()
            await _delete_default_cvss_version_setting(real_session_factory)


@pytest.mark.integration
@pytest.mark.usefixtures("_registered_stub_fetcher")
class TestLifespanFetcherConfigBootstrap:
    """Contract under test:
    `docs/features/platform/fetcher-infrastructure.md` (FetcherConfig)
    — the FastAPI lifespan bootstraps `FetcherConfig` rows for every
    registered fetcher in the same transaction as the system-settings
    bootstrap, before the API begins serving requests.
    """

    async def test_creates_a_row_for_each_registered_fetcher(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        try:
            async with main_module.lifespan(main_module.app):
                pass

            async with real_session_factory() as session:
                config = await session.get(FetcherConfig, _StubBootstrapFetcher.name)
                assert config is not None
                assert config.request_delay == 1.25
                assert config.enabled is True
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)
            await _delete_fetcher_config(
                real_session_factory, _StubBootstrapFetcher.name
            )

    async def test_preserves_an_existing_custom_fetcher_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        async with real_session_factory() as setup_session:
            setup_session.add(
                FetcherConfig(
                    fetcher_name=_StubBootstrapFetcher.name,
                    enabled=False,
                    request_delay=9.9,
                )
            )
            await setup_session.commit()

        try:
            async with main_module.lifespan(main_module.app):
                pass

            async with real_session_factory() as session:
                config = await session.get(FetcherConfig, _StubBootstrapFetcher.name)
                assert config is not None
                assert config.enabled is False
                assert config.request_delay == 9.9
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)
            await _delete_fetcher_config(
                real_session_factory, _StubBootstrapFetcher.name
            )

    async def test_fetcher_bootstrap_failure_propagates_and_aborts_startup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        monkeypatch.setattr(main_module, "async_session_factory", real_session_factory)

        async def _boom(session: AsyncSession) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(main_module, "bootstrap_fetcher_configs", _boom)

        try:
            with pytest.raises(OperationalError):
                async with main_module.lifespan(main_module.app):
                    pass

            # No degraded startup: the system-settings bootstrap ran
            # first and flushed within the shared transaction, but the
            # fetcher config bootstrap failure rolled back the entire
            # shared transaction — neither row persists.
            async with real_session_factory() as session:
                assert await session.get(SystemSetting, _DEFAULT_KEY) is None
                assert (
                    await session.get(FetcherConfig, _StubBootstrapFetcher.name) is None
                )
        finally:
            await _delete_default_cvss_version_setting(real_session_factory)
            await _delete_fetcher_config(
                real_session_factory, _StubBootstrapFetcher.name
            )
