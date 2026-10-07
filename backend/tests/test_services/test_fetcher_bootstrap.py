"""Tests for the fetcher config bootstrap service
(backend/app/services/fetcher_bootstrap.py).

See `docs/features/platform/fetcher-infrastructure.md` (Data Model —
FetcherConfig) for the contract under test: the idempotent batch
insert, preservation of administrator-modified rows, the
empty-registry database touch, the "no audit event" guarantee, and the
caller-owned transaction contract (flush without commit/rollback).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Generator
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.services.base_fetcher import FETCHER_REGISTRY
from app.services.fetcher_bootstrap import bootstrap_fetcher_configs


class _StubFetcherOne:
    """Minimal `FETCHER_REGISTRY` entry stub — exposes only the two
    class attributes `bootstrap_fetcher_configs()` reads."""

    name = "test_bootstrap_fetcher_one"
    default_request_delay = 0.5


class _StubFetcherTwo:
    name = "test_bootstrap_fetcher_two"
    default_request_delay = 2.5


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this
    file — mirrors `tests/test_services/test_base_fetcher.py` (Test
    Independence)."""
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


def _register(*stubs: type[Any]) -> None:
    """Replace `FETCHER_REGISTRY` with exactly the given stub classes."""
    FETCHER_REGISTRY.clear()
    for stub in stubs:
        FETCHER_REGISTRY[stub.name] = stub


@pytest.mark.integration
class TestBootstrapFetcherConfigsCreation:
    async def test_creates_a_row_for_each_registered_fetcher(
        self, db_session: AsyncSession
    ) -> None:
        _register(_StubFetcherOne, _StubFetcherTwo)

        await bootstrap_fetcher_configs(db_session)

        one = await db_session.get(FetcherConfig, _StubFetcherOne.name)
        two = await db_session.get(FetcherConfig, _StubFetcherTwo.name)
        assert one is not None
        assert two is not None

    async def test_uses_each_fetchers_own_default_request_delay(
        self, db_session: AsyncSession
    ) -> None:
        _register(_StubFetcherOne, _StubFetcherTwo)

        await bootstrap_fetcher_configs(db_session)

        one = await db_session.get(FetcherConfig, _StubFetcherOne.name)
        two = await db_session.get(FetcherConfig, _StubFetcherTwo.name)
        assert one is not None
        assert one.request_delay == 0.5
        assert two is not None
        assert two.request_delay == 2.5

    async def test_applies_column_defaults_for_every_other_field(
        self, db_session: AsyncSession
    ) -> None:
        _register(_StubFetcherOne)

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(FetcherConfig, _StubFetcherOne.name)
        assert config is not None
        assert config.enabled is True
        assert config.schedule_override is None
        assert config.run_timeout == 3600
        assert config.custom_settings == {}

    async def test_does_not_overwrite_an_existing_config(
        self, db_session: AsyncSession
    ) -> None:
        _register(_StubFetcherOne)
        existing = FetcherConfig(
            fetcher_name=_StubFetcherOne.name,
            enabled=False,
            schedule_override="0 */4 * * *",
            run_timeout=1800,
            request_delay=9.9,
            custom_settings={"custom": True},
        )
        db_session.add(existing)
        await db_session.flush()

        await bootstrap_fetcher_configs(db_session)

        config = await db_session.get(
            FetcherConfig, _StubFetcherOne.name, populate_existing=True
        )
        assert config is not None
        assert config.enabled is False
        assert config.schedule_override == "0 */4 * * *"
        assert config.run_timeout == 1800
        assert config.request_delay == 9.9
        assert config.custom_settings == {"custom": True}

    async def test_subsequent_call_only_creates_newly_registered_fetchers(
        self, db_session: AsyncSession
    ) -> None:
        _register(_StubFetcherOne)
        await bootstrap_fetcher_configs(db_session)
        first = await db_session.get(FetcherConfig, _StubFetcherOne.name)
        assert first is not None
        first.enabled = False
        await db_session.flush()

        _register(_StubFetcherOne, _StubFetcherTwo)
        await bootstrap_fetcher_configs(db_session)

        preserved = await db_session.get(
            FetcherConfig, _StubFetcherOne.name, populate_existing=True
        )
        created = await db_session.get(FetcherConfig, _StubFetcherTwo.name)
        assert preserved is not None
        assert preserved.enabled is False
        assert created is not None


@pytest.mark.integration
class TestBootstrapFetcherConfigsEmptyRegistry:
    """Empty-registry behavior — see fetcher-infrastructure.md, the
    empty-registry clarification added alongside this test module: the
    bootstrap MUST still touch PostgreSQL so a database/schema failure
    is observable at startup regardless of how many fetchers are
    currently registered."""

    async def test_touches_the_database(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FETCHER_REGISTRY.clear()
        execute_spy = AsyncMock(wraps=db_session.execute)
        monkeypatch.setattr(db_session, "execute", execute_spy)

        await bootstrap_fetcher_configs(db_session)

        execute_spy.assert_called_once()

    async def test_creates_no_rows(self, db_session: AsyncSession) -> None:
        FETCHER_REGISTRY.clear()

        await bootstrap_fetcher_configs(db_session)

        rows = (await db_session.execute(select(FetcherConfig))).scalars().all()
        assert rows == []

    async def test_propagates_database_errors(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        FETCHER_REGISTRY.clear()

        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await bootstrap_fetcher_configs(db_session)


@pytest.mark.integration
class TestBootstrapFetcherConfigsAuditEvents:
    async def test_creates_no_audit_event(self, db_session: AsyncSession) -> None:
        _register(_StubFetcherOne)

        await bootstrap_fetcher_configs(db_session)

        rows = (await db_session.execute(select(FetcherAuditEvent))).scalars().all()
        assert rows == []


@pytest.mark.integration
class TestBootstrapFetcherConfigsTransactionContract:
    async def test_does_not_commit(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _register(_StubFetcherOne)
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await bootstrap_fetcher_configs(db_session)

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _register(_StubFetcherOne)
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await bootstrap_fetcher_configs(db_session)

        flush_spy.assert_called_once()

    async def test_database_error_propagates_unchanged(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _register(_StubFetcherOne)

        async def _boom(*args: Any, **kwargs: Any) -> None:
            raise OperationalError("simulated", {}, Exception("boom"))

        monkeypatch.setattr(db_session, "execute", _boom)

        with pytest.raises(OperationalError):
            await bootstrap_fetcher_configs(db_session)


@pytest.mark.integration
class TestBootstrapFetcherConfigsConcurrency:
    async def test_concurrent_invocations_produce_exactly_one_row(
        self,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Two independent sessions bootstrap concurrently for the same
        fetcher name — the `ON CONFLICT DO NOTHING` insert guarantees
        at most one insert succeeds and every caller observes a
        completed insert or conflict before returning, leaving exactly
        one row."""
        _register(_StubFetcherOne)
        session_a = await db_session_factory()
        session_b = await db_session_factory()

        async def _bootstrap_and_commit(session: AsyncSession) -> None:
            await bootstrap_fetcher_configs(session)
            await session.commit()

        try:
            await asyncio.gather(
                _bootstrap_and_commit(session_a), _bootstrap_and_commit(session_b)
            )

            verify_session = await db_session_factory()
            rows = (
                (
                    await verify_session.execute(
                        select(FetcherConfig).where(
                            FetcherConfig.fetcher_name == _StubFetcherOne.name
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 1
        finally:
            # This test commits durable rows; db_session_factory's
            # rollback-on-teardown does not cover committed data (see
            # docs/features/platform/testing-strategy.md, Database
            # Strategy — Concurrency Testing). Cleanup runs even if the
            # assertion above fails, so a regression never leaks a
            # committed row into the shared test database.
            cleanup_session = await db_session_factory()
            await cleanup_session.execute(
                delete(FetcherConfig).where(
                    FetcherConfig.fetcher_name == _StubFetcherOne.name
                )
            )
            await cleanup_session.commit()
