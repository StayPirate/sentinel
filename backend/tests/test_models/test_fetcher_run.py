"""Integration tests for the FetcherRun model
(backend/app/models/fetcher_run.py).

See docs/data-model.md (FetcherRun) and
docs/features/platform/fetcher-infrastructure.md (Data Model —
FetcherRun) for the full specification.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.models.user import User


@pytest.mark.integration
class TestFetcherRunCreation:
    async def test_create_with_defaults(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory()

        assert run.id is not None
        assert run.fetcher_name is not None
        assert run.started_at is not None
        assert run.finished_at is None
        assert run.duration_seconds is None
        assert run.status == "running"
        assert run.items_succeeded == 0
        assert run.items_created == 0
        assert run.items_updated == 0
        assert run.items_failed == 0
        assert run.error_message is None
        assert run.error_detail is None
        assert run.error_traceback is None
        assert run.triggered_by == "schedule"
        assert run.triggered_by_user_id is None
        assert run.cursor is None
        assert run.created_at is not None

    async def test_create_a_finalized_manual_run(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        started = datetime.now(UTC)
        run = await fetcher_run_factory(
            started_at=started,
            finished_at=started,
            duration_seconds=12.5,
            status="success",
            items_created=3,
            items_updated=1,
            items_failed=0,
            triggered_by="manual",
            triggered_by_user_id=admin.id,
            cursor={"sha": "abc123", "committed_at": "2026-01-01T00:00:00Z"},
        )
        await db_session.refresh(run)

        assert run.status == "success"
        assert run.items_created == 3
        assert run.triggered_by == "manual"
        assert run.triggered_by_user_id == admin.id
        assert run.cursor == {"sha": "abc123", "committed_at": "2026-01-01T00:00:00Z"}

    async def test_create_a_failed_run_with_error_fields(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(
            status="failure",
            error_message="Connection to NVD timed out",
            error_detail="httpx.ConnectTimeout: timed out",
            error_traceback="Traceback (most recent call last): ...",
        )

        assert run.status == "failure"
        assert run.error_message == "Connection to NVD timed out"
        assert run.error_detail == "httpx.ConnectTimeout: timed out"
        assert run.error_traceback == "Traceback (most recent call last): ..."


@pytest.mark.unit
class TestFetcherRunMetadata:
    """Structural assertions over SQLAlchemy metadata, independent of
    any database round-trip."""

    def test_no_updated_at_column(self) -> None:
        """FetcherRun has no `updated_at` — the `queued -> running`
        adoption transition and finalization are the only in-place
        updates, and both are fully captured by
        `started_at`/`finished_at` (docs/data-model.md, Notes)."""
        assert not hasattr(FetcherRun, "updated_at")

    def test_started_at_column_is_nullable(self) -> None:
        """`started_at` is `NULL` while `status = queued` (see
        `docs/features/platform/fetcher-infrastructure.md`, Concurrency
        Control)."""
        column = FetcherRun.__table__.columns["started_at"]
        assert column.nullable is True

    def test_id_is_uuid_primary_key(self) -> None:
        table = Base.metadata.tables["fetcher_run"]
        pk_columns = list(table.primary_key.columns)
        assert len(pk_columns) == 1
        assert pk_columns[0].name == "id"

    def test_fetcher_name_foreign_key_uses_ondelete_restrict(self) -> None:
        fks = [
            fk
            for fk in FetcherRun.__table__.foreign_keys
            if fk.parent.name == "fetcher_name"
        ]
        assert len(fks) == 1
        assert fks[0].ondelete == "RESTRICT"

    def test_triggered_by_user_id_foreign_key_has_no_explicit_ondelete(self) -> None:
        """The approved data model documents this FK without a delete
        behavior, unlike fetcher_name and the audit actor FK, which
        explicitly require RESTRICT — PostgreSQL's default NO ACTION
        already protects the row."""
        fks = [
            fk
            for fk in FetcherRun.__table__.foreign_keys
            if fk.parent.name == "triggered_by_user_id"
        ]
        assert len(fks) == 1
        assert fks[0].ondelete is None

    def test_status_column_is_not_nullable(self) -> None:
        column = FetcherRun.__table__.columns["status"]
        assert column.nullable is False

    @pytest.mark.parametrize(
        "column_name",
        ["items_succeeded", "items_created", "items_updated", "items_failed"],
    )
    def test_item_counter_columns_are_not_nullable_with_server_default(
        self, column_name: str
    ) -> None:
        """All four item counters are `INTEGER NOT NULL DEFAULT 0`
        (docs/data-model.md, FetcherRun, and
        docs/features/platform/fetcher-infrastructure.md, Data Model —
        FetcherRun)."""
        column = FetcherRun.__table__.columns[column_name]
        assert column.nullable is False
        assert column.server_default is not None
        assert str(column.server_default.arg) == "0"

    def test_triggered_by_user_id_column_is_nullable(self) -> None:
        column = FetcherRun.__table__.columns["triggered_by_user_id"]
        assert column.nullable is True

    def test_finished_at_column_is_nullable(self) -> None:
        column = FetcherRun.__table__.columns["finished_at"]
        assert column.nullable is True


@pytest.mark.integration
class TestFetcherRunNotNullConstraints:
    async def test_missing_fetcher_name_rejected(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            FetcherRun(
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_missing_started_at_is_accepted_for_queued_run(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        """`started_at` is nullable — a `queued` manual run has not yet
        been adopted by a worker and therefore has no `started_at` (see
        `docs/features/platform/fetcher-infrastructure.md`, Concurrency
        Control)."""
        config = await fetcher_config_factory()
        run = FetcherRun(
            fetcher_name=config.fetcher_name,
            status="queued",
            triggered_by="manual",
        )
        db_session.add(run)
        await db_session.flush()

        assert run.started_at is None

    async def test_missing_status_rejected(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()
        db_session.add(
            FetcherRun(
                fetcher_name=config.fetcher_name,
                started_at=datetime.now(UTC),
                triggered_by="schedule",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_missing_triggered_by_rejected(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()
        db_session.add(
            FetcherRun(
                fetcher_name=config.fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestFetcherRunStatusCheckConstraint:
    async def test_each_valid_status_is_accepted(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        for status in ("queued", "running", "success", "failure", "partial"):
            run = await fetcher_run_factory(status=status)
            assert run.status == status

    async def test_unknown_status_rejected(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()
        db_session.add(
            FetcherRun(
                fetcher_name=config.fetcher_name,
                started_at=datetime.now(UTC),
                status="unknown_status",
                triggered_by="schedule",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestFetcherRunTriggeredByIsUnrestricted:
    """`FetcherRunTriggeredBy` is a Category B classification enum — no
    database CHECK constraint restricts `triggered_by` at this layer
    (validation is a service-layer concern)."""

    async def test_arbitrary_triggered_by_value_is_accepted_at_model_layer(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(triggered_by="not_a_real_value")
        assert run.triggered_by == "not_a_real_value"


@pytest.mark.integration
class TestFetcherRunForeignKeys:
    async def test_nonexistent_fetcher_name_rejected(
        self, db_session: AsyncSession
    ) -> None:
        db_session.add(
            FetcherRun(
                fetcher_name="nonexistent_fetcher",
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()

    async def test_nonexistent_triggered_by_user_id_rejected(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
    ) -> None:
        config = await fetcher_config_factory()
        db_session.add(
            FetcherRun(
                fetcher_name=config.fetcher_name,
                started_at=datetime.now(UTC),
                status="running",
                triggered_by="manual",
                triggered_by_user_id=uuid.uuid4(),
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestFetcherRunNoCascadeOnConfigDeletion:
    """The `fetcher_name` FK uses `ON DELETE RESTRICT`: historical run
    data must never be silently destroyed by deleting the referenced
    `FetcherConfig` row (docs/features/platform/fetcher-infrastructure.md,
    Deregistered Fetcher Lifecycle)."""

    async def test_deleting_referenced_config_raises(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory()
        await fetcher_run_factory(fetcher_name=config.fetcher_name)

        await db_session.delete(config)
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestFetcherRunNoCascadeOnUserDeletion:
    """`triggered_by_user_id` has no explicit `ondelete`, so PostgreSQL's
    default `NO ACTION` applies: deleting the admin who manually
    triggered a run must fail loudly instead of silently destroying or
    altering the historical run record."""

    async def test_deleting_triggered_by_user_raises(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        admin = await user_factory()
        await fetcher_run_factory(triggered_by="manual", triggered_by_user_id=admin.id)

        await db_session.delete(admin)
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestFetcherRunRelationships:
    async def test_config_relationship_resolves(
        self,
        db_session: AsyncSession,
        fetcher_config_factory: Callable[..., Awaitable[FetcherConfig]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        config = await fetcher_config_factory(fetcher_name="sync_epss_scores")
        run = await fetcher_run_factory(fetcher_name=config.fetcher_name)

        await db_session.refresh(run, attribute_names=["config"])

        assert run.config is not None
        assert run.config.fetcher_name == "sync_epss_scores"

    async def test_triggered_by_user_relationship_resolves(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        admin = await user_factory(username="triggeruser")
        run = await fetcher_run_factory(
            triggered_by="manual", triggered_by_user_id=admin.id
        )

        await db_session.refresh(run, attribute_names=["triggered_by_user"])

        assert run.triggered_by_user is not None
        assert run.triggered_by_user.username == "triggeruser"

    async def test_triggered_by_user_relationship_is_none_for_scheduled_run(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(triggered_by="schedule")

        await db_session.refresh(run, attribute_names=["triggered_by_user"])

        assert run.triggered_by_user is None

    def test_triggered_by_user_relationship_is_viewonly(self) -> None:
        mapper = inspect(FetcherRun)
        relationship_property = mapper.relationships["triggered_by_user"]
        assert relationship_property.viewonly is True


@pytest.mark.integration
class TestFetcherRunTimezoneAwareTimestamps:
    async def test_started_at_and_created_at_are_timezone_aware(
        self,
        db_session: AsyncSession,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory()
        await db_session.refresh(run)
        assert run.started_at is not None
        assert run.started_at.tzinfo is not None
        assert run.created_at.tzinfo is not None


@pytest.mark.integration
class TestFetcherRunSchemaIndexes:
    """Verifies the composite indexes declared on `fetcher_run`
    (docs/features/platform/fetcher-infrastructure.md, Data Model —
    FetcherRun, Indexes)."""

    async def test_composite_index_exists_with_expected_columns(
        self, db_session: AsyncSession
    ) -> None:
        conn = await db_session.connection()
        indexes = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes("fetcher_run")
        )
        index_map = {idx["name"]: idx for idx in indexes}
        assert "ix_fetcher_run_fetcher_name_started_at" in index_map
        assert index_map["ix_fetcher_run_fetcher_name_started_at"]["column_names"] == [
            "fetcher_name",
            "started_at",
        ]
        assert "ix_fetcher_run_fetcher_name_created_at" in index_map
        assert index_map["ix_fetcher_run_fetcher_name_created_at"]["column_names"] == [
            "fetcher_name",
            "created_at",
        ]


@pytest.mark.integration
class TestFetcherRunFactoryFixture:
    """Sanity checks for the shared fetcher_run_factory fixture."""

    async def test_multiple_calls_do_not_collide(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        first = await fetcher_run_factory()
        second = await fetcher_run_factory()

        assert first.id != second.id

    async def test_overrides_take_precedence(
        self,
        fetcher_run_factory: Callable[..., Awaitable[FetcherRun]],
    ) -> None:
        run = await fetcher_run_factory(status="partial")
        assert run.status == "partial"
