"""Integration tests for the CVESource model
(backend/app/models/cve_source.py).

See docs/data-model.md (CVESource, CVESourceFetchStatus Enum,
CVESourceType Python Enum) and docs/features/tickets/cve-service.md
(CVESource Management) for the full specification. These tests exercise
the raw persistence contract; `record_source_status()` write semantics
belong to the CVE service tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceFetchStatus, CVESourceType
from app.models.cve import CVE
from app.models.cve_source import CVESource


async def _count_sources(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        text("SELECT count(*) FROM cve_source WHERE cve_id = :cve_id"),
        {"cve_id": cve_id},
    )
    return int(result.scalar_one())


@pytest.mark.integration
class TestCVESourceCreation:
    async def test_create_with_defaults(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        row = await cve_source_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.status == "success"
        assert row.fetched_at is not None
        assert row.first_failed_at is None
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_create_failure_with_first_failed_at(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        instant = datetime(2099, 5, 6, 7, 8, 9, tzinfo=UTC)
        row = await cve_source_factory(
            source=CVESourceType.NVD.value,
            status=CVESourceFetchStatus.FAILURE.value,
            fetched_at=instant,
            first_failed_at=instant,
        )
        await db_session.refresh(row)

        assert row.source == "nvd"
        assert row.status == "failure"
        assert row.fetched_at == instant
        assert row.first_failed_at == instant


@pytest.mark.integration
class TestCVESourceClassificationColumns:
    """`source` and `status` are Category B: every enum value is stored
    as-is and the database accepts arbitrary strings (docs/data-model.md,
    CVESource)."""

    @pytest.mark.parametrize("source", list(CVESourceType), ids=lambda s: s.name)
    async def test_every_source_type_value_accepted(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
        source: CVESourceType,
    ) -> None:
        row = await cve_source_factory(source=source.value)
        await db_session.refresh(row)
        assert row.source == source.value

    @pytest.mark.parametrize("status", list(CVESourceFetchStatus), ids=lambda s: s.name)
    async def test_every_fetch_status_value_accepted(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
        status: CVESourceFetchStatus,
    ) -> None:
        row = await cve_source_factory(status=status.value)
        await db_session.refresh(row)
        assert row.status == status.value

    async def test_arbitrary_values_accepted_at_model_layer(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        """A deregistered source label and an unknown status persist: no
        CHECK constraint restricts either column."""
        row = await cve_source_factory(source="deregistered_source", status="stalled")
        await db_session.refresh(row)
        assert row.source == "deregistered_source"
        assert row.status == "stalled"


@pytest.mark.integration
class TestCVESourceUniqueConstraint:
    async def test_duplicate_cve_id_and_source_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        await cve_source_factory(cve_id=cve.id, source=CVESourceType.NVD.value)
        with pytest.raises(IntegrityError, match="uq_cve_source_cve_id_source"):
            await cve_source_factory(cve_id=cve.id, source=CVESourceType.NVD.value)

    async def test_same_source_for_different_cves_accepted(
        self,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        first = await cve_source_factory(
            cve_id=(await cve_factory()).id, source=CVESourceType.NVD.value
        )
        second = await cve_source_factory(
            cve_id=(await cve_factory()).id, source=CVESourceType.NVD.value
        )
        assert first.id != second.id

    async def test_different_sources_for_same_cve_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        await cve_source_factory(cve_id=cve.id, source=CVESourceType.NVD.value)
        await cve_source_factory(cve_id=cve.id, source=CVESourceType.MITRE.value)
        assert await _count_sources(db_session, cve.id) == 2


@pytest.mark.integration
class TestCVESourceNotNullConstraints:
    @pytest.mark.parametrize("column", ["cve_id", "source", "status", "fetched_at"])
    async def test_missing_required_column_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        column: str,
    ) -> None:
        values: dict[str, object] = {
            "cve_id": (await cve_factory()).id,
            "source": CVESourceType.NVD.value,
            "status": CVESourceFetchStatus.SUCCESS.value,
            "fetched_at": datetime.now(UTC),
        }
        del values[column]
        db_session.add(CVESource(**values))
        with pytest.raises(IntegrityError):
            await db_session.flush()

    @pytest.mark.parametrize("column", ["created_at", "updated_at"])
    async def test_explicit_null_timestamp_rejected(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
        column: str,
    ) -> None:
        row = await cve_source_factory()
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text(f"UPDATE cve_source SET {column} = NULL WHERE id = :id"),
                {"id": row.id},
            )


@pytest.mark.integration
class TestCVESourceForeignKey:
    async def test_nonexistent_cve_id_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            CVESource(
                cve_id=uuid.uuid4(),
                source=CVESourceType.NVD.value,
                status=CVESourceFetchStatus.SUCCESS.value,
                fetched_at=datetime.now(UTC),
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestCVESourceCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md, CVESource)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        await cve_source_factory(cve_id=cve.id)
        await cve_source_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()

        await db_session.execute(text("DELETE FROM cve WHERE id = :id"), {"id": cve_id})

        assert await _count_sources(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        await cve_source_factory(cve_id=cve.id)
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_sources(db_session, cve_id) == 0

    async def test_orm_delete_with_loaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        await cve_source_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["sources"])
        assert len(cve.sources) == 1
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_sources(db_session, cve_id) == 0

    async def test_other_cves_sources_untouched(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        deleted = await cve_factory()
        kept = await cve_factory()
        await cve_source_factory(cve_id=deleted.id)
        await cve_source_factory(cve_id=kept.id)

        await db_session.delete(deleted)
        await db_session.flush()

        assert await _count_sources(db_session, kept.id) == 1


@pytest.mark.integration
class TestCVESourceRelationships:
    async def test_source_cve_relationship(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        row = await cve_source_factory()
        await db_session.refresh(row, attribute_names=["cve"])
        assert row.cve.id == row.cve_id

    async def test_cve_sources_relationship(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        cve = await cve_factory()
        first = await cve_source_factory(cve_id=cve.id)
        second = await cve_source_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["sources"])

        assert {row.id for row in cve.sources} == {first.id, second.id}

    async def test_child_added_through_collection_persists(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory()
        await db_session.refresh(cve, attribute_names=["sources"])
        cve.sources.append(
            CVESource(
                source=CVESourceType.OSV.value,
                status=CVESourceFetchStatus.MISSING.value,
                fetched_at=datetime.now(UTC),
            )
        )
        await db_session.flush()

        count = await db_session.scalar(
            select(func.count())
            .select_from(CVESource)
            .where(CVESource.cve_id == cve.id)
        )
        assert count == 1


@pytest.mark.integration
class TestCVESourceTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        row = await cve_source_factory(first_failed_at=datetime.now(UTC))
        await db_session.refresh(row)

        for value in (
            row.fetched_at,
            row.first_failed_at,
            row.created_at,
            row.updated_at,
        ):
            assert value is not None
            assert value.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        cve_source_factory: Callable[..., Awaitable[CVESource]],
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_source_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.status = CVESourceFetchStatus.FAILURE.value
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated
