"""Integration tests for the CVEKEVEntry model
(backend/app/models/cve_kev_entry.py).

See docs/data-model.md (CVEKEVEntry) and
docs/features/tickets/cve-service.md (Child Persistence Matrix, KEV status
derivation). Only the persistence contract is covered here; additive
ingestion and the derived KEV source status are CVE service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.cve_kev_entry import CVEKEVEntry

CVEFactory = Callable[..., Awaitable[CVE]]
KEVFactory = Callable[..., Awaitable[CVEKEVEntry]]


async def _count_rows(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(CVEKEVEntry)
        .where(CVEKEVEntry.cve_id == cve_id)
    )
    return result.scalar_one()


@pytest.mark.integration
class TestCVEKEVEntryCreation:
    async def test_create_with_defaults(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        row = await cve_kev_entry_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.date_added == date(2099, 1, 15)
        assert row.reference_url is None
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_create_with_every_column(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        url = "https://kev.example.gov/catalog/CVE-2099-10001"
        row = await cve_kev_entry_factory(
            date_added=date(2099, 2, 28), reference_url=url
        )
        row_id = row.id
        db_session.expunge_all()

        reloaded = await db_session.get(CVEKEVEntry, row_id)
        assert reloaded is not None
        assert reloaded.date_added == date(2099, 2, 28)
        assert type(reloaded.date_added) is date
        assert reloaded.reference_url == url

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        cve = await cve_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO cve_kev_entry (cve_id, date_added) "
                "VALUES (:cve_id, DATE '2099-01-15') "
                "RETURNING id, created_at, updated_at"
            ),
            {"cve_id": cve.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None
        assert row.updated_at == row.created_at


@pytest.mark.integration
class TestCVEKEVEntryUniqueConstraint:
    """UNIQUE `cve_id`: one KEV entry per CVE."""

    async def test_second_entry_for_same_cve_rejected(
        self, cve_factory: CVEFactory, cve_kev_entry_factory: KEVFactory
    ) -> None:
        cve = await cve_factory()
        await cve_kev_entry_factory(cve_id=cve.id)
        with pytest.raises(IntegrityError, match="cve_kev_entry_cve_id_key"):
            await cve_kev_entry_factory(cve_id=cve.id, date_added=date(2099, 3, 1))

    async def test_entries_for_different_cves_accepted(
        self, cve_kev_entry_factory: KEVFactory
    ) -> None:
        first = await cve_kev_entry_factory()
        second = await cve_kev_entry_factory()
        assert first.cve_id != second.cve_id


@pytest.mark.integration
class TestCVEKEVEntryNotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["cve_id", "date_added", "created_at", "updated_at"]
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, cve_factory: CVEFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        cve = await cve_factory()
        values: dict[str, object] = {
            "cve_id": cve.id,
            "date_added": date(2099, 1, 15),
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CVEKEVEntry).values(values))


@pytest.mark.integration
class TestCVEKEVEntryForeignKey:
    async def test_nonexistent_cve_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CVEKEVEntry(cve_id=uuid.uuid7(), date_added=date(2099, 1, 15)))
        with pytest.raises(IntegrityError, match="cve_kev_entry_cve_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = CVEKEVEntry.__table__.c.cve_id.foreign_keys
        assert fk.target_fullname == "cve.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestCVEKEVEntryCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md, CVEKEVEntry)."""

    async def test_database_delete_cascades(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        row = await cve_kev_entry_factory()
        other = await cve_kev_entry_factory()
        cve_id = row.cve_id
        db_session.expunge_all()

        await db_session.execute(delete(CVE).where(CVE.id == cve_id))

        assert await _count_rows(db_session, cve_id) == 0
        assert await _count_rows(db_session, other.cve_id) == 1

    async def test_orm_delete_with_loaded_child_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_kev_entry_factory: KEVFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_kev_entry_factory(cve_id=cve.id)
        cve_id = cve.id
        await db_session.refresh(cve, ["kev_entry"])
        assert cve.kev_entry is not None

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_child_cascades(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        row = await cve_kev_entry_factory()
        cve_id = row.cve_id
        db_session.expunge_all()
        reloaded = await db_session.get(CVE, cve_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVEKEVEntryRelationships:
    async def test_cve_kev_entry_round_trip(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_kev_entry_factory: KEVFactory,
    ) -> None:
        cve = await cve_factory()
        await db_session.refresh(cve, ["kev_entry"])
        assert cve.kev_entry is None

        row = await cve_kev_entry_factory(cve_id=cve.id)
        await db_session.refresh(cve, ["kev_entry"])
        assert cve.kev_entry is not None
        assert cve.kev_entry.id == row.id

        await db_session.refresh(row, ["cve"])
        assert row.cve.id == cve.id


@pytest.mark.integration
class TestCVEKEVEntryTimestamps:
    """`updated_at` is the completed `fetched_at` of the derived `kev`
    source status (docs/data-model.md, CVEKEVEntry), so `onupdate` must
    advance it on every effective change."""

    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        row = await cve_kev_entry_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_kev_entry_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.reference_url = "https://kev.example.gov/catalog/updated"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, cve_kev_entry_factory: KEVFactory
    ) -> None:
        row = await cve_kev_entry_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.created_at = backdated
        await db_session.flush()

        row.reference_url = "https://kev.example.gov/catalog/updated"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.created_at == backdated
