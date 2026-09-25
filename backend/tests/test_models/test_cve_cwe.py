"""Integration tests for the CVECWE model (backend/app/models/cve_cwe.py).

See docs/data-model.md (CVECWE) and docs/features/tickets/cve-service.md
(Child Persistence Matrix). Only the persistence contract is covered here;
additive ingestion is CVE service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.cve_cwe import CVECWE

CVEFactory = Callable[..., Awaitable[CVE]]
CWEFactory = Callable[..., Awaitable[CVECWE]]

# Documented VARCHAR lengths (docs/data-model.md, CVECWE).
_COLUMN_LENGTHS = {"cwe_id": 20, "source": 100}


async def _count_rows(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count()).select_from(CVECWE).where(CVECWE.cve_id == cve_id)
    )
    return result.scalar_one()


@pytest.mark.integration
class TestCVECWECreation:
    async def test_create_with_defaults(
        self, db_session: AsyncSession, cve_cwe_factory: CWEFactory
    ) -> None:
        row = await cve_cwe_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.cwe_id.startswith("CWE-")
        assert row.source == "NVD"
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        cve = await cve_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO cve_cwe (cve_id, cwe_id, source) "
                "VALUES (:cve_id, 'CWE-79', 'NVD') "
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
class TestCVECWEColumnLengths:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self,
        db_session: AsyncSession,
        cve_cwe_factory: CWEFactory,
        column: str,
        length: int,
    ) -> None:
        row = await cve_cwe_factory(**{column: "x" * length})
        await db_session.refresh(row)
        assert len(getattr(row, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self, cve_cwe_factory: CWEFactory, column: str, length: int
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await cve_cwe_factory(**{column: "x" * (length + 1)})


@pytest.mark.integration
class TestCVECWEUniqueConstraint:
    """UNIQUE `(cve_id, cwe_id, source)` (docs/data-model.md, CVECWE)."""

    async def test_duplicate_key_rejected(
        self, cve_factory: CVEFactory, cve_cwe_factory: CWEFactory
    ) -> None:
        cve = await cve_factory()
        await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")
        with pytest.raises(IntegrityError, match="uq_cve_cwe_cve_id_cwe_id_source"):
            await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")

    @pytest.mark.parametrize(
        ("cwe_id", "source", "other_cve"),
        [
            ("CWE-79", "Red Hat", False),
            ("CWE-89", "NVD", False),
            ("CWE-79", "NVD", True),
        ],
        ids=["different-source", "different-cwe", "different-cve"],
    )
    async def test_key_differing_in_one_column_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
        cwe_id: str,
        source: str,
        other_cve: bool,
    ) -> None:
        cve = await cve_factory()
        await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")
        target = (await cve_factory()).id if other_cve else cve.id

        row = await cve_cwe_factory(cve_id=target, cwe_id=cwe_id, source=source)

        assert row.id is not None
        assert await _count_rows(db_session, target) == (1 if other_cve else 2)

    async def test_source_compared_exactly(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
    ) -> None:
        """`source` is a mixed-case provider label; the database compares
        it exactly (docs/data-model.md, CVESource `source` note)."""
        cve = await cve_factory()
        await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")
        await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="nvd")
        assert await _count_rows(db_session, cve.id) == 2


@pytest.mark.integration
class TestCVECWENotNullConstraints:
    @pytest.mark.parametrize(
        "column", ["cve_id", "cwe_id", "source", "created_at", "updated_at"]
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, cve_factory: CVEFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        cve = await cve_factory()
        values: dict[str, object] = {
            "cve_id": cve.id,
            "cwe_id": "CWE-79",
            "source": "NVD",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CVECWE).values(values))


@pytest.mark.integration
class TestCVECWEForeignKey:
    async def test_nonexistent_cve_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CVECWE(cve_id=uuid.uuid7(), cwe_id="CWE-79", source="NVD"))
        with pytest.raises(IntegrityError, match="cve_cwe_cve_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = CVECWE.__table__.c.cve_id.foreign_keys
        assert fk.target_fullname == "cve.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestCVECWECascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md, CVECWE)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
    ) -> None:
        cve = await cve_factory()
        other = await cve_cwe_factory()
        await cve_cwe_factory(cve_id=cve.id)
        await cve_cwe_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()

        await db_session.execute(delete(CVE).where(CVE.id == cve_id))

        assert await _count_rows(db_session, cve_id) == 0
        assert await _count_rows(db_session, other.cve_id) == 1

    async def test_orm_delete_with_loaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_cwe_factory(cve_id=cve.id)
        await cve_cwe_factory(cve_id=cve.id)
        cve_id = cve.id
        await db_session.refresh(cve, ["cwes"])
        assert len(cve.cwes) == 2

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_cwe_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()
        reloaded = await db_session.get(CVE, cve_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVECWERelationships:
    async def test_cve_cwes_round_trip(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_cwe_factory: CWEFactory,
    ) -> None:
        cve = await cve_factory()
        first = await cve_cwe_factory(cve_id=cve.id)
        second = await cve_cwe_factory(cve_id=cve.id)
        await db_session.refresh(cve, ["cwes"])
        assert {row.id for row in cve.cwes} == {first.id, second.id}

        await db_session.refresh(first, ["cve"])
        assert first.cve.id == cve.id


@pytest.mark.integration
class TestCVECWETimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, cve_cwe_factory: CWEFactory
    ) -> None:
        row = await cve_cwe_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, cve_cwe_factory: CWEFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_cwe_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.source = "Red Hat"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, cve_cwe_factory: CWEFactory
    ) -> None:
        row = await cve_cwe_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.created_at = backdated
        await db_session.flush()

        row.source = "Red Hat"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.created_at == backdated
