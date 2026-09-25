"""Integration tests for the CVESSVCAssessment model
(backend/app/models/cve_ssvc_assessment.py).

See docs/data-model.md (CVESSVCAssessment) and
docs/features/tickets/cve-service.md (Child Persistence Matrix). Only the
persistence contract is covered here; additive ingestion is CVE service
behavior.
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
from app.models.cve_ssvc_assessment import CVESSVCAssessment

CVEFactory = Callable[..., Awaitable[CVE]]
SSVCFactory = Callable[..., Awaitable[CVESSVCAssessment]]

# Documented VARCHAR lengths (docs/data-model.md, CVESSVCAssessment).
_COLUMN_LENGTHS = {
    "exploitation": 20,
    "automatable": 10,
    "technical_impact": 20,
    "version": 10,
}

_REQUIRED_VALUES: dict[str, object] = {
    "exploitation": "active",
    "automatable": "yes",
    "technical_impact": "total",
    "version": "2.0.3",
}


async def _count_rows(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(CVESSVCAssessment)
        .where(CVESSVCAssessment.cve_id == cve_id)
    )
    return result.scalar_one()


@pytest.mark.integration
class TestCVESSVCAssessmentCreation:
    async def test_create_with_defaults(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        row = await cve_ssvc_assessment_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert (row.exploitation, row.automatable, row.technical_impact) == (
            "none",
            "no",
            "partial",
        )
        assert row.version == "2.0.3"
        assert row.assessed_at is None
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_create_with_assessed_at(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        assessed_at = datetime(2099, 1, 15, 10, 30, tzinfo=UTC)
        row = await cve_ssvc_assessment_factory(
            **_REQUIRED_VALUES, assessed_at=assessed_at
        )
        row_id = row.id
        db_session.expunge_all()

        reloaded = await db_session.get(CVESSVCAssessment, row_id)
        assert reloaded is not None
        assert reloaded.exploitation == "active"
        assert reloaded.automatable == "yes"
        assert reloaded.technical_impact == "total"
        assert reloaded.assessed_at == assessed_at
        assert reloaded.assessed_at.tzinfo is not None

    async def test_arbitrary_label_accepted_at_model_layer(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        """No CHECK constraint on the descriptive labels (#611 decision A3)."""
        row = await cve_ssvc_assessment_factory(exploitation="unknown-label")
        await db_session.refresh(row)
        assert row.exploitation == "unknown-label"

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        cve = await cve_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO cve_ssvc_assessment "
                "(cve_id, exploitation, automatable, technical_impact, version) "
                "VALUES (:cve_id, 'poc', 'no', 'partial', '2.0.3') "
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
class TestCVESSVCAssessmentColumnLengths:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self,
        db_session: AsyncSession,
        cve_ssvc_assessment_factory: SSVCFactory,
        column: str,
        length: int,
    ) -> None:
        row = await cve_ssvc_assessment_factory(**{column: "x" * length})
        await db_session.refresh(row)
        assert len(getattr(row, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self, cve_ssvc_assessment_factory: SSVCFactory, column: str, length: int
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await cve_ssvc_assessment_factory(**{column: "x" * (length + 1)})


@pytest.mark.integration
class TestCVESSVCAssessmentUniqueConstraint:
    """UNIQUE `cve_id`: one SSVC assessment per CVE."""

    async def test_second_assessment_for_same_cve_rejected(
        self, cve_factory: CVEFactory, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        cve = await cve_factory()
        await cve_ssvc_assessment_factory(cve_id=cve.id)
        with pytest.raises(IntegrityError, match="cve_ssvc_assessment_cve_id_key"):
            await cve_ssvc_assessment_factory(cve_id=cve.id, **_REQUIRED_VALUES)

    async def test_assessments_for_different_cves_accepted(
        self, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        first = await cve_ssvc_assessment_factory()
        second = await cve_ssvc_assessment_factory()
        assert first.cve_id != second.cve_id


@pytest.mark.integration
class TestCVESSVCAssessmentNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        ["cve_id", *_REQUIRED_VALUES, "created_at", "updated_at"],
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, cve_factory: CVEFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        cve = await cve_factory()
        values: dict[str, object] = {
            "cve_id": cve.id,
            **_REQUIRED_VALUES,
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CVESSVCAssessment).values(values))


@pytest.mark.integration
class TestCVESSVCAssessmentForeignKey:
    async def test_nonexistent_cve_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CVESSVCAssessment(cve_id=uuid.uuid7(), **_REQUIRED_VALUES))
        with pytest.raises(IntegrityError, match="cve_ssvc_assessment_cve_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = CVESSVCAssessment.__table__.c.cve_id.foreign_keys
        assert fk.target_fullname == "cve.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestCVESSVCAssessmentCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md, CVESSVCAssessment)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_ssvc_assessment_factory: SSVCFactory,
    ) -> None:
        row = await cve_ssvc_assessment_factory()
        other = await cve_ssvc_assessment_factory()
        cve_id = row.cve_id
        db_session.expunge_all()

        await db_session.execute(delete(CVE).where(CVE.id == cve_id))

        assert await _count_rows(db_session, cve_id) == 0
        assert await _count_rows(db_session, other.cve_id) == 1

    async def test_orm_delete_with_loaded_child_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_ssvc_assessment_factory: SSVCFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_ssvc_assessment_factory(cve_id=cve.id)
        cve_id = cve.id
        await db_session.refresh(cve, ["ssvc_assessment"])
        assert cve.ssvc_assessment is not None

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_child_cascades(
        self,
        db_session: AsyncSession,
        cve_ssvc_assessment_factory: SSVCFactory,
    ) -> None:
        row = await cve_ssvc_assessment_factory()
        cve_id = row.cve_id
        db_session.expunge_all()
        reloaded = await db_session.get(CVE, cve_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVESSVCAssessmentRelationships:
    async def test_cve_ssvc_assessment_round_trip(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_ssvc_assessment_factory: SSVCFactory,
    ) -> None:
        cve = await cve_factory()
        await db_session.refresh(cve, ["ssvc_assessment"])
        assert cve.ssvc_assessment is None

        row = await cve_ssvc_assessment_factory(cve_id=cve.id)
        await db_session.refresh(cve, ["ssvc_assessment"])
        assert cve.ssvc_assessment is not None
        assert cve.ssvc_assessment.id == row.id

        await db_session.refresh(row, ["cve"])
        assert row.cve.id == cve.id


@pytest.mark.integration
class TestCVESSVCAssessmentTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        row = await cve_ssvc_assessment_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_ssvc_assessment_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.exploitation = "active"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, cve_ssvc_assessment_factory: SSVCFactory
    ) -> None:
        row = await cve_ssvc_assessment_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.created_at = backdated
        await db_session.flush()

        row.exploitation = "active"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.created_at == backdated
