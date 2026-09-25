"""Integration tests for the CVECVSSAssessment model
(backend/app/models/cve_cvss_assessment.py).

See docs/data-model.md (CVECVSSAssessment) and
docs/features/tickets/cvss-scoring.md (Version-Specific Assessment
Severity, Assessment Persistence and Ticket Status, Data Model) for the
full specification. These tests exercise the raw persistence contract;
vector derivation and assessment mutation semantics belong to the
service tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSAssessmentSeverity, CVSSVersion
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment

_V31_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


async def _count_assessments(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        text("SELECT count(*) FROM cve_cvss_assessment WHERE cve_id = :cve_id"),
        {"cve_id": cve_id},
    )
    return int(result.scalar_one())


@pytest.mark.integration
class TestCVECVSSAssessmentCreation:
    async def test_create_with_defaults(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        row = await cve_cvss_assessment_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.cvss_version == "3.1"
        assert row.score == Decimal("9.8")
        assert row.severity == "critical"
        assert row.vector_string == _V31_VECTOR
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_suse_assessment_with_maximum_width_vector(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        vector = "V" * 200
        row = await cve_cvss_assessment_factory(
            provider_name="SUSE",
            cvss_version=CVSSVersion.V4_0.value,
            score=Decimal("7.3"),
            severity=CVSSAssessmentSeverity.HIGH.value,
            vector_string=vector,
        )
        await db_session.refresh(row)

        assert row.provider_name == "SUSE"
        assert row.cvss_version == "4.0"
        assert row.vector_string == vector


@pytest.mark.integration
class TestCVECVSSAssessmentScore:
    """`score` is `DECIMAL(3,1)` and round-trips as `Decimal`
    (docs/data-model.md, CVECVSSAssessment)."""

    @pytest.mark.parametrize("score", ["0.0", "0.1", "5.5", "9.9", "10.0"])
    async def test_score_round_trips_as_decimal(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
        score: str,
    ) -> None:
        row = await cve_cvss_assessment_factory(score=Decimal(score))
        await db_session.refresh(row)

        assert isinstance(row.score, Decimal)
        assert row.score == Decimal(score)
        assert str(row.score) == score


@pytest.mark.integration
class TestCVECVSSAssessmentClassificationColumns:
    """`cvss_version` and `severity` are Category B columns without a
    CHECK constraint (docs/data-model.md, CVECVSSAssessment)."""

    @pytest.mark.parametrize("version", list(CVSSVersion), ids=lambda v: v.name)
    async def test_every_cvss_version_accepted(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
        version: CVSSVersion,
    ) -> None:
        row = await cve_cvss_assessment_factory(cvss_version=version.value)
        await db_session.refresh(row)
        assert row.cvss_version == version.value

    @pytest.mark.parametrize(
        "severity", list(CVSSAssessmentSeverity), ids=lambda s: s.name
    )
    async def test_every_assessment_severity_accepted(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
        severity: CVSSAssessmentSeverity,
    ) -> None:
        row = await cve_cvss_assessment_factory(severity=severity.value)
        await db_session.refresh(row)
        assert row.severity == severity.value

    async def test_arbitrary_values_accepted_at_model_layer(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        row = await cve_cvss_assessment_factory(cvss_version="5.0", severity="Moderate")
        await db_session.refresh(row)
        assert row.cvss_version == "5.0"
        assert row.severity == "Moderate"


@pytest.mark.integration
class TestCVECVSSAssessmentUniqueConstraint:
    async def test_duplicate_cve_provider_version_rejected(
        self,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="NVD", cvss_version="3.1"
        )
        with pytest.raises(
            IntegrityError,
            match="uq_cve_cvss_assessment_cve_id_provider_name_cvss_version",
        ):
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="NVD", cvss_version="3.1"
            )

    async def test_same_provider_different_versions_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="NVD", cvss_version="3.1"
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="NVD", cvss_version="4.0"
        )
        assert await _count_assessments(db_session, cve.id) == 2

    async def test_same_version_different_providers_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="NVD", cvss_version="3.1"
        )
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name="SUSE", cvss_version="3.1"
        )
        assert await _count_assessments(db_session, cve.id) == 2

    async def test_same_provider_version_for_different_cves_accepted(
        self,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        first = await cve_cvss_assessment_factory(
            cve_id=(await cve_factory()).id, provider_name="NVD", cvss_version="3.1"
        )
        second = await cve_cvss_assessment_factory(
            cve_id=(await cve_factory()).id, provider_name="NVD", cvss_version="3.1"
        )
        assert first.id != second.id


@pytest.mark.integration
class TestCVECVSSAssessmentNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        [
            "cve_id",
            "provider_name",
            "cvss_version",
            "score",
            "severity",
            "vector_string",
        ],
    )
    async def test_missing_required_column_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        column: str,
    ) -> None:
        values: dict[str, object] = {
            "cve_id": (await cve_factory()).id,
            "provider_name": "NVD",
            "cvss_version": CVSSVersion.V3_1.value,
            "score": Decimal("9.8"),
            "severity": CVSSAssessmentSeverity.CRITICAL.value,
            "vector_string": _V31_VECTOR,
        }
        del values[column]
        db_session.add(CVECVSSAssessment(**values))
        with pytest.raises(IntegrityError):
            await db_session.flush()

    @pytest.mark.parametrize("column", ["created_at", "updated_at"])
    async def test_explicit_null_timestamp_rejected(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
        column: str,
    ) -> None:
        row = await cve_cvss_assessment_factory()
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text(f"UPDATE cve_cvss_assessment SET {column} = NULL WHERE id = :id"),
                {"id": row.id},
            )


@pytest.mark.integration
class TestCVECVSSAssessmentForeignKey:
    async def test_nonexistent_cve_id_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            CVECVSSAssessment(
                cve_id=uuid.uuid4(),
                provider_name="NVD",
                cvss_version=CVSSVersion.V3_1.value,
                score=Decimal("9.8"),
                severity=CVSSAssessmentSeverity.CRITICAL.value,
                vector_string=_V31_VECTOR,
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestCVECVSSAssessmentCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md,
    CVECVSSAssessment)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id)
        await cve_cvss_assessment_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()

        await db_session.execute(text("DELETE FROM cve WHERE id = :id"), {"id": cve_id})

        assert await _count_assessments(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id)
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_assessments(db_session, cve_id) == 0

    async def test_orm_delete_with_loaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        await cve_cvss_assessment_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["cvss_assessments"])
        assert len(cve.cvss_assessments) == 1
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_assessments(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVECVSSAssessmentRelationships:
    async def test_assessment_cve_relationship(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        row = await cve_cvss_assessment_factory()
        await db_session.refresh(row, attribute_names=["cve"])
        assert row.cve.id == row.cve_id

    async def test_cve_cvss_assessments_relationship(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        cve = await cve_factory()
        first = await cve_cvss_assessment_factory(cve_id=cve.id)
        second = await cve_cvss_assessment_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["cvss_assessments"])

        assert {row.id for row in cve.cvss_assessments} == {first.id, second.id}


@pytest.mark.integration
class TestCVECVSSAssessmentTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        row = await cve_cvss_assessment_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_cvss_assessment_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.score = Decimal("7.5")
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated
