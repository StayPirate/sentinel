"""Integration tests for the CVEEPSSScore model
(backend/app/models/cve_epss_score.py).

See docs/data-model.md (CVEEPSSScore) and
docs/features/tickets/cve-service.md (Child Persistence Matrix). Only the
persistence contract is covered here; additive ingestion and the
active-Ticket refresh are CVE service and EPSS fetcher behavior.
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
from app.models.cve_epss_score import CVEEPSSScore

CVEFactory = Callable[..., Awaitable[CVE]]
EPSSFactory = Callable[..., Awaitable[CVEEPSSScore]]


async def _count_rows(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(CVEEPSSScore)
        .where(CVEEPSSScore.cve_id == cve_id)
    )
    return result.scalar_one()


@pytest.mark.integration
class TestCVEEPSSScoreCreation:
    async def test_create_with_defaults(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        row = await cve_epss_score_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.score == 0.00043
        assert row.percentile == 0.12345
        assert row.assessed_at == date(2099, 1, 15)
        assert row.created_at is not None
        assert row.updated_at is not None

    @pytest.mark.parametrize(
        ("score", "percentile"),
        [(0.0, 0.0), (1.0, 1.0), (0.97565, 0.99987), (0.00001, 0.00012)],
    )
    async def test_variable_precision_values_round_trip_exactly(
        self,
        db_session: AsyncSession,
        cve_epss_score_factory: EPSSFactory,
        score: float,
        percentile: float,
    ) -> None:
        """`FLOAT` (double precision) stores the variable-precision EPSS
        values without a DECIMAL scale (docs/data-model.md, CVEEPSSScore,
        FLOAT vs DECIMAL)."""
        row = await cve_epss_score_factory(score=score, percentile=percentile)
        row_id = row.id
        db_session.expunge_all()

        reloaded = await db_session.get(CVEEPSSScore, row_id)
        assert reloaded is not None
        assert reloaded.score == score
        assert reloaded.percentile == percentile
        assert type(reloaded.assessed_at) is date

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default, so the
        `uuidv7()` and `now()` server defaults must supply the columns."""
        cve = await cve_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO cve_epss_score (cve_id, score, percentile, assessed_at) "
                "VALUES (:cve_id, 0.5, 0.5, DATE '2099-01-15') "
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
class TestCVEEPSSScoreUniqueConstraint:
    """UNIQUE `cve_id`: one point-in-time EPSS snapshot per CVE."""

    async def test_second_score_for_same_cve_rejected(
        self, cve_factory: CVEFactory, cve_epss_score_factory: EPSSFactory
    ) -> None:
        cve = await cve_factory()
        await cve_epss_score_factory(cve_id=cve.id)
        with pytest.raises(IntegrityError, match="cve_epss_score_cve_id_key"):
            await cve_epss_score_factory(cve_id=cve.id, assessed_at=date(2099, 1, 16))

    async def test_scores_for_different_cves_accepted(
        self, cve_epss_score_factory: EPSSFactory
    ) -> None:
        first = await cve_epss_score_factory()
        second = await cve_epss_score_factory()
        assert first.cve_id != second.cve_id


@pytest.mark.integration
class TestCVEEPSSScoreNotNullConstraints:
    @pytest.mark.parametrize(
        "column",
        ["cve_id", "score", "percentile", "assessed_at", "created_at", "updated_at"],
    )
    async def test_explicit_null_rejected(
        self, db_session: AsyncSession, cve_factory: CVEFactory, column: str
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        cve = await cve_factory()
        values: dict[str, object] = {
            "cve_id": cve.id,
            "score": 0.5,
            "percentile": 0.5,
            "assessed_at": date(2099, 1, 15),
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CVEEPSSScore).values(values))


@pytest.mark.integration
class TestCVEEPSSScoreForeignKey:
    async def test_nonexistent_cve_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            CVEEPSSScore(
                cve_id=uuid.uuid7(),
                score=0.5,
                percentile=0.5,
                assessed_at=date(2099, 1, 15),
            )
        )
        with pytest.raises(IntegrityError, match="cve_epss_score_cve_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = CVEEPSSScore.__table__.c.cve_id.foreign_keys
        assert fk.target_fullname == "cve.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestCVEEPSSScoreCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md, CVEEPSSScore)."""

    async def test_database_delete_cascades(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        row = await cve_epss_score_factory()
        other = await cve_epss_score_factory()
        cve_id = row.cve_id
        db_session.expunge_all()

        await db_session.execute(delete(CVE).where(CVE.id == cve_id))

        assert await _count_rows(db_session, cve_id) == 0
        assert await _count_rows(db_session, other.cve_id) == 1

    async def test_orm_delete_with_loaded_child_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_epss_score_factory: EPSSFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_epss_score_factory(cve_id=cve.id)
        cve_id = cve.id
        await db_session.refresh(cve, ["epss_score"])
        assert cve.epss_score is not None

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_child_cascades(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        row = await cve_epss_score_factory()
        cve_id = row.cve_id
        db_session.expunge_all()
        reloaded = await db_session.get(CVE, cve_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVEEPSSScoreRelationships:
    async def test_cve_epss_score_round_trip(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_epss_score_factory: EPSSFactory,
    ) -> None:
        cve = await cve_factory()
        await db_session.refresh(cve, ["epss_score"])
        assert cve.epss_score is None

        row = await cve_epss_score_factory(cve_id=cve.id)
        await db_session.refresh(cve, ["epss_score"])
        assert cve.epss_score is not None
        assert cve.epss_score.id == row.id

        await db_session.refresh(row, ["cve"])
        assert row.cve.id == cve.id


@pytest.mark.integration
class TestCVEEPSSScoreTimestamps:
    async def test_timestamps_are_timezone_aware(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        row = await cve_epss_score_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_epss_score_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.score = 0.75
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self, db_session: AsyncSession, cve_epss_score_factory: EPSSFactory
    ) -> None:
        row = await cve_epss_score_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.created_at = backdated
        await db_session.flush()

        row.score = 0.75
        await db_session.flush()
        await db_session.refresh(row)

        assert row.created_at == backdated
