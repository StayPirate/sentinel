"""Integration tests for the CVE model (backend/app/models/cve.py).

See docs/data-model.md (CVE, CveState Enum) and
docs/features/tickets/cvss-scoring.md (Unified CVE Severity) for the
full specification. Child-table relationships and the ON DELETE CASCADE
behavior are covered in the child model test modules.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CveState, Severity
from app.models.cve import CVE


@pytest.mark.integration
class TestCVECreation:
    async def test_create_with_defaults(
        self, cve_factory: Callable[..., Awaitable[CVE]]
    ) -> None:
        cve = await cve_factory(cve_id="CVE-2099-0001")

        assert cve.id.version == 7
        assert cve.cve_id == "CVE-2099-0001"
        assert cve.cve_state == CveState.PUBLISHED
        assert cve.severity is None
        assert cve.title is None
        assert cve.description is None
        assert cve.published_date is None
        assert cve.modified_date is None
        assert cve.date_rejected is None
        assert cve.created_at is not None
        assert cve.updated_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        published = datetime(2099, 1, 2, 3, 4, 5, tzinfo=UTC)
        modified = datetime(2099, 2, 3, 4, 5, 6, tzinfo=UTC)
        rejected = datetime(2099, 3, 4, 5, 6, 7, tzinfo=UTC)
        cve = await cve_factory(
            cve_id="CVE-2099-1234567",
            title="T" * 256,
            description="Fictional description of a vulnerability.",
            severity=Severity.CRITICAL.value,
            published_date=published,
            modified_date=modified,
            cve_state=CveState.REJECTED.value,
            date_rejected=rejected,
        )
        await db_session.refresh(cve)

        assert cve.title == "T" * 256
        assert cve.description == "Fictional description of a vulnerability."
        assert cve.severity == "Critical"
        assert cve.published_date == published
        assert cve.modified_date == modified
        assert cve.cve_state == "REJECTED"
        assert cve.date_rejected == rejected

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession
    ) -> None:
        """An INSERT that bypasses the ORM still gets a UUIDv7 `id`,
        `cve_state = 'PUBLISHED'`, and both timestamps from the
        PostgreSQL-side defaults (docs/conventions.md, SQLAlchemy
        Conventions; docs/data-model.md, CVE)."""
        result = await db_session.execute(
            text(
                "INSERT INTO cve (cve_id) VALUES ('CVE-2099-0002') "
                "RETURNING id, cve_state, created_at, updated_at"
            )
        )
        row = result.one()

        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.cve_state == "PUBLISHED"
        assert row.created_at is not None
        assert row.updated_at is not None


@pytest.mark.integration
class TestCVEUniqueCveId:
    async def test_duplicate_cve_id_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        await cve_factory(cve_id="CVE-2099-0003")
        db_session.add(CVE(cve_id="CVE-2099-0003"))
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestCVENotNullConstraints:
    async def test_missing_cve_id_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CVE())
        with pytest.raises(IntegrityError):
            await db_session.flush()

    @pytest.mark.parametrize(
        "column", ["cve_id", "cve_state", "created_at", "updated_at"]
    )
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        column: str,
    ) -> None:
        """A raw UPDATE bypasses the ORM and server defaults, proving the
        database itself rejects NULL for each NOT NULL column."""
        cve = await cve_factory()
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text(f"UPDATE cve SET {column} = NULL WHERE id = :id"),
                {"id": cve.id},
            )


@pytest.mark.integration
class TestCVEStateCheckConstraint:
    """`cve_state` is Category A, protected by `chk_cve_cve_state_valid`
    (docs/data-model.md, CveState Enum)."""

    @pytest.mark.parametrize("state", list(CveState), ids=lambda s: s.name)
    async def test_every_member_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        state: CveState,
    ) -> None:
        cve = await cve_factory(cve_state=state.value)
        await db_session.refresh(cve)
        assert cve.cve_state == state.value

    @pytest.mark.parametrize("value", ["RESERVED", "published", ""])
    async def test_invalid_value_rejected_on_insert(
        self, db_session: AsyncSession, value: str
    ) -> None:
        db_session.add(CVE(cve_id="CVE-2099-0004", cve_state=value))
        with pytest.raises(IntegrityError, match="chk_cve_cve_state_valid"):
            await db_session.flush()

    async def test_invalid_value_rejected_on_update(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory()
        with pytest.raises(IntegrityError, match="chk_cve_cve_state_valid"):
            await db_session.execute(
                text("UPDATE cve SET cve_state = 'DISPUTED' WHERE id = :id"),
                {"id": cve.id},
            )

    async def test_rejected_state_without_date_rejected_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        """`date_rejected` is optional for a REJECTED CVE; no database
        constraint couples the two columns."""
        cve = await cve_factory(cve_state=CveState.REJECTED.value)
        await db_session.refresh(cve)
        assert cve.date_rejected is None


@pytest.mark.integration
class TestCVESeverityClassification:
    """`severity` is a Category B column: the database stores any string,
    and NULL (unresolved) is distinct from the resolved "None" label
    (docs/data-model.md, CVE; docs/features/tickets/cvss-scoring.md,
    Unified CVE Severity)."""

    @pytest.mark.parametrize("label", list(Severity), ids=lambda s: s.name)
    async def test_every_unified_label_round_trips(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        label: Severity,
    ) -> None:
        cve = await cve_factory(severity=label.value)
        await db_session.refresh(cve)
        assert cve.severity == label.value

    async def test_none_label_is_distinct_from_null(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        resolved = await cve_factory(severity=Severity.NONE.value)
        unresolved = await cve_factory(severity=None)

        result = await db_session.execute(
            text("SELECT id FROM cve WHERE severity IS NULL AND id IN (:a, :b)"),
            {"a": resolved.id, "b": unresolved.id},
        )
        assert result.scalars().all() == [unresolved.id]

    async def test_arbitrary_value_accepted_at_model_layer(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory(severity="Moderate")
        await db_session.refresh(cve)
        assert cve.severity == "Moderate"


@pytest.mark.integration
class TestCVETimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory(
            published_date=datetime(2099, 1, 1, tzinfo=UTC),
            modified_date=datetime(2099, 1, 2, tzinfo=UTC),
            date_rejected=datetime(2099, 1, 3, tzinfo=UTC),
        )
        await db_session.refresh(cve)

        for value in (
            cve.created_at,
            cve.updated_at,
            cve.published_date,
            cve.modified_date,
            cve.date_rejected,
        ):
            assert value is not None
            assert value.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing):
        `now()` is fixed for the test transaction, so the column is
        backdated explicitly before the mutation."""
        cve = await cve_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        cve.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(cve)
        assert cve.updated_at == backdated

        cve.severity = Severity.HIGH.value
        await db_session.flush()
        await db_session.refresh(cve)

        assert cve.updated_at > backdated

    async def test_created_at_unchanged_on_update(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
    ) -> None:
        cve = await cve_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        cve.created_at = backdated
        await db_session.flush()

        cve.description = "Updated fictional description."
        await db_session.flush()
        await db_session.refresh(cve)

        assert cve.created_at == backdated
