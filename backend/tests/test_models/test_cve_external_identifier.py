"""Integration tests for the CVEExternalIdentifier model
(backend/app/models/cve_external_identifier.py).

See docs/data-model.md (CVEExternalIdentifier,
CVEExternalIdentifierSource Python Enum) for the full specification.
These tests exercise the raw persistence contract; additive ingestion
semantics belong to the CVE service tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVEExternalIdentifierSource
from app.models.cve import CVE
from app.models.cve_external_identifier import CVEExternalIdentifier


async def _count_identifiers(session: AsyncSession, cve_id: uuid.UUID) -> int:
    result = await session.execute(
        text("SELECT count(*) FROM cve_external_identifier WHERE cve_id = :cve_id"),
        {"cve_id": cve_id},
    )
    return int(result.scalar_one())


@pytest.mark.integration
class TestCVEExternalIdentifierCreation:
    async def test_create_with_defaults(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        row = await cve_external_identifier_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.source == "GHSA"
        assert row.identifier.startswith("GHSA-")
        assert row.url is None
        assert row.created_at is not None
        assert row.updated_at is not None

    async def test_create_with_url(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        url = "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
        row = await cve_external_identifier_factory(
            identifier="GHSA-aaaa-bbbb-cccc", url=url
        )
        await db_session.refresh(row)
        assert row.url == url


@pytest.mark.integration
class TestCVEExternalIdentifierClassificationColumn:
    """`source` is a Category B column without a CHECK constraint
    (docs/data-model.md, CVEExternalIdentifier)."""

    @pytest.mark.parametrize(
        "source", list(CVEExternalIdentifierSource), ids=lambda s: s.name
    )
    async def test_every_source_value_accepted(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
        source: CVEExternalIdentifierSource,
    ) -> None:
        row = await cve_external_identifier_factory(source=source.value)
        await db_session.refresh(row)
        assert row.source == source.value

    async def test_arbitrary_value_accepted_at_model_layer(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        row = await cve_external_identifier_factory(source="unknown-source")
        await db_session.refresh(row)
        assert row.source == "unknown-source"


@pytest.mark.integration
class TestCVEExternalIdentifierUniqueConstraint:
    """`(source, identifier)` is globally unique — not scoped per CVE
    (docs/data-model.md, CVEExternalIdentifier)."""

    async def test_duplicate_for_same_cve_rejected(
        self,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        await cve_external_identifier_factory(
            cve_id=cve.id, source="GHSA", identifier="GHSA-aaaa-bbbb-cccc"
        )
        with pytest.raises(
            IntegrityError, match="uq_cve_external_identifier_source_identifier"
        ):
            await cve_external_identifier_factory(
                cve_id=cve.id, source="GHSA", identifier="GHSA-aaaa-bbbb-cccc"
            )

    async def test_duplicate_for_different_cve_rejected(
        self,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        await cve_external_identifier_factory(
            cve_id=(await cve_factory()).id,
            source="GHSA",
            identifier="GHSA-dddd-eeee-ffff",
        )
        other_cve = await cve_factory()
        with pytest.raises(
            IntegrityError, match="uq_cve_external_identifier_source_identifier"
        ):
            await cve_external_identifier_factory(
                cve_id=other_cve.id, source="GHSA", identifier="GHSA-dddd-eeee-ffff"
            )

    async def test_same_identifier_different_source_accepted(
        self,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        first = await cve_external_identifier_factory(
            source="PYSEC", identifier="SHARED-0001"
        )
        second = await cve_external_identifier_factory(
            source="RUSTSEC", identifier="SHARED-0001"
        )
        assert first.id != second.id

    async def test_multiple_identifiers_from_same_source_for_one_cve_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        await cve_external_identifier_factory(
            cve_id=cve.id, source="GHSA", identifier="GHSA-1111-2222-3333"
        )
        await cve_external_identifier_factory(
            cve_id=cve.id, source="GHSA", identifier="GHSA-4444-5555-6666"
        )
        await cve_external_identifier_factory(
            cve_id=cve.id, source="RUSTSEC", identifier="RUSTSEC-2099-0001"
        )
        assert await _count_identifiers(db_session, cve.id) == 3


@pytest.mark.integration
class TestCVEExternalIdentifierIndexes:
    """docs/data-model.md (CVEExternalIdentifier, Indexes): the
    `(source, identifier)` unique key does not lead with `cve_id`, so exactly
    one non-unique `cve_id` index serves per-CVE reads (#611 decision A3)."""

    async def test_exact_standalone_index_set(self, db_session: AsyncSession) -> None:
        conn = await db_session.connection()
        indexes = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes("cve_external_identifier")
        )
        standalone = [idx for idx in indexes if not idx.get("duplicates_constraint")]
        assert {(idx["name"], tuple(idx["column_names"])) for idx in standalone} == {
            ("ix_cve_external_identifier_cve_id", ("cve_id",)),
        }
        assert all(not idx["unique"] for idx in standalone)


@pytest.mark.integration
class TestCVEExternalIdentifierNotNullConstraints:
    @pytest.mark.parametrize("column", ["cve_id", "source", "identifier"])
    async def test_missing_required_column_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        column: str,
    ) -> None:
        values: dict[str, object] = {
            "cve_id": (await cve_factory()).id,
            "source": CVEExternalIdentifierSource.GHSA.value,
            "identifier": "GHSA-7777-8888-9999",
        }
        del values[column]
        db_session.add(CVEExternalIdentifier(**values))
        with pytest.raises(IntegrityError):
            await db_session.flush()

    @pytest.mark.parametrize("column", ["created_at", "updated_at"])
    async def test_explicit_null_timestamp_rejected(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
        column: str,
    ) -> None:
        row = await cve_external_identifier_factory()
        with pytest.raises(IntegrityError):
            await db_session.execute(
                text(
                    f"UPDATE cve_external_identifier SET {column} = NULL WHERE id = :id"
                ),
                {"id": row.id},
            )


@pytest.mark.integration
class TestCVEExternalIdentifierForeignKey:
    async def test_nonexistent_cve_id_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(
            CVEExternalIdentifier(
                cve_id=uuid.uuid4(),
                source=CVEExternalIdentifierSource.GHSA.value,
                identifier="GHSA-0000-0000-0001",
            )
        )
        with pytest.raises(IntegrityError):
            await db_session.flush()


@pytest.mark.integration
class TestCVEExternalIdentifierCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md,
    CVEExternalIdentifier)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        await cve_external_identifier_factory(cve_id=cve.id)
        await cve_external_identifier_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()

        await db_session.execute(text("DELETE FROM cve WHERE id = :id"), {"id": cve_id})

        assert await _count_identifiers(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        await cve_external_identifier_factory(cve_id=cve.id)
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_identifiers(db_session, cve_id) == 0

    async def test_orm_delete_with_loaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        await cve_external_identifier_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["external_identifiers"])
        assert len(cve.external_identifiers) == 1
        cve_id = cve.id

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_identifiers(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVEExternalIdentifierRelationships:
    async def test_identifier_cve_relationship(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        row = await cve_external_identifier_factory()
        await db_session.refresh(row, attribute_names=["cve"])
        assert row.cve.id == row.cve_id

    async def test_cve_external_identifiers_relationship(
        self,
        db_session: AsyncSession,
        cve_factory: Callable[..., Awaitable[CVE]],
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        cve = await cve_factory()
        first = await cve_external_identifier_factory(cve_id=cve.id)
        second = await cve_external_identifier_factory(cve_id=cve.id)
        await db_session.refresh(cve, attribute_names=["external_identifiers"])

        assert {row.id for row in cve.external_identifiers} == {first.id, second.id}


@pytest.mark.integration
class TestCVEExternalIdentifierTimestamps:
    async def test_timestamps_are_timezone_aware(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        row = await cve_external_identifier_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None
        assert row.updated_at.tzinfo is not None

    async def test_updated_at_advances_on_update(
        self,
        db_session: AsyncSession,
        cve_external_identifier_factory: Callable[
            ..., Awaitable[CVEExternalIdentifier]
        ],
    ) -> None:
        """Backdating pattern (docs/features/platform/testing-strategy.md,
        `server_default=func.now()` and `onupdate=func.now()` Testing)."""
        row = await cve_external_identifier_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.updated_at = backdated
        await db_session.flush()
        await db_session.refresh(row)
        assert row.updated_at == backdated

        row.url = "https://github.com/advisories/GHSA-test-0001-xxxx"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.updated_at > backdated
