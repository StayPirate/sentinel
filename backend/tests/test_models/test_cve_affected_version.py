"""Integration tests for the CVEAffectedVersion model
(backend/app/models/cve_affected_version.py).

See docs/data-model.md (CVEAffectedVersion) and
docs/features/tickets/cve-service.md (Child Persistence Matrix, Canonical
Payload Duplicate Handling, Affected-Version Snapshot Operations). Only the
persistence contract is covered here: the entry conflict key, duplicate
validation, and scoped replace/remove are CVE service behavior.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import UniqueConstraint, delete, func, insert, inspect, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Base
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion

CVEFactory = Callable[..., Awaitable[CVE]]
AffectedVersionFactory = Callable[..., Awaitable[CVEAffectedVersion]]

# Documented bounded VARCHAR lengths (docs/data-model.md, CVEAffectedVersion).
_COLUMN_LENGTHS = {
    "source_container": 100,
    "ecosystem": 50,
    "status": 20,
    "default_status": 20,
}

_TEXT_COLUMNS = (
    "vendor",
    "product",
    "package_url",
    "collection_url",
    "package_name",
    "repo",
    "version",
    "version_type",
    "version_end",
    "cpe",
)

_OPTIONAL_COLUMNS = (
    *_TEXT_COLUMNS,
    "version_end_inclusive",
    "program_files",
    "ecosystem",
    "status",
    "default_status",
)


async def _count_rows(
    session: AsyncSession, cve_id: uuid.UUID, source_container: str | None = None
) -> int:
    query = (
        select(func.count())
        .select_from(CVEAffectedVersion)
        .where(CVEAffectedVersion.cve_id == cve_id)
    )
    if source_container is not None:
        query = query.where(CVEAffectedVersion.source_container == source_container)
    return (await session.execute(query)).scalar_one()


@pytest.mark.integration
class TestCVEAffectedVersionCreation:
    async def test_create_with_defaults(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        row = await cve_affected_version_factory()
        await db_session.refresh(row)

        assert row.id.version == 7
        assert row.cve_id is not None
        assert row.source_container == "cna"
        for column in _OPTIONAL_COLUMNS:
            assert getattr(row, column) is None, column
        assert row.created_at is not None

    async def test_create_with_every_column(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        row = await cve_affected_version_factory(
            source_container="adp:CISA-ADP",
            vendor="Example Vendor",
            product="Example Product",
            package_url="pkg:pypi/example-package",
            collection_url="https://pypi.example.org",
            package_name="example-package",
            repo="https://git.example.com/example/example-package",
            version="1.0.0",
            version_type="semver",
            version_end="1.4.2",
            version_end_inclusive=False,
            program_files=["src/example/core.c", "src/example/util.c"],
            cpe="cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*",
            ecosystem="PyPI",
            status="affected",
            default_status="unaffected",
        )
        row_id = row.id
        db_session.expunge_all()

        reloaded = await db_session.get(CVEAffectedVersion, row_id)
        assert reloaded is not None
        assert reloaded.source_container == "adp:CISA-ADP"
        assert reloaded.vendor == "Example Vendor"
        assert reloaded.product == "Example Product"
        assert reloaded.package_url == "pkg:pypi/example-package"
        assert reloaded.collection_url == "https://pypi.example.org"
        assert reloaded.package_name == "example-package"
        assert reloaded.repo == "https://git.example.com/example/example-package"
        assert reloaded.version == "1.0.0"
        assert reloaded.version_type == "semver"
        assert reloaded.version_end == "1.4.2"
        assert reloaded.version_end_inclusive is False
        assert reloaded.program_files == ["src/example/core.c", "src/example/util.c"]
        assert reloaded.cpe == "cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*"
        assert reloaded.ecosystem == "PyPI"
        assert reloaded.status == "affected"
        assert reloaded.default_status == "unaffected"

    async def test_git_commit_range_entry(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        """`version_type = "git"` stores introducing and fixing commit SHAs
        (docs/data-model.md, CVEAffectedVersion)."""
        introduced = "a" * 40
        fixed = "b" * 40
        row = await cve_affected_version_factory(
            version=introduced, version_end=fixed, version_type="git"
        )
        await db_session.refresh(row)
        assert (row.version, row.version_end) == (introduced, fixed)

    async def test_raw_insert_applies_server_defaults(
        self, db_session: AsyncSession, cve_factory: CVEFactory
    ) -> None:
        """A raw SQL INSERT bypasses every Python-side default (a Core
        `insert()` would still apply `uuid.uuid7`), so the `uuidv7()` and
        `now()` server defaults must supply the columns."""
        cve = await cve_factory()
        result = await db_session.execute(
            text(
                "INSERT INTO cve_affected_version (cve_id, source_container) "
                "VALUES (:cve_id, 'cna') RETURNING id, created_at"
            ),
            {"cve_id": cve.id},
        )
        row = result.one()
        assert isinstance(row.id, uuid.UUID)
        assert row.id.version == 7
        assert row.created_at.tzinfo is not None


@pytest.mark.integration
class TestCVEAffectedVersionColumnTypes:
    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_documented_maximum_accepted(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
        column: str,
        length: int,
    ) -> None:
        row = await cve_affected_version_factory(**{column: "x" * length})
        await db_session.refresh(row)
        assert len(getattr(row, column)) == length

    @pytest.mark.parametrize(("column", "length"), list(_COLUMN_LENGTHS.items()))
    async def test_value_over_documented_maximum_rejected(
        self,
        cve_affected_version_factory: AffectedVersionFactory,
        column: str,
        length: int,
    ) -> None:
        with pytest.raises(DBAPIError, match="value too long"):
            await cve_affected_version_factory(**{column: "x" * (length + 1)})

    @pytest.mark.parametrize("column", _TEXT_COLUMNS)
    async def test_text_columns_have_no_length_bound(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
        column: str,
    ) -> None:
        """Length limits of the upstream-derived text columns belong to the
        ingestion payload schema, not the database (#617/#619)."""
        long_value = "x" * 5000
        row = await cve_affected_version_factory(**{column: long_value})
        await db_session.refresh(row)
        assert getattr(row, column) == long_value


@pytest.mark.integration
class TestCVEAffectedVersionNoEntryUniqueness:
    """No unique constraint or unique index over the entry columns: entry
    uniqueness is owned solely by the CVE service entry conflict key
    (docs/data-model.md, CVEAffectedVersion, No database entry uniqueness)."""

    async def test_identical_entries_in_one_scope_accepted(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        cve = await cve_factory()
        entry = {
            "cve_id": cve.id,
            "source_container": "cna",
            "vendor": "Example Vendor",
            "product": "Example Product",
            "version": "1.0.0",
            "version_type": "semver",
        }
        await cve_affected_version_factory(**entry)
        await cve_affected_version_factory(**entry)

        assert await _count_rows(db_session, cve.id, "cna") == 2

    def test_no_unique_constraint_declared(self) -> None:
        table = Base.metadata.tables["cve_affected_version"]
        assert not [c for c in table.constraints if isinstance(c, UniqueConstraint)]
        assert all(not index.unique for index in table.indexes)


@pytest.mark.integration
class TestCVEAffectedVersionIndexes:
    """docs/data-model.md (CVEAffectedVersion, Indexes): exactly the
    non-unique `(cve_id, source_container)` scope index (#611 decision A3)."""

    async def test_exact_index_set(self, db_session: AsyncSession) -> None:
        conn = await db_session.connection()
        indexes = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_indexes("cve_affected_version")
        )
        assert {(idx["name"], tuple(idx["column_names"])) for idx in indexes} == {
            (
                "ix_cve_affected_version_cve_id_source_container",
                ("cve_id", "source_container"),
            ),
        }
        assert all(not idx["unique"] for idx in indexes)


@pytest.mark.integration
class TestCVEAffectedVersionNotNullConstraints:
    @pytest.mark.parametrize("column", ["cve_id", "source_container", "created_at"])
    async def test_explicit_null_rejected(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        column: str,
    ) -> None:
        """A Core INSERT with an explicit NULL bypasses the ORM, which
        would otherwise omit a `None` server-defaulted column."""
        cve = await cve_factory()
        values: dict[str, object] = {
            "cve_id": cve.id,
            "source_container": "cna",
            column: None,
        }
        with pytest.raises(IntegrityError, match="not-null"):
            await db_session.execute(insert(CVEAffectedVersion).values(values))


@pytest.mark.integration
class TestCVEAffectedVersionForeignKey:
    async def test_nonexistent_cve_rejected(self, db_session: AsyncSession) -> None:
        db_session.add(CVEAffectedVersion(cve_id=uuid.uuid7(), source_container="cna"))
        with pytest.raises(IntegrityError, match="cve_affected_version_cve_id_fkey"):
            await db_session.flush()

    def test_foreign_key_uses_ondelete_cascade(self) -> None:
        (fk,) = CVEAffectedVersion.__table__.c.cve_id.foreign_keys
        assert fk.target_fullname == "cve.id"
        assert fk.ondelete == "CASCADE"


@pytest.mark.integration
class TestCVEAffectedVersionCascadeOnCVEDelete:
    """`FK(cve.id) ON DELETE CASCADE` (docs/data-model.md,
    CVEAffectedVersion)."""

    async def test_database_delete_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        cve = await cve_factory()
        other = await cve_affected_version_factory()
        await cve_affected_version_factory(cve_id=cve.id, source_container="cna")
        await cve_affected_version_factory(cve_id=cve.id, source_container="osv")
        cve_id = cve.id
        db_session.expunge_all()

        await db_session.execute(delete(CVE).where(CVE.id == cve_id))

        assert await _count_rows(db_session, cve_id) == 0
        assert await _count_rows(db_session, other.cve_id) == 1

    async def test_orm_delete_with_loaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_affected_version_factory(cve_id=cve.id)
        await cve_affected_version_factory(cve_id=cve.id)
        cve_id = cve.id
        await db_session.refresh(cve, ["affected_versions"])
        assert len(cve.affected_versions) == 2

        await db_session.delete(cve)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0

    async def test_orm_delete_with_unloaded_children_cascades(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        cve = await cve_factory()
        await cve_affected_version_factory(cve_id=cve.id)
        cve_id = cve.id
        db_session.expunge_all()
        reloaded = await db_session.get(CVE, cve_id)
        assert reloaded is not None

        await db_session.delete(reloaded)
        await db_session.flush()

        assert await _count_rows(db_session, cve_id) == 0


@pytest.mark.integration
class TestCVEAffectedVersionRelationships:
    async def test_cve_affected_versions_round_trip(
        self,
        db_session: AsyncSession,
        cve_factory: CVEFactory,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        cve = await cve_factory()
        first = await cve_affected_version_factory(cve_id=cve.id)
        second = await cve_affected_version_factory(
            cve_id=cve.id, source_container="osv"
        )
        await db_session.refresh(cve, ["affected_versions"])
        assert {row.id for row in cve.affected_versions} == {first.id, second.id}

        await db_session.refresh(first, ["cve"])
        assert first.cve.id == cve.id


@pytest.mark.integration
class TestCVEAffectedVersionTimestamps:
    """`created_at` only: rows are replaced or removed as a scope and never
    updated in place (docs/data-model.md, Notes)."""

    def test_has_no_updated_at_column(self) -> None:
        assert "updated_at" not in CVEAffectedVersion.__table__.c

    async def test_created_at_is_timezone_aware(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        row = await cve_affected_version_factory()
        await db_session.refresh(row)
        assert row.created_at.tzinfo is not None

    async def test_created_at_has_no_onupdate(
        self,
        db_session: AsyncSession,
        cve_affected_version_factory: AffectedVersionFactory,
    ) -> None:
        row = await cve_affected_version_factory()
        backdated = datetime.now(UTC) - timedelta(days=7)
        row.created_at = backdated
        await db_session.flush()

        row.status = "affected"
        await db_session.flush()
        await db_session.refresh(row)

        assert row.created_at == backdated
