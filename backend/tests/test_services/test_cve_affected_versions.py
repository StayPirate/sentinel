"""Tests for `cve_service.get_cve_affected_versions()`.

Owning specifications: docs/features/tickets/cve-service.md (CVE Read and
Accessibility Boundary; Service Read Contracts > CVE Affected Versions;
Affected-Version Snapshot Operations); docs/features/tickets/cve-tracking.md
(Get CVE Affected Versions; Child data preservation); docs/data-model.md
(CVEAffectedVersion); docs/api-spec.md (CVE Accessibility Check; CVE
Identifier Resolution); docs/features/platform/testing-strategy.md (CVE and
Source Reads > Per-CVE affected versions; Concurrency Testing).

Every `db_session` test rolls back. The independent-session races commit
their rows through `db_session_factory` and delete them explicitly.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, Final

import pytest
from sqlalchemy import delete, event, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Executable

from app.core.enums import CVESourceType, CveState, Scope
from app.core.exceptions import CVENotFoundError
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.user import User
from app.services.cve_ingest import CVEIngestPayload
from app.services.cve_service import (
    CVEAffectedVersionEntryProjection,
    CVEAffectedVersionGroupProjection,
    CVEAffectedVersionsResult,
    get_cve_affected_versions,
    upsert_cve,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.cve_ingest import av_entry, remove, replace

Factory = Callable[..., Awaitable[Any]]
SessionFactory = Callable[[], Awaitable[AsyncSession]]

ALL_SCOPE = TicketCaller.authenticated(uuid.uuid4(), Scope.ALL)
ROW_LOCKS: Final = ("FOR UPDATE", "FOR NO KEY UPDATE", "FOR SHARE", "FOR KEY SHARE")
MALFORMED_CVE_IDS: Final = [
    "cve-2099-10001",
    " CVE-2099-10001",
    "CVE-2099-10001 ",
    "CVE-2099-" + "1" * 12,
    "018f0e2a-7b1c-7cde-8f00-000000000001",
    "<internal-uuid>",
]

FULL_ROW: Final[dict[str, Any]] = {
    "vendor": "Example Vendor",
    "product": "Example Product",
    "package_url": "pkg:generic/example-product@1.0",
    "collection_url": "https://example.test/packages",
    "package_name": "example-product",
    "repo": "https://example.test/example-product.git",
    "version": "1.0",
    "version_type": "semver",
    "version_end": "1.5",
    "version_end_inclusive": False,
    "program_files": ["src/alpha.c", "src/beta.c"],
    "cpe": "cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*",
    "ecosystem": "PyPI",
    "status": "affected",
    "default_status": "unaffected",
}


def _entry(**values: Any) -> CVEAffectedVersionEntryProjection:
    """An entry projection with the given fields; every other one absent."""
    fields = {
        f.name: None for f in dataclasses.fields(CVEAffectedVersionEntryProjection)
    }
    return CVEAffectedVersionEntryProjection(**{**fields, **values})


def _restricted(user: User | uuid.UUID) -> TicketCaller:
    user_id = user if isinstance(user, uuid.UUID) else user.id
    return TicketCaller.authenticated(user_id, Scope.NON_CONFIDENTIAL)


class _StatementRecorder:
    """Records every SQL statement executed through the session's engine."""

    def __init__(self, db: AsyncSession) -> None:
        self._engine = db.get_bind().engine
        self.statements: list[str] = []

    def _record(self, *args: Any) -> None:
        self.statements.append(args[2])

    def __enter__(self) -> _StatementRecorder:
        event.listen(self._engine, "before_cursor_execute", self._record)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self._engine, "before_cursor_execute", self._record)


def _versions(result: CVEAffectedVersionsResult) -> dict[str, list[str | None]]:
    return {
        group.source_container: [entry.version for entry in group.entries]
        for group in result.groups
    }


# ---------------------------------------------------------------------------
# Accessibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAccess:
    @pytest.mark.parametrize("cve_id", MALFORMED_CVE_IDS)
    async def test_malformed_identifier_raises_without_any_statement(
        self, db_session: AsyncSession, cve_factory: Factory, cve_id: str
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-10001")
        cve_id = str(cve.id) if cve_id == "<internal-uuid>" else cve_id

        with (
            _StatementRecorder(db_session) as recorder,
            pytest.raises(CVENotFoundError),
        ):
            await get_cve_affected_versions(db_session, ALL_SCOPE, cve_id)

        assert recorder.statements == []

    async def test_canonical_predicate_decides_and_denial_equals_missing(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        ticket_access_grant_factory: Factory,
        user_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        user: User = await user_factory()
        cves: dict[str, CVE] = {
            name: await cve_factory(cve_id=f"CVE-2099-{20001 + index}")
            for index, name in enumerate(("ticketless", "public", "hidden", "granted"))
        }
        await ticket_factory(cve_id=cves["public"].id, is_confidential=False)
        await ticket_factory(cve_id=cves["hidden"].id, is_confidential=True)
        granted = await ticket_factory(cve_id=cves["granted"].id, is_confidential=True)
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=user.id)
        for cve in cves.values():
            await cve_affected_version_factory(cve_id=cve.id, version="1.0")
        public = ["ticketless", "public"]
        expectations = {
            ANONYMOUS_CALLER: public,
            _restricted(uuid.uuid4()): public,
            _restricted(user): [*public, "granted"],
            ALL_SCOPE: list(cves),
        }
        with pytest.raises(CVENotFoundError) as missing:
            await get_cve_affected_versions(
                db_session, ANONYMOUS_CALLER, "CVE-2099-99999"
            )

        for caller, visible in expectations.items():
            for name, cve in cves.items():
                if name in visible:
                    result = await get_cve_affected_versions(
                        db_session, caller, cve.cve_id
                    )
                    assert _versions(result) == {"cna": ["1.0"]}, name
                    continue
                with pytest.raises(CVENotFoundError) as denied:
                    await get_cve_affected_versions(db_session, caller, cve.cve_id)
                assert type(denied.value) is type(missing.value)
                assert str(denied.value) == str(missing.value)


# ---------------------------------------------------------------------------
# Projection, grouping, and ordering
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProjection:
    async def test_every_content_field_is_projected_as_stored_in_one_read(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-30001")
        await ticket_factory(cve_id=cve.id, is_confidential=True)
        await cve_affected_version_factory(
            cve_id=cve.id, source_container="adp:Example", **FULL_ROW
        )
        await cve_affected_version_factory(
            cve_id=cve.id,
            source_container="adp:Example",
            product="Example Product",
            version="2.0",
            version_end_inclusive=True,
            program_files=[],
        )
        rows_before = await db_session.scalar(
            select(func.count()).select_from(CVEAffectedVersion)
        )

        with _StatementRecorder(db_session) as recorder:
            result = await get_cve_affected_versions(db_session, ALL_SCOPE, cve.cve_id)

        assert result == CVEAffectedVersionsResult(
            groups=(
                CVEAffectedVersionGroupProjection(
                    source_container="adp:Example",
                    entries=(
                        _entry(
                            **{
                                **FULL_ROW,
                                "program_files": ("src/alpha.c", "src/beta.c"),
                            }
                        ),
                        _entry(
                            product="Example Product",
                            version="2.0",
                            version_end_inclusive=True,
                            program_files=(),
                        ),
                    ),
                ),
            )
        )
        (statement,) = recorder.statements
        assert statement.lstrip().upper().startswith("SELECT")
        for row_lock in ROW_LOCKS:
            assert row_lock not in statement.upper()
        projections: list[Any] = [result, *result.groups, *result.groups[0].entries]
        for value in projections:
            for field in dataclasses.fields(value):
                assert not isinstance(getattr(value, field.name), uuid.UUID)
        assert not db_session.new
        assert not db_session.dirty
        assert not db_session.deleted
        assert db_session.in_transaction()
        assert (
            await db_session.scalar(
                select(func.count()).select_from(CVEAffectedVersion)
            )
            == rows_before
        )

    async def test_cve_without_entries_yields_no_groups(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-30002")

        result = await get_cve_affected_versions(
            db_session, ANONYMOUS_CALLER, cve.cve_id
        )

        assert result == CVEAffectedVersionsResult(groups=())

    async def test_groups_are_scopes_in_code_point_order(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        """Code-point order puts `CNA-upper` < `adp:CISA-ADP` < `cna` < `osv`;
        a case-insensitive or linguistic collation would not. Another CVE's
        rows never leak in."""
        cve: CVE = await cve_factory(cve_id="CVE-2099-30003")
        other: CVE = await cve_factory(cve_id="CVE-2099-30004")
        for scope, version in (
            ("osv", "4"),
            ("cna", "3"),
            ("adp:CISA-ADP", "2"),
            ("cna", "3.1"),
            ("CNA-upper", "1"),
        ):
            await cve_affected_version_factory(
                cve_id=cve.id, source_container=scope, version=version
            )
        await cve_affected_version_factory(
            cve_id=other.id, source_container="ghsa", version="9"
        )

        result = await get_cve_affected_versions(db_session, ALL_SCOPE, cve.cve_id)

        assert _versions(result) == {
            "CNA-upper": ["1"],
            "adp:CISA-ADP": ["2"],
            "cna": ["3", "3.1"],
            "osv": ["4"],
        }
        assert [g.source_container for g in result.groups] == [
            "CNA-upper",
            "adp:CISA-ADP",
            "cna",
            "osv",
        ]

    async def test_entries_follow_the_documented_field_sequence(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        """Rows are inserted in reverse of the expected order. The expected
        order shows: package coordinates before version fields (`a`/`9`
        before `b`/`1`), ecosystem before version, code-point order
        (`Zlib` before `acme`; `1.10` before `1.9`), the empty string first
        among present values, and an absent value after every present one
        for each compared field, and each adjacent field pair decisive."""
        cve: CVE = await cve_factory(cve_id="CVE-2099-30005")
        expected = [
            _entry(vendor="", product="x"),
            _entry(vendor="Zlib", product="x"),
            _entry(vendor="acme", product="x"),
            # One pair per adjacent field pair: the earlier field ascends
            # while the later one descends, every other field tied.
            _entry(vendor="m-1", product="d", package_name="z"),
            _entry(vendor="m-1", product="e", package_name="a"),
            _entry(vendor="m-2", package_name="p1", ecosystem="Z"),
            _entry(vendor="m-2", package_name="p2", ecosystem="A"),
            _entry(vendor="m-3", ecosystem="A", repo="z"),
            _entry(vendor="m-3", ecosystem="B", repo="a"),
            _entry(vendor="m-4", repo="r1", version_type="z"),
            _entry(vendor="m-4", repo="r2", version_type="a"),
            _entry(vendor="m-5", version_type="a", version="9"),
            _entry(vendor="m-5", version_type="b", version="1"),
            _entry(vendor="m-6", version="1", version_end="9"),
            _entry(vendor="m-6", version="2", version_end="0"),
            _entry(vendor=None, product="a", version="9"),
            _entry(vendor=None, product="b", ecosystem="Go", version="2"),
            _entry(vendor=None, product="b", ecosystem="PyPI", version="1"),
            _entry(vendor=None, product="b", ecosystem=None, version="0"),
            _entry(vendor=None, product="c", version_type="git", version="1.10"),
            _entry(vendor=None, product="c", version_type="git", version="1.9"),
            _entry(vendor=None, product="c", version_type="git", version=None),
            _entry(vendor=None, product="c", version_type="semver", version="0"),
            _entry(vendor=None, product="c", version_type=None, version="0"),
            _entry(vendor=None, product=None, version="0", version_end=""),
            _entry(vendor=None, product=None, version="0", version_end="2"),
            _entry(vendor=None, product=None, version="0", version_end=None),
        ]
        for entry in reversed(expected):
            await cve_affected_version_factory(
                cve_id=cve.id, source_container="osv", **dataclasses.asdict(entry)
            )

        result = await get_cve_affected_versions(db_session, ALL_SCOPE, cve.cve_id)

        (group,) = result.groups
        assert list(group.entries) == expected

    async def test_rejected_cve_returns_its_preserved_entries(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve: CVE = await cve_factory(
            cve_id="CVE-2099-30006", cve_state=CveState.REJECTED.value
        )
        await cve_affected_version_factory(cve_id=cve.id, version="1.0")

        result = await get_cve_affected_versions(
            db_session, ANONYMOUS_CALLER, cve.cve_id
        )

        assert _versions(result) == {"cna": ["1.0"]}

    @pytest.mark.parametrize(
        "operation",
        [
            pytest.param(replace("cna"), id="empty-replace"),
            pytest.param(remove("cna"), id="remove"),
        ],
    )
    async def test_emptied_or_removed_scope_is_absent(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        operation: Any,
    ) -> None:
        cve: CVE = await cve_factory(cve_id="CVE-2099-30007")
        await ticket_factory(cve_id=cve.id)
        seeded = CVEIngestPayload(
            affected_version_operations=[
                replace("cna", av_entry(product="Alpha", version="1")),
                replace("osv", av_entry(product="Beta", version="2")),
            ]
        )
        await upsert_cve(db_session, cve.cve_id, CVESourceType.NVD, seeded)
        assert _versions(
            await get_cve_affected_versions(db_session, ALL_SCOPE, cve.cve_id)
        ) == {"cna": ["1"], "osv": ["2"]}

        await upsert_cve(
            db_session,
            cve.cve_id,
            CVESourceType.NVD,
            CVEIngestPayload(affected_version_operations=[operation]),
        )

        result = await get_cve_affected_versions(db_session, ALL_SCOPE, cve.cve_id)
        assert _versions(result) == {"osv": ["2"]}


# ---------------------------------------------------------------------------
# Independent-session races (one coherent observation)
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes them
    at teardown in FK-safe order (testing-strategy.md, Concurrency Testing).
    Affected-version rows are removed by the `ON DELETE CASCADE` of their
    CVE."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.user_ids: list[uuid.UUID] = []
        self.cve_ids: list[uuid.UUID] = []
        self.ticket_ids: list[uuid.UUID] = []

    async def user(self) -> User:
        suffix = uuid.uuid4().hex[:10]
        user = User(
            username=f"fictional.cveav.{suffix}",
            email=f"cveav.{suffix}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        await self.session.commit()
        return user

    async def confidential_cve(self, *versions: str) -> tuple[CVE, Ticket]:
        """A CVE with `cna` entries for `versions` and a confidential
        Ticket."""
        cve = CVE(cve_id=f"CVE-2099-{uuid.uuid4().int % 10**9:09d}")
        self.session.add(cve)
        await self.session.flush()
        self.cve_ids.append(cve.id)
        for version in versions:
            self.session.add(
                CVEAffectedVersion(
                    cve_id=cve.id, source_container="cna", version=version
                )
            )
        ticket = Ticket(is_confidential=True, cve_id=cve.id)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        await self.session.commit()
        return cve, ticket

    async def grant(self, ticket: Ticket, user: User, granter: User) -> None:
        self.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await self.session.commit()

    async def cleanup(self) -> None:
        await self.session.rollback()
        for statement in (
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(CVE).where(CVE.id.in_(self.cve_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@dataclasses.dataclass(frozen=True)
class _Race:
    """A granted confidential CVE with one `cna` entry, its restricted
    caller, the revocation that removes access, and the reader, writer,
    and fresh-session factory."""

    cve: CVE
    caller: TicketCaller
    revoke: Executable
    reader: AsyncSession
    writer: AsyncSession
    sessions: SessionFactory

    async def read(self, *, fresh: bool = False) -> CVEAffectedVersionsResult:
        db = await self.sessions() if fresh else self.reader
        return await get_cve_affected_versions(db, self.caller, self.cve.cve_id)

    def replace_scope(self, *versions: str) -> tuple[Executable, ...]:
        """The physical delete-and-insert of the `cna` scope."""
        scope = (CVEAffectedVersion.cve_id == self.cve.id) & (
            CVEAffectedVersion.source_container == "cna"
        )
        return (
            delete(CVEAffectedVersion).where(scope),
            *(
                insert(CVEAffectedVersion).values(
                    cve_id=self.cve.id, source_container="cna", version=version
                )
                for version in versions
            ),
        )


@pytest.fixture
async def race(db_session_factory: SessionFactory) -> AsyncIterator[_Race]:
    world = _CommittedWorld(await db_session_factory())
    try:
        user, granter = await world.user(), await world.user()
        cve, ticket = await world.confidential_cve("1.0")
        await world.grant(ticket, user, granter)
        yield _Race(
            cve,
            _restricted(user),
            delete(TicketAccessGrant).where(TicketAccessGrant.ticket_id == ticket.id),
            await db_session_factory(),
            await db_session_factory(),
            db_session_factory,
        )
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Executable) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@pytest.mark.integration
class TestRaces:
    async def test_access_lost_before_the_protected_selection(
        self, race: _Race
    ) -> None:
        assert _versions(await race.read()) == {"cna": ["1.0"]}
        await _commit(race.writer, race.revoke)

        with pytest.raises(CVENotFoundError):
            await race.read()

    async def test_change_committed_after_the_read_never_mixes_snapshots(
        self, race: _Race, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A replacement and the access loss committed right after the
        reader's one statement returns: the read is the complete pre-change
        snapshot, while a fresh session observes the replacement only
        through a caller that keeps access."""
        original = race.reader.execute
        calls = [0]

        async def _execute(*args: Any, **kwargs: Any) -> Any:
            result = await original(*args, **kwargs)
            calls[0] += 1
            if calls[0] == 1:
                await _commit(
                    race.writer, *race.replace_scope("2.0", "3.0"), race.revoke
                )
            return result

        monkeypatch.setattr(race.reader, "execute", _execute)
        result = await race.read()

        assert calls == [1]
        assert _versions(result) == {"cna": ["1.0"]}
        with pytest.raises(CVENotFoundError):
            await race.read(fresh=True)
        fresh = await race.sessions()
        after = await get_cve_affected_versions(fresh, ALL_SCOPE, race.cve.cve_id)
        assert _versions(after) == {"cna": ["2.0", "3.0"]}
