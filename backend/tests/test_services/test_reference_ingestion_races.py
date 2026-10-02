"""Independent-session races of automatic Ticket reference ingestion
(`upsert_references()` in backend/app/services/reference_service.py)
against the manual reference operations and against another automatic
writer.

Owning specifications:

- docs/features/tickets/ticket-references.md (Automatic Ingestion >
  Database Merge Rules, the concurrency paragraphs; Mutability and
  Concurrency > Race Outcomes, the automatic bullets; Ticket Audit Events).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: "Automatic reference upsert").
- docs/features/platform/testing-strategy.md (Concurrency Testing and
  Lock-Wait Observation; Ticket References: "Audit, rollback, and
  concurrency", the manual/automatic race and forced unique-key conflict
  bullets).

`upsert_references()` acquires no Ticket lock: without a lock already held
by its caller, the unique key and its conflict-aware statement serialize it
against the other writer. The races therefore observe three waits:

- an automatic candidate whose identity has an uncommitted insert, update,
  or delete of another transaction waits at the unique key for that
  transaction (a transaction-ID wait, at the `INSERT ... ON CONFLICT`) and
  then takes the insert or update path against the committed outcome;
- an automatic candidate that meets a committed row locks that row, even
  when the manual-priority rule skips the update, so a later manual PATCH
  or DELETE of the row waits on the row lock after taking the Ticket lock;
- an automatic insert holds `FOR KEY SHARE` on the parent Ticket through
  its foreign-key check, so a later manual operation waits at its Ticket
  `FOR UPDATE`.

Covered here: manual create first against an automatic upsert of the same
normalized identity; automatic upsert against a committed manual row with
an identity-keeping PATCH in flight; a manual PATCH moving a reference to,
or away from, the automatic candidate's identity; manual DELETE against
automatic processing; automatic/automatic races of different and of the
same source; and the committed form of a forced automatic unique-key
conflict followed by further writes in the same transaction.

Covered elsewhere: the automatic-first manual create and manual URL change
races, both release orders (`TestAutomaticFirstRace` in
`tests/test_services/test_reference_service_atomicity.py`, whose automatic
row is written by `upsert_references()`), and the single-session merge,
preparation, and transaction-usability behavior
(`tests/test_services/test_reference_ingestion.py`).

Deferred to the CVE ingestion workflow tests: the race where `upsert_cve()`
already holds the Ticket lock through Ticket-associated CVSS processing (so
manual mutations serialize on that lock), and the per-CVE rollback injected
after Ticket creation, CVSS/severity, Product eligibility, lifecycle,
audit, source-success, and an earlier reference write.

Every race keeps the first session's transaction open after its call
returns, proves the second session blocked by the first with
`assert_lock_wait()` (never a sleep) at the statement the scenario names,
releases the first (commit or rollback), and waits for the second with a
bounded wait. Committed rows are deleted at teardown by `CommittedWorld`
(testing-strategy.md, Concurrency Testing); `ticket_reference` rows follow
by their `ON DELETE CASCADE` Ticket foreign key. Final rows and events are
read through an independent probe session. Expected values are transcribed
from the specifications, never computed with the module under test.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ReferenceType, Role, Scope
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.services.reference_service import (
    AutomaticReferenceInput,
    ManualReferenceCreateInput,
    ManualReferenceUpdateInput,
    TicketReferenceProjection,
    create_reference,
    delete_reference,
    update_reference,
    upsert_references,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.database import assert_lock_wait
from tests.support.suse_cvss_races import CommittedWorld, SessionStatementRecorder
from tests.support.ticket_mutations import EventRow, ticket_events_by_id

Factory = Callable[[], Awaitable[AsyncSession]]
Call = Callable[[AsyncSession], Awaitable[Any]]

AUTO_SOURCE = "sync_example_cves"
OTHER_SOURCE = "sync_other_cves"
"""Fictional stable automatic fetcher names (`BaseFetcher.name`)."""

CVE_ID = "CVE-2026-0001"

SEEDED_URL = "https://issues.example.test/tickets/1"
SEEDED_RAW_VARIANT = "HTTP://ISSUES.EXAMPLE.TEST/tickets/1"
"""Normalizes to `SEEDED_URL` (URL Normalization)."""

NEW_RAW_URL = "http://New.Example.TEST/advisories/7"
NEW_RAW_VARIANT = "HTTPS://NEW.EXAMPLE.TEST/advisories/7"
NEW_URL = "https://new.example.test/advisories/7"
"""Both raw forms normalize to `NEW_URL`."""

SPARE_URL = "https://spare.example.test/notes/3"
"""An unrelated identity used to prove a transaction is still usable."""

UPSTREAM_TITLE = "Fictional upstream advisory"
MANUAL_DESCRIPTION = "Fictional analyst context"

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
"""The backdated `created_at` and `updated_at` of seeded rows."""

REFERENCE_INSERT = "INSERT INTO ticket_reference"
REFERENCE_UPDATE = "UPDATE ticket_reference"
REFERENCE_DELETE = "DELETE FROM ticket_reference"
WRITE_PREFIXES = ("INSERT", "UPDATE", "DELETE")

TICKET_STATEMENT = re.compile(r"\b(?:FROM|JOIN|INTO|UPDATE) ticket\b")
WAIT = 5
"""Upper bound, in seconds, of every wait that is expected to finish."""


# ---------------------------------------------------------------------------
# Committed world and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: Factory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


@pytest.fixture
async def probe(world: CommittedWorld) -> AsyncSession:
    """An independent session that only observes committed state."""
    return await world.open_session()


@dataclass(frozen=True, slots=True)
class RefRow:
    """One persisted reference, as stored (keyed by its URL)."""

    id: uuid.UUID
    title: str | None
    description: str | None
    type: str | None
    source: str
    created_at: datetime
    updated_at: datetime

    @property
    def fields(self) -> tuple[str | None, str | None, str | None, str]:
        """`(title, description, type, source)`."""
        return self.title, self.description, self.type, self.source


Committed = tuple[dict[str, RefRow], list[EventRow]]
"""The committed references of a Ticket keyed by URL, and its audit events
in insertion order."""


async def _committed(probe: AsyncSession, ticket: Ticket) -> Committed:
    result = await probe.execute(
        select(
            TicketReference.url,
            TicketReference.id,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    rows = {r.url: RefRow(*r[1:]) for r in result}
    events = await ticket_events_by_id(probe, ticket.id)
    await probe.rollback()
    return rows, events


async def _ticket(world: CommittedWorld) -> Ticket:
    """A committed CVE-less `Analysis` Ticket registered for cleanup."""
    return await world.ticket(cve_id=None)


async def _actor(world: CommittedWorld) -> User:
    return await world.user(role=Role.VULNERABILITY_ANALYST)


async def _seed(
    world: CommittedWorld,
    ticket: Ticket,
    *,
    url: str = SEEDED_URL,
    title: str | None = None,
    description: str | None = MANUAL_DESCRIPTION,
    type: str | None = None,
    source: str = "manual",
) -> uuid.UUID:
    """A committed reference with backdated timestamps. The manual default
    leaves `title` and `type` `NULL`, so any automatic fill would show."""
    reference = TicketReference(
        ticket_id=ticket.id,
        url=url,
        title=title,
        description=description,
        type=type,
        source=source,
        created_at=PAST,
        updated_at=PAST,
    )
    world.session.add(reference)
    await world.session.commit()
    return reference.id


def _caller(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.ALL)


def _locator(ticket: Ticket) -> str:
    """The canonical `SNTL-{n}` locator, built literally."""
    return f"SNTL-{ticket.sequence_id}"


def _auto(
    ticket: Ticket,
    url: str,
    *,
    source: str = AUTO_SOURCE,
    title: str | None = UPSTREAM_TITLE,
    type: ReferenceType | None = ReferenceType.ADVISORY,
) -> Call:
    """One automatic upstream candidate; none of the URLs above matches a
    URL Pattern Mapping row, so `type` is exactly the explicit hint."""
    candidate = AutomaticReferenceInput(url=url, title=title, explicit_type=type)

    def call(db: AsyncSession) -> Awaitable[None]:
        return upsert_references(db, ticket.id, CVE_ID, source, None, [candidate])

    return call


def _create(ticket: Ticket, actor: User, url: str, **fields: Any) -> Call:
    def call(db: AsyncSession) -> Awaitable[TicketReferenceProjection]:
        return create_reference(
            db,
            _locator(ticket),
            _caller(actor),
            ManualReferenceCreateInput(url=url, **fields),
        )

    return call


def _update(
    ticket: Ticket, reference_id: uuid.UUID, actor: User, **fields: Any
) -> Call:
    def call(db: AsyncSession) -> Awaitable[TicketReferenceProjection]:
        return update_reference(
            db,
            _locator(ticket),
            reference_id,
            _caller(actor),
            ManualReferenceUpdateInput(**fields),
        )

    return call


def _delete(ticket: Ticket, reference_id: uuid.UUID, actor: User) -> Call:
    def call(db: AsyncSession) -> Awaitable[None]:
        return delete_reference(db, _locator(ticket), reference_id, _caller(actor))

    return call


def _added(actor: User, url: str) -> EventRow:
    return EventRow("reference_added", actor.id, None, url, None, None)


def _deleted(actor: User, url: str) -> EventRow:
    return EventRow("reference_deleted", actor.id, url, None, None, None)


def _url_changed(actor: User, old: str, new: str) -> EventRow:
    return EventRow("reference_url_changed", actor.id, old, new, None, None)


def _title_changed(actor: User, old: str | None, new: str | None, url: str) -> EventRow:
    return EventRow("reference_title_changed", actor.id, old, new, None, {"url": url})


def _is_ticket_lock(statement: str) -> bool:
    return TICKET_STATEMENT.search(
        statement
    ) is not None and statement.rstrip().endswith("FOR UPDATE")


def _assert_waiting_at(statements: list[str], prefix: str) -> None:
    """The statement PostgreSQL holds is the waiter's last one, starts with
    `prefix`, and is the waiter's only write so far.

    An automatic waiter waits at its first and only statement, the
    candidate's `INSERT ... ON CONFLICT`. A manual waiter has already been
    granted the Ticket `FOR UPDATE` (its first statement) and waits on the
    reference row."""
    assert statements[-1].lstrip().startswith(prefix)
    writes = [s for s in statements if s.lstrip().upper().startswith(WRITE_PREFIXES)]
    assert writes == [statements[-1]]
    if prefix == REFERENCE_INSERT:
        assert len(statements) == 1
    else:
        assert _is_ticket_lock(statements[0])


@dataclass
class _Race:
    first_result: Any
    second: AsyncSession
    task: asyncio.Task[Any]


async def _race(
    world: CommittedWorld,
    first: Call,
    then: Call,
    *,
    waits_at: str,
    release: str = "commit",
) -> _Race:
    """Run `first` in a holder session and keep its transaction open,
    start `then` in a waiter session, prove the waiter blocked by the
    holder at the `waits_at` statement, release the holder (`commit` or
    `rollback`), and wait for the waiter to finish. The waiter's
    transaction is left open.

    The holder has finished every statement before the waiter starts, so
    the holder never waits on the waiter and no lock cycle can form."""
    holder = await world.open_session()
    waiter = await world.open_session()
    first_result = await first(holder)
    with SessionStatementRecorder(waiter) as recorder:
        task: asyncio.Task[Any] = world.start(waiter, then(waiter))
        await assert_lock_wait(task, waiter=waiter, blocked_by=holder)
        _assert_waiting_at(recorder.statements, waits_at)
        if release == "commit":
            await holder.commit()
        else:
            await holder.rollback()
        done, _pending = await asyncio.wait({task}, timeout=WAIT)
        assert task in done
    return _Race(first_result, waiter, task)


# ---------------------------------------------------------------------------
# Manual create first (Race Outcomes: "If the manual row owns the normalized
# URL first, automatic upsert observes a manual winner and leaves every
# field untouched")
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestManualCreateFirst:
    """The manual create holds the Ticket lock and its uncommitted row; the
    automatic candidate, another raw form of the same normalized URL, waits
    at the unique key for the manual transaction. The manual row leaves
    `title` and `type` `NULL`, so any automatic fill would show."""

    async def test_committed_manual_winner_is_left_untouched(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)

        race = await _race(
            world,
            _create(
                ticket, actor, NEW_RAW_URL, description=MANUAL_DESCRIPTION, type=None
            ),
            _auto(ticket, NEW_RAW_VARIANT),
            waits_at=REFERENCE_INSERT,
        )

        assert race.task.result() is None
        await race.second.commit()
        created = race.first_result
        assert await _committed(probe, ticket) == (
            {
                NEW_URL: RefRow(
                    created.id,
                    None,
                    MANUAL_DESCRIPTION,
                    None,
                    "manual",
                    created.created_at,
                    created.updated_at,
                )
            },
            [_added(actor, NEW_URL)],
        )

    async def test_rolled_back_manual_create_lets_automatic_insert_as_owner(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)

        race = await _race(
            world,
            _create(
                ticket, actor, NEW_RAW_URL, description=MANUAL_DESCRIPTION, type=None
            ),
            _auto(ticket, NEW_RAW_VARIANT),
            waits_at=REFERENCE_INSERT,
            release="rollback",
        )

        assert race.task.result() is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [NEW_URL]
        assert rows[NEW_URL].fields == (UPSTREAM_TITLE, None, "advisory", AUTO_SOURCE)
        assert events == []


# ---------------------------------------------------------------------------
# Committed manual row with an identity-keeping PATCH in flight (Race
# Outcomes: "Automatic upsert that observes an existing manual row while a
# PATCH keeps that identity has no effect")
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIdentityKeepingPatch:
    @pytest.mark.parametrize("order", ["patch-first", "automatic-first"])
    async def test_automatic_upsert_leaves_the_manual_row_untouched(
        self, world: CommittedWorld, probe: AsyncSession, order: str
    ) -> None:
        """PATCH first: the automatic candidate waits at the unique key for
        the PATCH transaction and then skips the PATCHed manual row.
        Automatic first: its conflict locks the manual row without changing
        it, and the PATCH, holding the Ticket lock, waits on that row lock
        and then applies. Either way the row carries exactly the PATCHed
        values and the PATCH's single event."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)
        patch = _update(ticket, reference_id, actor, title="Patched title")
        automatic = _auto(ticket, SEEDED_RAW_VARIANT)

        if order == "patch-first":
            race = await _race(world, patch, automatic, waits_at=REFERENCE_INSERT)
            patched, automatic_result = race.first_result, race.task.result()
        else:
            race = await _race(world, automatic, patch, waits_at=REFERENCE_UPDATE)
            patched, automatic_result = race.task.result(), race.first_result

        assert automatic_result is None
        assert (patched.title, patched.type) == ("Patched title", None)
        assert patched.updated_at > PAST
        await race.second.commit()
        assert await _committed(probe, ticket) == (
            {
                SEEDED_URL: RefRow(
                    reference_id,
                    "Patched title",
                    MANUAL_DESCRIPTION,
                    None,
                    "manual",
                    PAST,
                    patched.updated_at,
                )
            },
            [_title_changed(actor, None, "Patched title", SEEDED_URL)],
        )


# ---------------------------------------------------------------------------
# Manual URL change (Race Outcomes: "If a manual PATCH moves a reference away
# from an identity ..."; "For a PATCH moving to the automatic candidate's
# identity, ... manual first owns that identity and causes automatic fill
# behavior to skip the manual winner")
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestManualUrlChange:
    @pytest.mark.parametrize("release", ["commit", "rollback"])
    async def test_patch_moving_to_the_candidate_identity_first(
        self, world: CommittedWorld, probe: AsyncSession, release: str
    ) -> None:
        """The automatic candidate waits at the unique key for the PATCH's
        uncommitted new identity. After commit the moved manual row wins
        and stays untouched; after rollback the automatic candidate
        inserts as owner beside the unmoved manual row."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)
        before, _ = await _committed(probe, ticket)

        race = await _race(
            world,
            _update(ticket, reference_id, actor, url=NEW_RAW_URL),
            _auto(ticket, NEW_RAW_VARIANT),
            waits_at=REFERENCE_INSERT,
            release=release,
        )

        assert race.task.result() is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        if release == "commit":
            moved = race.first_result
            assert rows == {
                NEW_URL: RefRow(
                    reference_id,
                    None,
                    MANUAL_DESCRIPTION,
                    None,
                    "manual",
                    PAST,
                    moved.updated_at,
                )
            }
            assert events == [_url_changed(actor, SEEDED_URL, NEW_URL)]
        else:
            assert set(rows) == {SEEDED_URL, NEW_URL}
            assert rows[SEEDED_URL] == before[SEEDED_URL]
            assert rows[NEW_URL].fields == (
                UPSTREAM_TITLE,
                None,
                "advisory",
                AUTO_SOURCE,
            )
            assert events == []

    @pytest.mark.parametrize("order", ["patch-first", "automatic-first"])
    async def test_patch_moving_away_from_the_candidate_identity(
        self, world: CommittedWorld, probe: AsyncSession, order: str
    ) -> None:
        """PATCH first: the automatic candidate for the old URL waits at the
        unique key for the PATCH and, once the move commits, creates an
        automatic row at the old URL. Automatic first: its conflict locks
        the manual row without changing it, the PATCH waits on that row
        lock and then moves the row, leaving no row at the old URL."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)
        move = _update(ticket, reference_id, actor, url=NEW_RAW_URL)
        automatic = _auto(ticket, SEEDED_RAW_VARIANT)

        if order == "patch-first":
            race = await _race(world, move, automatic, waits_at=REFERENCE_INSERT)
            moved, automatic_result = race.first_result, race.task.result()
        else:
            race = await _race(world, automatic, move, waits_at=REFERENCE_UPDATE)
            moved, automatic_result = race.task.result(), race.first_result

        assert automatic_result is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        assert rows[NEW_URL] == RefRow(
            reference_id,
            None,
            MANUAL_DESCRIPTION,
            None,
            "manual",
            PAST,
            moved.updated_at,
        )
        if order == "patch-first":
            assert set(rows) == {NEW_URL, SEEDED_URL}
            assert rows[SEEDED_URL].id != reference_id
            assert rows[SEEDED_URL].fields == (
                UPSTREAM_TITLE,
                None,
                "advisory",
                AUTO_SOURCE,
            )
        else:
            assert set(rows) == {NEW_URL}
        assert events == [_url_changed(actor, SEEDED_URL, NEW_URL)]


# ---------------------------------------------------------------------------
# Manual delete (Race Outcomes: "If manual DELETE commits before automatic
# processing of that URL, automatic upsert may create an automatic row. If
# automatic processing serializes against the existing manual row first, it
# leaves that row untouched and the later delete removes it")
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestManualDelete:
    @pytest.mark.parametrize("order", ["delete-first", "automatic-first"])
    async def test_final_state_follows_the_serialization(
        self, world: CommittedWorld, probe: AsyncSession, order: str
    ) -> None:
        actor = await _actor(world)
        ticket = await _ticket(world)
        reference_id = await _seed(world, ticket)
        delete = _delete(ticket, reference_id, actor)
        automatic = _auto(ticket, SEEDED_RAW_VARIANT)

        if order == "delete-first":
            race = await _race(world, delete, automatic, waits_at=REFERENCE_INSERT)
            deleted, automatic_result = race.first_result, race.task.result()
        else:
            race = await _race(world, automatic, delete, waits_at=REFERENCE_DELETE)
            deleted, automatic_result = race.task.result(), race.first_result

        assert deleted is None
        assert automatic_result is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        if order == "delete-first":
            assert list(rows) == [SEEDED_URL]
            assert rows[SEEDED_URL].id != reference_id
            assert rows[SEEDED_URL].fields == (
                UPSTREAM_TITLE,
                None,
                "advisory",
                AUTO_SOURCE,
            )
        else:
            assert rows == {}
        assert events == [_deleted(actor, SEEDED_URL)]


# ---------------------------------------------------------------------------
# Automatic/automatic (Database Merge Rules: "Concurrent automatic writers
# may serialize in either order. The transaction that creates a new
# identity first owns `source`; the other observes that current row and
# applies same-source or different-source rules")
# ---------------------------------------------------------------------------

_DIFFERENT_SOURCE_CASES = [
    pytest.param(
        AUTO_SOURCE,
        "commit",
        ("Example title", None, "patch", AUTO_SOURCE),
        True,
        id="example-first-commit",
    ),
    pytest.param(
        OTHER_SOURCE,
        "commit",
        ("Other title", None, "patch", OTHER_SOURCE),
        False,
        id="other-first-commit",
    ),
    pytest.param(
        AUTO_SOURCE,
        "rollback",
        ("Other title", None, "patch", OTHER_SOURCE),
        False,
        id="example-first-rollback",
    ),
    pytest.param(
        OTHER_SOURCE,
        "rollback",
        ("Example title", None, None, AUTO_SOURCE),
        False,
        id="other-first-rollback",
    ),
]
"""`(first source, release, final fields, filled)`. The `AUTO_SOURCE`
candidate supplies only a title; the `OTHER_SOURCE` candidate supplies a
title and `patch`. The committed first creator owns `source` and keeps its
non-NULL title; the other source fills only its `NULL` type (`filled`: an
effective update that advances `updated_at`). After a rollback the second
inserts its own candidate as owner."""


@pytest.mark.integration
class TestAutomaticRaces:
    @pytest.mark.parametrize(
        ("first_source", "release", "expected", "filled"), _DIFFERENT_SOURCE_CASES
    )
    async def test_different_sources_first_creator_owns_the_source(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        first_source: str,
        release: str,
        expected: tuple[str | None, str | None, str | None, str],
        filled: bool,
    ) -> None:
        ticket = await _ticket(world)
        candidates = {
            AUTO_SOURCE: _auto(
                ticket,
                NEW_RAW_URL,
                source=AUTO_SOURCE,
                title="Example title",
                type=None,
            ),
            OTHER_SOURCE: _auto(
                ticket,
                NEW_RAW_VARIANT,
                source=OTHER_SOURCE,
                title="Other title",
                type=ReferenceType.PATCH,
            ),
        }
        second_source = OTHER_SOURCE if first_source == AUTO_SOURCE else AUTO_SOURCE

        race = await _race(
            world,
            candidates[first_source],
            candidates[second_source],
            waits_at=REFERENCE_INSERT,
            release=release,
        )

        assert race.first_result is None
        assert race.task.result() is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [NEW_URL]
        row = rows[NEW_URL]
        assert row.fields == expected
        if filled:
            assert row.updated_at > row.created_at
        else:
            assert row.updated_at == row.created_at
        assert events == []

    @pytest.mark.parametrize("release", ["commit", "rollback"])
    @pytest.mark.parametrize("initial", ["absent", "existing"])
    async def test_same_source_writes_apply_in_serialization_order(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        initial: str,
        release: str,
    ) -> None:
        """The first write supplies a title and `advisory`; the second
        supplies only `patch`. Serialized first-then-second, the second's
        non-NULL type replaces the first's and its absent title clears
        nothing. The identity is either new (both insert) or an existing
        same-source row (both update it). After a rollback only the
        second write applies, to the absent or seeded row."""
        ticket = await _ticket(world)
        seeded_id: uuid.UUID | None = None
        if initial == "existing":
            seeded_id = await _seed(
                world,
                ticket,
                url=NEW_URL,
                title="Seeded title",
                description=None,
                type="issue",
                source=AUTO_SOURCE,
            )

        race = await _race(
            world,
            _auto(
                ticket, NEW_RAW_URL, title="First title", type=ReferenceType.ADVISORY
            ),
            _auto(ticket, NEW_RAW_VARIANT, title=None, type=ReferenceType.PATCH),
            waits_at=REFERENCE_INSERT,
            release=release,
        )

        assert race.first_result is None
        assert race.task.result() is None
        await race.second.commit()
        rows, events = await _committed(probe, ticket)
        assert list(rows) == [NEW_URL]
        row = rows[NEW_URL]
        expected_title = {
            ("absent", "commit"): "First title",
            ("existing", "commit"): "First title",
            ("absent", "rollback"): None,
            ("existing", "rollback"): "Seeded title",
        }[(initial, release)]
        assert row.fields == (expected_title, None, "patch", AUTO_SOURCE)
        if seeded_id is not None:
            assert (row.id, row.created_at) == (seeded_id, PAST)
            assert row.updated_at > PAST
        assert events == []


# ---------------------------------------------------------------------------
# Forced automatic unique-key conflict, committed form (testing-strategy.md:
# "A subsequent reference and unrelated per-CVE write in that same
# transaction must flush and commit successfully")
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestForcedConflictKeepsTheTransactionUsable:
    @pytest.mark.parametrize("winner", ["same-source", "other-source", "manual"])
    async def test_waiting_upsert_then_further_writes_commit(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        winner: str,
    ) -> None:
        """The waiting upsert reaches the unique key against the winner's
        uncommitted row and, after the winner commits, merges (same
        source), fills (other source), or skips (manual) without aborting
        its transaction: a later reference upsert and an unrelated Ticket
        write in that transaction flush and commit."""
        actor = await _actor(world)
        ticket = await _ticket(world)
        first = {
            "same-source": _auto(ticket, NEW_RAW_URL, title="Winner title", type=None),
            "other-source": _auto(
                ticket,
                NEW_RAW_URL,
                source=OTHER_SOURCE,
                title="Winner title",
                type=None,
            ),
            "manual": _create(
                ticket,
                actor,
                NEW_RAW_URL,
                title="Winner title",
                description=MANUAL_DESCRIPTION,
                type=None,
            ),
        }[winner]

        race = await _race(
            world,
            first,
            _auto(ticket, NEW_RAW_VARIANT, title="Waiter title"),
            waits_at=REFERENCE_INSERT,
        )

        assert race.task.result() is None
        await _auto(ticket, SPARE_URL, title="Spare title", type=None)(race.second)
        await race.second.execute(
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True)
        )
        await race.second.flush()
        await race.second.commit()

        rows, events = await _committed(probe, ticket)
        assert set(rows) == {NEW_URL, SPARE_URL}
        assert (
            rows[NEW_URL].fields
            == {
                "same-source": ("Waiter title", None, "advisory", AUTO_SOURCE),
                "other-source": ("Winner title", None, "advisory", OTHER_SOURCE),
                "manual": ("Winner title", MANUAL_DESCRIPTION, None, "manual"),
            }[winner]
        )
        assert rows[SPARE_URL].fields == ("Spare title", None, None, AUTO_SOURCE)
        assert events == ([_added(actor, NEW_URL)] if winner == "manual" else [])
        confidential = await probe.scalar(
            select(Ticket.is_confidential).where(Ticket.id == ticket.id)
        )
        await probe.rollback()
        assert confidential is True
