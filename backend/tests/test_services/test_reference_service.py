"""Single-session service integration tests for the manual Ticket
reference operations (backend/app/services/reference_service.py):
`create_reference()`, `update_reference()`, `delete_reference()`, and
`list_references()`.

Owning specifications:

- docs/features/tickets/ticket-references.md (Semantic Types; URL
  Normalization, including the title and description rules; Type
  Auto-Classification; Mutability and Concurrency > Manual-Zone Exception
  and Manual Mutation Ordering; Service Layer > Service Exceptions,
  `create_reference()`, `update_reference()`, `delete_reference()`,
  `list_references()`; Ticket Audit Events; Security and Privacy).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract and
  detail JSONB Schema Contract rows `reference_added`,
  `reference_deleted`, `reference_url_changed`, `reference_type_changed`,
  `reference_title_changed`, `reference_description_changed`; Canonical
  Mutation and No-Event Matrix: "Manual reference create/update/delete";
  Testing Requirements 1-7, 12, 22, and 25).
- docs/features/platform/testing-strategy.md (Ticket References, manual
  parts; Ticket Accessibility > Single, nested, and assembled reads and
  Locked mutations, single-session parts; Audit Trail Testing).

Testing Requirement 25 (no mutation or authorization path reads Ticket
audit history as current state) is enforced structurally by
`tests/test_architecture/test_ticket_accessibility.py` and is not
duplicated here; the tests below only observe that the event rows are
outputs of the operations.

Out of scope here:

- automatic ingestion (`upsert_references()`), which is not implemented
  by this work item;
- the pure URL boundary (`tests/test_core/test_reference_urls.py`) and
  the URL-pattern table (`tests/test_services/test_reference_classification.py`),
  which are exercised here only through representative service inputs;
- the locator grammar and lock helper matrix
  (`tests/test_services/test_lock_accessible_ticket_by_locator.py`);
- independent-session races, injected failure atomicity, caller
  rollback, and the committed cross-transaction `updated_at` proof,
  which belong to the atomicity tests; and
- the HTTP contract (capability check, status codes, envelopes), which
  belongs to the e2e tier.

`created_at` and `updated_at` use PostgreSQL `now()`, the start time of
the single test transaction, so a no-op is proven here by the absence of
any write statement and event rather than by an unchanged `updated_at`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import PackageStatus, ReferenceType, Scope, TicketStatus
from app.core.exceptions import ServiceError, TicketNotFoundError
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.ticket_package_product import TicketPackageProduct
from app.models.ticket_package_track import TicketPackageTrack
from app.models.ticket_reference import TicketReference
from app.models.user import User
from app.services import ticket_convergence_registry, ticket_mutations
from app.services.reference_service import (
    UNSET,
    ManualReferenceCreateInput,
    ManualReferenceUpdateInput,
    ReferenceConflictError,
    ReferenceNotEditableError,
    ReferenceNotFoundError,
    ReferenceServiceError,
    TicketReferenceProjection,
    create_reference,
    delete_reference,
    list_references,
    update_reference,
)
from app.services.ticket_convergence_registry import (
    pending_ticket_convergence_effects,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.no_outbound import OutboundGuard
from tests.support.ticket_api import MAX_SEQUENCE
from tests.support.ticket_mutations import (
    EventRow,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    UserFactory,
    VAUser,
    cveless,
    ticket_events_by_id,
)

pytest_plugins = [
    "tests.support.ticket_mutation_fixtures",
    "tests.support.no_outbound_fixtures",
]
"""Provides the shared `va_user` and `tree` fixtures and the `no_outbound`
guard."""

ReferenceFactory = Callable[..., Awaitable[TicketReference]]
GrantFactory = Callable[..., Awaitable[TicketAccessGrant]]
PackageFactory = Callable[..., Awaitable[TicketPackage]]
MaintainerFactory = Callable[..., Awaitable[TicketPackageMaintainer]]

ALL_STATUSES = [
    TicketStatus.NEW,
    TicketStatus.ANALYSIS,
    TicketStatus.ANALYZED,
    TicketStatus.RESOLVED,
    TicketStatus.IGNORED,
    TicketStatus.DUPLICATED,
]

MUTATIONS = ["create", "update", "delete"]
OPERATIONS = [*MUTATIONS, "list"]

AUTO_SOURCE = "sync_example_cves"
"""A fictional stable automatic fetcher name (ticket-references.md,
TicketReference: `source`)."""

SEEDED_URL = "https://issues.example.test/tickets/1"
SEEDED_RAW_VARIANT = "HTTP://ISSUES.EXAMPLE.TEST/tickets/1"
"""Normalizes to `SEEDED_URL` (URL Normalization steps 4-5)."""

NEW_RAW_URL = "http://Issues.Example.TEST/tickets/2"
NEW_URL = "https://issues.example.test/tickets/2"

GITHUB_COMMIT_URL = "https://github.com/example-org/example-repo/commit/0123abcd"
"""A URL whose pattern classification is `patch` (URL Pattern Mapping)."""

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)

FORBIDDEN_MUTATIONS = (
    "ensure_ticket_operable",
    "auto_assign_actor",
    "reconcile_ticket_status",
    "stabilize_acting_user",
    "refresh_priority_auto",
    "recalculate_cvss_chain",
)
"""`ticket_mutations` collaborators a manual reference mutation never calls
(ticket-references.md, Manual-Zone Exception: no operability guard,
assignment, reconciliation, or status change)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RefRow:
    """One persisted reference, as stored."""

    id: uuid.UUID
    url: str
    title: str | None
    description: str | None
    type: str | None
    source: str
    created_at: datetime
    updated_at: datetime


def _locator(ticket: Ticket) -> str:
    """The canonical `SNTL-{n}` locator, built literally."""
    return f"SNTL-{ticket.sequence_id}"


def _caller(user: User, scope: Scope = Scope.ALL) -> TicketCaller:
    return TicketCaller.authenticated(user.id, scope)


def _added(actor: User, url: str) -> EventRow:
    """`reference_added`: `old_value` `NULL`, `new_value` the normalized
    URL, `comment` and `detail` `NULL`."""
    return EventRow("reference_added", actor.id, None, url, None, None)


def _deleted(actor: User, url: str) -> EventRow:
    """`reference_deleted`: `old_value` the normalized URL, `new_value`,
    `comment`, and `detail` `NULL`."""
    return EventRow("reference_deleted", actor.id, url, None, None, None)


def _url_changed(actor: User, old: str, new: str) -> EventRow:
    """`reference_url_changed`: both URLs, `detail` `NULL`."""
    return EventRow("reference_url_changed", actor.id, old, new, None, None)


def _field_changed(
    field: str, actor: User, old: str | None, new: str | None, url: str
) -> EventRow:
    """`reference_{type,title,description}_changed`: `detail` carries the
    post-update normalized URL."""
    return EventRow(
        f"reference_{field}_changed", actor.id, old, new, None, {"url": url}
    )


async def _rows(db: AsyncSession, ticket_id: uuid.UUID) -> dict[uuid.UUID, RefRow]:
    """Every persisted reference of the Ticket, keyed by id."""
    result = await db.execute(
        select(
            TicketReference.id,
            TicketReference.url,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket_id)
    )
    return {r.id: RefRow(*r) for r in result}


async def _row(db: AsyncSession, reference_id: uuid.UUID) -> RefRow | None:
    result = await db.execute(
        select(
            TicketReference.id,
            TicketReference.url,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.id == reference_id)
    )
    row = result.one_or_none()
    return None if row is None else RefRow(*row)


def _projection_of(row: RefRow, ticket: Ticket) -> TicketReferenceProjection:
    """The expected projection of a persisted row (Semantic Types,
    TicketReferenceProjection)."""
    return TicketReferenceProjection(
        id=row.id,
        ticket_id=_locator(ticket),
        url=row.url,
        title=row.title,
        description=row.description,
        type=None if row.type is None else ReferenceType(row.type),
        source=row.source,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _transaction_now(db: AsyncSession) -> datetime:
    """PostgreSQL `now()`, the value every `server_default=func.now()` and
    `onupdate=func.now()` receives inside this test's transaction."""
    return (await db.execute(select(func.now()))).scalar_one()


def _data_writes(recorder: StatementRecorder) -> list[str]:
    """`"<VERB> <table>"` for each recorded data write, ignoring the
    savepoint control statements a flush may emit."""
    out: list[str] = []
    for statement in recorder.writes():
        words = statement.split()
        verb = words[0].upper()
        if verb in {"SAVEPOINT", "RELEASE", "ROLLBACK"}:
            continue
        table = words[2] if verb in {"INSERT", "DELETE"} else words[1]
        out.append(f"{verb} {table}")
    return out


def _forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every forbidden collaborator with a failing recorder."""
    calls: list[str] = []

    def _recorder(name: str) -> Callable[..., Any]:
        def _called(*_args: Any, **_kwargs: Any) -> Any:
            calls.append(name)
            raise AssertionError(f"{name} must not be called")

        return _called

    for name in FORBIDDEN_MUTATIONS:
        monkeypatch.setattr(ticket_mutations, name, _recorder(name))
    monkeypatch.setattr(
        ticket_convergence_registry,
        "register_ticket_convergence",
        _recorder("register_ticket_convergence"),
    )
    return calls


async def _seed(
    ticket_reference_factory: ReferenceFactory,
    ticket: Ticket,
    *,
    url: str = SEEDED_URL,
    title: str | None = "Original title",
    description: str | None = "Original description",
    type: str | None = "issue",
    source: str = "manual",
    **overrides: Any,
) -> TicketReference:
    """A persisted reference with fully populated defaults."""
    return await ticket_reference_factory(
        ticket_id=ticket.id,
        url=url,
        title=title,
        description=description,
        type=type,
        source=source,
        **overrides,
    )


async def _create(
    db: AsyncSession, ticket: Ticket, actor: User, **fields: Any
) -> TicketReferenceProjection:
    return await create_reference(
        db, _locator(ticket), _caller(actor), ManualReferenceCreateInput(**fields)
    )


async def _update(
    db: AsyncSession,
    ticket: Ticket,
    reference_id: uuid.UUID,
    actor: User,
    **fields: Any,
) -> TicketReferenceProjection:
    return await update_reference(
        db,
        _locator(ticket),
        reference_id,
        _caller(actor),
        ManualReferenceUpdateInput(**fields),
    )


async def _invoke(
    op: str,
    db: AsyncSession,
    locator: str,
    caller: TicketCaller,
    reference_id: uuid.UUID,
) -> Any:
    """Call one of the four operations with a valid, effective input."""
    if op == "create":
        return await create_reference(
            db,
            locator,
            caller,
            ManualReferenceCreateInput(url="https://issues.example.test/tickets/new"),
        )
    if op == "update":
        return await update_reference(
            db,
            locator,
            reference_id,
            caller,
            ManualReferenceUpdateInput(title="Changed title"),
        )
    if op == "delete":
        return await delete_reference(db, locator, reference_id, caller)
    return await list_references(
        db, locator, caller, source=None, type=None, type_was_supplied=False
    )


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptionHierarchy:
    def test_module_base_is_a_service_error(self) -> None:
        """Service Exceptions: `ReferenceServiceError` inherits from
        `ServiceError`."""
        assert issubclass(ReferenceServiceError, ServiceError)

    @pytest.mark.parametrize(
        "error_type",
        [ReferenceNotFoundError, ReferenceNotEditableError, ReferenceConflictError],
    )
    def test_every_module_exception_is_a_reference_service_error(
        self, error_type: type[Exception]
    ) -> None:
        assert issubclass(error_type, ReferenceServiceError)
        assert issubclass(error_type, ServiceError)

    def test_shared_ticket_not_found_is_caught_separately(self) -> None:
        """† Shared exception; not a subclass of `ReferenceServiceError`."""
        assert issubclass(TicketNotFoundError, ServiceError)
        assert not issubclass(TicketNotFoundError, ReferenceServiceError)


# ---------------------------------------------------------------------------
# Input-only validation (before any database access)
# ---------------------------------------------------------------------------

_BAD_URLS: list[tuple[str, object]] = [
    ("non-string", 12345),
    ("empty", ""),
    ("ftp-scheme", "ftp://files.example.com/archive"),
    ("relative", "/tickets/1"),
    ("hostless", "https://"),
    ("username-only", "https://reviewer@example.com/path"),
    ("username-password", "https://reviewer:secret@example.com/path"),
    ("nul-control", "https://example.com/a\x00b"),
    ("del-control", "https://example.com/a\x7fb"),
    ("tab-control", "https://example.com/a\tb"),
    ("too-long", "https://example.com/" + "a" * 2029),
]
"""URL Normalization steps 1-3 and 6 rejections. `too-long` is 2049
characters."""

_BAD_TITLES: list[tuple[str, object]] = [
    ("non-string", 5),
    ("empty", ""),
    ("space", " "),
    ("two-spaces", "  "),
    ("tab", "\t"),
    ("too-long", "x" * 501),
]

_BAD_DESCRIPTIONS: list[tuple[str, object]] = [
    ("non-string", 5),
    ("empty", ""),
    ("two-spaces", "  "),
    ("tab", "\t"),
    ("too-long", "y" * 2001),
]

_BAD_TYPES: list[tuple[str, object]] = [
    ("plain-string", "patch"),
    ("integer", 1),
]
"""Not a `ReferenceType` member (Semantic Types)."""


def _subject(case_id: str) -> str:
    """A case-insensitive pattern naming the rejected subject, so a
    `ValueError` raised for another reason does not satisfy the case."""
    if case_id == "all-omitted":
        return r"^At least one field must be provided\.$"
    return r"(?i)" + case_id.split("-", 1)[0]


_CREATE_INVALID: list[tuple[str, dict[str, Any]]] = [
    *((f"url-{n}", {"url": v}) for n, v in _BAD_URLS),
    *((f"title-{n}", {"url": SEEDED_URL, "title": v}) for n, v in _BAD_TITLES),
    *(
        (f"description-{n}", {"url": SEEDED_URL, "description": v})
        for n, v in _BAD_DESCRIPTIONS
    ),
    *((f"type-{n}", {"url": SEEDED_URL, "type": v}) for n, v in _BAD_TYPES),
]

_UPDATE_INVALID: list[tuple[str, dict[str, Any]]] = [
    ("all-omitted", {}),
    ("url-null", {"url": None}),
    ("url-null-with-title", {"url": None, "title": "Valid title"}),
    *((f"url-{n}", {"url": v}) for n, v in _BAD_URLS),
    *((f"title-{n}", {"title": v}) for n, v in _BAD_TITLES),
    *((f"description-{n}", {"description": v}) for n, v in _BAD_DESCRIPTIONS),
    *((f"type-{n}", {"type": v}) for n, v in _BAD_TYPES),
]


@pytest.mark.integration
class TestInputValidation:
    @pytest.mark.parametrize(
        ("case_id", "fields"), _CREATE_INVALID, ids=[n for n, _ in _CREATE_INVALID]
    )
    async def test_create_rejects_invalid_input_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        case_id: str,
        fields: dict[str, Any],
    ) -> None:
        """URL Normalization (manual callers receive `ValueError`) and
        Manual Mutation Ordering (input-only validation may complete before
        database access)."""
        actor = await va_user()
        ticket = await ticket_factory()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=_subject(case_id)),
        ):
            await _create(db_session, ticket, actor, **fields)

        assert recorder.statements == []
        assert await _rows(db_session, ticket.id) == {}
        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize(
        ("case_id", "fields"), _UPDATE_INVALID, ids=[n for n, _ in _UPDATE_INVALID]
    )
    async def test_update_rejects_invalid_input_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        case_id: str,
        fields: dict[str, Any],
    ) -> None:
        """ManualReferenceUpdateInput: at least one field; `url` cannot be
        `null`; every supplied value obeys the shared boundary."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=_subject(case_id)),
        ):
            await _update(db_session, ticket, reference.id, actor, **fields)

        assert recorder.statements == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_update_with_every_field_omitted_has_the_documented_message(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """TicketReferenceUpdate: `At least one field must be provided.`"""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)

        with pytest.raises(
            ValueError, match=r"^At least one field must be provided\.$"
        ):
            await _update(
                db_session,
                ticket,
                reference.id,
                actor,
                url=UNSET,
                title=UNSET,
                description=UNSET,
                type=UNSET,
            )

    @pytest.mark.parametrize("op", MUTATIONS)
    async def test_anonymous_caller_is_a_programming_error(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        op: str,
    ) -> None:
        """Service Layer: an anonymous caller at a manual mutation boundary
        raises `ValueError` before database access."""
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=r"(?i)authenticated"),
        ):
            await _invoke(
                op, db_session, _locator(ticket), ANONYMOUS_CALLER, reference.id
            )

        assert recorder.statements == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# create_reference()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCreate:
    async def test_creates_manual_row_and_returns_its_persisted_projection(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """`create_reference()`: the normalized URL, explicit metadata,
        `source = manual`, UTC timestamps, and the canonical `SNTL-{n}`
        identity; exactly one `reference_added` event."""
        actor = await va_user()
        ticket = await ticket_factory()
        now = await _transaction_now(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await _create(
                db_session,
                ticket,
                actor,
                url="http://Issues.Example.TEST/tickets/12345",
                title="Fictional packaging issue",
                description="Tracks the downstream packaging review",
                type=ReferenceType.ISSUE,
            )

        assert result == TicketReferenceProjection(
            id=result.id,
            ticket_id=f"SNTL-{ticket.sequence_id}",
            url="https://issues.example.test/tickets/12345",
            title="Fictional packaging issue",
            description="Tracks the downstream packaging review",
            type=ReferenceType.ISSUE,
            source="manual",
            created_at=now,
            updated_at=now,
        )
        assert isinstance(result.id, uuid.UUID)
        for stamp in (result.created_at, result.updated_at):
            assert stamp.tzinfo is not None
            assert stamp.utcoffset() == timedelta(0)
        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [result.id]
        assert _projection_of(rows[result.id], ticket) == result
        assert rows[result.id].type == "issue"
        assert _data_writes(recorder) == [
            "INSERT ticket_reference",
            "INSERT ticket_audit_event",
        ]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(actor, "https://issues.example.test/tickets/12345")
        ]

    async def test_omitted_title_and_description_persist_null(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()

        result = await _create(db_session, ticket, actor, url=SEEDED_URL)

        row = await _row(db_session, result.id)
        assert row is not None
        assert (row.title, row.description) == (None, None)
        assert (result.title, result.description) == (None, None)

    @pytest.mark.parametrize(
        ("url", "stored_url", "expected"),
        [
            (GITHUB_COMMIT_URL, GITHUB_COMMIT_URL, "patch"),
            (
                "HTTP://GITHUB.COM/example-org/example-repo/pull/7",
                "https://github.com/example-org/example-repo/pull/7",
                "patch",
            ),
            (
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
                "advisory",
            ),
            (
                "https://bugzilla.suse.com/show_bug.cgi?id=12345",
                "https://bugzilla.suse.com/show_bug.cgi?id=12345",
                "issue",
            ),
            (
                "https://seclists.org/oss-sec/2026/q1/1",
                "https://seclists.org/oss-sec/2026/q1/1",
                "article",
            ),
            (
                "https://issues.example.test/tickets/7",
                "https://issues.example.test/tickets/7",
                None,
            ),
        ],
        ids=[
            "commit",
            "pull-http-upgrade",
            "advisory",
            "issue",
            "article",
            "unmatched",
        ],
    )
    async def test_omitted_type_classifies_the_normalized_url(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        url: str,
        stored_url: str,
        expected: str | None,
    ) -> None:
        """Type Auto-Classification: only an omitted type uses
        normalized-URL pattern matching and then `NULL`."""
        actor = await va_user()
        ticket = await ticket_factory()

        result = await _create(db_session, ticket, actor, url=url)

        row = await _row(db_session, result.id)
        assert row is not None
        assert (row.url, row.type) == (stored_url, expected)
        assert result.type == (None if expected is None else ReferenceType(expected))

    async def test_explicit_null_type_suppresses_classification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """ManualReferenceCreateInput: explicit `null` stores `NULL` even for
        a classifiable URL."""
        actor = await va_user()
        ticket = await ticket_factory()

        result = await _create(
            db_session, ticket, actor, url=GITHUB_COMMIT_URL, type=None
        )

        row = await _row(db_session, result.id)
        assert row is not None
        assert row.type is None
        assert result.type is None

    @pytest.mark.parametrize("value", list(ReferenceType), ids=str)
    async def test_explicit_type_is_stored_over_classification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        value: ReferenceType,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()

        result = await _create(
            db_session, ticket, actor, url=GITHUB_COMMIT_URL, type=value
        )

        row = await _row(db_session, result.id)
        assert row is not None
        assert row.type == value.value
        assert result.type is value

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("title", "a"),
            ("title", "x" * 500),
            ("title", " a "),
            ("title", "\ta\n"),
            ("description", "d"),
            ("description", "y" * 2000),
            ("description", "  context  "),
        ],
        ids=[
            "title-1",
            "title-500",
            "title-padded",
            "title-tab-newline",
            "description-1",
            "description-2000",
            "description-padded",
        ],
    )
    async def test_text_boundaries_are_accepted_and_stored_untrimmed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        field: str,
        value: str,
    ) -> None:
        """URL Normalization (titles 1-500, descriptions 1-2000 characters;
        values are not trimmed)."""
        actor = await va_user()
        ticket = await ticket_factory()

        result = await _create(
            db_session, ticket, actor, url=SEEDED_URL, **{field: value}
        )

        row = await _row(db_session, result.id)
        assert row is not None
        assert getattr(row, field) == value
        assert getattr(result, field) == value

    @pytest.mark.parametrize("source", ["manual", AUTO_SOURCE])
    async def test_normalized_identity_conflict_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        source: str,
    ) -> None:
        """`create_reference()`: a pre-existing normalized identity,
        including an automatic row, raises `ReferenceConflictError`; zero
        events and no write."""
        actor = await va_user()
        ticket = await ticket_factory()
        await _seed(
            ticket_reference_factory, ticket, url="https://example.com", source=source
        )
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceConflictError),
        ):
            await _create(db_session, ticket, actor, url="HTTP://Example.COM/")

        assert _data_writes(recorder) == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_reinvocation_conflicts_without_a_second_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        """Re-invocation is not idempotent: it conflicts and creates no
        second event."""
        actor = await va_user()
        ticket = await ticket_factory()
        first = await _create(db_session, ticket, actor, url=SEEDED_URL)

        with pytest.raises(ReferenceConflictError):
            await _create(db_session, ticket, actor, url=SEEDED_RAW_VARIANT)

        assert list(await _rows(db_session, ticket.id)) == [first.id]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(actor, SEEDED_URL)
        ]

    async def test_same_normalized_url_on_another_ticket_is_allowed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """The `(ticket_id, url)` identity is Ticket-scoped, not global."""
        actor = await va_user()
        other = await ticket_factory()
        ticket = await ticket_factory()
        existing = await _seed(
            ticket_reference_factory, other, url="https://example.com"
        )

        result = await _create(db_session, ticket, actor, url="HTTP://Example.COM/")

        assert result.url == "https://example.com"
        assert result.id != existing.id
        assert list(await _rows(db_session, ticket.id)) == [result.id]
        assert list(await _rows(db_session, other.id)) == [existing.id]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _added(actor, "https://example.com")
        ]
        assert await ticket_events_by_id(db_session, other.id) == []


# ---------------------------------------------------------------------------
# update_reference()
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PatchCase:
    """One PATCH field-state case against the default seeded reference
    (`SEEDED_URL`, type `issue`, title `Original title`, description
    `Original description`)."""

    fields: dict[str, Any]
    final: tuple[str, str | None, str | None, str | None]
    """Expected `(url, type, title, description)` after the update."""
    events: Callable[[User], list[EventRow]]


_PATCH_CASES: dict[str, PatchCase] = {
    "url-only-preserves-type": PatchCase(
        {"url": "http://GitHub.com/example-org/example-repo/commit/0123abcd"},
        (GITHUB_COMMIT_URL, "issue", "Original title", "Original description"),
        lambda a: [_url_changed(a, SEEDED_URL, GITHUB_COMMIT_URL)],
    ),
    "type-only": PatchCase(
        {"type": ReferenceType.PATCH},
        (SEEDED_URL, "patch", "Original title", "Original description"),
        lambda a: [_field_changed("type", a, "issue", "patch", SEEDED_URL)],
    ),
    "type-null-clears": PatchCase(
        {"type": None},
        (SEEDED_URL, None, "Original title", "Original description"),
        lambda a: [_field_changed("type", a, "issue", None, SEEDED_URL)],
    ),
    "title-only": PatchCase(
        {"title": "Updated fictional issue title"},
        (SEEDED_URL, "issue", "Updated fictional issue title", "Original description"),
        lambda a: [
            _field_changed(
                "title",
                a,
                "Original title",
                "Updated fictional issue title",
                SEEDED_URL,
            )
        ],
    ),
    "title-null-clears": PatchCase(
        {"title": None},
        (SEEDED_URL, "issue", None, "Original description"),
        lambda a: [_field_changed("title", a, "Original title", None, SEEDED_URL)],
    ),
    "description-only": PatchCase(
        {"description": "New context"},
        (SEEDED_URL, "issue", "Original title", "New context"),
        lambda a: [
            _field_changed(
                "description", a, "Original description", "New context", SEEDED_URL
            )
        ],
    ),
    "description-null-clears": PatchCase(
        {"description": None},
        (SEEDED_URL, "issue", "Original title", None),
        lambda a: [
            _field_changed("description", a, "Original description", None, SEEDED_URL)
        ],
    ),
    "all-fields": PatchCase(
        {
            "url": NEW_RAW_URL,
            "type": ReferenceType.ADVISORY,
            "title": "New title",
            "description": "New description",
        },
        (NEW_URL, "advisory", "New title", "New description"),
        lambda a: [
            _url_changed(a, SEEDED_URL, NEW_URL),
            _field_changed("type", a, "issue", "advisory", NEW_URL),
            _field_changed("title", a, "Original title", "New title", NEW_URL),
            _field_changed(
                "description", a, "Original description", "New description", NEW_URL
            ),
        ],
    ),
    "mixed-omitted-null-value": PatchCase(
        {"title": None, "description": "Replacement context"},
        (SEEDED_URL, "issue", None, "Replacement context"),
        lambda a: [
            _field_changed("title", a, "Original title", None, SEEDED_URL),
            _field_changed(
                "description",
                a,
                "Original description",
                "Replacement context",
                SEEDED_URL,
            ),
        ],
    ),
    "url-and-null-type": PatchCase(
        {"url": NEW_RAW_URL, "type": None},
        (NEW_URL, None, "Original title", "Original description"),
        lambda a: [
            _url_changed(a, SEEDED_URL, NEW_URL),
            _field_changed("type", a, "issue", None, NEW_URL),
        ],
    ),
    "url-same-title-null-description": PatchCase(
        {"url": NEW_RAW_URL, "title": "Original title", "description": None},
        (NEW_URL, "issue", "Original title", None),
        lambda a: [
            _url_changed(a, SEEDED_URL, NEW_URL),
            _field_changed("description", a, "Original description", None, NEW_URL),
        ],
    ),
    "same-title-new-description": PatchCase(
        {"title": "Original title", "description": "Only this changes"},
        (SEEDED_URL, "issue", "Original title", "Only this changes"),
        lambda a: [
            _field_changed(
                "description",
                a,
                "Original description",
                "Only this changes",
                SEEDED_URL,
            )
        ],
    ),
    "same-url-raw-form-new-type": PatchCase(
        {"url": SEEDED_RAW_VARIANT, "type": ReferenceType.ARTICLE},
        (SEEDED_URL, "article", "Original title", "Original description"),
        lambda a: [_field_changed("type", a, "issue", "article", SEEDED_URL)],
    ),
}


_NO_OP_CASES: dict[str, dict[str, Any]] = {
    "url-raw-variant": {"url": SEEDED_RAW_VARIANT},
    "url-identical": {"url": SEEDED_URL},
    "type-equal": {"type": ReferenceType.ISSUE},
    "title-equal": {"title": "Original title"},
    "description-equal": {"description": "Original description"},
    "all-equal": {
        "url": SEEDED_RAW_VARIANT,
        "type": ReferenceType.ISSUE,
        "title": "Original title",
        "description": "Original description",
    },
}


@pytest.mark.integration
class TestUpdate:
    @pytest.mark.parametrize(
        "case", list(_PATCH_CASES.values()), ids=list(_PATCH_CASES)
    )
    async def test_field_states_update_row_and_emit_changed_field_events(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        case: PatchCase,
    ) -> None:
        """`update_reference()`: omitted fields preserve; `null` clears; a
        URL change without `type` preserves the type; one event per
        effectively changed field in URL, type, title, description order
        with the post-update URL as detail (Ticket Audit Events;
        ticket-audit-log.md Testing Requirement 22)."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket, created_at=PAST)
        sibling = await _seed(
            ticket_reference_factory, ticket, url="https://example.com/sibling"
        )
        sibling_before = await _row(db_session, sibling.id)
        now = await _transaction_now(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await _update(
                db_session, ticket, reference.id, actor, **case.fields
            )

        row = await _row(db_session, reference.id)
        assert row is not None
        assert (row.url, row.type, row.title, row.description) == case.final
        assert row.source == "manual"
        assert row.created_at == PAST
        assert row.updated_at == now
        assert result == _projection_of(row, ticket)
        assert result.ticket_id == f"SNTL-{ticket.sequence_id}"
        assert await _row(db_session, sibling.id) == sibling_before
        expected_events = case.events(actor)
        assert _data_writes(recorder) == [
            "UPDATE ticket_reference",
            *["INSERT ticket_audit_event"] * len(expected_events),
        ]
        assert await ticket_events_by_id(db_session, ticket.id) == expected_events

    @pytest.mark.parametrize(
        "fields", list(_NO_OP_CASES.values()), ids=list(_NO_OP_CASES)
    )
    async def test_equivalent_only_patch_is_a_true_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        fields: dict[str, Any],
    ) -> None:
        """`update_reference()`: equivalent supplied values (after URL
        normalization) return the current projection without writing the
        row or creating an event."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(
            ticket_reference_factory, ticket, created_at=PAST, updated_at=PAST
        )
        before = await _row(db_session, reference.id)
        assert before is not None

        with StatementRecorder(db_session) as recorder:
            result = await _update(db_session, ticket, reference.id, actor, **fields)

        assert recorder.writes() == []
        assert await _row(db_session, reference.id) == before
        assert result == _projection_of(before, ticket)
        assert result.updated_at == PAST
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_null_supplied_for_null_fields_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(
            ticket_reference_factory,
            ticket,
            title=None,
            description=None,
            type=None,
            created_at=PAST,
            updated_at=PAST,
        )
        before = await _row(db_session, reference.id)
        assert before is not None

        with StatementRecorder(db_session) as recorder:
            result = await _update(
                db_session,
                ticket,
                reference.id,
                actor,
                title=None,
                description=None,
                type=None,
            )

        assert recorder.writes() == []
        assert result == _projection_of(before, ticket)
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_repeating_an_effective_patch_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """Repeating an effective PATCH with the same input creates no
        second event."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        await _update(db_session, ticket, reference.id, actor, title="Second title")

        with StatementRecorder(db_session) as recorder:
            await _update(db_session, ticket, reference.id, actor, title="Second title")

        assert recorder.writes() == []
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _field_changed("title", actor, "Original title", "Second title", SEEDED_URL)
        ]

    @pytest.mark.parametrize("kind", ["wrong-parent", "unknown"])
    async def test_reference_outside_the_parent_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        kind: str,
    ) -> None:
        """Manual Mutation Ordering step 2: the lookup is scoped by
        `(ticket, reference_id)`; another accessible Ticket's UUID is
        indistinguishable from an unknown UUID."""
        actor = await va_user()
        ticket = await ticket_factory()
        other = await ticket_factory()
        await _seed(ticket_reference_factory, ticket)
        foreign = await _seed(ticket_reference_factory, other)
        reference_id = foreign.id if kind == "wrong-parent" else uuid.uuid7()
        before = await _rows(db_session, ticket.id)
        before_other = await _rows(db_session, other.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceNotFoundError) as caught,
        ):
            await _update(
                db_session, ticket, reference_id, actor, title="Changed title"
            )

        assert str(caught.value) == "Reference not found."
        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await _rows(db_session, other.id) == before_other
        assert await ticket_events_by_id(db_session, ticket.id) == []
        assert await ticket_events_by_id(db_session, other.id) == []

    async def test_wrong_parent_and_unknown_have_identical_messages(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        foreign = await _seed(ticket_reference_factory, await ticket_factory())
        messages: list[str] = []
        for reference_id in (foreign.id, uuid.uuid7()):
            with pytest.raises(ReferenceNotFoundError) as caught:
                await _update(db_session, ticket, reference_id, actor, title="Changed")
            messages.append(str(caught.value))
        assert messages[0] == messages[1]

    async def test_automatic_reference_is_not_editable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """Manual Mutation Ordering step 3: only `source = manual` rows are
        consumer-editable."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket, source=AUTO_SOURCE)
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceNotEditableError),
        ):
            await _update(
                db_session, ticket, reference.id, actor, title="Changed title"
            )

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize("source", ["manual", AUTO_SOURCE])
    async def test_url_owned_by_another_reference_conflicts(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        source: str,
    ) -> None:
        """Manual Mutation Ordering step 4: the normalized supplied URL owned
        by another manual or automatic reference raises
        `ReferenceConflictError` with no write and no event."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        await _seed(
            ticket_reference_factory,
            ticket,
            url="https://example.com/other",
            source=source,
        )
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceConflictError),
        ):
            await _update(
                db_session, ticket, reference.id, actor, url="HTTP://EXAMPLE.COM/other"
            )

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_url_owned_on_another_ticket_does_not_conflict(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        other = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        await _seed(ticket_reference_factory, other, url=NEW_URL)

        result = await _update(db_session, ticket, reference.id, actor, url=NEW_RAW_URL)

        assert result.url == NEW_URL
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _url_changed(actor, SEEDED_URL, NEW_URL)
        ]


# ---------------------------------------------------------------------------
# delete_reference()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDelete:
    async def test_deletes_the_row_with_one_exact_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """`delete_reference()`: exactly one `reference_deleted` with the
        normalized URL; other references are untouched."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        sibling = await _seed(
            ticket_reference_factory, ticket, url="https://example.com/sibling"
        )
        sibling_before = await _row(db_session, sibling.id)

        with StatementRecorder(db_session) as recorder:
            # `_invoke()` is typed `Any`, so the documented `None` result
            # can be asserted without a `func-returns-value` error.
            result = await _invoke(
                "delete", db_session, _locator(ticket), _caller(actor), reference.id
            )

        assert result is None
        assert await _row(db_session, reference.id) is None
        assert await _rows(db_session, ticket.id) == {sibling.id: sibling_before}
        assert _data_writes(recorder) == [
            "DELETE ticket_reference",
            "INSERT ticket_audit_event",
        ]
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _deleted(actor, SEEDED_URL)
        ]

    async def test_second_delete_is_not_found_without_a_second_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        await delete_reference(
            db_session, _locator(ticket), reference.id, _caller(actor)
        )

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceNotFoundError),
        ):
            await delete_reference(
                db_session, _locator(ticket), reference.id, _caller(actor)
            )

        assert recorder.writes() == []
        assert await ticket_events_by_id(db_session, ticket.id) == [
            _deleted(actor, SEEDED_URL)
        ]

    @pytest.mark.parametrize("kind", ["wrong-parent", "unknown"])
    async def test_reference_outside_the_parent_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        kind: str,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        other = await ticket_factory()
        await _seed(ticket_reference_factory, ticket)
        foreign = await _seed(ticket_reference_factory, other)
        reference_id = foreign.id if kind == "wrong-parent" else uuid.uuid7()
        before = await _rows(db_session, ticket.id)
        before_other = await _rows(db_session, other.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceNotFoundError) as caught,
        ):
            await delete_reference(
                db_session, _locator(ticket), reference_id, _caller(actor)
            )

        assert str(caught.value) == "Reference not found."
        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await _rows(db_session, other.id) == before_other
        assert await ticket_events_by_id(db_session, ticket.id) == []
        assert await ticket_events_by_id(db_session, other.id) == []

    async def test_automatic_reference_is_not_editable_and_retained(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket, source=AUTO_SOURCE)
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ReferenceNotEditableError),
        ):
            await delete_reference(
                db_session, _locator(ticket), reference.id, _caller(actor)
            )

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Error precedence (after the API capability check)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPrecedence:
    @pytest.mark.parametrize("target", ["missing", "automatic", "manual"])
    @pytest.mark.parametrize("op", ["update", "delete"])
    async def test_inaccessible_ticket_precedes_every_nested_outcome(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        user_factory: UserFactory,
        op: str,
        target: str,
    ) -> None:
        """Manual Mutation Ordering: accessibility denial precedes the
        nested missing, editability, and effective outcomes."""
        caller = _caller(await user_factory(), Scope.NON_CONFIDENTIAL)
        ticket = await ticket_factory(is_confidential=True)
        reference_id = uuid.uuid7()
        if target != "missing":
            source = AUTO_SOURCE if target == "automatic" else "manual"
            reference_id = (
                await _seed(ticket_reference_factory, ticket, source=source)
            ).id
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _invoke(op, db_session, _locator(ticket), caller, reference_id)

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_inaccessible_ticket_precedes_create_conflict(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        user_factory: UserFactory,
    ) -> None:
        caller = _caller(await user_factory(), Scope.NON_CONFIDENTIAL)
        ticket = await ticket_factory(is_confidential=True)
        await _seed(ticket_reference_factory, ticket)

        with pytest.raises(TicketNotFoundError):
            await create_reference(
                db_session,
                _locator(ticket),
                caller,
                ManualReferenceCreateInput(url=SEEDED_RAW_VARIANT),
            )

        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize("op", ["update", "delete"])
    async def test_lookup_precedes_editability(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        op: str,
    ) -> None:
        """An automatic row under another Ticket is not found, never
        not-editable: the scoped lookup precedes the source check."""
        actor = await va_user()
        ticket = await ticket_factory()
        foreign = await _seed(
            ticket_reference_factory, await ticket_factory(), source=AUTO_SOURCE
        )

        with pytest.raises(ReferenceNotFoundError):
            await _invoke(op, db_session, _locator(ticket), _caller(actor), foreign.id)

    async def test_editability_precedes_conflict(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        actor = await va_user()
        ticket = await ticket_factory()
        automatic = await _seed(ticket_reference_factory, ticket, source=AUTO_SOURCE)
        await _seed(ticket_reference_factory, ticket, url="https://example.com/other")

        with pytest.raises(ReferenceNotEditableError):
            await _update(
                db_session,
                ticket,
                automatic.id,
                actor,
                url="HTTP://EXAMPLE.COM/other",
            )

        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_conflict_precedes_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """A conflicting URL with otherwise equivalent fields conflicts
        rather than partially applying or returning the current state."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        await _seed(ticket_reference_factory, ticket, url="https://example.com/other")
        before = await _rows(db_session, ticket.id)

        with pytest.raises(ReferenceConflictError):
            await _update(
                db_session,
                ticket,
                reference.id,
                actor,
                url="https://example.com/other",
                title="Original title",
                description="Original description",
                type=ReferenceType.ISSUE,
            )

        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# Ticket accessibility
# ---------------------------------------------------------------------------


async def _make_visible(
    path: str,
    ticket: Ticket,
    user: User,
    *,
    ticket_access_grant_factory: GrantFactory,
    ticket_package_factory: PackageFactory,
    ticket_package_maintainer_factory: MaintainerFactory,
) -> Scope:
    """Install one visibility path for `user` and return its scope."""
    if path == "scope-all":
        return Scope.ALL
    if path == "grant":
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
    elif path in {"maintainer", "excluded-maintainer"}:
        package = await ticket_package_factory(
            ticket_id=ticket.id,
            deleted_at=PAST if path == "excluded-maintainer" else None,
        )
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
    return Scope.NON_CONFIDENTIAL


_MALFORMED: list[tuple[str, Callable[[Ticket], str]]] = [
    ("lowercase-prefix", lambda t: f"sntl-{t.sequence_id}"),
    ("zero-padded", lambda t: f"SNTL-0{t.sequence_id}"),
    ("ticket-uuid", lambda t: str(t.id)),
    ("missing", lambda _t: f"SNTL-{MAX_SEQUENCE}"),
]
"""Malformed locators built against an existing Ticket, plus a
well-formed missing one."""


@pytest.mark.integration
class TestAccessibility:
    @pytest.mark.parametrize(
        "build", [b for _, b in _MALFORMED], ids=[n for n, _ in _MALFORMED]
    )
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_malformed_or_missing_locator_is_ticket_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        op: str,
        build: Callable[[Ticket], str],
    ) -> None:
        """Missing and malformed parents raise `TicketNotFoundError` for all
        four functions, even with a valid reference UUID of the Ticket the
        locator was built from."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _invoke(op, db_session, build(ticket), _caller(actor), reference.id)

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize("path", ["none", "excluded-maintainer"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_confidential_ticket_without_a_visibility_path_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        user_factory: UserFactory,
        op: str,
        path: str,
    ) -> None:
        """A `non_confidential`-scope caller without a grant, or whose only
        maintained package is excluded, cannot see the confidential Ticket
        (testing-strategy.md, Ticket Accessibility, canonical predicate)."""
        user = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        reference = await _seed(ticket_reference_factory, ticket)
        scope = await _make_visible(
            path,
            ticket,
            user,
            ticket_access_grant_factory=ticket_access_grant_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_maintainer_factory=ticket_package_maintainer_factory,
        )
        before = await _rows(db_session, ticket.id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _invoke(
                op, db_session, _locator(ticket), _caller(user, scope), reference.id
            )

        assert recorder.writes() == []
        assert await _rows(db_session, ticket.id) == before
        assert await ticket_events_by_id(db_session, ticket.id) == []

    @pytest.mark.parametrize("path", ["scope-all", "grant", "maintainer"])
    @pytest.mark.parametrize("op", OPERATIONS)
    async def test_confidential_ticket_with_a_visibility_path_succeeds(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        ticket_access_grant_factory: GrantFactory,
        ticket_package_factory: PackageFactory,
        ticket_package_maintainer_factory: MaintainerFactory,
        user_factory: UserFactory,
        op: str,
        path: str,
    ) -> None:
        """Effective scope `all`, an explicit grant, and included-package
        maintainership each make the confidential Ticket accessible."""
        user = await user_factory()
        ticket = await ticket_factory(is_confidential=True)
        reference = await _seed(ticket_reference_factory, ticket)
        scope = await _make_visible(
            path,
            ticket,
            user,
            ticket_access_grant_factory=ticket_access_grant_factory,
            ticket_package_factory=ticket_package_factory,
            ticket_package_maintainer_factory=ticket_package_maintainer_factory,
        )

        result = await _invoke(
            op, db_session, _locator(ticket), _caller(user, scope), reference.id
        )

        events = await ticket_events_by_id(db_session, ticket.id)
        if op == "create":
            assert result.url == "https://issues.example.test/tickets/new"
            assert events == [_added(user, "https://issues.example.test/tickets/new")]
        elif op == "update":
            assert result.title == "Changed title"
            assert events == [
                _field_changed(
                    "title", user, "Original title", "Changed title", SEEDED_URL
                )
            ]
        elif op == "delete":
            assert await _row(db_session, reference.id) is None
            assert events == [_deleted(user, SEEDED_URL)]
        else:
            assert [p.id for p in result] == [reference.id]
            assert events == []

    async def test_anonymous_list_sees_only_non_confidential_tickets(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        """Security and Privacy: anonymous callers see references only for
        non-confidential Tickets."""
        public = await ticket_factory()
        confidential = await ticket_factory(is_confidential=True)
        reference = await _seed(ticket_reference_factory, public)
        await _seed(ticket_reference_factory, confidential)

        listed = await list_references(
            db_session,
            _locator(public),
            ANONYMOUS_CALLER,
            source=None,
            type=None,
            type_was_supplied=False,
        )
        assert [p.id for p in listed] == [reference.id]

        with pytest.raises(TicketNotFoundError):
            await list_references(
                db_session,
                _locator(confidential),
                ANONYMOUS_CALLER,
                source=None,
                type=None,
                type_was_supplied=False,
            )

    @pytest.mark.parametrize("scope", list(Scope), ids=str)
    async def test_non_confidential_ticket_is_mutable_for_any_scope(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
        scope: Scope,
    ) -> None:
        user = await user_factory()
        ticket = await ticket_factory()

        result = await create_reference(
            db_session,
            _locator(ticket),
            _caller(user, scope),
            ManualReferenceCreateInput(url=SEEDED_URL),
        )

        assert result.url == SEEDED_URL


# ---------------------------------------------------------------------------
# Lock order
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLockOrder:
    @pytest.mark.parametrize("op", MUTATIONS)
    async def test_first_statement_locks_the_ticket_and_no_user_is_locked(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        op: str,
    ) -> None:
        """Manual Mutation Ordering: the first persistent read locks the
        Ticket row `FOR UPDATE`; it is the only row lock (the acting User
        is not stabilized)."""
        actor = await va_user()
        ticket = await ticket_factory()
        reference = await _seed(ticket_reference_factory, ticket)

        with StatementRecorder(db_session) as recorder:
            await _invoke(
                op, db_session, _locator(ticket), _caller(actor), reference.id
            )

        first = recorder.statements[0]
        assert first.lstrip().upper().startswith("SELECT")
        assert "FROM ticket" in first
        assert "ticket.sequence_id =" in first
        assert first.rstrip().endswith("FOR UPDATE")
        assert recorder.row_locks() == [first]
        assert not any('"user"' in s for s in recorder.row_locks())


# ---------------------------------------------------------------------------
# list_references()
# ---------------------------------------------------------------------------

T0 = datetime(2026, 1, 10, 8, 0, tzinfo=UTC)


def _ref_id(n: int) -> uuid.UUID:
    """An explicit, lexically ordered UUID (`...0001` < `...0002`)."""
    return uuid.UUID(f"00000000-0000-7000-8000-{n:012d}")


_LISTED: list[tuple[str, int, str | None, int, str]] = [
    # (name, id suffix, type, created_at offset in minutes, source)
    ("uncategorized-late", 80, None, 10, "manual"),
    ("article", 70, "article", 20, AUTO_SOURCE),
    ("patch-tie-high-id", 32, "patch", 20, "manual"),
    ("issue", 60, "issue", 5, "manual"),
    ("advisory-late", 10, "advisory", 50, AUTO_SOURCE),
    ("patch-tie-low-id", 31, "patch", 20, AUTO_SOURCE),
    ("advisory-early", 90, "advisory", 1, "manual"),
    ("uncategorized-early", 20, None, 0, AUTO_SOURCE),
    ("patch-earliest", 99, "patch", 15, "manual"),
]
"""Inserted in this (deliberately unsorted) order. Ids are chosen so that
no group order coincides with id order except for the equal-`created_at`
patch tie."""

_EXPECTED_ORDER = [
    "advisory-early",
    "advisory-late",
    "patch-earliest",
    "patch-tie-low-id",
    "patch-tie-high-id",
    "issue",
    "article",
    "uncategorized-early",
    "uncategorized-late",
]
"""`list_references()`: type priority `advisory`, `patch`, `issue`,
`article`, `NULL`, then `created_at ASC`, then `id ASC`."""


async def _seed_listing(
    ticket_reference_factory: ReferenceFactory, ticket: Ticket
) -> dict[str, uuid.UUID]:
    ids: dict[str, uuid.UUID] = {}
    for name, suffix, type_, minutes, source in _LISTED:
        reference = await ticket_reference_factory(
            id=_ref_id(suffix),
            ticket_id=ticket.id,
            url=f"https://refs.example.test/{name}",
            type=type_,
            source=source,
            created_at=T0 + timedelta(minutes=minutes),
            updated_at=T0 + timedelta(minutes=minutes),
        )
        ids[name] = reference.id
    return ids


async def _list(
    db: AsyncSession,
    ticket: Ticket,
    *,
    caller: TicketCaller = ANONYMOUS_CALLER,
    source: str | None = None,
    type: ReferenceType | None = None,
    type_was_supplied: bool = False,
) -> list[TicketReferenceProjection]:
    return await list_references(
        db,
        _locator(ticket),
        caller,
        source=source,
        type=type,
        type_was_supplied=type_was_supplied,
    )


@pytest.mark.integration
class TestList:
    async def test_accessible_ticket_without_references_is_empty(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()
        assert await _list(db_session, ticket) == []

    async def test_fixed_order_over_automatic_and_manual_rows(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        ticket = await ticket_factory()
        other = await ticket_factory()
        await _seed(ticket_reference_factory, other)
        ids = await _seed_listing(ticket_reference_factory, ticket)

        listed = await _list(db_session, ticket)

        assert [p.id for p in listed] == [ids[n] for n in _EXPECTED_ORDER]
        assert {p.source for p in listed} == {"manual", AUTO_SOURCE}

    async def test_items_are_complete_projections(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        ticket = await ticket_factory()
        reference = await _seed(
            ticket_reference_factory,
            ticket,
            source=AUTO_SOURCE,
            type="advisory",
            created_at=T0,
            updated_at=T0 + timedelta(hours=1),
        )

        (item,) = await _list(db_session, ticket)

        assert item == TicketReferenceProjection(
            id=reference.id,
            ticket_id=f"SNTL-{ticket.sequence_id}",
            url=SEEDED_URL,
            title="Original title",
            description="Original description",
            type=ReferenceType.ADVISORY,
            source=AUTO_SOURCE,
            created_at=T0,
            updated_at=T0 + timedelta(hours=1),
        )
        assert item.created_at.utcoffset() == timedelta(0)

    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            (
                "manual",
                [
                    "advisory-early",
                    "patch-earliest",
                    "patch-tie-high-id",
                    "issue",
                    "uncategorized-late",
                ],
            ),
            (
                AUTO_SOURCE,
                [
                    "advisory-late",
                    "patch-tie-low-id",
                    "article",
                    "uncategorized-early",
                ],
            ),
            ("Manual", []),
            ("sync_example", []),
            ("unknown_source", []),
        ],
        ids=["manual", "automatic", "case-sensitive", "prefix", "unknown"],
    )
    async def test_source_filter_is_exact_and_case_sensitive(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        source: str,
        expected: list[str],
    ) -> None:
        ticket = await ticket_factory()
        ids = await _seed_listing(ticket_reference_factory, ticket)

        listed = await _list(db_session, ticket, source=source)

        assert [p.id for p in listed] == [ids[n] for n in expected]

    @pytest.mark.parametrize(
        ("type_", "expected"),
        [
            (ReferenceType.ADVISORY, ["advisory-early", "advisory-late"]),
            (
                ReferenceType.PATCH,
                ["patch-earliest", "patch-tie-low-id", "patch-tie-high-id"],
            ),
            (ReferenceType.ISSUE, ["issue"]),
            (ReferenceType.ARTICLE, ["article"]),
        ],
        ids=str,
    )
    async def test_type_filter_is_exact(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        type_: ReferenceType,
        expected: list[str],
    ) -> None:
        ticket = await ticket_factory()
        ids = await _seed_listing(ticket_reference_factory, ticket)

        listed = await _list(db_session, ticket, type=type_, type_was_supplied=True)

        assert [p.id for p in listed] == [ids[n] for n in expected]

    @pytest.mark.parametrize(
        ("source", "type_", "expected"),
        [
            ("manual", ReferenceType.PATCH, ["patch-earliest", "patch-tie-high-id"]),
            (AUTO_SOURCE, ReferenceType.PATCH, ["patch-tie-low-id"]),
            (AUTO_SOURCE, ReferenceType.ISSUE, []),
        ],
        ids=["manual-patch", "automatic-patch", "automatic-issue-empty"],
    )
    async def test_filters_combine_with_and(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        source: str,
        type_: ReferenceType,
        expected: list[str],
    ) -> None:
        ticket = await ticket_factory()
        ids = await _seed_listing(ticket_reference_factory, ticket)

        listed = await _list(
            db_session, ticket, source=source, type=type_, type_was_supplied=True
        )

        assert [p.id for p in listed] == [ids[n] for n in expected]

    async def test_invalid_supplied_type_is_empty_only_for_an_accessible_ticket(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        """`type_was_supplied = True` with `type = None` returns `[]`, but
        only after parent accessibility succeeds."""
        ticket = await ticket_factory()
        confidential = await ticket_factory(is_confidential=True)
        await _seed_listing(ticket_reference_factory, ticket)
        await _seed(ticket_reference_factory, confidential)

        assert await _list(db_session, ticket, type=None, type_was_supplied=True) == []
        assert (
            await _list(
                db_session, ticket, source="manual", type=None, type_was_supplied=True
            )
            == []
        )
        with pytest.raises(TicketNotFoundError):
            await _list(db_session, confidential, type=None, type_was_supplied=True)

    async def test_non_matching_filter_on_an_inaccessible_ticket_is_not_found(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        user_factory: UserFactory,
    ) -> None:
        caller = _caller(await user_factory(), Scope.NON_CONFIDENTIAL)
        confidential = await ticket_factory(is_confidential=True)

        with pytest.raises(TicketNotFoundError):
            await _list(db_session, confidential, caller=caller, source="Manual")

    async def test_one_statement_without_lock_write_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
    ) -> None:
        """`list_references()`: one database operation, no mutation lock,
        no event, no flush."""
        actor = await va_user()
        ticket = await ticket_factory(is_confidential=True)
        ids = await _seed_listing(ticket_reference_factory, ticket)

        with StatementRecorder(db_session) as recorder:
            listed = await _list(db_session, ticket, caller=_caller(actor))

        assert [p.id for p in listed] == [ids[n] for n in _EXPECTED_ORDER]
        assert len(recorder.statements) == 1
        assert recorder.row_locks() == []
        assert recorder.writes() == []
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_denied_list_issues_one_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        confidential = await ticket_factory(is_confidential=True)
        await _seed(ticket_reference_factory, confidential)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(TicketNotFoundError),
        ):
            await _list(db_session, confidential)

        assert len(recorder.statements) == 1
        assert recorder.row_locks() == []

    async def test_pending_caller_state_is_not_flushed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
    ) -> None:
        """`list_references()` "does not flush": a pending object of the
        caller's transaction stays pending (autoflush is suspended)."""
        ticket = await ticket_factory()
        other = await ticket_factory()
        pending = TicketReference(
            ticket_id=other.id,
            url="https://pending.example.test",
            source="manual",
        )
        db_session.add(pending)

        with StatementRecorder(db_session) as recorder:
            assert await _list(db_session, ticket) == []

        assert len(recorder.statements) == 1
        assert recorder.writes() == []
        assert pending in db_session.new


# ---------------------------------------------------------------------------
# Manual-zone exception: every Ticket status
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TicketSnapshot:
    """Workflow and package-gate state a manual reference mutation must
    leave unchanged."""

    ticket: tuple[Any, ...]
    packages: frozenset[tuple[Any, ...]]
    tracks: frozenset[tuple[Any, ...]]
    products: frozenset[tuple[Any, ...]]


async def _snapshot(db: AsyncSession, ticket: Ticket) -> TicketSnapshot:
    ticket_row = (
        await db.execute(
            select(
                Ticket.status,
                Ticket.assignee_id,
                Ticket.duplicate_of_id,
                Ticket.is_confidential,
                Ticket.severity_manual,
                Ticket.priority_auto,
                Ticket.updated_at,
            ).where(Ticket.id == ticket.id)
        )
    ).one()
    packages = await db.execute(
        select(
            TicketPackage.id, TicketPackage.deleted_at, TicketPackage.updated_at
        ).where(TicketPackage.ticket_id == ticket.id)
    )
    tracks = await db.execute(
        select(
            TicketPackageTrack.id,
            TicketPackageTrack.status,
            TicketPackageTrack.delivery_status,
            TicketPackageTrack.deleted_at,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == ticket.id)
    )
    products = await db.execute(
        select(
            TicketPackageProduct.id,
            TicketPackageProduct.eligible,
            TicketPackageProduct.is_eligible_override,
            TicketPackageProduct.released_at,
            TicketPackageProduct.deleted_at,
        )
        .join(
            TicketPackageTrack,
            TicketPackageTrack.id == TicketPackageProduct.ticket_package_track_id,
        )
        .join(TicketPackage, TicketPackage.id == TicketPackageTrack.ticket_package_id)
        .where(TicketPackage.ticket_id == ticket.id)
    )
    return TicketSnapshot(
        ticket=tuple(ticket_row),
        packages=frozenset(tuple(r) for r in packages),
        tracks=frozenset(tuple(r) for r in tracks),
        products=frozenset(tuple(r) for r in products),
    )


@pytest.mark.integration
class TestManualZoneException:
    @pytest.mark.parametrize("op", MUTATIONS)
    @pytest.mark.parametrize("status", ALL_STATUSES, ids=str)
    async def test_mutation_succeeds_in_every_status_without_workflow_effects(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        va_user: VAUser,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
        op: str,
    ) -> None:
        """Manual-Zone Exception: valid for every status, including
        `Ignored` and `Duplicated`, with no operability guard, assignment,
        reconciliation, status change, or convergence registration. An
        unassigned Ticket, an active VA actor, and a package tree whose gate
        result differs from most statuses make any such effect observable;
        only reference rows and reference events are written."""
        actor = await va_user()
        ticket = await cveless(ticket_factory, status=status)
        await tree(ticket, status=PackageStatus.AFFECTED)
        reference = await _seed(ticket_reference_factory, ticket)
        before = await _snapshot(db_session, ticket)
        calls = _forbid(monkeypatch)

        with StatementRecorder(db_session) as recorder:
            await _invoke(
                op, db_session, _locator(ticket), _caller(actor), reference.id
            )

        assert calls == []
        assert await _snapshot(db_session, ticket) == before
        assert pending_ticket_convergence_effects(db_session) == ()
        assert {w.split()[1] for w in _data_writes(recorder)} == {
            "ticket_reference",
            "ticket_audit_event",
        }
        expected = {
            "create": "reference_added",
            "update": "reference_title_changed",
            "delete": "reference_deleted",
        }[op]
        assert [
            e.event_type for e in await ticket_events_by_id(db_session, ticket.id)
        ] == [expected]


# ---------------------------------------------------------------------------
# Zero outbound operations
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOutbound:
    async def test_manual_operations_perform_no_outbound_call(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        no_outbound: OutboundGuard,
    ) -> None:
        """URL Normalization and Security and Privacy: no DNS lookup,
        connection, or HTTP request for any submitted URL."""
        actor = await va_user()
        ticket = await ticket_factory()

        created = await _create(
            db_session,
            ticket,
            actor,
            url="http://Issues.Example.TEST:8443/tickets/9?view=full#analysis",
        )
        await _update(
            db_session,
            ticket,
            created.id,
            actor,
            url="http://advisories.example.com/notice/9",
            title="Fictional notice",
        )
        listed = await _list(db_session, ticket, caller=_caller(actor))
        await delete_reference(db_session, _locator(ticket), created.id, _caller(actor))

        assert (
            created.url
            == "https://issues.example.test:8443/tickets/9?view=full#analysis"
        )
        assert [p.url for p in listed] == ["https://advisories.example.com/notice/9"]
        assert no_outbound.attempts == []
