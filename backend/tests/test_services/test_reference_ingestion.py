"""Service integration tests for automatic Ticket reference ingestion
(`upsert_references()` in backend/app/services/reference_service.py).

Owning specifications:

- docs/features/tickets/ticket-references.md (Semantic Types >
  AutomaticReferenceInput; URL Boundary > URL Normalization, including the
  title rules, and Automatic Rejection Logging; Type Auto-Classification,
  including the CVE Source Tag Mapping and URL Pattern Mapping; Automatic
  Ingestion > Source Reference, Deterministic Candidate Preparation, and
  Database Merge Rules; Mutability and Concurrency; Service Layer >
  Service Exceptions and `upsert_references()`; Ticket Audit Events;
  Security and Privacy).
- docs/features/tickets/ticket-audit-log.md (Canonical Mutation and
  No-Event Matrix: "Automatic reference upsert"; Testing Requirements 12).
- docs/features/platform/testing-strategy.md (Ticket References, the
  automatic parts; `server_default=func.now()` and `onupdate=func.now()`
  Testing; Audit Trail Testing).
- docs/features/platform/logging.md (Secrets and PII Discipline).

Most tests use the single `db_session` transaction. A real caller-owned
rollback (after a successful call and after an injected database
failure) needs independent committed sessions (`CommittedWorld`,
testing-strategy.md Concurrency Testing), whose committed Tickets are
deleted at teardown and whose references follow by `ON DELETE CASCADE`.

PostgreSQL `now()` is the start time of the test transaction, so the
`updated_at` proofs backdate `created_at` and `updated_at` explicitly
before the call (testing-strategy.md, backdating pattern): an effective
update sets `updated_at` to the transaction's `now()`, while a no-op, a
manual row, and a different-source row with nothing to fill keep the
backdated value.

The order in which prepared candidates are applied is observed through
the recorded `INSERT INTO ticket_reference ... ON CONFLICT` statements,
one per prepared candidate. Rejection logs are observed through the
stdlib records of the module's structlog logger (the repository's
`caplog` pattern); the pipeline's own metadata keys (`logger`, `level`,
`timestamp`, `app`) are set aside and everything else must be exactly
the bounded `event`, `cve_id`, `source`, and `reason`.

Out of scope here:

- the pure classifiers (`tests/test_services/test_reference_classification.py`)
  and the pure URL boundary (`tests/test_core/test_reference_urls.py`),
  exercised here only through representative candidates;
- independent-session manual/automatic and automatic/automatic races,
  and the committed form of transaction usability after a forced
  unique-key conflict; and
- the race where `upsert_cve()` already holds the Ticket lock and the
  complete per-CVE rollback after Ticket creation, CVSS, eligibility,
  lifecycle, audit, source-success, and an earlier reference write,
  which belong to the CVE ingestion workflow tests.

Expected values are transcribed from the specifications, never computed
with the module under test. Hosts are fictional `*.example.test` hosts
except where a URL Pattern Mapping host is needed for classification.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import event, func, select, update
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from app.core.enums import ReferenceType, TicketStatus
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import reference_service
from app.services.reference_service import (
    AutomaticReferenceInput,
    ReferenceServiceError,
    upsert_references,
)
from tests.support.no_outbound import OutboundGuard
from tests.support.suse_cvss_races import CommittedWorld
from tests.support.ticket_mutations import (
    StatementRecorder,
    TicketFactory,
    ticket_events_by_id,
)

pytest_plugins = ["tests.support.no_outbound_fixtures"]
"""Provides the `no_outbound` guard."""

ReferenceFactory = Callable[..., Awaitable[TicketReference]]
Factory = Callable[[], Awaitable[AsyncSession]]

SOURCE = "sync_example_cves"
"""A fictional stable automatic fetcher name (`BaseFetcher.name`)."""

OTHER_SOURCE = "sync_other_example_cves"
"""A second fictional automatic fetcher name."""

CVE_ID = "CVE-2026-0001"

PAST = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)
"""The backdated `created_at` and `updated_at` of seeded rows."""

MISSING_TICKET_ID = uuid.UUID("00000000-0000-7000-8000-000000000000")
"""A Ticket UUID that is never persisted (foreign-key violation)."""

LOGGER_NAME = "app.services.reference_service"
REJECTED = "automatic_reference_rejected"
LOG_METADATA = frozenset({"logger", "level", "timestamp", "app"})
"""Keys added by the logging pipeline itself (app/core/logging.py)."""

LEAK = "zqleak"
"""A distinctive fictional marker placed in rejected URLs and titles; it
must never reach a log record."""

REFERENCE_INSERT = "INSERT INTO ticket_reference"
FAILING_SQL = "SELECT 1 / 0"
"""A statement PostgreSQL rejects (`division_by_zero`)."""

SOURCE_PAGE_URL = "https://cves.example.test/CVE-2026-0001"
SOURCE_PAGE_TITLE = "Example CVE source page"

FIRST_URL = "https://first.example.test/notes/1"
FIRST_RAW_VARIANT = "HTTP://First.Example.TEST/notes/1"
"""Normalizes to `FIRST_URL` (URL Normalization steps 4-5)."""

SECOND_URL = "https://second.example.test/notes/2"
THIRD_URL = "https://third.example.test/notes/3"
FOURTH_URL = "https://fourth.example.test/notes/4"
BEFORE_URL = "https://before.example.test/notes/0"
AFTER_URL = "https://after.example.test/notes/9"

UNMATCHED_URL = "https://research.example.test/notes/5"
"""Matches no URL Pattern Mapping row."""

GITHUB_COMMIT_URL = "https://github.com/example-org/example-repo/commit/0123abcd"
"""`github.com/*/commit/*`: `patch`."""

NVD_URL = "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
"""`nvd.nist.gov/vuln/detail/*`: `advisory`."""

BUGZILLA_URL = "https://bugzilla.suse.com/show_bug.cgi?id=1200000"
"""`bugzilla.suse.com/*`: `issue`."""

OPENWALL_URL = "https://www.openwall.com/lists/oss-security/2026/01/01/1"
"""`www.openwall.com/lists/*`: `article`."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _ref(url: object, **fields: Any) -> AutomaticReferenceInput:
    """An automatic candidate; `fields` may deliberately violate the typed
    contract (the boundary is untrusted)."""
    return AutomaticReferenceInput(url=url, **fields)


async def _upsert(
    db: AsyncSession,
    ticket_id: uuid.UUID,
    source_reference: AutomaticReferenceInput | None = None,
    upstream: Sequence[AutomaticReferenceInput] = (),
    *,
    source: Any = SOURCE,
    cve_id: Any = CVE_ID,
) -> object:
    """Call `upsert_references()` and return its result, typed `object` so
    that tests can assert the documented `None`."""
    upsert: Callable[..., Awaitable[object]] = upsert_references
    return await upsert(db, ticket_id, cve_id, source, source_reference, upstream)


async def _rows(db: AsyncSession, ticket_id: uuid.UUID) -> dict[str, RefRow]:
    """Every persisted reference of the Ticket, keyed by URL."""
    result = await db.execute(
        select(
            TicketReference.url,
            TicketReference.id,
            TicketReference.title,
            TicketReference.description,
            TicketReference.type,
            TicketReference.source,
            TicketReference.created_at,
            TicketReference.updated_at,
        ).where(TicketReference.ticket_id == ticket_id)
    )
    return {r.url: RefRow(*r[1:]) for r in result}


async def _transaction_now(db: AsyncSession) -> datetime:
    """PostgreSQL `now()` inside this session's transaction."""
    return (await db.execute(select(func.now()))).scalar_one()


async def _seed(
    ticket_reference_factory: ReferenceFactory,
    ticket: Ticket,
    url: str,
    *,
    title: str | None = None,
    description: str | None = None,
    type: str | None = None,
    source: str = SOURCE,
) -> TicketReference:
    """A persisted reference with backdated timestamps."""
    return await ticket_reference_factory(
        ticket_id=ticket.id,
        url=url,
        title=title,
        description=description,
        type=type,
        source=source,
        created_at=PAST,
        updated_at=PAST,
    )


async def _backdate(db: AsyncSession, ticket_id: uuid.UUID) -> None:
    """Backdate every reference of the Ticket explicitly."""
    await db.execute(
        update(TicketReference)
        .where(TicketReference.ticket_id == ticket_id)
        .values(created_at=PAST, updated_at=PAST)
    )


def _merged_urls(recorder: StatementRecorder) -> list[str]:
    """The URL of each recorded `INSERT ... ON CONFLICT`, in order."""
    urls: list[str] = []
    for statement, parameters in zip(
        recorder.statements, recorder.parameters, strict=True
    ):
        if statement.lstrip().startswith(REFERENCE_INSERT):
            urls.append(
                next(
                    p
                    for p in parameters
                    if isinstance(p, str) and p.startswith("https://")
                )
            )
    return urls


def _app_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """Every captured record of an application logger."""
    return [r for r in caplog.records if r.name.split(".")[0] == "app"]


def _service_logs(caplog: pytest.LogCaptureFixture) -> list[tuple[int, dict[str, Any]]]:
    """`(level, fields)` of every record of the module's logger, without
    the logging pipeline's own metadata keys."""
    out: list[tuple[int, dict[str, Any]]] = []
    for record in caplog.records:
        if record.name != LOGGER_NAME:
            continue
        assert isinstance(record.msg, dict)
        fields = {k: v for k, v in record.msg.items() if k not in LOG_METADATA}
        out.append((record.levelno, fields))
    return out


def _rejection(reason: str, *, source: str = SOURCE) -> tuple[int, dict[str, Any]]:
    """Automatic Rejection Logging: one WARNING with only the canonical CVE
    ID, the automatic source, and the closed reason."""
    return (
        logging.WARNING,
        {"event": REJECTED, "cve_id": CVE_ID, "source": source, "reason": reason},
    )


def _assert_nothing_leaked(caplog: pytest.LogCaptureFixture) -> None:
    """No application record carries submitted content: the marker, a
    host, or the text of a validation exception (every boundary error
    message says "must")."""
    for record in _app_records(caplog):
        for text in (record.getMessage(), repr(record.msg)):
            assert LEAK not in text.lower()
            assert "example.test" not in text
            assert "must" not in text


@pytest.fixture(autouse=True)
def _capture_service_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger=LOGGER_NAME)


# ---------------------------------------------------------------------------
# Source and CVE-ID contract (ValueError before persistent work)
# ---------------------------------------------------------------------------

_INVALID_SOURCES: list[tuple[str, object]] = [
    ("manual", "manual"),
    ("empty", ""),
    ("101-characters", "s" * 101),
    ("none", None),
    ("integer", 42),
    ("bytes", b"sync_example_cves"),
]

_INVALID_CVE_IDS: list[tuple[str, object]] = [
    ("short-year", "CVE-26-0001"),
    ("short-sequence", "CVE-2026-001"),
    ("lowercase", "cve-2026-0001"),
    ("leading-space", " CVE-2026-0001"),
    ("trailing-newline", "CVE-2026-0001\n"),
    ("ghsa", "GHSA-xxxx-yyyy-zzzz"),
    ("empty", ""),
    ("none", None),
    ("21-characters", "CVE-2026-" + "1" * 12),
]


@pytest.mark.integration
class TestContractGuards:
    """`upsert_references()`: an invalid automatic `source` or malformed
    `cve_id` raises `ValueError` before persistent work and is not a
    candidate rejection."""

    @pytest.mark.parametrize(
        "source", [v for _, v in _INVALID_SOURCES], ids=[n for n, _ in _INVALID_SOURCES]
    )
    async def test_invalid_source_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        source: object,
    ) -> None:
        ticket = await ticket_factory()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=r"(?i)source"),
        ):
            await _upsert(
                db_session,
                ticket.id,
                _ref(SOURCE_PAGE_URL, explicit_type=ReferenceType.ADVISORY),
                [_ref(FIRST_URL), _ref(f"ftp://{LEAK}.example.test/")],
                source=source,
            )

        assert recorder.statements == []
        assert _app_records(caplog) == []
        assert await _rows(db_session, ticket.id) == {}

    @pytest.mark.parametrize(
        "cve_id", [v for _, v in _INVALID_CVE_IDS], ids=[n for n, _ in _INVALID_CVE_IDS]
    )
    async def test_malformed_cve_id_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        cve_id: object,
    ) -> None:
        ticket = await ticket_factory()

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=r"(?i)cve_id"),
        ):
            await _upsert(
                db_session,
                ticket.id,
                _ref(SOURCE_PAGE_URL, explicit_type=ReferenceType.ADVISORY),
                [_ref(FIRST_URL), _ref(f"ftp://{LEAK}.example.test/")],
                cve_id=cve_id,
            )

        assert recorder.statements == []
        assert _app_records(caplog) == []
        assert await _rows(db_session, ticket.id) == {}

    async def test_source_of_exactly_100_characters_is_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ticket = await ticket_factory()
        source = "s" * 100

        await _upsert(db_session, ticket.id, None, [_ref(FIRST_URL)], source=source)

        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [FIRST_URL]
        assert rows[FIRST_URL].source == source
        assert _service_logs(caplog) == []

    async def test_cve_id_of_20_characters_is_accepted(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """The canonical pattern accepts four or more sequence digits up to
        the 20-character limit."""
        ticket = await ticket_factory()

        await _upsert(
            db_session,
            ticket.id,
            None,
            [_ref(FIRST_URL)],
            cve_id="CVE-2026-" + "1" * 11,
        )

        assert list(await _rows(db_session, ticket.id)) == [FIRST_URL]


# ---------------------------------------------------------------------------
# Candidate sets (Source Reference; Deterministic Candidate Preparation)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCandidateSets:
    async def test_source_candidate_is_written_when_upstream_is_empty(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Source Reference: callers invoke the function even when the
        upstream list is empty; the row is inserted with the automatic
        source and `description = NULL`."""
        ticket = await ticket_factory()
        now = await _transaction_now(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(
                db_session,
                ticket.id,
                _ref(
                    "http://CVES.Example.TEST/CVE-2026-0001",
                    title=SOURCE_PAGE_TITLE,
                    explicit_type=ReferenceType.ADVISORY,
                ),
                [],
            )

        assert result is None
        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [SOURCE_PAGE_URL]
        row = rows[SOURCE_PAGE_URL]
        assert (row.title, row.description, row.type, row.source) == (
            SOURCE_PAGE_TITLE,
            None,
            "advisory",
            SOURCE,
        )
        assert row.created_at == row.updated_at == now
        assert _merged_urls(recorder) == [SOURCE_PAGE_URL]
        assert _service_logs(caplog) == []
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_absent_source_candidate_writes_upstream_only(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """A fetcher with no human-readable page passes
        `source_reference=None`."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                None,
                [_ref(FIRST_URL, title="First upstream"), _ref(SECOND_URL)],
            )

        rows = await _rows(db_session, ticket.id)
        assert set(rows) == {FIRST_URL, SECOND_URL}
        assert rows[FIRST_URL].title == "First upstream"
        assert rows[SECOND_URL].title is None
        assert {row.source for row in rows.values()} == {SOURCE}
        assert {row.description for row in rows.values()} == {None}
        assert _merged_urls(recorder) == [FIRST_URL, SECOND_URL]

    async def test_source_candidate_is_applied_before_upstream_candidates(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                _ref(
                    SOURCE_PAGE_URL,
                    title=SOURCE_PAGE_TITLE,
                    explicit_type=ReferenceType.ADVISORY,
                ),
                [_ref(FIRST_URL), _ref(SECOND_URL), _ref(THIRD_URL)],
            )

        assert _merged_urls(recorder) == [
            SOURCE_PAGE_URL,
            FIRST_URL,
            SECOND_URL,
            THIRD_URL,
        ]
        assert len(await _rows(db_session, ticket.id)) == 4

    async def test_no_candidates_execute_no_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(db_session, ticket.id, None, [])

        assert result is None
        assert recorder.statements == []
        assert _app_records(caplog) == []

    async def test_all_invalid_candidates_write_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Q4: with no valid candidate, nothing is written."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(
                db_session,
                ticket.id,
                _ref(None, title=SOURCE_PAGE_TITLE),
                [_ref(f"ftp://{LEAK}.example.test/"), _ref(FIRST_URL, title="")],
            )

        assert result is None
        assert recorder.statements == []
        assert _service_logs(caplog) == [
            _rejection("url_not_string"),
            _rejection("invalid_scheme"),
            _rejection("invalid_metadata"),
        ]
        assert await _rows(db_session, ticket.id) == {}

    async def test_mixed_validity_skips_invalid_and_preserves_relative_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deterministic Candidate Preparation step 2: invalid candidates
        are logged and removed without changing the relative order of
        the valid ones."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                _ref(f"https://{LEAK}user@cves.example.test/x", title="Source"),
                [
                    _ref(THIRD_URL),
                    _ref(""),
                    _ref(FIRST_URL),
                    _ref(SECOND_URL, explicit_type="patch"),
                    _ref(FOURTH_URL),
                    _ref(SECOND_URL),
                ],
            )

        assert _merged_urls(recorder) == [THIRD_URL, FIRST_URL, FOURTH_URL, SECOND_URL]
        assert set(await _rows(db_session, ticket.id)) == {
            THIRD_URL,
            FIRST_URL,
            FOURTH_URL,
            SECOND_URL,
        }
        assert _service_logs(caplog) == [
            _rejection("userinfo_forbidden"),
            _rejection("url_empty"),
            _rejection("invalid_metadata"),
        ]
        _assert_nothing_leaked(caplog)


# ---------------------------------------------------------------------------
# URL boundary and Automatic Rejection Logging
# ---------------------------------------------------------------------------


def _padded(prefix: str, length: int) -> str:
    return prefix + "a" * (length - len(prefix))


MARKED_TITLE = f"Fictional {LEAK} title"
VALID_MARKED_URL = (
    f"https://valid.example.test/{LEAK}-path?{LEAK}-query=1#{LEAK}-fragment"
)

_URL_REJECTIONS: list[tuple[str, object, str]] = [
    ("none", None, "url_not_string"),
    ("integer", 12345, "url_not_string"),
    ("bytes", f"https://{LEAK}.example.test/".encode(), "url_not_string"),
    ("empty", "", "url_empty"),
    (
        "2049-before-normalization",
        _padded(f"https://{LEAK}.example.test/", 2049),
        "url_too_long",
    ),
    (
        "2049-after-http-upgrade",
        _padded(f"http://{LEAK}.example.test/", 2048),
        "url_too_long",
    ),
    ("nul", f"https://{LEAK}.example.test/a\x00b", "control_character"),
    ("unit-separator", f"https://{LEAK}.example.test/a\x1fb", "control_character"),
    ("delete", f"https://{LEAK}.example.test/a\x7fb", "control_character"),
    ("newline", f"https://{LEAK}.example.test/a\nb", "control_character"),
    ("relative", f"/{LEAK}/relative?{LEAK}=1#{LEAK}", "invalid_url"),
    ("port-out-of-range", f"https://{LEAK}.example.test:65536/path", "invalid_url"),
    ("empty-port", f"https://{LEAK}.example.test:/path", "invalid_url"),
    ("ftp-scheme", f"ftp://{LEAK}.example.test/file", "invalid_scheme"),
    ("javascript-scheme", f"javascript:{LEAK}()", "invalid_scheme"),
    ("hostless", f"https:///{LEAK}/path", "invalid_host"),
    ("empty-authority", "https://", "invalid_host"),
    ("digits-only-host", f"https://999.1.1.1/{LEAK}", "invalid_host"),
    ("username-only", f"https://{LEAK}user@host.example.test/p", "userinfo_forbidden"),
    (
        "username-password",
        f"https://{LEAK}user:{LEAK}secret@host.example.test/p?{LEAK}q#{LEAK}f",
        "userinfo_forbidden",
    ),
]
"""One or more raw URLs per `ReferenceUrlRejection` category; each also
carries `MARKED_TITLE`."""

_METADATA_REJECTIONS: list[tuple[str, dict[str, Any]]] = [
    ("title-non-string", {"title": 5}),
    ("title-empty", {"title": ""}),
    ("title-501-characters", {"title": _padded(LEAK, 501)}),
    ("title-spaces", {"title": "   "}),
    ("title-tab", {"title": "\t"}),
    ("title-newline", {"title": "\n"}),
    ("type-plain-string", {"explicit_type": "patch"}),
    ("type-integer", {"explicit_type": 1}),
]
"""Invalid non-NULL title or invalid explicit type on a valid, marked URL
(tracking-issue decision: `invalid_metadata`)."""


@pytest.mark.integration
class TestRejections:
    """Automatic Rejection Logging: an invalid candidate is skipped,
    processing continues, and exactly one WARNING records only the CVE
    ID, the automatic source, and the closed reason; never the raw URL,
    title, query, fragment, user information, or exception text."""

    async def _assert_skipped(
        self,
        db: AsyncSession,
        caplog: pytest.LogCaptureFixture,
        ticket: Ticket,
        rejected: AutomaticReferenceInput,
        reason: str,
    ) -> None:
        with StatementRecorder(db) as recorder:
            await _upsert(
                db, ticket.id, None, [_ref(BEFORE_URL), rejected, _ref(AFTER_URL)]
            )

        assert _merged_urls(recorder) == [BEFORE_URL, AFTER_URL]
        assert set(await _rows(db, ticket.id)) == {BEFORE_URL, AFTER_URL}
        assert _service_logs(caplog) == [_rejection(reason)]
        _assert_nothing_leaked(caplog)
        assert await ticket_events_by_id(db, ticket.id) == []

    @pytest.mark.parametrize(
        ("url", "reason"),
        [(url, reason) for _, url, reason in _URL_REJECTIONS],
        ids=[name for name, _, _ in _URL_REJECTIONS],
    )
    async def test_invalid_url_is_skipped_with_its_reason(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        url: object,
        reason: str,
    ) -> None:
        ticket = await ticket_factory()

        await self._assert_skipped(
            db_session, caplog, ticket, _ref(url, title=MARKED_TITLE), reason
        )

    @pytest.mark.parametrize(
        "fields",
        [fields for _, fields in _METADATA_REJECTIONS],
        ids=[name for name, _ in _METADATA_REJECTIONS],
    )
    async def test_invalid_metadata_is_skipped(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        fields: dict[str, Any],
    ) -> None:
        ticket = await ticket_factory()

        await self._assert_skipped(
            db_session,
            caplog,
            ticket,
            _ref(VALID_MARKED_URL, **fields),
            "invalid_metadata",
        )

    @pytest.mark.parametrize(
        ("fields", "reason"),
        [
            ({"url": f"ftp://{LEAK}.example.test/", "title": ""}, "invalid_scheme"),
            ({"url": None, "explicit_type": "patch"}, "url_not_string"),
            (
                {"url": f"https://{LEAK}@x.example.test/", "title": "x" * 501},
                "userinfo_forbidden",
            ),
        ],
        ids=["scheme-and-title", "none-and-type", "userinfo-and-title"],
    )
    async def test_url_reason_wins_when_url_and_metadata_are_invalid(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        fields: dict[str, Any],
        reason: str,
    ) -> None:
        """Tracking-issue decision: the URL is validated first, so one
        candidate yields one record with the URL reason."""
        ticket = await ticket_factory()

        await self._assert_skipped(db_session, caplog, ticket, _ref(**fields), reason)

    async def test_invalid_source_candidate_is_skipped_and_upstream_continues(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                _ref(
                    f"https://cves.example.test/{LEAK}\x00",
                    title=MARKED_TITLE,
                    explicit_type=ReferenceType.ADVISORY,
                ),
                [_ref(FIRST_URL)],
                source=OTHER_SOURCE,
            )

        assert _merged_urls(recorder) == [FIRST_URL]
        assert _service_logs(caplog) == [
            _rejection("control_character", source=OTHER_SOURCE)
        ]
        _assert_nothing_leaked(caplog)

    async def test_each_rejection_logs_once_in_candidate_order(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ticket = await ticket_factory()

        await _upsert(
            db_session,
            ticket.id,
            None,
            [
                _ref(f"https://{LEAK}.example.test/a\tb"),
                _ref(FIRST_URL),
                _ref(VALID_MARKED_URL, title=" "),
                _ref(f"gopher://{LEAK}.example.test/"),
                _ref(SECOND_URL),
                _ref(f"https://{LEAK}.example.test/a\tb"),
            ],
        )

        assert set(await _rows(db_session, ticket.id)) == {FIRST_URL, SECOND_URL}
        assert _service_logs(caplog) == [
            _rejection("control_character"),
            _rejection("invalid_metadata"),
            _rejection("invalid_scheme"),
            _rejection("control_character"),
        ]
        _assert_nothing_leaked(caplog)

    async def test_accepted_boundaries(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A 500-character title and a 2048-character URL are accepted;
        titles are not trimmed; `NULL` titles and unknown or non-string
        tags never reject a candidate."""
        ticket = await ticket_factory()
        title_500 = "t" * 500
        url_2048 = _padded("https://long.example.test/", 2048)
        padded_title = "  Fictional padded title  "

        await _upsert(
            db_session,
            ticket.id,
            None,
            [
                _ref(FIRST_URL, title=title_500),
                _ref(url_2048),
                _ref(SECOND_URL, title=padded_title),
                _ref(THIRD_URL, title=None, upstream_tags=[7, None, "Unknown Tag"]),
            ],
        )

        rows = await _rows(db_session, ticket.id)
        assert set(rows) == {FIRST_URL, url_2048, SECOND_URL, THIRD_URL}
        assert rows[FIRST_URL].title == title_500
        assert rows[SECOND_URL].title == padded_title
        assert (rows[THIRD_URL].title, rows[THIRD_URL].type) == (None, None)
        assert _service_logs(caplog) == []


# ---------------------------------------------------------------------------
# Ticket status and scope independence; no Ticket lock (Mutability and
# Concurrency)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTicketIndependence:
    @pytest.mark.parametrize("status", list(TicketStatus), ids=lambda s: s.value)
    async def test_any_status_and_confidentiality_without_ticket_access(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
    ) -> None:
        """Automatic upsert is independent of Ticket status and consumer
        scope, acquires no Ticket lock, and performs no parent lookup: its
        only statements are the reference upserts."""
        ticket = await ticket_factory(status=status.value, is_confidential=True)

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                _ref(SOURCE_PAGE_URL, explicit_type=ReferenceType.ADVISORY),
                [_ref(FIRST_URL)],
            )

        assert recorder.row_locks() == []
        assert [s.split("(")[0].strip() for s in recorder.statements] == [
            REFERENCE_INSERT
        ] * 2
        assert set(await _rows(db_session, ticket.id)) == {SOURCE_PAGE_URL, FIRST_URL}


# ---------------------------------------------------------------------------
# Normalized identity
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNormalizedIdentity:
    async def test_raw_variants_coalesce_into_one_normalized_row(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Normalized collision: raw URLs that normalize to the same value
        have one `(ticket_id, url)` identity."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                None,
                [
                    _ref(FIRST_RAW_VARIANT),
                    _ref("https://first.example.test/notes/1", title="Filled"),
                    _ref("http://first.example.test/notes/1"),
                ],
            )

        assert _merged_urls(recorder) == [FIRST_URL]
        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [FIRST_URL]
        assert rows[FIRST_URL].title == "Filled"

    async def test_non_host_components_keep_distinct_identities(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Path case, a non-root trailing slash, a query, and a fragment are
        preserved, so they are distinct identities; only the root slash is
        removed."""
        ticket = await ticket_factory()

        await _upsert(
            db_session,
            ticket.id,
            None,
            [
                _ref("https://root.example.test/"),
                _ref("https://root.example.test"),
                _ref("https://root.example.test/Path"),
                _ref("https://root.example.test/path"),
                _ref("https://root.example.test/path/"),
                _ref("https://root.example.test/path?view=full"),
                _ref("https://root.example.test/path#analysis"),
            ],
        )

        assert set(await _rows(db_session, ticket.id)) == {
            "https://root.example.test",
            "https://root.example.test/Path",
            "https://root.example.test/path",
            "https://root.example.test/path/",
            "https://root.example.test/path?view=full",
            "https://root.example.test/path#analysis",
        }

    async def test_same_normalized_url_on_different_tickets(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Ticket scope: uniqueness is per Ticket, not global."""
        first = await ticket_factory()
        second = await ticket_factory()

        await _upsert(db_session, first.id, None, [_ref(FIRST_URL, title="One")])
        await _upsert(
            db_session,
            second.id,
            None,
            [_ref(FIRST_RAW_VARIANT, title="Two")],
            source=OTHER_SOURCE,
        )

        first_rows = await _rows(db_session, first.id)
        second_rows = await _rows(db_session, second.id)
        assert (first_rows[FIRST_URL].title, first_rows[FIRST_URL].source) == (
            "One",
            SOURCE,
        )
        assert (second_rows[FIRST_URL].title, second_rows[FIRST_URL].source) == (
            "Two",
            OTHER_SOURCE,
        )
        assert first_rows[FIRST_URL].id != second_rows[FIRST_URL].id


# ---------------------------------------------------------------------------
# Classification precedence (Type Auto-Classification)
# ---------------------------------------------------------------------------

_PRECEDENCE: list[tuple[str, dict[str, Any], str, str | None]] = [
    # (case, candidate, stored URL, expected stored type)
    (
        "explicit-over-tags-and-url",
        {
            "url": GITHUB_COMMIT_URL,
            "upstream_tags": ["Vendor Advisory"],
            "explicit_type": ReferenceType.ISSUE,
        },
        GITHUB_COMMIT_URL,
        "issue",
    ),
    (
        "explicit-over-url",
        {"url": NVD_URL, "explicit_type": ReferenceType.PATCH},
        NVD_URL,
        "patch",
    ),
    (
        "explicit-over-null",
        {"url": UNMATCHED_URL, "explicit_type": ReferenceType.ARTICLE},
        UNMATCHED_URL,
        "article",
    ),
    (
        "nvd-tag-over-url",
        {"url": GITHUB_COMMIT_URL, "upstream_tags": ["Issue Tracking"]},
        GITHUB_COMMIT_URL,
        "issue",
    ),
    (
        "mitre-tag-over-url",
        {"url": BUGZILLA_URL, "upstream_tags": ["vendor-advisory"]},
        BUGZILLA_URL,
        "advisory",
    ),
    (
        "tag-over-null",
        {"url": UNMATCHED_URL, "upstream_tags": ["Mailing List"]},
        UNMATCHED_URL,
        "article",
    ),
    (
        "multi-tag-priority",
        {
            "url": UNMATCHED_URL,
            "upstream_tags": ["Exploit", "Issue Tracking", "Third Party Advisory"],
        },
        UNMATCHED_URL,
        "advisory",
    ),
    (
        "multi-tag-priority-mixed-forms",
        {"url": OPENWALL_URL, "upstream_tags": ["exploit", "Patch", "vdb-entry"]},
        OPENWALL_URL,
        "patch",
    ),
    (
        "null-tag-then-tag",
        {"url": GITHUB_COMMIT_URL, "upstream_tags": ["Broken Link", "Exploit"]},
        GITHUB_COMMIT_URL,
        "article",
    ),
    (
        "null-tag-then-url",
        {"url": GITHUB_COMMIT_URL, "upstream_tags": ["Broken Link"]},
        GITHUB_COMMIT_URL,
        "patch",
    ),
    (
        "mitre-null-tags-then-url",
        {"url": NVD_URL, "upstream_tags": ["broken-link", "related"]},
        NVD_URL,
        "advisory",
    ),
    (
        "unknown-and-non-string-tags-then-url",
        {"url": BUGZILLA_URL, "upstream_tags": ["Unknown Example Tag", 7]},
        BUGZILLA_URL,
        "issue",
    ),
    (
        "url-pattern-after-normalization",
        {"url": "HTTP://GITHUB.COM/example-org/example-repo/pull/7"},
        "https://github.com/example-org/example-repo/pull/7",
        "patch",
    ),
    ("url-pattern-article", {"url": OPENWALL_URL}, OPENWALL_URL, "article"),
    ("null", {"url": UNMATCHED_URL}, UNMATCHED_URL, None),
    (
        "null-tags-only",
        {"url": UNMATCHED_URL, "upstream_tags": ["Not Applicable"]},
        UNMATCHED_URL,
        None,
    ),
    ("empty-tags", {"url": UNMATCHED_URL, "upstream_tags": []}, UNMATCHED_URL, None),
]


@pytest.mark.integration
class TestClassificationPrecedence:
    """Explicit type, then a recognized tag mapping, then the normalized-URL
    pattern, then `NULL` (Type Auto-Classification)."""

    @pytest.mark.parametrize(
        ("candidate", "stored_url", "expected"),
        [(c, u, e) for _, c, u, e in _PRECEDENCE],
        ids=[name for name, _, _, _ in _PRECEDENCE],
    )
    async def test_stored_type(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
        candidate: dict[str, Any],
        stored_url: str,
        expected: str | None,
    ) -> None:
        ticket = await ticket_factory()

        await _upsert(db_session, ticket.id, None, [_ref(**candidate)])

        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [stored_url]
        assert rows[stored_url].type == expected
        assert _service_logs(caplog) == []


# ---------------------------------------------------------------------------
# Coalescing (Deterministic Candidate Preparation step 4)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCoalescing:
    async def test_first_candidate_keeps_position_and_non_null_fields(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Later duplicates only fill the first candidate's missing `title`
        or `type`; the first duplicate with a non-NULL value wins."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                None,
                [
                    _ref(FIRST_URL, title="First title"),
                    _ref(SECOND_URL, explicit_type=ReferenceType.ISSUE),
                    _ref(FIRST_RAW_VARIANT, title="Second title"),
                    _ref(FIRST_URL, upstream_tags=["Exploit"], title="Third title"),
                    _ref(FIRST_URL, explicit_type=ReferenceType.PATCH),
                    _ref(SECOND_URL, title="Filled title", upstream_tags=["Patch"]),
                ],
            )

        assert _merged_urls(recorder) == [FIRST_URL, SECOND_URL]
        rows = await _rows(db_session, ticket.id)
        assert (rows[FIRST_URL].title, rows[FIRST_URL].type) == (
            "First title",
            "article",
        )
        assert (rows[SECOND_URL].title, rows[SECOND_URL].type) == (
            "Filled title",
            "issue",
        )

    async def test_null_classification_of_a_duplicate_does_not_fill(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Only non-NULL values fill: a duplicate whose classification is
        `NULL` leaves the type for a later duplicate."""
        ticket = await ticket_factory()

        await _upsert(
            db_session,
            ticket.id,
            None,
            [
                _ref(FIRST_URL),
                _ref(FIRST_URL, upstream_tags=["Broken Link"]),
                _ref(FIRST_URL, upstream_tags=["mailing-list"]),
            ],
        )

        rows = await _rows(db_session, ticket.id)
        assert (rows[FIRST_URL].title, rows[FIRST_URL].type) == (None, "article")

    async def test_upstream_duplicate_cannot_overwrite_the_source_candidate(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """The source candidate is first and supplies its title and
        advisory type, so an upstream duplicate cannot overwrite them."""
        ticket = await ticket_factory()

        with StatementRecorder(db_session) as recorder:
            await _upsert(
                db_session,
                ticket.id,
                _ref(
                    SOURCE_PAGE_URL,
                    title=SOURCE_PAGE_TITLE,
                    explicit_type=ReferenceType.ADVISORY,
                ),
                [
                    _ref(FIRST_URL),
                    _ref(
                        "HTTP://cves.example.test/CVE-2026-0001",
                        title="Upstream title",
                        upstream_tags=["Patch"],
                        explicit_type=ReferenceType.PATCH,
                    ),
                ],
            )

        assert _merged_urls(recorder) == [SOURCE_PAGE_URL, FIRST_URL]
        row = (await _rows(db_session, ticket.id))[SOURCE_PAGE_URL]
        assert (row.title, row.type) == (SOURCE_PAGE_TITLE, "advisory")

    async def test_reordered_upstream_duplicates_change_only_the_winner(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        """Reordering upstream duplicates may change which duplicate
        supplies the first non-NULL value, and nothing else."""
        in_order = await ticket_factory()
        reordered = await ticket_factory()
        first_duplicate = _ref(FIRST_URL, title="Title one", upstream_tags=["Patch"])
        second_duplicate = _ref(
            FIRST_RAW_VARIANT, title="Title two", upstream_tags=["Exploit"]
        )
        others = (_ref(SECOND_URL, title="Unrelated"), _ref(THIRD_URL))

        with StatementRecorder(db_session) as in_order_recorder:
            await _upsert(
                db_session,
                in_order.id,
                None,
                [others[0], first_duplicate, second_duplicate, others[1]],
            )
        with StatementRecorder(db_session) as reordered_recorder:
            await _upsert(
                db_session,
                reordered.id,
                None,
                [others[0], second_duplicate, first_duplicate, others[1]],
            )

        expected_order = [SECOND_URL, FIRST_URL, THIRD_URL]
        assert _merged_urls(in_order_recorder) == expected_order
        assert _merged_urls(reordered_recorder) == expected_order

        def _fields(rows: dict[str, RefRow]) -> dict[str, tuple[Any, ...]]:
            return {
                url: (row.title, row.type, row.source, row.description)
                for url, row in rows.items()
            }

        in_order_rows = _fields(await _rows(db_session, in_order.id))
        reordered_rows = _fields(await _rows(db_session, reordered.id))
        assert in_order_rows[FIRST_URL] == ("Title one", "patch", SOURCE, None)
        assert reordered_rows[FIRST_URL] == ("Title two", "article", SOURCE, None)
        del in_order_rows[FIRST_URL], reordered_rows[FIRST_URL]
        assert (
            in_order_rows
            == reordered_rows
            == {
                SECOND_URL: ("Unrelated", None, SOURCE, None),
                THIRD_URL: (None, None, SOURCE, None),
            }
        )


# ---------------------------------------------------------------------------
# Database Merge Rules and the effective-update timestamp
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MergeCase:
    seeded: dict[str, Any]
    candidate: dict[str, Any]
    expected: tuple[str | None, str | None]
    """`(title, type)` after the call."""
    effective: bool
    """Whether the call is an effective update (`updated_at` advances)."""


_SEEDED_DESCRIPTION = "Seeded description"

_MERGE_CASES: dict[str, MergeCase] = {
    "same-source-replaces-both": MergeCase(
        {"title": "Old title", "type": "issue"},
        {"title": "New title", "explicit_type": ReferenceType.PATCH},
        ("New title", "patch"),
        effective=True,
    ),
    "same-source-title-only": MergeCase(
        {"title": "Old title", "type": "issue"},
        {"title": "New title"},
        ("New title", "issue"),
        effective=True,
    ),
    "same-source-type-only": MergeCase(
        {"title": "Old title", "type": "issue"},
        {"upstream_tags": ["Exploit"]},
        ("Old title", "article"),
        effective=True,
    ),
    "same-source-fills-null": MergeCase(
        {"title": None, "type": None},
        {"title": "New title", "explicit_type": ReferenceType.PATCH},
        ("New title", "patch"),
        effective=True,
    ),
    "same-source-null-candidate-does-not-clear": MergeCase(
        {"title": "Old title", "type": "issue"},
        {"upstream_tags": ["Broken Link"]},
        ("Old title", "issue"),
        effective=False,
    ),
    "same-source-equal-values": MergeCase(
        {"title": "Old title", "type": "issue"},
        {"title": "Old title", "explicit_type": ReferenceType.ISSUE},
        ("Old title", "issue"),
        effective=False,
    ),
    "other-source-fills-both-null": MergeCase(
        {"title": None, "type": None, "source": OTHER_SOURCE},
        {"title": "Filled title", "explicit_type": ReferenceType.PATCH},
        ("Filled title", "patch"),
        effective=True,
    ),
    "other-source-fills-null-type-only": MergeCase(
        {"title": "Owner title", "type": None, "source": OTHER_SOURCE},
        {"title": "Other title", "explicit_type": ReferenceType.PATCH},
        ("Owner title", "patch"),
        effective=True,
    ),
    "other-source-fills-null-title-only": MergeCase(
        {"title": None, "type": "advisory", "source": OTHER_SOURCE},
        {"title": "Other title", "explicit_type": ReferenceType.PATCH},
        ("Other title", "advisory"),
        effective=True,
    ),
    "other-source-keeps-non-null": MergeCase(
        {"title": "Owner title", "type": "advisory", "source": OTHER_SOURCE},
        {"title": "Other title", "explicit_type": ReferenceType.PATCH},
        ("Owner title", "advisory"),
        effective=False,
    ),
    "other-source-null-candidate-has-nothing-to-fill": MergeCase(
        {"title": None, "type": None, "source": OTHER_SOURCE},
        {},
        (None, None),
        effective=False,
    ),
    "manual-with-values-untouched": MergeCase(
        {"title": "Manual title", "type": "issue", "source": "manual"},
        {"title": "New title", "explicit_type": ReferenceType.PATCH},
        ("Manual title", "issue"),
        effective=False,
    ),
    "manual-with-nulls-untouched": MergeCase(
        {"title": None, "type": None, "source": "manual", "description": None},
        {"title": "New title", "explicit_type": ReferenceType.PATCH},
        (None, None),
        effective=False,
    ),
}


@pytest.mark.integration
class TestMergeRules:
    """Database Merge Rules against a pre-existing row for the normalized
    URL: same automatic source updates only non-NULL prepared fields; a
    different automatic source fills only `NULL` fields; a manual row is
    untouched. `source`, `description`, `id`, and `created_at` never
    change; `updated_at` advances only on an effective update."""

    @pytest.mark.parametrize(
        "case", list(_MERGE_CASES.values()), ids=list(_MERGE_CASES)
    )
    async def test_merge_outcome(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        caplog: pytest.LogCaptureFixture,
        case: MergeCase,
    ) -> None:
        ticket = await ticket_factory()
        seeded = {"description": _SEEDED_DESCRIPTION, **case.seeded}
        reference = await _seed(ticket_reference_factory, ticket, FIRST_URL, **seeded)
        before = (await _rows(db_session, ticket.id))[FIRST_URL]
        assert before.updated_at == PAST
        now = await _transaction_now(db_session)

        with StatementRecorder(db_session) as recorder:
            result = await _upsert(
                db_session, ticket.id, None, [_ref(FIRST_RAW_VARIANT, **case.candidate)]
            )

        assert result is None
        assert _merged_urls(recorder) == [FIRST_URL]
        rows = await _rows(db_session, ticket.id)
        assert list(rows) == [FIRST_URL]
        assert rows[FIRST_URL] == RefRow(
            id=reference.id,
            title=case.expected[0],
            description=seeded["description"],
            type=case.expected[1],
            source=seeded.get("source", SOURCE),
            created_at=PAST,
            updated_at=now if case.effective else PAST,
        )
        assert _service_logs(caplog) == []
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_no_stale_deletion(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        """A source removing a URL neither deletes nor clears the
        accumulated reference."""
        ticket = await ticket_factory()
        await _seed(
            ticket_reference_factory,
            ticket,
            FIRST_URL,
            title="Accumulated",
            description=_SEEDED_DESCRIPTION,
            type="patch",
        )
        await _seed(ticket_reference_factory, ticket, SECOND_URL, title="Kept")
        before = await _rows(db_session, ticket.id)

        await _upsert(db_session, ticket.id, None, [_ref(SECOND_URL, title="Kept")])
        assert await _rows(db_session, ticket.id) == before

        await _upsert(db_session, ticket.id, None, [])
        assert await _rows(db_session, ticket.id) == before

    async def test_identical_reinvocation_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deterministic re-invocation with the same candidates creates no
        duplicate and makes no effective update once every fill
        opportunity is satisfied."""
        ticket = await ticket_factory()
        source_reference = _ref(
            SOURCE_PAGE_URL,
            title=SOURCE_PAGE_TITLE,
            explicit_type=ReferenceType.ADVISORY,
        )
        upstream = [
            _ref(GITHUB_COMMIT_URL, upstream_tags=["Patch"]),
            _ref(FIRST_URL),
            _ref(FIRST_RAW_VARIANT, title="Filled title"),
            _ref(f"ftp://{LEAK}.example.test/"),
            _ref(SECOND_URL, upstream_tags=["Broken Link"]),
        ]
        await _upsert(db_session, ticket.id, source_reference, upstream)
        await _backdate(db_session, ticket.id)
        before = await _rows(db_session, ticket.id)
        assert {row.updated_at for row in before.values()} == {PAST}
        assert len(before) == 4

        await _upsert(db_session, ticket.id, source_reference, upstream)

        assert await _rows(db_session, ticket.id) == before
        assert _service_logs(caplog) == [_rejection("invalid_scheme")] * 2
        assert await ticket_events_by_id(db_session, ticket.id) == []

    async def test_effective_reinvocation_advances_only_the_changed_row(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        ticket = await ticket_factory()
        await _seed(ticket_reference_factory, ticket, FIRST_URL, title="Same")
        await _seed(ticket_reference_factory, ticket, SECOND_URL, title="Old")
        now = await _transaction_now(db_session)

        await _upsert(
            db_session,
            ticket.id,
            None,
            [_ref(FIRST_URL, title="Same"), _ref(SECOND_URL, title="New")],
        )

        rows = await _rows(db_session, ticket.id)
        assert (rows[FIRST_URL].title, rows[FIRST_URL].updated_at) == ("Same", PAST)
        assert (rows[SECOND_URL].title, rows[SECOND_URL].updated_at) == ("New", now)


# ---------------------------------------------------------------------------
# No Ticket audit event (ticket-audit-log.md, matrix row and TR 12)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoAuditEvent:
    @pytest.mark.parametrize(
        "outcome",
        [
            "insert",
            "same-source-update",
            "other-source-fill",
            "no-op",
            "manual-skip",
            "rejected",
        ],
    )
    async def test_automatic_outcome_creates_no_ticket_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        outcome: str,
    ) -> None:
        ticket = await ticket_factory()
        seeds: dict[str, dict[str, Any]] = {
            "same-source-update": {"title": "Old", "source": SOURCE},
            "other-source-fill": {"title": None, "source": OTHER_SOURCE},
            "no-op": {"title": "New", "source": SOURCE},
            "manual-skip": {"title": None, "source": "manual"},
        }
        if outcome in seeds:
            await _seed(ticket_reference_factory, ticket, FIRST_URL, **seeds[outcome])
        candidate = (
            _ref(f"ftp://{LEAK}.example.test/", title="New")
            if outcome == "rejected"
            else _ref(FIRST_URL, title="New")
        )
        assert await ticket_events_by_id(db_session, ticket.id) == []

        await _upsert(db_session, ticket.id, None, [candidate])
        await _upsert(db_session, ticket.id, None, [candidate])

        assert await ticket_events_by_id(db_session, ticket.id) == []


# ---------------------------------------------------------------------------
# No outbound call (Security and Privacy)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNoOutboundCalls:
    async def test_ingestion_performs_no_outbound_call(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
        no_outbound: OutboundGuard,
    ) -> None:
        ticket = await ticket_factory()
        await _seed(ticket_reference_factory, ticket, BUGZILLA_URL, source="manual")

        await _upsert(
            db_session,
            ticket.id,
            _ref(
                NVD_URL, title="Example NVD page", explicit_type=ReferenceType.ADVISORY
            ),
            [
                _ref(GITHUB_COMMIT_URL),
                _ref("http://GitHub.com/example-org/example-repo/pull/7"),
                _ref(BUGZILLA_URL, upstream_tags=["Issue Tracking"]),
                _ref(OPENWALL_URL, upstream_tags=["mailing-list"]),
                _ref("https://[2001:db8::1]:8443/advisory"),
                _ref("https://192.0.2.10/advisory"),
                _ref(UNMATCHED_URL),
                _ref("https://user@unreachable.example.test/"),
                _ref("ftp://unreachable.example.test/"),
            ],
        )
        await _upsert(db_session, ticket.id, None, [_ref(GITHUB_COMMIT_URL)])

        assert len(await _rows(db_session, ticket.id)) == 8
        assert no_outbound.attempts == []


# ---------------------------------------------------------------------------
# Parent Ticket and unexpected failures (Service Exceptions)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestParentAndFailures:
    async def test_absent_ticket_with_a_valid_candidate_raises_integrity_error(
        self, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No redundant parent lookup: the foreign-key violation of the
        write propagates unchanged."""
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(IntegrityError) as raised,
        ):
            await _upsert(db_session, MISSING_TICKET_ID, None, [_ref(FIRST_URL)])

        assert not isinstance(raised.value, ReferenceServiceError)
        assert getattr(raised.value.driver_exception, "sqlstate", None) == "23503"
        assert not recorder.selects_from("ticket")
        assert _app_records(caplog) == []

    async def test_absent_ticket_without_a_valid_candidate_returns_none(
        self, db_session: AsyncSession, caplog: pytest.LogCaptureFixture
    ) -> None:
        with StatementRecorder(db_session) as recorder:
            result = await _upsert(
                db_session,
                MISSING_TICKET_ID,
                None,
                [_ref(f"ftp://{LEAK}.example.test/")],
            )

        assert result is None
        assert recorder.statements == []
        assert _service_logs(caplog) == [_rejection("invalid_scheme")]

    @pytest.mark.parametrize(
        ("target", "failure"),
        [
            ("classify_reference_url", RuntimeError("injected classifier failure")),
            ("classify_reference_tags", TypeError("injected tag failure")),
            ("normalize_reference_url", ValueError("injected parser failure")),
        ],
        ids=["url-classifier", "tag-classifier", "parser-value-error"],
    )
    async def test_programming_failure_propagates_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        target: str,
        failure: Exception,
    ) -> None:
        """Parser-programming and other programming errors are never
        converted into a skip-and-continue rejection; a plain `ValueError`
        from the URL parser is not a `ReferenceUrlError`."""
        ticket = await ticket_factory()

        def failing(*_args: Any, **_kwargs: Any) -> Any:
            raise failure

        monkeypatch.setattr(reference_service, target, failing)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(type(failure)) as raised,
        ):
            await _upsert(
                db_session,
                ticket.id,
                None,
                [_ref(FIRST_URL, upstream_tags=["Patch"]), _ref(SECOND_URL)],
            )

        assert raised.value is failure
        assert recorder.statements == []
        assert _app_records(caplog) == []


# ---------------------------------------------------------------------------
# Caller-owned transaction (Service Layer)
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


async def _committed_rows(probe: AsyncSession, ticket: Ticket) -> dict[str, RefRow]:
    rows = await _rows(probe, ticket.id)
    await probe.rollback()
    return rows


async def _seed_committed(
    world: CommittedWorld, ticket: Ticket, url: str, **fields: Any
) -> None:
    """A committed automatic reference with backdated timestamps."""
    world.session.add(
        TicketReference(
            ticket_id=ticket.id,
            url=url,
            source=SOURCE,
            created_at=PAST,
            updated_at=PAST,
            **fields,
        )
    )
    await world.session.commit()


def _sync_connection(session: AsyncSession) -> Connection:
    bind = session.bind
    assert isinstance(bind, AsyncConnection)
    connection = bind.sync_connection
    assert connection is not None
    return connection


class _Rewrite:
    """Replaces the `nth` reference upsert of one session's connection by
    `FAILING_SQL`, so PostgreSQL itself fails at exactly that write."""

    def __init__(self, nth: int) -> None:
        self.nth = nth
        self.reached = 0

    def __call__(
        self,
        _conn: Any,
        _cursor: Any,
        statement: str,
        parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> tuple[str, Any]:
        if statement.lstrip().startswith(REFERENCE_INSERT):
            self.reached += 1
            if self.reached == self.nth:
                return FAILING_SQL, ()
        return statement, parameters


@contextmanager
def _fail_upsert(session: AsyncSession, nth: int) -> Iterator[_Rewrite]:
    rewrite = _Rewrite(nth)
    connection = _sync_connection(session)
    event.listen(connection, "before_cursor_execute", rewrite, retval=True)
    try:
        yield rewrite
    finally:
        event.remove(connection, "before_cursor_execute", rewrite)


@pytest.mark.integration
class TestCallerOwnedTransaction:
    """The function never commits or rolls back; the per-CVE workflow owner
    rolls back on any escaping exception or by its own decision."""

    async def test_caller_rollback_after_success_removes_every_change(
        self, world: CommittedWorld, probe: AsyncSession
    ) -> None:
        ticket = await world.ticket(cve_id=None)
        await _seed_committed(world, ticket, FIRST_URL, description=_SEEDED_DESCRIPTION)
        before = await _committed_rows(probe, ticket)
        session = await world.open_session()

        result = await _upsert(
            session,
            ticket.id,
            _ref(SOURCE_PAGE_URL, title=SOURCE_PAGE_TITLE),
            [
                _ref(FIRST_URL, title="Filled", upstream_tags=["Patch"]),
                _ref(SECOND_URL),
            ],
        )

        assert result is None
        inside = await _rows(session, ticket.id)
        assert set(inside) == {SOURCE_PAGE_URL, FIRST_URL, SECOND_URL}
        assert (inside[FIRST_URL].title, inside[FIRST_URL].type) == ("Filled", "patch")
        assert inside[FIRST_URL].updated_at > PAST
        await session.rollback()

        assert await _committed_rows(probe, ticket) == before
        assert list(before) == [FIRST_URL]
        assert before[FIRST_URL].title is None
        assert before[FIRST_URL].updated_at == PAST

    @pytest.mark.parametrize("nth", [1, 2], ids=["first-write", "after-a-write"])
    async def test_database_failure_propagates_and_caller_rollback_restores(
        self,
        world: CommittedWorld,
        probe: AsyncSession,
        caplog: pytest.LogCaptureFixture,
        nth: int,
    ) -> None:
        """An unexpected database failure on a reference write propagates
        unchanged (not an integrity error, not a domain error, not a
        rejection); the caller's rollback leaves the committed state."""
        ticket = await world.ticket(cve_id=None)
        await _seed_committed(world, ticket, FIRST_URL)
        before = await _committed_rows(probe, ticket)
        session = await world.open_session()

        with (
            _fail_upsert(session, nth) as rewrite,
            pytest.raises(DBAPIError) as raised,
        ):
            await _upsert(
                session,
                ticket.id,
                None,
                [_ref(FIRST_URL, title="Filled"), _ref(SECOND_URL), _ref(THIRD_URL)],
            )

        assert rewrite.reached == nth
        assert not isinstance(raised.value, IntegrityError)
        assert not isinstance(raised.value, ReferenceServiceError)
        assert "division by zero" in str(raised.value.orig)
        assert _app_records(caplog) == []
        await session.rollback()
        assert await _committed_rows(probe, ticket) == before


@pytest.mark.integration
class TestTransactionUsableAfterConflict:
    async def test_conflict_paths_keep_the_transaction_usable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        ticket_reference_factory: ReferenceFactory,
    ) -> None:
        """Forced automatic unique-key conflicts (manual winner, same-source
        update, different-source no-op) are merged or skipped without
        aborting the transaction: a later reference upsert and an
        unrelated write flush successfully."""
        ticket = await ticket_factory()
        await _seed(ticket_reference_factory, ticket, FIRST_URL, source="manual")
        await _seed(ticket_reference_factory, ticket, SECOND_URL, title="Old")
        await _seed(
            ticket_reference_factory,
            ticket,
            THIRD_URL,
            title="Owner",
            type="advisory",
            source=OTHER_SOURCE,
        )

        await _upsert(
            db_session,
            ticket.id,
            None,
            [
                _ref(FIRST_RAW_VARIANT, title="Ignored"),
                _ref("HTTP://SECOND.example.test/notes/2", title="New"),
                _ref("http://third.example.test/notes/3", title="Ignored"),
            ],
        )
        await _upsert(db_session, ticket.id, None, [_ref(FOURTH_URL, title="Later")])
        ticket.is_confidential = True
        await db_session.flush()

        rows = await _rows(db_session, ticket.id)
        assert {url: (row.title, row.source) for url, row in rows.items()} == {
            FIRST_URL: (None, "manual"),
            SECOND_URL: ("New", SOURCE),
            THIRD_URL: ("Owner", OTHER_SOURCE),
            FOURTH_URL: ("Later", SOURCE),
        }
        confidential = await db_session.scalar(
            select(Ticket.is_confidential)
            .where(Ticket.id == ticket.id)
            .execution_options(populate_existing=True)
        )
        assert confidential is True
