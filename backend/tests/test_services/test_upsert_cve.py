"""Single-session integration tests for `upsert_cve()` and
`record_source_status()` (backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (Primary Entry Point: `upsert_cve()`
  — Format guard, Parameter `source`, evaluation date; Merge Strategy;
  CVESource Management; Ticket Creation Decision; Complete `upsert_cve()`
  Composition steps 1-9; Transaction Boundaries > Phase 1, including CVSS
  assessment ingestion; Concurrency > Child Persistence Matrix, Canonical
  Payload Duplicate Handling, Affected-Version Snapshot Operations,
  Idempotency; Exceptions; Transaction Ownership; UpsertResult and its
  Design Context).
- docs/features/tickets/cvss-scoring.md (Input Rules; Provider Identity and
  Authority).
- docs/data-model.md (CVE, CVESource, CVECVSSAssessment,
  CVEExternalIdentifier, CVEAffectedVersion, CVECWE, CVESSVCAssessment,
  CVEKEVEntry, CVEEPSSScore).
- docs/features/platform/testing-strategy.md (CVE Ingestion Persistence;
  `server_default=func.now()` and `onupdate=func.now()` Testing; Audit
  Trail Testing).
- Decisions D5 and D7-D10 of issue #750 (naive payload datetimes are UTC;
  conflict-aware child writes without `updated_at` churn and complete-set
  affected-version comparison; one `INSERT ... ON CONFLICT` status write
  with one `clock_timestamp()`; contradictory canonical CVSS duplicates
  raise `ValidationError` before any database write; CVSS candidate
  classification and its sanitized skip warning).

No-op proofs. PostgreSQL `now()` is constant inside the test transaction,
so comparing `updated_at` before and after a call is tautological. Each
proof therefore backdates `updated_at` to a fixed past instant first (an
effective conflict-aware write sets it to `now()`) and also compares the
row's `ctid`: every `UPDATE` writes a new tuple version, so an unchanged
`ctid` proves the row was not rewritten at all (see
`tests.support.cve_ingest.ctid`). Affected-version rows have no
`updated_at`; an equal replacement keeps their ids and `ctid`s.

Skip warnings are captured with `structlog.testing.capture_logs()`, which
replaces the configured processors, so each captured entry carries only
structlog's `event` and `log_level` beside the call's own fields.

Out of scope here: independent-session races (create/create,
create/ensure, rolled-back insert winner, same-source status orderings),
the complete Ticket lifecycle composition (rejection, republication, every
ingestion label, priority events per evidence), and payload construction
details already owned by `tests/test_services/test_cve_ingest.py`.

All identifiers, names, and hosts are fictional.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import func, literal_column, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

from app.core.enums import (
    CVEExternalIdentifierSource,
    CVESourceFetchStatus,
    CVESourceType,
    CveState,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.models.cve import CVE
from app.models.cve_affected_version import CVEAffectedVersion
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_epss_score import CVEEPSSScore
from app.models.cve_external_identifier import CVEExternalIdentifier
from app.models.cve_kev_entry import CVEKEVEntry
from app.models.cve_source import CVESource
from app.models.cve_ssvc_assessment import CVESSVCAssessment
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.services import cve_service, ticket_mutations
from app.services import cvss as cvss_parser
from app.services.cve_ingest import (
    AffectedVersionEntry,
    CVEIngestPayload,
    CWEEntry,
    EPSSEntry,
    ExternalIdentifierEntry,
    KEVEntry,
    SSVCEntry,
    UpsertAction,
    UpsertResult,
)
from app.services.cve_service import (
    CVEIdFormatError,
    ensure_cve_exists,
    record_source_status,
    upsert_cve,
)
from tests.support.cve_ingest import (
    BACKDATED,
    SKIP_EVENT,
    SKIP_EVENT_KEYS,
    av_entry,
    backdate,
    child_counts,
    create_default_cvss_version,
    ctid,
    cvss,
    remove,
    replace,
    row_state,
    skip_events,
    source_rows,
)
from tests.support.cvss_chain import priority_event
from tests.support.suse_cvss import (
    V31_CRITICAL,
    V31_CRITICAL_REORDERED,
    V31_HIGH,
    V40_CRITICAL,
    persisted_assessments,
    unit,
)
from tests.support.ticket_creation import creation_events, ingestion_comment
from tests.support.ticket_mutations import EVAL, StatementRecorder, ticket_events

Factory = Callable[..., Awaitable[Any]]
ExistingCVE = Callable[..., Awaitable[CVE]]

NEW_CVE_ID = "CVE-2099-0100"
NVD = CVESourceType.NVD
SUCCESS = CVESourceFetchStatus.SUCCESS
FAILURE = CVESourceFetchStatus.FAILURE
MISSING = CVESourceFetchStatus.MISSING

CREATED = UpsertAction.CREATED
UPDATED = UpsertAction.UPDATED
UNCHANGED = UpsertAction.UNCHANGED

T1 = datetime(2099, 1, 2, 3, 4, 5, tzinfo=UTC)
T2 = datetime(2099, 2, 3, 4, 5, 6, tzinfo=UTC)

PROVIDER = "Example CNA"
OTHER_PROVIDER = "Example Vendor"


@pytest.fixture(autouse=True)
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none); the
    CVSS batch reads it only for a non-empty candidate set."""
    return await create_default_cvss_version(system_setting_factory)


@pytest.fixture
def existing(cve_factory: Factory, ticket_factory: Factory) -> ExistingCVE:
    """An existing CVE with the given columns, by default with an associated
    `New` Ticket so that no Ticket creation or rejection-on-creation
    lifecycle runs (a `PUBLISHED -> REJECTED` transition still does)."""

    async def _create(*, ticketed: bool = True, **columns: Any) -> CVE:
        cve: CVE = await cve_factory(**columns)
        if ticketed:
            await ticket_factory(cve_id=cve.id)
        return cve

    return _create


async def _upsert(
    db: AsyncSession,
    cve_id: str = NEW_CVE_ID,
    payload: CVEIngestPayload | None = None,
    *,
    source: CVESourceType = NVD,
) -> UpsertResult:
    result = await upsert_cve(
        db, cve_id, source, payload if payload is not None else CVEIngestPayload()
    )
    # Every successful result carries the Ticket associated with its CVE.
    assert result.ticket.cve_id == result.cve.id
    assert result.cve.cve_id == cve_id
    return result


async def _reload(db: AsyncSession, cve: CVE) -> CVE:
    reloaded: CVE = (
        await db.execute(
            select(CVE)
            .where(CVE.id == cve.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return reloaded


async def _count(db: AsyncSession, model: Any, *where: Any) -> int:
    return (await db.scalar(select(func.count()).select_from(model).where(*where))) or 0


async def _totals(db: AsyncSession) -> dict[str, int]:
    """Row totals of every table an `upsert_cve()` call may write."""
    models: tuple[Any, ...] = (
        CVE,
        Ticket,
        TicketAuditEvent,
        CVESource,
        CVECVSSAssessment,
        CVECWE,
        CVEExternalIdentifier,
        CVEAffectedVersion,
        CVESSVCAssessment,
        CVEKEVEntry,
        CVEEPSSScore,
    )
    return {model.__tablename__: await _count(db, model) for model in models}


async def _ticket_of(db: AsyncSession, cve: CVE) -> Ticket:
    ticket: Ticket = (
        await db.execute(
            select(Ticket)
            .where(Ticket.cve_id == cve.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    return ticket


@pytest.mark.integration
class TestObservationPreconditions:
    async def test_identical_value_rewrite_changes_ctid_but_row_lock_does_not(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        """The no-op proofs rely on this: a lock keeps the tuple, any
        `UPDATE` (even assigning the same value) writes a new one."""
        cve: CVE = await cve_factory(title="Same")
        initial = await ctid(db_session, CVE, cve.id)

        await db_session.execute(
            select(CVE.id).where(CVE.id == cve.id).with_for_update(key_share=True)
        )
        locked = await ctid(db_session, CVE, cve.id)
        await db_session.execute(
            text("UPDATE cve SET title = title WHERE id = :id"), {"id": cve.id}
        )

        assert locked == initial
        assert await ctid(db_session, CVE, cve.id) != initial


# ---------------------------------------------------------------------------
# Guards before any database operation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestGuards:
    @pytest.mark.parametrize(
        "cve_id",
        [
            pytest.param("cve-2099-0100", id="lowercase"),
            pytest.param("CVE-2099-123456789012", id="21-characters"),
            pytest.param("CVE-2099-01", id="short-sequence"),
            pytest.param("", id="empty"),
            pytest.param(None, id="none"),
        ],
    )
    async def test_malformed_cve_id_raises_format_error_before_any_statement(
        self, db_session: AsyncSession, cve_id: Any
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVEIdFormatError),
        ):
            await upsert_cve(db_session, cve_id, NVD, CVEIngestPayload(title="T"))

        assert recorder.statements == []

    async def test_format_guard_precedes_the_source_guard(
        self, db_session: AsyncSession
    ) -> None:
        raw_source: Any = "nvd"

        with pytest.raises(CVEIdFormatError):
            await upsert_cve(
                db_session, "cve-2099-0100", raw_source, CVEIngestPayload()
            )

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param("nvd", id="raw-value"),
            pytest.param("NVD", id="raw-name"),
            pytest.param(None, id="none"),
        ],
    )
    async def test_non_enum_source_raises_value_error_before_any_statement(
        self, db_session: AsyncSession, source: Any
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="CVESourceType"),
        ):
            await upsert_cve(db_session, NEW_CVE_ID, source, CVEIngestPayload())

        assert recorder.statements == []
        assert await _count(db_session, CVE, CVE.cve_id == NEW_CVE_ID) == 0

    @pytest.mark.parametrize(
        "cve_data",
        [
            pytest.param({}, id="empty-dict"),
            pytest.param({"title": "Fictional"}, id="dict"),
            pytest.param(None, id="none"),
            pytest.param(CWEEntry(cwe_id="CWE-79", source="NVD"), id="other-model"),
        ],
    )
    async def test_non_payload_cve_data_raises_value_error_before_any_statement(
        self, db_session: AsyncSession, cve_data: Any
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="CVEIngestPayload"),
        ):
            await upsert_cve(db_session, NEW_CVE_ID, NVD, cve_data)

        assert recorder.statements == []
        assert await _count(db_session, CVE, CVE.cve_id == NEW_CVE_ID) == 0

    def test_invalid_global_payloads_are_rejected_at_construction(self) -> None:
        """Explicit-null `cve_state` and `PUBLISHED` with a `date_rejected`
        never reach `upsert_cve()`: construction raises first."""
        with pytest.raises(ValidationError):
            CVEIngestPayload(cve_state=None)
        with pytest.raises(ValidationError):
            CVEIngestPayload(cve_state=CveState.PUBLISHED, date_rejected=T1)


# ---------------------------------------------------------------------------
# Canonical CVSS duplicates (step 2, D9)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCanonicalCVSSDuplicates:
    async def test_contradictory_duplicates_reject_before_any_statement(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            title="Fictional title",
            cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
            affected_version_operations=[replace("cna", av_entry(vendor="V"))],
            kev_data=KEVEntry(date_added=date(2099, 1, 15)),
            cvss_assessments=[
                cvss(PROVIDER, V31_CRITICAL.canonical),
                cvss(OTHER_PROVIDER, V31_HIGH.canonical),
                cvss(PROVIDER, V31_HIGH.canonical),
            ],
        )
        before = await _totals(db_session)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValidationError) as raised,
        ):
            await upsert_cve(db_session, NEW_CVE_ID, NVD, payload)

        assert recorder.statements == []
        errors = raised.value.errors()
        assert [(e["type"], e["loc"]) for e in errors] == [
            ("cvss_assessment_conflict", ("cvss_assessments", 2))
        ]
        message = str(raised.value)
        assert PROVIDER not in message
        assert "CVSS:" not in message
        assert await _totals(db_session) == before

    async def test_contradiction_on_existing_cve_changes_nothing(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing(title="Kept")
        payload = CVEIngestPayload(
            title="Replaced",
            cvss_assessments=[
                cvss(PROVIDER, V40_CRITICAL.canonical),
                cvss(
                    PROVIDER,
                    "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                ),
            ],
        )

        with StatementRecorder(db_session) as recorder, pytest.raises(ValidationError):
            await upsert_cve(db_session, cve.cve_id, NVD, payload)

        assert recorder.statements == []
        assert (await _reload(db_session, cve)).title == "Kept"

    @pytest.mark.parametrize(
        "second",
        [
            pytest.param(V31_CRITICAL.canonical, id="identical"),
            pytest.param(V31_CRITICAL_REORDERED, id="reordered-metrics"),
            pytest.param(f"  {V31_CRITICAL.canonical}\t", id="outer-whitespace"),
        ],
    )
    async def test_same_canonical_vector_collapses_to_one_row(
        self, db_session: AsyncSession, second: str
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(PROVIDER, V31_CRITICAL.canonical),
                cvss(PROVIDER, second),
            ]
        )

        result = await _upsert(db_session, payload=payload)

        assert result.action is CREATED
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_CRITICAL)
        ]

    async def test_same_provider_different_versions_do_not_conflict(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(PROVIDER, V31_CRITICAL.canonical),
                cvss(PROVIDER, V40_CRITICAL.canonical),
            ]
        )

        result = await _upsert(db_session, payload=payload)

        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_CRITICAL),
            unit(PROVIDER, V40_CRITICAL),
        ]


# ---------------------------------------------------------------------------
# Global fields (Merge Strategy)
# ---------------------------------------------------------------------------

OLD_NEW: dict[str, tuple[Any, Any]] = {
    "title": ("Fictional old title", "Fictional new title"),
    "description": ("Fictional old description", "Fictional new description"),
    "published_date": (T1, T2),
    "modified_date": (T1 + timedelta(days=1), T2 + timedelta(days=1)),
}
NULLABLE_FIELDS = list(OLD_NEW)


def _globals(cve: CVE) -> dict[str, Any]:
    return {name: getattr(cve, name) for name in NULLABLE_FIELDS}


def _old_globals() -> dict[str, Any]:
    return {name: old for name, (old, _) in OLD_NEW.items()}


@pytest.mark.integration
@pytest.mark.parametrize("field", NULLABLE_FIELDS)
class TestNullableGlobalField:
    async def test_omitted_field_preserves_value_and_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing(**_old_globals())
        others = {n: v for n, v in OLD_NEW.items() if n != field}
        payload = CVEIngestPayload(**{n: v[0] for n, v in others.items()})

        result = await _upsert(db_session, cve.cve_id, payload)

        assert result.action is UNCHANGED
        assert _globals(await _reload(db_session, cve)) == _old_globals()

    async def test_explicit_null_clears_only_that_field_and_is_updated(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing(**_old_globals())

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{field: None})
        )

        assert result.action is UPDATED
        assert _globals(await _reload(db_session, cve)) == {
            **_old_globals(),
            field: None,
        }

    async def test_value_replaces_only_that_field_and_is_updated(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing(**_old_globals())
        new = OLD_NEW[field][1]

        result = await _upsert(db_session, cve.cve_id, CVEIngestPayload(**{field: new}))

        assert result.action is UPDATED
        assert _globals(await _reload(db_session, cve)) == {
            **_old_globals(),
            field: new,
        }

    async def test_value_sets_null_field_and_is_updated(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing()
        new = OLD_NEW[field][1]

        result = await _upsert(db_session, cve.cve_id, CVEIngestPayload(**{field: new}))

        assert result.action is UPDATED
        assert getattr(await _reload(db_session, cve), field) == new

    async def test_equal_value_is_noop_without_rewrite(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing(**_old_globals())
        await backdate(db_session, CVE, cve.id)
        before = await row_state(db_session, CVE, cve.id)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{field: OLD_NEW[field][0]})
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVE, cve.id) == before
        assert before[1] == BACKDATED

    async def test_explicit_null_on_null_field_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE, field: str
    ) -> None:
        cve = await existing()

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{field: None})
        )

        assert result.action is UNCHANGED
        assert getattr(await _reload(db_session, cve), field) is None


@pytest.mark.integration
class TestGlobalTimestamps:
    @pytest.mark.parametrize(
        "equal",
        [
            pytest.param(T1.replace(tzinfo=None), id="naive-utc"),
            pytest.param(T1.astimezone(timezone(timedelta(hours=2))), id="offset"),
        ],
    )
    async def test_equal_instant_in_another_form_is_noop_without_rewrite(
        self, db_session: AsyncSession, existing: ExistingCVE, equal: datetime
    ) -> None:
        cve = await existing(published_date=T1)
        await backdate(db_session, CVE, cve.id)
        before = await row_state(db_session, CVE, cve.id)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(published_date=equal)
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVE, cve.id) == before

    async def test_naive_datetime_is_persisted_as_the_same_utc_wall_clock(
        self, db_session: AsyncSession
    ) -> None:
        naive = datetime(2099, 5, 6, 7, 8, 9)  # noqa: DTZ001 - naive input under test
        payload = CVEIngestPayload(modified_date=naive)

        result = await _upsert(db_session, payload=payload)

        stored = (await _reload(db_session, result.cve)).modified_date
        assert stored == datetime(2099, 5, 6, 7, 8, 9, tzinfo=UTC)

    async def test_effective_change_advances_cve_updated_at(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing(title="Old")
        await backdate(db_session, CVE, cve.id)

        await _upsert(db_session, cve.cve_id, CVEIngestPayload(title="New"))

        assert (await _reload(db_session, cve)).updated_at > BACKDATED


@pytest.mark.integration
class TestCVEStateAndDateRejected:
    @pytest.mark.parametrize("state", list(CveState))
    async def test_omitted_state_preserves_value_and_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE, state: CveState
    ) -> None:
        date_rejected = T1 if state is CveState.REJECTED else None
        cve = await existing(cve_state=state.value, date_rejected=date_rejected)

        result = await _upsert(db_session, cve.cve_id, CVEIngestPayload())

        assert result.action is UNCHANGED
        reloaded = await _reload(db_session, cve)
        assert (reloaded.cve_state, reloaded.date_rejected) == (
            state.value,
            date_rejected,
        )

    @pytest.mark.parametrize("state", list(CveState))
    async def test_each_state_value_is_accepted_on_create(
        self, db_session: AsyncSession, state: CveState
    ) -> None:
        result = await _upsert(db_session, payload=CVEIngestPayload(cve_state=state))

        assert result.action is CREATED
        assert (await _reload(db_session, result.cve)).cve_state == state.value

    @pytest.mark.parametrize("state", list(CveState))
    async def test_equal_state_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE, state: CveState
    ) -> None:
        date_rejected = T1 if state is CveState.REJECTED else None
        cve = await existing(cve_state=state.value, date_rejected=date_rejected)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(cve_state=state)
        )

        assert result.action is UNCHANGED
        assert (await _reload(db_session, cve)).date_rejected == date_rejected

    @pytest.mark.parametrize(
        ("payload", "expected_date"),
        [
            pytest.param({"date_rejected": T1}, T1, id="with-date"),
            pytest.param({}, None, id="date-omitted"),
            pytest.param({"date_rejected": None}, None, id="date-null"),
        ],
    )
    async def test_published_to_rejected_is_updated(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        payload: dict[str, Any],
        expected_date: datetime | None,
    ) -> None:
        cve = await existing()

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cve_state=CveState.REJECTED, **payload),
        )

        assert result.action is UPDATED
        reloaded = await _reload(db_session, cve)
        assert (reloaded.cve_state, reloaded.date_rejected) == (
            "REJECTED",
            expected_date,
        )

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({}, id="date-omitted"),
            pytest.param({"date_rejected": None}, id="date-null"),
        ],
    )
    async def test_rejected_to_published_always_clears_date_rejected(
        self, db_session: AsyncSession, existing: ExistingCVE, payload: dict[str, Any]
    ) -> None:
        cve = await existing(cve_state="REJECTED", date_rejected=T1)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cve_state=CveState.PUBLISHED, **payload),
        )

        assert result.action is UPDATED
        reloaded = await _reload(db_session, cve)
        assert (reloaded.cve_state, reloaded.date_rejected) == ("PUBLISHED", None)

    async def test_date_rejected_without_state_on_published_cve_stays_null(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        """A resulting `PUBLISHED` always leaves `date_rejected` `NULL`."""
        cve = await existing()

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(date_rejected=T2)
        )

        assert result.action is UNCHANGED
        assert (await _reload(db_session, cve)).date_rejected is None

    @pytest.mark.parametrize(
        ("payload", "expected", "action"),
        [
            pytest.param({}, T1, UNCHANGED, id="omitted"),
            pytest.param(
                {"cve_state": CveState.REJECTED}, T1, UNCHANGED, id="omitted-with-state"
            ),
            pytest.param({"date_rejected": None}, None, UPDATED, id="null"),
            pytest.param(
                {"cve_state": CveState.REJECTED, "date_rejected": None},
                None,
                UPDATED,
                id="null-with-state",
            ),
            pytest.param({"date_rejected": T2}, T2, UPDATED, id="timestamp"),
            pytest.param(
                {"cve_state": CveState.REJECTED, "date_rejected": T2},
                T2,
                UPDATED,
                id="timestamp-with-state",
            ),
            pytest.param(
                {"date_rejected": T1.replace(tzinfo=None)}, T1, UNCHANGED, id="equal"
            ),
        ],
    )
    async def test_rejected_date_matrix(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        payload: dict[str, Any],
        expected: datetime | None,
        action: UpsertAction,
    ) -> None:
        cve = await existing(cve_state="REJECTED", date_rejected=T1)

        result = await _upsert(db_session, cve.cve_id, CVEIngestPayload(**payload))

        assert result.action is action
        reloaded = await _reload(db_session, cve)
        assert (reloaded.cve_state, reloaded.date_rejected) == ("REJECTED", expected)

    async def test_timestamp_sets_null_date_of_rejected_cve(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing(cve_state="REJECTED")

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(date_rejected=T2)
        )

        assert result.action is UPDATED
        assert (await _reload(db_session, cve)).date_rejected == T2

    async def test_rejection_alone_deletes_no_child_row(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cvss_assessment_factory: Factory,
        cve_cwe_factory: Factory,
        cve_external_identifier_factory: Factory,
        cve_affected_version_factory: Factory,
        cve_ssvc_assessment_factory: Factory,
        cve_kev_entry_factory: Factory,
        cve_epss_score_factory: Factory,
    ) -> None:
        cve = await existing()
        for factory in (
            cve_cvss_assessment_factory,
            cve_cwe_factory,
            cve_external_identifier_factory,
            cve_affected_version_factory,
            cve_ssvc_assessment_factory,
            cve_kev_entry_factory,
            cve_epss_score_factory,
        ):
            await factory(cve_id=cve.id)
        before = await child_counts(db_session, cve.id)
        assert set(before.values()) == {1}

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cve_state=CveState.REJECTED, date_rejected=T1),
        )

        assert result.action is UPDATED
        assert await child_counts(db_session, cve.id) == before


# ---------------------------------------------------------------------------
# Additive children: CVSS (through the batch), CWE, external identifiers
# ---------------------------------------------------------------------------

ABSENT_COLLECTION = [
    pytest.param({}, id="omitted"),
    pytest.param(None, id="explicit-null"),
    pytest.param([], id="empty"),
]


def _with(field: str, value: Any) -> CVEIngestPayload:
    """A payload omitting `field` for `{}`, else supplying `value`."""
    if value == {}:
        return CVEIngestPayload()
    return CVEIngestPayload(**{field: value})


@pytest.mark.integration
class TestCVSSChild:
    @pytest.mark.parametrize("value", ABSENT_COLLECTION)
    async def test_absent_input_retains_rows_and_applies_an_empty_batch(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cvss_assessment_factory: Factory,
        monkeypatch: pytest.MonkeyPatch,
        value: Any,
    ) -> None:
        cve = await existing()
        row = await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=PROVIDER, **V31_HIGH.columns()
        )
        await backdate(db_session, CVECVSSAssessment, row.id)
        before = await row_state(db_session, CVECVSSAssessment, row.id)
        batches: list[Any] = []
        original = ticket_mutations.upsert_external_cvss_batch

        async def spy(db: AsyncSession, **kwargs: Any) -> Any:
            batches.append(list(kwargs["assessments"]))
            return await original(db, **kwargs)

        monkeypatch.setattr(ticket_mutations, "upsert_external_cvss_batch", spy)

        result = await _upsert(db_session, cve.cve_id, _with("cvss_assessments", value))

        assert result.action is UNCHANGED
        assert batches == [[]]
        assert await row_state(db_session, CVECVSSAssessment, row.id) == before

    async def test_new_provider_version_is_created_and_updates(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing()

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V31_HIGH.canonical)]),
        )

        assert result.action is UPDATED
        assert await persisted_assessments(db_session, cve.id) == [
            unit(PROVIDER, V31_HIGH)
        ]

    async def test_changed_vector_is_an_effective_update(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve = await existing()
        row = await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=PROVIDER, **V31_HIGH.columns()
        )

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V31_CRITICAL_REORDERED)]),
        )

        assert result.action is UPDATED
        assert await persisted_assessments(db_session, cve.id) == [
            unit(PROVIDER, V31_CRITICAL)
        ]
        assert await _count(
            db_session, CVECVSSAssessment, CVECVSSAssessment.id == row.id
        )

    async def test_equal_canonical_vector_is_noop_without_rewrite(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve = await existing()
        row = await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=PROVIDER, **V31_CRITICAL.columns()
        )
        await backdate(db_session, CVECVSSAssessment, row.id)
        before = await row_state(db_session, CVECVSSAssessment, row.id)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V31_CRITICAL_REORDERED)]),
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVECVSSAssessment, row.id) == before

    async def test_unmentioned_provider_is_retained(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cvss_assessment_factory: Factory,
    ) -> None:
        cve = await existing()
        await cve_cvss_assessment_factory(
            cve_id=cve.id, provider_name=OTHER_PROVIDER, **V31_HIGH.columns()
        )

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V40_CRITICAL.canonical)]),
        )

        assert result.action is UPDATED
        assert await persisted_assessments(db_session, cve.id) == [
            unit(OTHER_PROVIDER, V31_HIGH),
            unit(PROVIDER, V40_CRITICAL),
        ]


@pytest.mark.integration
class TestCWEChild:
    @pytest.mark.parametrize("value", ABSENT_COLLECTION)
    async def test_absent_input_retains_rows(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_cwe_factory: Factory,
        value: Any,
    ) -> None:
        cve = await existing()
        row = await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")
        await backdate(db_session, CVECWE, row.id)
        before = await row_state(db_session, CVECWE, row.id)

        result = await _upsert(
            db_session, cve.cve_id, _with("cwe_classifications", value)
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVECWE, row.id) == before

    async def test_new_key_is_created_and_existing_key_retained(
        self, db_session: AsyncSession, existing: ExistingCVE, cve_cwe_factory: Factory
    ) -> None:
        cve = await existing()
        await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                cwe_classifications=[
                    CWEEntry(cwe_id="CWE-79", source="cna:Example"),
                    CWEEntry(cwe_id="CWE-787", source="NVD"),
                ]
            ),
        )

        assert result.action is UPDATED
        rows = (
            await db_session.execute(
                select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
            )
        ).all()
        assert sorted(tuple(r) for r in rows) == [
            ("CWE-787", "NVD"),
            ("CWE-79", "NVD"),
            ("CWE-79", "cna:Example"),
        ]

    async def test_equal_key_is_noop_without_rewrite(
        self, db_session: AsyncSession, existing: ExistingCVE, cve_cwe_factory: Factory
    ) -> None:
        cve = await existing()
        row = await cve_cwe_factory(cve_id=cve.id, cwe_id="CWE-79", source="NVD")
        await backdate(db_session, CVECWE, row.id)
        before = await row_state(db_session, CVECWE, row.id)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")]
            ),
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVECWE, row.id) == before

    async def test_identical_duplicates_collapse_to_one_row(
        self, db_session: AsyncSession
    ) -> None:
        entry = CWEEntry(cwe_id="CWE-79", source="NVD")

        result = await _upsert(
            db_session, payload=CVEIngestPayload(cwe_classifications=[entry, entry])
        )

        assert await _count(db_session, CVECWE, CVECWE.cve_id == result.cve.id) == 1


GHSA = CVEExternalIdentifierSource.GHSA
GHSA_ID = "GHSA-test-0001-xxxx"
URL_A = "https://example.test/advisories/a"
URL_B = "https://example.test/advisories/b"


def _identifier(
    url: str | None = URL_A, identifier: str = GHSA_ID
) -> ExternalIdentifierEntry:
    return ExternalIdentifierEntry(source=GHSA, identifier=identifier, url=url)


@pytest.mark.integration
class TestExternalIdentifierChild:
    @pytest.mark.parametrize("value", ABSENT_COLLECTION)
    async def test_absent_input_retains_rows(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_external_identifier_factory: Factory,
        value: Any,
    ) -> None:
        cve = await existing()
        row = await cve_external_identifier_factory(cve_id=cve.id, url=URL_A)
        await backdate(db_session, CVEExternalIdentifier, row.id)
        before = await row_state(db_session, CVEExternalIdentifier, row.id)

        result = await _upsert(
            db_session, cve.cve_id, _with("external_identifiers", value)
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVEExternalIdentifier, row.id) == before

    async def test_new_identifier_is_created(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing()

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(external_identifiers=[_identifier()]),
        )

        assert result.action is UPDATED
        rows = (
            await db_session.execute(
                select(
                    CVEExternalIdentifier.cve_id,
                    CVEExternalIdentifier.source,
                    CVEExternalIdentifier.identifier,
                    CVEExternalIdentifier.url,
                )
            )
        ).all()
        assert [tuple(r) for r in rows] == [(cve.id, "GHSA", GHSA_ID, URL_A)]

    @pytest.mark.parametrize("url", [URL_B, None], ids=["changed-url", "cleared-url"])
    async def test_url_change_is_an_effective_update(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_external_identifier_factory: Factory,
        url: str | None,
    ) -> None:
        cve = await existing()
        row = await cve_external_identifier_factory(
            cve_id=cve.id, identifier=GHSA_ID, url=URL_A
        )
        await backdate(db_session, CVEExternalIdentifier, row.id)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(external_identifiers=[_identifier(url)]),
        )

        assert result.action is UPDATED
        stored = (
            await db_session.execute(
                select(
                    CVEExternalIdentifier.url, CVEExternalIdentifier.updated_at
                ).where(CVEExternalIdentifier.id == row.id)
            )
        ).one()
        assert stored[0] == url
        assert stored[1] > BACKDATED

    async def test_equal_content_is_noop_without_rewrite(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_external_identifier_factory: Factory,
    ) -> None:
        cve = await existing()
        row = await cve_external_identifier_factory(
            cve_id=cve.id, identifier=GHSA_ID, url=URL_A
        )
        await backdate(db_session, CVEExternalIdentifier, row.id)
        before = await row_state(db_session, CVEExternalIdentifier, row.id)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(external_identifiers=[_identifier()]),
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, CVEExternalIdentifier, row.id) == before

    async def test_identifier_of_another_cve_moves_to_this_cve(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_external_identifier_factory: Factory,
    ) -> None:
        previous = await existing()
        cve = await existing()
        row = await cve_external_identifier_factory(
            cve_id=previous.id, identifier=GHSA_ID, url=URL_A
        )

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(external_identifiers=[_identifier()]),
        )

        assert result.action is UPDATED
        rows = (
            await db_session.execute(
                select(CVEExternalIdentifier.id, CVEExternalIdentifier.cve_id).where(
                    CVEExternalIdentifier.identifier == GHSA_ID
                )
            )
        ).all()
        assert [tuple(r) for r in rows] == [(row.id, cve.id)]

    async def test_identical_duplicates_collapse_to_one_row(
        self, db_session: AsyncSession
    ) -> None:
        result = await _upsert(
            db_session,
            payload=CVEIngestPayload(
                external_identifiers=[_identifier(), _identifier()]
            ),
        )

        assert (
            await _count(
                db_session,
                CVEExternalIdentifier,
                CVEExternalIdentifier.cve_id == result.cve.id,
            )
            == 1
        )


# ---------------------------------------------------------------------------
# 1:1 children: SSVC, KEV, EPSS
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OneToOne:
    field: str
    model: Any
    factory: str
    stored: dict[str, Any]
    equal: Any
    changed: Any
    changed_values: dict[str, Any]


ONE_TO_ONE = [
    pytest.param(
        OneToOne(
            field="ssvc_assessment",
            model=CVESSVCAssessment,
            factory="cve_ssvc_assessment_factory",
            stored={
                "exploitation": "none",
                "automatable": "no",
                "technical_impact": "partial",
                "version": "2.0.3",
                "assessed_at": T1,
            },
            # A naive `assessed_at` is the same UTC instant (D5).
            equal=SSVCEntry(
                exploitation=SSVCExploitation.NONE,
                automatable=SSVCAutomatable.NO,
                technical_impact=SSVCTechnicalImpact.PARTIAL,
                version="2.0.3",
                assessed_at=T1.replace(tzinfo=None),
            ),
            changed=SSVCEntry(
                exploitation=SSVCExploitation.POC,
                automatable=SSVCAutomatable.NO,
                technical_impact=SSVCTechnicalImpact.PARTIAL,
                version="2.0.3",
                assessed_at=T2,
            ),
            changed_values={
                "exploitation": "poc",
                "automatable": "no",
                "technical_impact": "partial",
                "version": "2.0.3",
                "assessed_at": T2,
            },
        ),
        id="ssvc",
    ),
    pytest.param(
        OneToOne(
            field="kev_data",
            model=CVEKEVEntry,
            factory="cve_kev_entry_factory",
            stored={
                "date_added": date(2099, 1, 15),
                "reference_url": "https://example.test/kev/0001",
            },
            equal=KEVEntry(
                date_added=date(2099, 1, 15),
                reference_url="https://example.test/kev/0001",
            ),
            changed=KEVEntry(date_added=date(2099, 1, 16)),
            changed_values={"date_added": date(2099, 1, 16), "reference_url": None},
        ),
        id="kev",
    ),
    pytest.param(
        OneToOne(
            field="epss_score",
            model=CVEEPSSScore,
            factory="cve_epss_score_factory",
            stored={
                "score": 0.00043,
                "percentile": 0.12345,
                "assessed_at": date(2099, 1, 15),
            },
            equal=EPSSEntry(
                score=0.00043, percentile=0.12345, assessed_at=date(2099, 1, 15)
            ),
            changed=EPSSEntry(
                score=0.5, percentile=0.12345, assessed_at=date(2099, 1, 16)
            ),
            changed_values={
                "score": 0.5,
                "percentile": 0.12345,
                "assessed_at": date(2099, 1, 16),
            },
        ),
        id="epss",
    ),
]


async def _one_to_one_values(
    db: AsyncSession, case: OneToOne, cve: CVE
) -> list[dict[str, Any]]:
    columns = [getattr(case.model, name) for name in case.stored]
    rows = (await db.execute(select(*columns).where(case.model.cve_id == cve.id))).all()
    return [dict(zip(case.stored, row, strict=True)) for row in rows]


@pytest.mark.integration
@pytest.mark.parametrize("case", ONE_TO_ONE)
class TestOneToOneChild:
    @pytest.mark.parametrize("value", [{}, None], ids=["omitted", "explicit-null"])
    async def test_absent_input_retains_the_row(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        request: pytest.FixtureRequest,
        case: OneToOne,
        value: Any,
    ) -> None:
        cve = await existing()
        row = await request.getfixturevalue(case.factory)(cve_id=cve.id, **case.stored)
        await backdate(db_session, case.model, row.id)
        before = await row_state(db_session, case.model, row.id)

        result = await _upsert(db_session, cve.cve_id, _with(case.field, value))

        assert result.action is UNCHANGED
        assert await row_state(db_session, case.model, row.id) == before

    async def test_supplied_value_is_created(
        self, db_session: AsyncSession, existing: ExistingCVE, case: OneToOne
    ) -> None:
        cve = await existing()

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{case.field: case.equal})
        )

        assert result.action is UPDATED
        assert await _one_to_one_values(db_session, case, cve) == [case.stored]

    async def test_changed_value_is_an_effective_update(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        request: pytest.FixtureRequest,
        case: OneToOne,
    ) -> None:
        cve = await existing()
        row = await request.getfixturevalue(case.factory)(cve_id=cve.id, **case.stored)
        await backdate(db_session, case.model, row.id)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{case.field: case.changed})
        )

        assert result.action is UPDATED
        assert await _one_to_one_values(db_session, case, cve) == [case.changed_values]
        _, updated_at = await row_state(db_session, case.model, row.id)
        assert updated_at > BACKDATED

    async def test_equal_value_is_noop_without_rewrite(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        request: pytest.FixtureRequest,
        case: OneToOne,
    ) -> None:
        cve = await existing()
        row = await request.getfixturevalue(case.factory)(cve_id=cve.id, **case.stored)
        await backdate(db_session, case.model, row.id)
        before = await row_state(db_session, case.model, row.id)

        result = await _upsert(
            db_session, cve.cve_id, CVEIngestPayload(**{case.field: case.equal})
        )

        assert result.action is UNCHANGED
        assert await row_state(db_session, case.model, row.id) == before


# ---------------------------------------------------------------------------
# Affected-version scopes
# ---------------------------------------------------------------------------

FULL_ENTRY = av_entry(
    vendor="Example Vendor",
    product="Example Product",
    package_url="pkg:generic/example-product@1.0",
    collection_url="https://example.test/packages",
    package_name="example-product",
    repo="https://example.test/example-product.git",
    version="1.0",
    version_type="semver",
    version_end="1.5",
    version_end_inclusive=False,
    program_files=["src/alpha.c", "src/beta.c"],
    cpe="cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*",
    ecosystem="PyPI",
    status="affected",
    default_status="unaffected",
)
E1 = av_entry(vendor="Example", product="Alpha", version="1.0", status="affected")
E2 = av_entry(vendor="Example", product="Beta", version="2.0", program_files=["b.c"])
E3 = av_entry(vendor="Example", product="Gamma", version="3.0")
E4 = av_entry(vendor="Example", product="Delta", version="4.0")

ENTRY_COLUMNS = (
    "vendor",
    "product",
    "package_url",
    "collection_url",
    "package_name",
    "repo",
    "version",
    "version_type",
    "version_end",
    "version_end_inclusive",
    "program_files",
    "cpe",
    "ecosystem",
    "status",
    "default_status",
)


async def _seed(
    factory: Factory, cve: CVE, scope: str, *entries: AffectedVersionEntry
) -> list[uuid.UUID]:
    """Persist `entries` in `scope` directly; their ids."""
    ids = []
    for entry in entries:
        row = await factory(cve_id=cve.id, source_container=scope, **entry.model_dump())
        ids.append(row.id)
    return ids


async def _scope(db: AsyncSession, cve: CVE, scope: str) -> list[tuple[Any, ...]]:
    """`(id, ctid, product)` of every row of one scope, by product."""
    rows: Any = await db.execute(
        select(
            CVEAffectedVersion.id,
            literal_column("ctid::text"),
            CVEAffectedVersion.product,
        )
        .where(
            CVEAffectedVersion.cve_id == cve.id,
            CVEAffectedVersion.source_container == scope,
        )
        .order_by(CVEAffectedVersion.product)
    )
    return [tuple(r) for r in rows]


def _products(rows: list[tuple[Any, ...]]) -> list[str]:
    return [r[2] for r in rows]


@pytest.mark.integration
class TestAffectedVersionScopes:
    async def test_replacement_persists_every_field_and_the_scope(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            affected_version_operations=[replace("adp:Example", FULL_ENTRY)]
        )

        result = await _upsert(db_session, payload=payload)

        assert result.action is CREATED
        rows = (
            await db_session.execute(
                select(
                    CVEAffectedVersion.source_container,
                    *(getattr(CVEAffectedVersion, n) for n in ENTRY_COLUMNS),
                ).where(CVEAffectedVersion.cve_id == result.cve.id)
            )
        ).all()
        assert [tuple(r) for r in rows] == [
            (
                "adp:Example",
                "Example Vendor",
                "Example Product",
                "pkg:generic/example-product@1.0",
                "https://example.test/packages",
                "example-product",
                "https://example.test/example-product.git",
                "1.0",
                "semver",
                "1.5",
                False,
                ["src/alpha.c", "src/beta.c"],
                "cpe:2.3:a:example:example_product:*:*:*:*:*:*:*:*",
                "PyPI",
                "affected",
                "unaffected",
            )
        ]

    @pytest.mark.parametrize("value", ABSENT_COLLECTION)
    async def test_absent_operations_leave_every_scope_untouched(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
        value: Any,
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "cna", E1)
        before = await _scope(db_session, cve, "cna")

        result = await _upsert(
            db_session, cve.cve_id, _with("affected_version_operations", value)
        )

        assert result.action is UNCHANGED
        assert await _scope(db_session, cve, "cna") == before

    async def test_non_empty_replacement_replaces_only_its_scope(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "cna", E1, E2)
        await _seed(cve_affected_version_factory, cve, "adp:Example", E1)
        unobserved = await _scope(db_session, cve, "adp:Example")

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(affected_version_operations=[replace("cna", E3)]),
        )

        assert result.action is UPDATED
        assert _products(await _scope(db_session, cve, "cna")) == ["Gamma"]
        assert await _scope(db_session, cve, "adp:Example") == unobserved

    @pytest.mark.parametrize(
        "operation",
        [
            pytest.param(replace("cna"), id="empty-replace"),
            pytest.param(remove("cna"), id="remove"),
        ],
    )
    async def test_empty_replacement_or_removal_leaves_zero_rows(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
        operation: Any,
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "cna", E1, E2)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(affected_version_operations=[operation]),
        )

        assert result.action is UPDATED
        # No marker row: the CVE has no affected-version row at all.
        assert (
            await _count(
                db_session, CVEAffectedVersion, CVEAffectedVersion.cve_id == cve.id
            )
            == 0
        )

    @pytest.mark.parametrize(
        "entries",
        [
            pytest.param((E1, E2), id="same-order"),
            pytest.param((E2, E1), id="reordered"),
        ],
    )
    async def test_equal_replacement_is_noop_and_keeps_rows(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
        entries: tuple[AffectedVersionEntry, ...],
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "cna", E1, E2)
        before = await _scope(db_session, cve, "cna")

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(affected_version_operations=[replace("cna", *entries)]),
        )

        assert result.action is UNCHANGED
        assert await _scope(db_session, cve, "cna") == before

    @pytest.mark.parametrize(
        "operation",
        [
            pytest.param(replace("cna"), id="empty-replace"),
            pytest.param(remove("cna"), id="remove"),
        ],
    )
    async def test_operation_on_already_empty_scope_is_noop(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
        operation: Any,
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "adp:Example", E1)
        other = await _scope(db_session, cve, "adp:Example")

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(affected_version_operations=[operation]),
        )

        assert result.action is UNCHANGED
        assert await _scope(db_session, cve, "cna") == []
        assert await _scope(db_session, cve, "adp:Example") == other

    async def test_operations_on_multiple_scopes_never_affect_each_other(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        cve_affected_version_factory: Factory,
    ) -> None:
        cve = await existing()
        await _seed(cve_affected_version_factory, cve, "cna", E1)
        await _seed(cve_affected_version_factory, cve, "adp:Example", E2)
        await _seed(cve_affected_version_factory, cve, "osv", E3)
        await _seed(cve_affected_version_factory, cve, "ghsa", E1, E2)
        unobserved = await _scope(db_session, cve, "adp:Example")
        equal = await _scope(db_session, cve, "ghsa")

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                affected_version_operations=[
                    replace("cna", E4),
                    remove("osv"),
                    replace("ghsa", E2, E1),
                ]
            ),
        )

        assert result.action is UPDATED
        assert _products(await _scope(db_session, cve, "cna")) == ["Delta"]
        assert await _scope(db_session, cve, "osv") == []
        assert await _scope(db_session, cve, "adp:Example") == unobserved
        assert await _scope(db_session, cve, "ghsa") == equal

    async def test_identical_entries_collapse_to_one_row(
        self, db_session: AsyncSession
    ) -> None:
        result = await _upsert(
            db_session,
            payload=CVEIngestPayload(
                affected_version_operations=[replace("cna", E1, E1)]
            ),
        )

        assert _products(await _scope(db_session, result.cve, "cna")) == ["Alpha"]

    @pytest.mark.parametrize("field", ["vendor", "product"])
    async def test_absent_vendor_or_product_differs_from_empty_string(
        self, db_session: AsyncSession, field: str
    ) -> None:
        base = {"vendor": "Example", "product": "Alpha"}
        absent = av_entry(**{**base, field: None})
        empty = av_entry(**{**base, field: ""})

        result = await _upsert(
            db_session,
            payload=CVEIngestPayload(
                affected_version_operations=[replace("cna", absent, empty)]
            ),
        )

        assert (
            await _count(
                db_session,
                CVEAffectedVersion,
                CVEAffectedVersion.cve_id == result.cve.id,
            )
            == 2
        )


# ---------------------------------------------------------------------------
# `UpsertResult.action` and Ticket presence
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestUpsertAction:
    async def test_insert_winner_with_empty_payload_is_created(
        self, db_session: AsyncSession
    ) -> None:
        result = await _upsert(db_session)

        assert result.action is CREATED
        cve = await _reload(db_session, result.cve)
        assert (cve.title, cve.description, cve.cve_state, cve.date_rejected) == (
            None,
            None,
            "PUBLISHED",
            None,
        )
        assert (await _ticket_of(db_session, cve)).id == result.ticket.id
        assert await _count(db_session, CVE, CVE.cve_id == NEW_CVE_ID) == 1

    async def test_insert_winner_with_data_is_created_not_updated(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            title="Fictional title",
            cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
            cvss_assessments=[cvss(PROVIDER, V31_HIGH.canonical)],
        )

        result = await _upsert(db_session, payload=payload)

        assert result.action is CREATED

    @pytest.mark.parametrize(
        ("payload", "action"),
        [
            pytest.param(CVEIngestPayload(), UNCHANGED, id="empty"),
            pytest.param(CVEIngestPayload(title="Fictional"), UPDATED, id="title"),
        ],
    )
    async def test_placeholder_from_ensure_is_never_created(
        self, db_session: AsyncSession, payload: CVEIngestPayload, action: UpsertAction
    ) -> None:
        placeholder = await ensure_cve_exists(db_session, NEW_CVE_ID)

        result = await _upsert(db_session, payload=payload)

        assert result.action is action
        assert result.cve.id == placeholder.id

    async def test_repeated_identical_payload_is_unchanged_without_new_rows_or_events(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            title="Fictional title",
            description="Fictional description",
            published_date=T1,
            cve_state=CveState.PUBLISHED,
            cvss_assessments=[cvss(PROVIDER, V31_HIGH.canonical)],
            cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
            external_identifiers=[_identifier()],
            affected_version_operations=[replace("cna", E1, E2), remove("osv")],
            ssvc_assessment=SSVCEntry(
                exploitation=SSVCExploitation.POC,
                automatable=SSVCAutomatable.YES,
                technical_impact=SSVCTechnicalImpact.TOTAL,
                version="2.0.3",
            ),
            kev_data=KEVEntry(date_added=date(2099, 1, 15)),
            epss_score=EPSSEntry(
                score=0.5, percentile=0.5, assessed_at=date(2099, 1, 15)
            ),
        )
        first = await _upsert(db_session, payload=payload)
        totals = await _totals(db_session)
        events = await ticket_events(db_session, first.ticket)

        second = await _upsert(db_session, payload=payload)

        assert (first.action, second.action) == (CREATED, UNCHANGED)
        assert second.ticket.id == first.ticket.id
        assert await _totals(db_session) == totals
        assert await ticket_events(db_session, first.ticket) == events

    async def test_source_status_write_alone_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing()
        await record_source_status(db_session, cve.id, NVD, FAILURE)

        result = await _upsert(db_session, cve.cve_id)

        assert result.action is UNCHANGED
        [(source, status, _, first_failed_at)] = await source_rows(db_session, cve.id)
        assert (source, status, first_failed_at) == ("nvd", "success", None)

    async def test_ticket_creation_for_ticketless_cve_is_unchanged(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing(ticketed=False)

        result = await _upsert(db_session, cve.cve_id, source=CVESourceType.MITRE)

        assert result.action is UNCHANGED
        assert (await _ticket_of(db_session, cve)).id == result.ticket.id
        assert await ticket_events(db_session, result.ticket) == creation_events(
            creator_id=None,
            comment=ingestion_comment(CVESourceType.MITRE),
            cve_id=cve.cve_id,
        )

    async def test_priority_change_alone_is_unchanged(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        ticket_factory: Factory,
        cve_kev_entry_factory: Factory,
    ) -> None:
        """A KEV-listed CVE whose Ticket has a stale automatic priority: the
        refresh writes `P1` with its delegated event, yet nothing CVE-owned
        changed."""
        cve: CVE = await cve_factory()
        ticket: Ticket = await ticket_factory(cve_id=cve.id)
        await cve_kev_entry_factory(cve_id=cve.id)

        result = await _upsert(db_session, cve.cve_id)

        assert result.action is UNCHANGED
        assert (await _ticket_of(db_session, cve)).priority_auto == "P1"
        assert await ticket_events(db_session, ticket) == [priority_event(None, "P1")]

    async def test_enrichment_writes_create_no_ticket_event(
        self, db_session: AsyncSession, existing: ExistingCVE
    ) -> None:
        cve = await existing(title="Old")
        ticket = await _ticket_of(db_session, cve)

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                title="New",
                description="Fictional",
                modified_date=T2,
                cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
                external_identifiers=[_identifier()],
                affected_version_operations=[replace("cna", E1)],
            ),
        )

        assert result.action is UPDATED
        assert result.ticket.id == ticket.id
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# CVSS candidate classification and sanitized skip warnings (step 2, D10)
# ---------------------------------------------------------------------------

V31_PADDED_200 = f"{' ' * 78}{V31_CRITICAL.canonical}{' ' * 78}"
V31_PADDED_201 = f"{' ' * 79}{V31_CRITICAL.canonical}{' ' * 78}"


def _skip(ordinal: int, reason: str, *, source: str = "nvd") -> dict[str, Any]:
    return {
        "event": SKIP_EVENT,
        "log_level": "warning",
        "cve_id": NEW_CVE_ID,
        "source": source,
        "ordinal": ordinal,
        "reason": reason,
    }


@pytest.mark.integration
class TestCVSSCandidateSkips:
    def test_padded_vector_lengths(self) -> None:
        """Precondition of the received-length cases."""
        assert (len(V31_PADDED_200), len(V31_PADDED_201)) == (200, 201)

    @pytest.mark.parametrize(
        "provider",
        [
            pytest.param(42, id="non-string"),
            pytest.param(None, id="none"),
            pytest.param("", id="empty"),
            pytest.param("  \t ", id="whitespace-only"),
            pytest.param("P" * 101, id="101-characters"),
            pytest.param(" suse ", id="reserved-padded"),
            pytest.param("Suse", id="reserved-mixed-case"),
            pytest.param("SUSE", id="reserved"),
        ],
    )
    async def test_invalid_provider_is_skipped_and_valid_sibling_persisted(
        self, db_session: AsyncSession, provider: object
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(PROVIDER, V31_HIGH.canonical),
                cvss(provider, V40_CRITICAL.canonical),
            ]
        )

        with capture_logs() as logs:
            result = await _upsert(db_session, payload=payload)

        assert skip_events(logs) == [_skip(1, "invalid_provider")]
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_HIGH)
        ]

    @pytest.mark.parametrize(
        "vector",
        [
            pytest.param(None, id="none"),
            pytest.param(42, id="integer"),
            pytest.param("", id="empty"),
            pytest.param("not-a-cvss-vector", id="malformed"),
            pytest.param(
                "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="unsupported-version"
            ),
            pytest.param(f"{V31_CRITICAL.canonical}/E:P", id="temporal-metric"),
            pytest.param("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", id="incomplete"),
            pytest.param(V31_PADDED_201, id="201-received-characters"),
        ],
    )
    async def test_invalid_vector_is_skipped_and_valid_sibling_persisted(
        self, db_session: AsyncSession, vector: object
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(OTHER_PROVIDER, vector),
                cvss(PROVIDER, V31_HIGH.canonical),
            ]
        )

        with capture_logs() as logs:
            result = await _upsert(db_session, payload=payload)

        assert skip_events(logs) == [_skip(0, "invalid_vector")]
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_HIGH)
        ]

    async def test_candidate_invalid_on_both_grounds_is_invalid_provider(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(cvss_assessments=[cvss("SUSE", "not-a-vector")])

        with capture_logs() as logs:
            await _upsert(db_session, payload=payload)

        assert skip_events(logs) == [_skip(0, "invalid_provider")]

    async def test_overlength_vector_never_reaches_the_parser(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        parsed: list[object] = []
        original = cvss_parser.validate_cvss_vector

        def spy(vector: str) -> Any:
            parsed.append(vector)
            return original(vector)

        monkeypatch.setattr(cve_service, "validate_cvss_vector", spy)
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(PROVIDER, V31_PADDED_201),
                cvss(OTHER_PROVIDER, V31_PADDED_200),
            ]
        )

        with capture_logs() as logs:
            result = await _upsert(db_session, payload=payload)

        assert parsed == [V31_PADDED_200]
        assert skip_events(logs) == [_skip(0, "invalid_vector")]
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(OTHER_PROVIDER, V31_CRITICAL)
        ]

    async def test_exactly_200_received_characters_is_parsed_and_accepted(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(cvss_assessments=[cvss(PROVIDER, V31_PADDED_200)])

        with capture_logs() as logs:
            result = await _upsert(db_session, payload=payload)

        assert skip_events(logs) == []
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_CRITICAL)
        ]

    async def test_skips_follow_input_order_with_zero_based_ordinals(
        self, db_session: AsyncSession
    ) -> None:
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(" SUSE", V31_HIGH.canonical),
                cvss(PROVIDER, V31_HIGH.canonical),
                cvss(PROVIDER, "CVSS:3.1/AV:X"),
                cvss(OTHER_PROVIDER, V40_CRITICAL.canonical),
                cvss(None, None),
            ]
        )

        with capture_logs() as logs:
            result = await _upsert(
                db_session, payload=payload, source=CVESourceType.OSV
            )

        assert skip_events(logs) == [
            _skip(0, "invalid_provider", source="osv"),
            _skip(2, "invalid_vector", source="osv"),
            _skip(4, "invalid_provider", source="osv"),
        ]
        assert await persisted_assessments(db_session, result.cve.id) == [
            unit(PROVIDER, V31_HIGH),
            unit(OTHER_PROVIDER, V40_CRITICAL),
        ]

    async def test_skip_warning_carries_only_the_permitted_fields(
        self, db_session: AsyncSession
    ) -> None:
        marker = "LeakMarker"
        payload = CVEIngestPayload(
            cvss_assessments=[
                cvss(f"{marker} " + "x" * 100, V31_HIGH.canonical),
                cvss(PROVIDER, f"CVSS:3.1/{marker}"),
                cvss(" suse ", f"{marker}-vector"),
            ]
        )

        with capture_logs() as logs:
            await _upsert(db_session, payload=payload)

        skipped = skip_events(logs)
        assert len(skipped) == 3
        assert all(set(entry) == SKIP_EVENT_KEYS for entry in skipped)
        assert all(entry["log_level"] == "warning" for entry in skipped)
        for entry in logs:
            assert marker not in repr(entry)
            assert "CVSS:" not in repr(entry)

    async def test_single_valid_candidate_uses_the_external_batch_only(
        self, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        batches: list[dict[str, Any]] = []
        manual: list[object] = []
        original = ticket_mutations.upsert_external_cvss_batch

        async def batch_spy(db: AsyncSession, **kwargs: Any) -> Any:
            batches.append(kwargs)
            return await original(db, **kwargs)

        async def manual_spy(*args: object, **kwargs: object) -> None:
            manual.append(args)

        monkeypatch.setattr(ticket_mutations, "upsert_external_cvss_batch", batch_spy)
        monkeypatch.setattr(ticket_mutations, "upsert_cvss_assessment", manual_spy)
        monkeypatch.setattr(
            cve_service, "_utc_now", lambda: datetime(2026, 9, 27, 23, 59, tzinfo=UTC)
        )

        result = await _upsert(
            db_session,
            payload=CVEIngestPayload(
                cvss_assessments=[cvss(PROVIDER, V31_CRITICAL_REORDERED)]
            ),
        )

        assert manual == []
        assert len(batches) == 1
        assert batches[0]["cve_id"] == result.cve.id
        assert batches[0]["evaluation_date"] == EVAL
        [candidate] = batches[0]["assessments"]
        assert (candidate.provider, candidate.parsed.canonical_vector) == (
            PROVIDER,
            V31_CRITICAL.canonical,
        )


# ---------------------------------------------------------------------------
# `record_source_status()`
# ---------------------------------------------------------------------------


async def _pause(db: AsyncSession) -> None:
    """Advance the database wall clock between two statements."""
    await db.execute(text("SELECT pg_sleep(0.002)"))


@pytest.mark.integration
class TestRecordSourceStatus:
    @pytest.mark.parametrize(
        ("cve_id", "source", "status", "match"),
        [
            pytest.param("uuid-string", NVD, SUCCESS, "UUID", id="string-cve-id"),
            pytest.param(None, NVD, SUCCESS, "UUID", id="none-cve-id"),
            pytest.param("uuid", "nvd", SUCCESS, "CVESourceType", id="raw-source"),
            pytest.param(
                "uuid", NVD, "success", "CVESourceFetchStatus", id="raw-status"
            ),
        ],
    )
    async def test_invalid_argument_raises_value_error_before_any_statement(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        cve_id: Any,
        source: Any,
        status: Any,
        match: str,
    ) -> None:
        cve: CVE = await cve_factory()
        argument: Any = {"uuid": cve.id, "uuid-string": str(cve.id)}.get(cve_id, cve_id)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=match),
        ):
            await record_source_status(db_session, argument, source, status)

        assert recorder.statements == []

    @pytest.mark.parametrize("status", [SUCCESS, MISSING])
    async def test_create_with_success_or_missing_has_no_failure_streak(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        status: CVESourceFetchStatus,
    ) -> None:
        cve: CVE = await cve_factory()

        await record_source_status(db_session, cve.id, NVD, status)

        [(source, stored, fetched_at, first_failed_at)] = await source_rows(
            db_session, cve.id
        )
        assert (source, stored, first_failed_at) == ("nvd", status.value, None)
        assert fetched_at is not None

    async def test_create_with_failure_starts_streak_at_fetched_at(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        await record_source_status(db_session, cve.id, NVD, FAILURE)

        [(_, status, fetched_at, first_failed_at)] = await source_rows(
            db_session, cve.id
        )
        assert status == "failure"
        assert first_failed_at == fetched_at

    async def test_repeated_failure_preserves_streak_and_advances_fetched_at(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        await record_source_status(db_session, cve.id, NVD, FAILURE)
        [(_, _, first_fetched, streak)] = await source_rows(db_session, cve.id)
        await _pause(db_session)

        await record_source_status(db_session, cve.id, NVD, FAILURE)

        [(_, status, fetched_at, first_failed_at)] = await source_rows(
            db_session, cve.id
        )
        assert status == "failure"
        assert first_failed_at == streak
        assert fetched_at > first_fetched

    @pytest.mark.parametrize("status", [SUCCESS, MISSING])
    async def test_success_or_missing_after_failure_clears_streak(
        self,
        db_session: AsyncSession,
        cve_factory: Factory,
        status: CVESourceFetchStatus,
    ) -> None:
        cve: CVE = await cve_factory()
        await record_source_status(db_session, cve.id, NVD, FAILURE)
        [(_, _, failed_fetch, _)] = await source_rows(db_session, cve.id)
        await _pause(db_session)

        await record_source_status(db_session, cve.id, NVD, status)

        [(_, stored, fetched_at, first_failed_at)] = await source_rows(
            db_session, cve.id
        )
        assert (stored, first_failed_at) == (status.value, None)
        assert fetched_at > failed_fetch

    async def test_later_failure_starts_a_new_streak(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        await record_source_status(db_session, cve.id, NVD, FAILURE)
        [(_, _, _, old_streak)] = await source_rows(db_session, cve.id)
        await _pause(db_session)
        await record_source_status(db_session, cve.id, NVD, SUCCESS)
        await _pause(db_session)

        await record_source_status(db_session, cve.id, NVD, FAILURE)

        [(_, status, fetched_at, first_failed_at)] = await source_rows(
            db_session, cve.id
        )
        assert status == "failure"
        assert first_failed_at == fetched_at
        assert old_streak is not None
        assert first_failed_at is not None
        assert first_failed_at > old_streak

    async def test_fetched_at_is_the_statement_wall_clock_not_transaction_start(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        transaction_start = await db_session.scalar(text("SELECT now()"))
        await _pause(db_session)
        before = await db_session.scalar(text("SELECT clock_timestamp()"))

        await record_source_status(db_session, cve.id, NVD, FAILURE)

        after = await db_session.scalar(text("SELECT clock_timestamp()"))
        [(_, _, fetched_at, first_failed_at)] = await source_rows(db_session, cve.id)
        assert transaction_start < before <= fetched_at <= after
        assert first_failed_at == fetched_at

    async def test_unknown_cve_raises_integrity_error_and_session_stays_usable(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()

        with pytest.raises(IntegrityError):
            async with db_session.begin_nested():
                await record_source_status(db_session, uuid.uuid4(), NVD, SUCCESS)

        await record_source_status(db_session, cve.id, NVD, SUCCESS)
        assert len(await source_rows(db_session, cve.id)) == 1

    async def test_one_row_per_cve_and_source(
        self, db_session: AsyncSession, cve_factory: Factory
    ) -> None:
        cve: CVE = await cve_factory()
        other: CVE = await cve_factory()

        for status in (FAILURE, SUCCESS, MISSING, FAILURE):
            await record_source_status(db_session, cve.id, NVD, status)
        await record_source_status(db_session, cve.id, CVESourceType.MITRE, SUCCESS)
        await record_source_status(db_session, other.id, NVD, SUCCESS)

        assert [(s, st) for s, st, _, _ in await source_rows(db_session, cve.id)] == [
            ("mitre", "success"),
            ("nvd", "failure"),
        ]
        assert len(await source_rows(db_session, other.id)) == 1

    @pytest.mark.parametrize("source", list(CVESourceType))
    async def test_upsert_cve_records_success_for_its_source(
        self, db_session: AsyncSession, source: CVESourceType
    ) -> None:
        result = await _upsert(db_session, source=source)

        [(stored, status, _, first_failed_at)] = await source_rows(
            db_session, result.cve.id
        )
        assert (stored, status, first_failed_at) == (source.value, "success", None)


# ---------------------------------------------------------------------------
# Transaction ownership
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestTransactionOwnership:
    async def test_upsert_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        existing: ExistingCVE,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await existing(title="Old")
        calls: list[str] = []

        def async_spy(name: str) -> Callable[..., Awaitable[None]]:
            async def _spy(*args: object, **kwargs: object) -> None:
                calls.append(name)

            return _spy

        def sync_spy(name: str) -> Callable[..., None]:
            def _spy(*args: object, **kwargs: object) -> None:
                calls.append(name)

            return _spy

        # Both the async facade and its underlying sync Session.
        for name in ("commit", "rollback"):
            monkeypatch.setattr(db_session, name, async_spy(name))
            monkeypatch.setattr(db_session.sync_session, name, sync_spy(f"sync_{name}"))

        result = await _upsert(
            db_session,
            cve.cve_id,
            CVEIngestPayload(
                cve_state=CveState.REJECTED,
                title="New",
                cvss_assessments=[cvss(PROVIDER, V31_HIGH.canonical)],
                cwe_classifications=[CWEEntry(cwe_id="CWE-79", source="NVD")],
                affected_version_operations=[replace("cna", E1)],
            ),
        )

        assert result.action is UPDATED
        assert calls == []
        assert db_session.in_transaction()
