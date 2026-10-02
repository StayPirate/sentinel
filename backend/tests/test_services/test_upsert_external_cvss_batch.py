"""Single-session service integration tests for `upsert_external_cvss_batch()`
and its provider guard `is_valid_external_provider_name()`
(backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (CVSS Vector Parsing, trusted
  external lock order; CVSS Mutation Authority and Result: propagation
  dispositions; CVSS Status Matrix, trusted external batch column;
  `upsert_external_cvss_batch()`: Guards, Behavior 1-9, Audit order;
  `reconcile_ticket_status()`; Architectural Test Requirement: CVSS status
  matrix, Manual SUSE assignment (the batch never assigns), CVE severity
  ownership, Authority and audit, Complete atomic chain (one evaluation
  date), Automatic priority; Service Exceptions).
- docs/features/tickets/cvss-scoring.md (Severity Resolution Cascade;
  Eligibility Score Resolution; Provider Identity and Authority;
  Assessment Persistence and Ticket Status; Direct Audit Summary;
  Serialization and Concurrent Outcomes; Workflow Gate; Required Tests >
  Persistence and API Tests, external rows).
- docs/features/tickets/tickets.md (Gate: Analysis → Analyzed; Gate:
  Analyzed → Resolved).
- docs/features/tickets/ticket-priority.md (Refresh Points, external CVSS
  row; Testing Requirements 3, 4, 6).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract;
  Canonical Mutation and No-Event Matrix row "Effective CVSS assessment
  mutation or ingestion batch"; Cross-Event Ordering, Locking, and
  Rollback; Testing Requirements 1-6, 12, 15-18, 20, 25, 28).
- docs/features/platform/testing-strategy.md (Audit Trail Testing).
- Decisions D2-D6 and D8 of issue #749 (whitespace-only provider is empty;
  an all-unchanged non-empty batch reads the setting once, the empty batch
  issues no SQL; the empty-batch result; the re-parse guard; a CVE absent
  after the lock lookup; the reconciliation trigger).

Rollback and independent-session races of the batch are owned by a
separate atomicity module. A ticketless CVE is not reachable through
`cve_service.upsert_cve()` (the status matrix's first row), but the
boundary itself still defines its outcome (Behavior 7, Audit order), which
is tested here.

Expected values are transcribed from the specifications and the `Vector`
constants, never computed with the module under test.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVSSVersion, PackageStatus, Severity, TicketStatus
from app.models.cve import CVE
from app.models.system_setting import SystemSetting
from app.services import ticket_mutations
from app.services.cvss import validate_cvss_vector
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    EXTERNAL_PROVIDER_MAX_LENGTH,
    CVSSAssessmentAction,
    CVSSPropagation,
    ExternalCVSSAssessmentOutcome,
    ExternalCVSSBatchResult,
    ParsedExternalCVSSAssessment,
    ProductPropagationSummary,
    is_valid_external_provider_name,
    upsert_external_cvss_batch,
)
from tests.support.cvss_chain import (
    FALLBACK,
    CallCounter,
    assessment_snapshot,
    cve_severity,
    eligibility,
    priority_event,
    product_event,
    severity_event,
    severity_resolution,
    subjects,
    suse_eligibility,
    ticket_state,
    total_ticket_events,
)
from tests.support.external_cvss import (
    external,
    external_cvss_event,
    external_value,
    run_batch,
)
from tests.support.suse_cvss import (
    V20_CRITICAL,
    V30_CRITICAL,
    V31_CRITICAL,
    V31_CRITICAL_REORDERED,
    V31_HIGH,
    V31_MEDIUM,
    V40_CRITICAL,
    Vector,
    persisted_assessments,
    unit,
)
from tests.support.ticket_mutations import (
    BEFORE_EVAL,
    EVAL,
    REACTIVE_GS_END,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]
CVEOf = Callable[..., Awaitable[CVE]]

CREATED = CVSSAssessmentAction.CREATED
UPDATED = CVSSAssessmentAction.UPDATED
UNCHANGED = CVSSAssessmentAction.UNCHANGED

GATE_ZONE = (TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED)
MANUAL_ZONE = (TicketStatus.IGNORED, TicketStatus.DUPLICATED)
EVERY_STATUS = (TicketStatus.NEW, *GATE_ZONE, *MANUAL_ZONE)

T7 = Decimal("7.0")
"""A Product threshold met by the `10.0` fallback but by no `Medium` score."""

T9 = Decimal("9.0")
"""A Product threshold met by 9.8 but not by 8.1."""

NO_PRODUCTS = ProductPropagationSummary()

LONG_S_SUSE = "\u017fuse"
"""`suse` spelled with U+017F LATIN SMALL LETTER LONG S, which Unicode
case-folds to `s`: a reserved variant reachable only through
case-folding."""


@pytest.fixture
async def default_setting(system_setting_factory: Factory) -> SystemSetting:
    """The persisted `default_cvss_version` (the test schema has none)."""
    setting: SystemSetting = await system_setting_factory(
        key="default_cvss_version", value="3.1"
    )
    return setting


@pytest.fixture
def cve_of(cve_factory: Factory, cve_cvss_assessment_factory: Factory) -> CVEOf:
    """Create a CVE with a persisted `severity` and `(provider, vector)`
    assessments whose vector-derived units are consistent."""

    async def _create(
        *assessments: tuple[str, Vector], severity: Severity | None = None
    ) -> CVE:
        cve: CVE = await cve_factory(severity=severity.value if severity else None)
        for provider, vector in assessments:
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name=provider, **vector.columns()
            )
        return cve

    return _create


def outcome(
    provider: str, version: CVSSVersion, action: CVSSAssessmentAction
) -> ExternalCVSSAssessmentOutcome:
    return ExternalCVSSAssessmentOutcome(
        provider=provider, version=version, action=action
    )


def created_event(provider: str, vector: Vector) -> EventRow:
    """The system `cvss_assessment_changed` of a created external row."""
    return external_cvss_event(None, external_value(provider, vector))


def updated_event(provider: str, old: Vector, new: Vector) -> EventRow:
    """The system `cvss_assessment_changed` of an updated external row."""
    return external_cvss_event(
        external_value(provider, old), external_value(provider, new)
    )


def tampered(vector: Vector = V31_HIGH, **changes: Any) -> ParsedExternalCVSSAssessment:
    """A candidate whose parsed result was changed after parsing."""
    parsed = validate_cvss_vector(vector.canonical)
    return ParsedExternalCVSSAssessment(
        provider="Example CNA", parsed=dataclasses.replace(parsed, **changes)
    )


# ---------------------------------------------------------------------------
# The provider guard (Category C, pure)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestProviderPredicate:
    def test_long_s_case_folds_to_suse(self) -> None:
        """Precondition of the Unicode case-folding variant below: U+017F
        LATIN SMALL LETTER LONG S case-folds to `s`."""
        assert LONG_S_SUSE.casefold() == "suse"

    @pytest.mark.parametrize(
        "provider",
        [
            pytest.param("NVD", id="plain"),
            pytest.param(" Example CNA", id="outer-whitespace-kept"),
            pytest.param("SUSE CNA", id="contains-suse"),
            pytest.param("SUSEx", id="suse-prefix"),
            pytest.param("Ärzte CNA", id="non-ascii"),
            pytest.param("P" * EXTERNAL_PROVIDER_MAX_LENGTH, id="100-characters"),
            pytest.param(" " + "P" * 99, id="100-characters-with-whitespace"),
        ],
    )
    def test_accepts(self, provider: str) -> None:
        assert is_valid_external_provider_name(provider) is True

    @pytest.mark.parametrize(
        "provider",
        [
            pytest.param("", id="empty"),
            pytest.param("   ", id="spaces-only"),
            pytest.param("\t\n", id="whitespace-only"),
            pytest.param("P" * (EXTERNAL_PROVIDER_MAX_LENGTH + 1), id="101-characters"),
            pytest.param(" " + "P" * 100, id="101-characters-as-received"),
            pytest.param("SUSE", id="reserved"),
            pytest.param("suse", id="reserved-lowercase"),
            pytest.param(" SuSe ", id="reserved-mixed-case-padded"),
            pytest.param("\tSUSE\n", id="reserved-tab-newline"),
            pytest.param(LONG_S_SUSE, id="reserved-unicode-case-fold"),
            pytest.param(None, id="none"),
            pytest.param(42, id="integer"),
            pytest.param(b"NVD", id="bytes"),
        ],
    )
    def test_rejects(self, provider: object) -> None:
        assert is_valid_external_provider_name(provider) is False


# ---------------------------------------------------------------------------
# Guards: input-only `ValueError` before any SQL statement
# ---------------------------------------------------------------------------


def _valid() -> ParsedExternalCVSSAssessment:
    return external("Example CNA", V31_HIGH)


def _reordered_critical() -> ParsedExternalCVSSAssessment:
    """A stable parse of `V31_CRITICAL` whose canonical vector was replaced
    by a non-canonical metric order of the same vector."""
    return tampered(V31_CRITICAL, canonical_vector=V31_CRITICAL_REORDERED)


DATE = "requires an evaluation_date"
CVE_ID = "requires the CVE UUID"
SEQUENCE = "must be a sequence"
ITEM = "must be a ParsedExternalCVSSAssessment"
PROVIDER = "empty, overlength, or reserved"
MALFORMED = "parsed result is malformed"
DUPLICATE = "Duplicate canonical"

Override = Callable[[], dict[str, Any]]


def _guard(override: Override, match: str, case: str) -> Any:
    return pytest.param(override, match, id=case)


def _provider_guard(provider: object, case: str) -> Any:
    """A valid first candidate followed by one with an invalid provider."""

    def override() -> dict[str, Any]:
        invalid = ParsedExternalCVSSAssessment(
            provider=cast(Any, provider),
            parsed=validate_cvss_vector(V40_CRITICAL.canonical),
        )
        return {"assessments": [_valid(), invalid]}

    return _guard(override, PROVIDER, f"provider-{case}")


GUARD_CASES = [
    _guard(lambda: {"evaluation_date": None}, DATE, "missing-evaluation-date"),
    _guard(
        lambda: {"evaluation_date": datetime(2026, 9, 27, tzinfo=UTC)},
        DATE,
        "datetime-evaluation-date",
    ),
    _guard(lambda: {"evaluation_date": "2026-09-27"}, DATE, "string-date"),
    _guard(lambda: {"cve_id": None}, CVE_ID, "missing-cve-id"),
    _guard(lambda: {"cve_id": "CVE-2099-0001"}, CVE_ID, "cve-identifier"),
    _guard(lambda: {"cve_id": str(uuid.uuid7())}, CVE_ID, "uuid-string"),
    _guard(lambda: {"assessments": None}, SEQUENCE, "none-sequence"),
    _guard(lambda: {"assessments": iter([_valid()])}, SEQUENCE, "iterator"),
    _guard(lambda: {"assessments": {"NVD": _valid()}}, SEQUENCE, "mapping"),
    _guard(lambda: {"assessments": "NVD"}, SEQUENCE, "string"),
    _guard(lambda: {"assessments": b"NVD"}, SEQUENCE, "bytes"),
    _guard(lambda: {"assessments": [None]}, ITEM, "none-item"),
    _guard(
        lambda: {"assessments": [("NVD", validate_cvss_vector(V31_HIGH.canonical))]},
        ITEM,
        "tuple-item",
    ),
    _guard(lambda: {"assessments": [_valid(), "NVD"]}, ITEM, "invalid-after-valid"),
    _guard(
        lambda: {
            "assessments": [
                ParsedExternalCVSSAssessment(
                    provider="NVD", parsed=cast(Any, V31_HIGH.canonical)
                )
            ]
        },
        MALFORMED,
        "vector-string-instead-of-parsed",
    ),
    _guard(
        lambda: {"assessments": [tampered(canonical_vector=None)]},
        MALFORMED,
        "canonical-vector-not-string",
    ),
    _guard(
        lambda: {"assessments": [tampered(score=Decimal("1.0"))]},
        MALFORMED,
        "tampered-score",
    ),
    _guard(
        lambda: {"assessments": [tampered(version=CVSSVersion.V3_0)]},
        MALFORMED,
        "tampered-version",
    ),
    _guard(
        lambda: {
            "assessments": [
                tampered(severity=validate_cvss_vector(V31_CRITICAL.canonical).severity)
            ]
        },
        MALFORMED,
        "tampered-severity",
    ),
    _guard(
        lambda: {
            "assessments": [
                tampered(metrics=validate_cvss_vector(V31_CRITICAL.canonical).metrics)
            ]
        },
        MALFORMED,
        "tampered-metrics",
    ),
    _guard(
        lambda: {"assessments": [tampered(canonical_vector="CVSS:3.1/AV:N")]},
        MALFORMED,
        "unparseable-canonical-vector",
    ),
    _guard(
        lambda: {"assessments": [_reordered_critical()]},
        MALFORMED,
        "non-canonical-vector",
    ),
    _provider_guard("", "empty"),
    _provider_guard("   ", "spaces-only"),
    _provider_guard("\t\n", "whitespace-only"),
    _provider_guard("P" * (EXTERNAL_PROVIDER_MAX_LENGTH + 1), "101-characters"),
    _provider_guard(None, "none"),
    _provider_guard(42, "integer"),
    _provider_guard("SUSE", "reserved"),
    _provider_guard("suse", "reserved-lowercase"),
    _provider_guard(" SuSe ", "reserved-mixed-case-padded"),
    _provider_guard("\tSUSE\n", "reserved-tab-newline"),
    _provider_guard(LONG_S_SUSE, "reserved-unicode-case-fold"),
    _guard(
        lambda: {
            "assessments": [external("NVD", V31_HIGH), external("NVD", V31_CRITICAL)]
        },
        DUPLICATE,
        "duplicate-key-different-vectors",
    ),
    _guard(
        lambda: {"assessments": [external("NVD", V31_HIGH), external("NVD", V31_HIGH)]},
        DUPLICATE,
        "duplicate-key-identical-vectors",
    ),
]


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestGuards:
    @pytest.mark.parametrize(("override", "match"), GUARD_CASES)
    async def test_contract_violation_raises_before_any_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        override: Override,
        match: str,
    ) -> None:
        """A stale severity, Product, and priority would all change if any
        part of the chain ran."""
        cve = await cve_of(("NVD", V31_MEDIUM), severity=Severity.LOW)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, priority_auto="P3"
        )
        await tree(ticket, products=(Prod(eligible=False, threshold=T7),))
        kwargs: dict[str, Any] = {
            "cve_id": cve.id,
            "assessments": [_valid()],
            "evaluation_date": EVAL,
            **override(),
        }
        upsert = CallCounter(monkeypatch, "upsert_cvss_assessment")

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match=match),
        ):
            await upsert_external_cvss_batch(db_session, **kwargs)

        assert recorder.statements == []
        assert upsert.calls == []
        assert await persisted_assessments(db_session, cve.id) == [
            unit("NVD", V31_MEDIUM)
        ]
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            "P3",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []

    async def test_missing_cve_raises_after_the_lock_lookup_without_effect(
        self, db_session: AsyncSession
    ) -> None:
        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="existing CVE"),
        ):
            await run_batch(db_session, uuid.uuid7(), external("NVD", V31_HIGH))

        assert len(recorder.statements) == 1
        assert "FROM cve " in recorder.statements[0]
        assert "FOR NO KEY UPDATE" in recorder.statements[0]
        assert recorder.writes() == []
        assert recorder.selects_from("system_setting") == []
        assert await total_ticket_events(db_session) == 0

    async def test_distinct_versions_and_distinct_providers_are_not_duplicates(
        self, db_session: AsyncSession, cve_of: CVEOf
    ) -> None:
        """The duplicate key is the exact `(provider, version)` pair: the
        same provider at another version, another provider at the same
        version, and a provider differing only in outer whitespace are all
        distinct candidates."""
        cve = await cve_of()

        result = await run_batch(
            db_session,
            cve.id,
            external("NVD", V31_HIGH),
            external("NVD", V40_CRITICAL),
            external("Example CNA", V31_MEDIUM),
            external(" NVD", V31_CRITICAL),
        )

        assert result.actions == (
            outcome("NVD", CVSSVersion.V4_0, CREATED),
            outcome(" NVD", CVSSVersion.V3_1, CREATED),
            outcome("Example CNA", CVSSVersion.V3_1, CREATED),
            outcome("NVD", CVSSVersion.V3_1, CREATED),
        )
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [
                unit("NVD", V31_HIGH),
                unit("NVD", V40_CRITICAL),
                unit("Example CNA", V31_MEDIUM),
                unit(" NVD", V31_CRITICAL),
            ]
        )


# ---------------------------------------------------------------------------
# Empty batch (Guards; D4)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestEmptyBatch:
    """No `default_cvss_version` row exists here: any setting read would
    raise `RequiredSystemSettingMissingError`."""

    @pytest.mark.parametrize(
        "assessments",
        [pytest.param([], id="list"), pytest.param((), id="tuple")],
    )
    async def test_issues_no_statement_and_has_no_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
        assessments: Sequence[ParsedExternalCVSSAssessment],
    ) -> None:
        cve = await cve_of(("NVD", V31_HIGH), severity=Severity.LOW)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, priority_auto="P4"
        )
        await tree(ticket, products=(Prod(eligible=False, threshold=T7),))
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        with StatementRecorder(db_session) as recorder:
            result = await upsert_external_cvss_batch(
                db_session,
                cve_id=cve.id,
                assessments=assessments,
                evaluation_date=EVAL,
            )

        assert recorder.statements == []
        assert result == ExternalCVSSBatchResult(
            actions=(),
            severity_resolution=None,
            eligibility_resolution=None,
            propagation=CVSSPropagation.NONE,
            products=NO_PRODUCTS,
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert result.effective is False
        assert (refresh.calls, reconcile.calls) == ([], [])
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []

    async def test_missing_cve_is_not_looked_up(self, db_session: AsyncSession) -> None:
        with StatementRecorder(db_session) as recorder:
            result = await run_batch(db_session, uuid.uuid7())

        assert recorder.statements == []
        assert result.actions == ()
        assert result.propagation is CVSSPropagation.NONE


# ---------------------------------------------------------------------------
# CVSS status matrix, trusted external batch column
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestStatusMatrix:
    @pytest.mark.parametrize("status", EVERY_STATUS)
    async def test_every_ticket_status(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        status: TicketStatus,
    ) -> None:
        """No SUSE assessment: eligibility is the `10.0` fallback, so the
        stale automatic `false` (threshold 7.0) is repaired only by an
        immediate pass. Without canonical SUSE the Analyzed gate is unmet,
        so every gate-zone Ticket evaluates to the `Analysis` floor; an
        unassigned `New` stays unassigned and outside reconciliation."""
        owner = await va_user()
        assignee = None if status is TicketStatus.NEW else owner.id
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(
            status=status.value, cve_id=cve.id, assignee_id=assignee
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=T7),),
        )
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        assign = CallCounter(monkeypatch, "auto_assign_actor")

        result = await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        immediate = status not in MANUAL_ZONE
        gate = status in GATE_ZONE
        assert result == ExternalCVSSBatchResult(
            actions=(outcome("NVD", CVSSVersion.V3_1, CREATED),),
            severity_resolution=severity_resolution(
                "8.1", Severity.HIGH, provider="NVD"
            ),
            eligibility_resolution=FALLBACK,
            propagation=(
                CVSSPropagation.IMMEDIATE
                if immediate
                else CVSSPropagation.DEFERRED_UNTIL_REACTIVATION
            ),
            products=ProductPropagationSummary(1, 0, 1) if immediate else NO_PRODUCTS,
            severity_changed=True,
            reconciled=gate,
            evaluation_date=EVAL,
        )
        assert result.effective is True
        assert len(refresh.calls) == 1
        assert reconcile.calls == ([{"evaluation_date": EVAL}] if gate else [])
        assert assign.calls == []
        assert await cve_severity(db_session, cve.id) == "High"
        assert await persisted_assessments(db_session, cve.id) == [
            unit("NVD", V31_HIGH)
        ]
        assert await eligibility(db_session, ticket.id) == [(immediate, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS if gate else status,
            assignee,
            "P3",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        products = [product_event(detail[0], False, True)] if immediate else []
        final = (
            [status_event(status.value, TicketStatus.ANALYSIS.value)]
            if status in (TicketStatus.ANALYZED, TicketStatus.RESOLVED)
            else []
        )
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_HIGH),
            severity_event(None, "High"),
            *products,
            priority_event(None, "P3"),
            *final,
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            (TicketConvergenceEffect(ticket.id),)
            if status is TicketStatus.RESOLVED
            else ()
        )

    async def test_ticketless_cve_receives_severity_only(
        self,
        db_session: AsyncSession,
        cve_of: CVEOf,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_of(("Example CNA", V31_MEDIUM), severity=Severity.MEDIUM)
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")

        result = await run_batch(db_session, cve.id, external("NVD", V31_CRITICAL))

        assert result == ExternalCVSSBatchResult(
            actions=(outcome("NVD", CVSSVersion.V3_1, CREATED),),
            severity_resolution=severity_resolution(
                "9.8", Severity.CRITICAL, provider="NVD"
            ),
            eligibility_resolution=FALLBACK,
            propagation=CVSSPropagation.NOT_APPLICABLE,
            products=NO_PRODUCTS,
            severity_changed=True,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert (refresh.calls, reconcile.calls, propagate.calls) == ([], [], [])
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [unit("Example CNA", V31_MEDIUM), unit("NVD", V31_CRITICAL)]
        )
        assert await total_ticket_events(db_session) == 0
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# All-unchanged batches and re-invocation (Behavior 4-6; Q5; D3)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestAllUnchanged:
    async def test_reads_the_setting_once_and_has_no_other_effect(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Stale `CVE.severity`, Product, and `priority_auto` values and an
        inactive assignee prove that no severity write, Product pass,
        priority refresh, reconciliation, or sanitation runs. The `NVD`
        candidate is parsed from a different metric order: the comparison
        is by canonical vector."""
        inactive = await va_user(active=False)
        cve = await cve_of(
            ("NVD", V31_CRITICAL), ("Example CNA", V40_CRITICAL), severity=Severity.LOW
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=inactive.id,
            priority_auto="P4",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=False, threshold=T7),),
        )
        snapshot = await assessment_snapshot(db_session, cve.id)
        counters = [
            CallCounter(monkeypatch, name)
            for name in (
                "refresh_priority_auto",
                "reconcile_ticket_status",
                "_propagate_automatic_product_eligibility",
                "auto_assign_actor",
            )
        ]
        reordered = ParsedExternalCVSSAssessment(
            provider="NVD", parsed=validate_cvss_vector(V31_CRITICAL_REORDERED)
        )

        with StatementRecorder(db_session) as recorder:
            result = await run_batch(
                db_session, cve.id, reordered, external("Example CNA", V40_CRITICAL)
            )

        # Default 3.1: the non-SUSE default-version step outranks the
        # non-SUSE v4.0 assessment (cvss-scoring.md, Severity Resolution
        # Cascade).
        assert result == ExternalCVSSBatchResult(
            actions=(
                outcome("Example CNA", CVSSVersion.V4_0, UNCHANGED),
                outcome("NVD", CVSSVersion.V3_1, UNCHANGED),
            ),
            severity_resolution=severity_resolution(
                "9.8", Severity.CRITICAL, provider="NVD"
            ),
            eligibility_resolution=FALLBACK,
            propagation=CVSSPropagation.NONE,
            products=NO_PRODUCTS,
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert result.effective is False
        assert len(recorder.selects_from("system_setting")) == 1
        assert recorder.writes() == []
        assert [c.calls for c in counters] == [[], [], [], []]
        assert await assessment_snapshot(db_session, cve.id) == snapshot
        assert await cve_severity(db_session, cve.id) == "Low"
        assert await eligibility(db_session, ticket.id) == [(False, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            inactive.id,
            "P4",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_reinvocation_after_an_effective_batch_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        owner = await va_user()
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )
        await tree(ticket, products=(Prod(eligible=False, threshold=T7),))
        candidates = (external("NVD", V31_HIGH), external("Example CNA", V40_CRITICAL))

        first = await run_batch(db_session, cve.id, *candidates)
        events = await ticket_events(db_session, ticket)
        state = await ticket_state(db_session, ticket.id)
        with StatementRecorder(db_session) as recorder:
            second = await run_batch(db_session, cve.id, *reversed(candidates))

        assert first.effective is True
        assert second == ExternalCVSSBatchResult(
            actions=(
                outcome("Example CNA", CVSSVersion.V4_0, UNCHANGED),
                outcome("NVD", CVSSVersion.V3_1, UNCHANGED),
            ),
            severity_resolution=severity_resolution(
                "8.1", Severity.HIGH, provider="NVD"
            ),
            eligibility_resolution=FALLBACK,
            propagation=CVSSPropagation.NONE,
            products=NO_PRODUCTS,
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert recorder.writes() == []
        assert await ticket_events(db_session, ticket) == events
        assert await ticket_state(db_session, ticket.id) == state
        assert await cve_severity(db_session, cve.id) == "High"


# ---------------------------------------------------------------------------
# Mixed batch: canonical order and the complete audit order
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestMixedBatch:
    async def test_canonical_order_independent_of_input_order_and_collation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Within v3.1 the Unicode code-point order is `Zeta` (U+005A) <
        `alpha` (U+0061) < `Ärzte CNA` (U+00C4), unlike a case-insensitive
        or linguistic collation. `Ärzte CNA` at v4.0 and v3.1 (same
        provider, different versions) and the three v3.1 providers (same
        version) are all distinct candidates.

        No SUSE assessment exists: severity resolves from the non-SUSE
        default-version step (`Medium` before, `Ärzte CNA` 9.8 `Critical`
        after) and eligibility is the `10.0` fallback. The `Analyzed`
        Ticket therefore evaluates to the `Analysis` floor, which sanitizes
        the inactive assignee before the final status event."""
        inactive = await va_user(active=False)
        cve = await cve_of(
            ("Zeta", V31_MEDIUM), ("alpha", V31_MEDIUM), severity=Severity.MEDIUM
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYZED.value,
            cve_id=cve.id,
            assignee_id=inactive.id,
            priority_auto="P4",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(
                Prod(eligible=False, threshold=T7),
                Prod(eligible=False, threshold=T7, override=True),
                Prod(eligible=False, threshold=T7, excluded=True),
            ),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        refresh = CallCounter(monkeypatch, "refresh_priority_auto")
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        assign = CallCounter(monkeypatch, "auto_assign_actor")

        with StatementRecorder(db_session) as recorder:
            result = await run_batch(
                db_session,
                cve.id,
                external("NVD", V20_CRITICAL),
                external("alpha", V31_MEDIUM),
                external("Ärzte CNA", V31_CRITICAL),
                external("NVD", V30_CRITICAL),
                external("Zeta", V31_HIGH),
                external("Ärzte CNA", V40_CRITICAL),
            )

        assert result == ExternalCVSSBatchResult(
            actions=(
                outcome("Ärzte CNA", CVSSVersion.V4_0, CREATED),
                outcome("Zeta", CVSSVersion.V3_1, UPDATED),
                outcome("alpha", CVSSVersion.V3_1, UNCHANGED),
                outcome("Ärzte CNA", CVSSVersion.V3_1, CREATED),
                outcome("NVD", CVSSVersion.V3_0, CREATED),
                outcome("NVD", CVSSVersion.V2_0, CREATED),
            ),
            severity_resolution=severity_resolution(
                "9.8", Severity.CRITICAL, provider="Ärzte CNA"
            ),
            eligibility_resolution=FALLBACK,
            propagation=CVSSPropagation.IMMEDIATE,
            products=ProductPropagationSummary(
                examined=3, override_skipped=1, changed=2
            ),
            severity_changed=True,
            reconciled=True,
            evaluation_date=EVAL,
        )
        assert len(recorder.selects_from("system_setting")) == 1
        assert len(propagate.calls) == 1
        assert len(refresh.calls) == 1
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert assign.calls == []
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [
                unit("Zeta", V31_HIGH),
                unit("alpha", V31_MEDIUM),
                unit("Ärzte CNA", V31_CRITICAL),
                unit("Ärzte CNA", V40_CRITICAL),
                unit("NVD", V30_CRITICAL),
                unit("NVD", V20_CRITICAL),
            ]
        )
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await eligibility(db_session, ticket.id) == [
            (True, False),
            (False, True),
            (True, False),
        ]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            None,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            created_event("Ärzte CNA", V40_CRITICAL),
            updated_event("Zeta", V31_MEDIUM, V31_HIGH),
            created_event("Ärzte CNA", V31_CRITICAL),
            created_event("NVD", V30_CRITICAL),
            created_event("NVD", V20_CRITICAL),
            severity_event("Medium", "Critical"),
            product_event(detail[0], False, True),
            product_event(detail[2], False, True),
            priority_event("P4", "P2"),
            unassigned_event(inactive.username, "inactive assignee"),
            status_event(TicketStatus.ANALYZED.value, TicketStatus.ANALYSIS.value),
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_canonical_event_values_use_the_exact_score_format(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
    ) -> None:
        """Transcribed literal values (ticket-audit-log.md, Event Type
        Contract): `"{provider} v{version} {vector} ({score:.1f})"`."""
        cve = await cve_of(("NVD", V31_MEDIUM), severity=Severity.MEDIUM)
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)

        await run_batch(
            db_session,
            cve.id,
            external("NVD", V31_CRITICAL),
            external("NVD", V20_CRITICAL),
        )

        events = await ticket_events(db_session, ticket)
        assert [(e.old_value, e.new_value) for e in events[:2]] == [
            (
                "NVD v3.1 CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N (4.8)",
                "NVD v3.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
            ),
            (None, "NVD v2.0 AV:N/AC:L/Au:N/C:C/I:C/A:C (10.0)"),
        ]


# ---------------------------------------------------------------------------
# Gate inputs and reconciliation (Behavior 7-8; D8)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestReconciliation:
    async def test_effective_update_changing_no_gate_input_does_not_reconcile(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A non-winning external row is updated: the unified severity
        stays `Critical` and the converged Product is unchanged."""
        owner = await va_user()
        cve = await cve_of(
            ("NVD", V31_CRITICAL),
            ("Example CNA", V31_MEDIUM),
            severity=Severity.CRITICAL,
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=owner.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.AFFECTED,
            products=(Prod(eligible=True, threshold=T7),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_batch(db_session, cve.id, external("Example CNA", V31_HIGH))

        assert result.actions == (outcome("Example CNA", CVSSVersion.V3_1, UPDATED),)
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.products == ProductPropagationSummary(1, 0, 0)
        assert (result.severity_changed, result.reconciled) == (False, False)
        assert reconcile.calls == []
        assert await cve_severity(db_session, cve.id) == "Critical"
        assert await ticket_events(db_session, ticket) == [
            updated_event("Example CNA", V31_MEDIUM, V31_HIGH)
        ]

    async def test_resolved_with_converged_products_reloads_without_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """External assessments never participate in the Eligibility Score
        Resolution: the SUSE default-version score is unchanged."""
        owner = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            cve_id=cve.id,
            assignee_id=owner.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.NOT_AFFECTED,
            products=(Prod(eligible=True, threshold=T9),),
        )
        propagate = CallCounter(monkeypatch, "_propagate_automatic_product_eligibility")
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_batch(db_session, cve.id, external("NVD", V31_MEDIUM))

        assert result == ExternalCVSSBatchResult(
            actions=(outcome("NVD", CVSSVersion.V3_1, CREATED),),
            severity_resolution=severity_resolution("9.8", Severity.CRITICAL),
            eligibility_resolution=suse_eligibility("9.8"),
            propagation=CVSSPropagation.IMMEDIATE,
            products=ProductPropagationSummary(1, 0, 0),
            severity_changed=False,
            reconciled=False,
            evaluation_date=EVAL,
        )
        assert [
            (call["eligibility"], call["evaluation_date"]) for call in propagate.calls
        ] == [(suse_eligibility("9.8"), EVAL)]
        assert reconcile.calls == []
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.RESOLVED,
            owner.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_MEDIUM)
        ]
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_resolved_stale_product_is_repaired_and_regresses_once(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A FIXED track whose stale automatic `false` Product is repaired
        to `true` without `released_at`: resolution is no longer complete,
        an ordinary `Resolved` regression that registers one effect."""
        owner = await va_user()
        cve = await cve_of(("SUSE", V31_CRITICAL), severity=Severity.CRITICAL)
        ticket = await ticket_factory(
            status=TicketStatus.RESOLVED.value,
            cve_id=cve.id,
            assignee_id=owner.id,
            priority_auto="P2",
        )
        await tree(
            ticket,
            status=PackageStatus.FIXED,
            products=(Prod(eligible=False, threshold=T9),),
        )
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_batch(db_session, cve.id, external("NVD", V31_MEDIUM))

        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert result.products == ProductPropagationSummary(1, 0, 1)
        assert (result.severity_changed, result.reconciled) == (False, True)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await eligibility(db_session, ticket.id) == [(True, False)]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            owner.id,
            "P2",
            None,
            None,
        )
        detail = await subjects(db_session, ticket.id)
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_MEDIUM),
            product_event(detail[0], False, True),
            status_event(TicketStatus.RESOLVED.value, TicketStatus.ANALYZED.value),
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_severity_becoming_resolved_promotes_analysis_to_analyzed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The SUSE assessment exists but the persisted severity is a stale
        `NULL`: the batch persists the resolved `High` (the SUSE
        default-version winner), which satisfies the last unmet Analyzed
        gate input."""
        owner = await va_user()
        cve = await cve_of(("SUSE", V31_HIGH), severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(),))
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_batch(db_session, cve.id, external("NVD", V31_CRITICAL))

        assert result.severity_resolution == severity_resolution("8.1", Severity.HIGH)
        assert result.eligibility_resolution == suse_eligibility("8.1")
        assert result.products == ProductPropagationSummary(1, 0, 0)
        assert (result.severity_changed, result.reconciled) == (True, True)
        assert reconcile.calls == [{"evaluation_date": EVAL}]
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYZED,
            owner.id,
            "P3",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_CRITICAL),
            severity_event(None, "High"),
            priority_event(None, "P3"),
            status_event(TicketStatus.ANALYSIS.value, TicketStatus.ANALYZED.value),
        ]


# ---------------------------------------------------------------------------
# Automatic priority (ticket-priority.md, Refresh Points)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestPriority:
    async def test_change_masked_by_an_override_creates_no_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
    ) -> None:
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.NEW.value, cve_id=cve.id, priority_override="P1"
        )

        await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.NEW,
            None,
            "P3",
            "P1",
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_HIGH),
            severity_event(None, "High"),
        ]

    async def test_priority_change_alone_never_reconciles_or_assigns(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A stale `priority_auto` is refreshed by an effective update that
        changes no gate input; the inactive assignee would be sanitized if
        reconciliation ran."""
        inactive = await va_user(active=False)
        cve = await cve_of(
            ("NVD", V31_CRITICAL),
            ("Example CNA", V31_MEDIUM),
            severity=Severity.CRITICAL,
        )
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value,
            cve_id=cve.id,
            assignee_id=inactive.id,
            priority_auto="P4",
        )
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(),))
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")
        assign = CallCounter(monkeypatch, "auto_assign_actor")

        result = await run_batch(db_session, cve.id, external("Example CNA", V31_HIGH))

        assert (result.severity_changed, result.reconciled) == (False, False)
        assert result.products == ProductPropagationSummary(1, 0, 0)
        assert (reconcile.calls, assign.calls) == ([], [])
        assert await ticket_state(db_session, ticket.id) == (
            TicketStatus.ANALYSIS,
            inactive.id,
            "P2",
            None,
            None,
        )
        assert await ticket_events(db_session, ticket) == [
            updated_event("Example CNA", V31_MEDIUM, V31_HIGH),
            priority_event("P4", "P2"),
        ]


# ---------------------------------------------------------------------------
# Batch boundary, lock order, persistence
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestBoundary:
    async def test_one_element_batch_never_routes_through_the_manual_upsert(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def forbidden(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("the batch must not call upsert_cvss_assessment()")

        monkeypatch.setattr(ticket_mutations, "upsert_cvss_assessment", forbidden)
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)

        result = await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        assert result.actions == (outcome("NVD", CVSSVersion.V3_1, CREATED),)
        assert result.propagation is CVSSPropagation.IMMEDIATE
        assert await ticket_events(db_session, ticket) == [
            created_event("NVD", V31_HIGH),
            severity_event(None, "High"),
            priority_event(None, "P3"),
        ]

    @pytest.mark.parametrize("with_ticket", [True, False], ids=["ticket", "ticketless"])
    async def test_cve_then_ticket_locks_are_the_first_statements(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        with_ticket: bool,
    ) -> None:
        """No User lock and no audit-history read; the sanitation User read
        of a gate-zone assignee is an unlocked observation."""
        owner = await va_user()
        cve = await cve_of(severity=None)
        if with_ticket:
            ticket = await ticket_factory(
                status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
            )
            await tree(ticket, products=(Prod(eligible=False, threshold=T7),))

        with StatementRecorder(db_session) as recorder:
            await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        statements = recorder.statements
        assert "FROM cve " in statements[0]
        assert "FOR NO KEY UPDATE" in statements[0]
        assert "FROM ticket " in statements[1]
        assert "FOR UPDATE" in statements[1]
        assert "NO KEY" not in statements[1]
        assert "FROM system_setting" in statements[2]
        assert recorder.row_locks() == statements[:2]
        assert not any("FOR SHARE" in s for s in statements)
        assert recorder.selects_from("ticket_audit_event") == []

    async def test_external_row_absent_from_the_batch_is_retained(
        self, db_session: AsyncSession, cve_of: CVEOf
    ) -> None:
        cve = await cve_of(("Example CNA", V31_MEDIUM), severity=Severity.MEDIUM)
        before = await assessment_snapshot(db_session, cve.id)

        await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        after = await assessment_snapshot(db_session, cve.id)
        assert len(after) == 2
        assert before[0] in after
        assert sorted(await persisted_assessments(db_session, cve.id)) == sorted(
            [unit("Example CNA", V31_MEDIUM), unit("NVD", V31_HIGH)]
        )

    @pytest.mark.parametrize(
        "provider",
        [
            pytest.param(" Example CNA", id="leading-space"),
            pytest.param("Example CNA\t", id="trailing-tab"),
            pytest.param("SUSE CNA", id="contains-suse"),
            pytest.param("P" * EXTERNAL_PROVIDER_MAX_LENGTH, id="100-characters"),
        ],
    )
    async def test_accepted_provider_is_persisted_unchanged(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        provider: str,
    ) -> None:
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)

        result = await run_batch(db_session, cve.id, external(provider, V31_HIGH))

        assert result.actions == (outcome(provider, CVSSVersion.V3_1, CREATED),)
        assert result.severity_resolution == severity_resolution(
            "8.1", Severity.HIGH, provider=provider
        )
        assert await persisted_assessments(db_session, cve.id) == [
            unit(provider, V31_HIGH)
        ]
        assert (await ticket_events(db_session, ticket))[0] == created_event(
            provider, V31_HIGH
        )

    async def test_never_commits_or_rolls_back(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(status=TicketStatus.ANALYZED.value, cve_id=cve.id)
        await tree(ticket, products=(Prod(eligible=False, threshold=T7),))

        async def forbidden() -> None:
            raise AssertionError("the batch must not end the transaction")

        monkeypatch.setattr(db_session, "commit", forbidden)
        monkeypatch.setattr(db_session, "rollback", forbidden)

        result = await run_batch(db_session, cve.id, external("NVD", V31_HIGH))

        assert result.reconciled is True


# ---------------------------------------------------------------------------
# The supplied evaluation date (Guards; Behavior 8)
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.usefixtures("default_setting")
class TestEvaluationDate:
    @pytest.mark.parametrize(
        ("evaluation_date", "eligible"),
        [
            pytest.param(EVAL, False, id="reactive-support"),
            pytest.param(
                REACTIVE_GS_END - timedelta(days=30), True, id="general-support"
            ),
        ],
    )
    async def test_supplied_date_governs_the_product_lifecycle(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
        evaluation_date: date,
        eligible: bool,
    ) -> None:
        """Reactive Support forces an automatic record ineligible
        (package-model.md, Axis 2); in General Support the `10.0` fallback
        keeps it eligible."""
        owner = await va_user()
        cve = await cve_of(severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )
        await tree(ticket, products=(Prod(eligible=True, reactive=True),))
        reconcile = CallCounter(monkeypatch, "reconcile_ticket_status")

        result = await run_batch(
            db_session,
            cve.id,
            external("NVD", V31_HIGH),
            evaluation_date=evaluation_date,
        )

        assert result.evaluation_date == evaluation_date
        assert result.products == ProductPropagationSummary(1, 0, 0 if eligible else 1)
        assert reconcile.calls == [{"evaluation_date": evaluation_date}]
        assert await eligibility(db_session, ticket.id) == [(eligible, False)]

    @pytest.mark.parametrize(
        ("evaluation_date", "expected"),
        [
            pytest.param(EVAL, TicketStatus.RESOLVED, id="eol-not-actionable"),
            pytest.param(
                BEFORE_EVAL - timedelta(days=10),
                TicketStatus.ANALYSIS,
                id="in-support-actionable",
            ),
        ],
    )
    async def test_supplied_date_governs_gate_actionability(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        cve_of: CVEOf,
        tree: TreeBuilder,
        va_user: VAUser,
        evaluation_date: date,
        expected: TicketStatus,
    ) -> None:
        """The only track is still in `ANALYSIS`; its Product is EOL on
        `EVAL`, so the track is not actionable: it blocks neither the
        Analyzed gate nor universal resolution completeness over the empty
        actionable set (tickets.md, Gate: Analyzed → Resolved), and the
        Ticket resolves. On the earlier date the Product is in General
        Support and the actionable `ANALYSIS` track holds the `Analysis`
        floor. The SUSE assessment's stale `NULL` severity makes the batch
        change a gate input."""
        owner = await va_user()
        cve = await cve_of(("SUSE", V31_HIGH), severity=None)
        ticket = await ticket_factory(
            status=TicketStatus.ANALYSIS.value, cve_id=cve.id, assignee_id=owner.id
        )
        await tree(ticket, status=PackageStatus.ANALYSIS, products=(Prod(eol=True),))

        result = await run_batch(
            db_session,
            cve.id,
            external("NVD", V31_CRITICAL),
            evaluation_date=evaluation_date,
        )

        assert result.reconciled is True
        assert result.evaluation_date == evaluation_date
        assert (await ticket_state(db_session, ticket.id))[0] == expected
