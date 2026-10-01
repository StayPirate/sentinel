"""Tests for the Ticket mutation primitives (backend/app/services/ticket_mutations.py).

Owning specifications:

- docs/features/tickets/ticket-mutations.md (`ensure_ticket_operable()`;
  Auto-Assignment Rule and `auto_assign_actor()`; `reconcile_ticket_status()`
  with Behavior steps 1-6, Assignment Eligibility Sanitization,
  `previous_status`, Multiple invocations, and Transaction-Local Ticket
  Convergence Registration steps 1-3; Concurrency Control; Architectural
  Test Requirement: edge cases, SUSE gate independence, and the primitive
  part of Composed workflows).
- docs/features/tickets/tickets.md (Statuses, Status Transitions, both
  gates with Deterministic Gate Edge Cases, Automatic Status Evaluation,
  Reassignment, Auto-Assignment on Unassigned Tickets, Mutability Guard).
- docs/features/tickets/cvss-scoring.md (Workflow Gate).
- docs/features/packages/package-model.md (Derived Actionability, Gate
  Participation).
- docs/features/tickets/ticket-audit-log.md (Event Type Contract, Canonical
  Automatic Comment Vocabulary, Canonical Mutation and No-Event Matrix,
  Cross-Event Ordering; Testing Requirements 1-7, 12, 18, 23, 25).
- docs/conventions.md (Cross-Domain Root Lock Order).

Expected values are transcribed from the specifications, never computed by
the module under test. Transaction-lifecycle tests of the convergence
registry live in test_ticket_convergence_registry.py.
"""

from __future__ import annotations

import ast
import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    CVSSVersion,
    PackageStatus,
    Role,
    Severity,
    TicketStatus,
)
from app.core.exceptions import ServiceError, TicketNotMutableError, UserNotFoundError
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.product import Product
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package_product import TicketPackageProduct
from app.models.user import User
from app.models.user_role import UserRole
from app.services import ticket_mutations
from app.services.ticket_audit_log import TicketAuditLog
from app.services.ticket_convergence_registry import (
    TicketConvergenceEffect,
    pending_ticket_convergence_effects,
)
from app.services.ticket_mutations import (
    InvalidCVSSVectorError,
    TicketMutationsError,
    auto_assign_actor,
    ensure_ticket_operable,
    reconcile_ticket_status,
    stabilize_acting_user,
)
from tests.support.database import assert_lock_wait, rollback_test_scope
from tests.support.ticket_mutations import (
    BEFORE_EVAL,
    EVAL,
    EventRow,
    Prod,
    StatementRecorder,
    TicketFactory,
    TreeBuilder,
    VAUser,
    cveless,
    lock_ticket,
    status_event,
    ticket_events,
    tree_for,
    unassigned_event,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _service_event_fields(
    caplog: pytest.LogCaptureFixture, event_name: str
) -> list[dict[str, Any]]:
    matches = []
    for record in caplog.records:
        if record.name != "app.services.ticket_mutations":
            continue
        try:
            parsed = ast.literal_eval(record.getMessage())
        except ValueError, SyntaxError:
            continue
        if isinstance(parsed, dict) and parsed.get("event") == event_name:
            matches.append(parsed)
    return matches


@pytest.fixture
def cve_ticket(
    ticket_factory: TicketFactory,
    cve_factory: Callable[..., Awaitable[CVE]],
    cve_cvss_assessment_factory: Callable[..., Awaitable[CVECVSSAssessment]],
) -> Callable[..., Awaitable[Ticket]]:
    """A Ticket with a CVE, its unified severity, and its assessments."""

    async def _create(
        *,
        status: TicketStatus = TicketStatus.ANALYSIS,
        severity: Severity | None = Severity.HIGH,
        suse_versions: tuple[CVSSVersion, ...] = (CVSSVersion.V3_1,),
        external_versions: tuple[CVSSVersion, ...] = (),
    ) -> Ticket:
        cve = await cve_factory(severity=severity.value if severity else None)
        for version in suse_versions:
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="SUSE", cvss_version=version.value
            )
        for version in external_versions:
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="NVD", cvss_version=version.value
            )
        return await ticket_factory(status=status.value, cve_id=cve.id)

    return _create


async def _reconcile(db: AsyncSession, ticket: Ticket, **kwargs: Any) -> TicketStatus:
    kwargs.setdefault("evaluation_date", EVAL)
    await reconcile_ticket_status(ticket, db, **kwargs)
    return TicketStatus(ticket.status)


# ---------------------------------------------------------------------------
# Exceptions and module surface
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExceptions:
    def test_ticket_not_mutable_is_a_shared_service_error(self) -> None:
        assert issubclass(TicketNotMutableError, ServiceError)
        assert not issubclass(TicketNotMutableError, TicketMutationsError)

    def test_ticket_not_mutable_message_is_static(self) -> None:
        assert str(TicketNotMutableError()) == "Ticket is not mutable."

    def test_module_reexports_its_leaf_error_hierarchy(self) -> None:
        assert issubclass(InvalidCVSSVectorError, TicketMutationsError)
        assert issubclass(TicketMutationsError, ServiceError)
        assert ticket_mutations.TicketNotMutableError is TicketNotMutableError


# ---------------------------------------------------------------------------
# ensure_ticket_operable()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEnsureTicketOperable:
    @pytest.mark.parametrize(
        "status",
        [
            TicketStatus.NEW,
            TicketStatus.ANALYSIS,
            TicketStatus.ANALYZED,
            TicketStatus.RESOLVED,
        ],
    )
    def test_operable_status_passes(self, status: TicketStatus) -> None:
        # A transient Ticket bound to no session: any query would fail.
        ensure_ticket_operable(Ticket(status=status.value))

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    def test_manual_zone_status_raises(self, status: TicketStatus) -> None:
        with pytest.raises(TicketNotMutableError):
            ensure_ticket_operable(Ticket(status=status.value))


# ---------------------------------------------------------------------------
# stabilize_acting_user()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStabilizeActingUser:
    async def test_locks_user_for_share_and_loads_roles(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        user = await va_user(roles=(Role.VULNERABILITY_ANALYST, Role.ADMIN))
        user_id = user.id
        db_session.expire(user)

        with StatementRecorder(db_session) as recorder:
            stabilized = await stabilize_acting_user(db_session, user_id)

        assert stabilized.id == user_id
        assert any("FOR SHARE" in s and 'FROM "user"' in s for s in recorder.statements)
        assert {r.role for r in stabilized.roles} == {
            Role.VULNERABILITY_ANALYST.value,
            Role.ADMIN.value,
        }

    async def test_refreshes_stale_identity_map_state(
        self, db_session: AsyncSession, va_user: VAUser
    ) -> None:
        user = await va_user()
        assert user.active is True
        await db_session.execute(
            update(User).where(User.id == user.id).values(active=False)
        )
        await db_session.execute(delete(UserRole).where(UserRole.user_id == user.id))

        stabilized = await stabilize_acting_user(db_session, user.id)

        assert stabilized.active is False
        assert stabilized.roles == []

    async def test_unknown_user_raises_user_not_found(
        self, db_session: AsyncSession
    ) -> None:
        with pytest.raises(UserNotFoundError):
            await stabilize_acting_user(db_session, uuid.uuid7())


@pytest.mark.integration
class TestStabilizeActingUserLocking:
    """Independent sessions: `FOR SHARE` serializes with the
    `FOR NO KEY UPDATE` of eligibility loss and is compatible with other
    assignment paths (docs/conventions.md, Cross-Domain Root Lock Order)."""

    @pytest.fixture
    async def committed_user(
        self, db_session_factory: Callable[[], Awaitable[AsyncSession]]
    ) -> AsyncIterator[uuid.UUID]:
        setup = await db_session_factory()
        user = User(
            username=f"lock-{uuid.uuid4().hex[:12]}",
            email=f"lock-{uuid.uuid4().hex[:12]}@example.com",
            password_hash="$2b$12$" + "x" * 53,
        )
        setup.add(user)
        await setup.flush()
        setup.add(UserRole(user_id=user.id, role=Role.VULNERABILITY_ANALYST.value))
        await setup.commit()
        try:
            yield user.id
        finally:
            await setup.rollback()
            await setup.execute(delete(UserRole).where(UserRole.user_id == user.id))
            await setup.execute(delete(User).where(User.id == user.id))
            await setup.commit()

    async def test_share_lock_blocks_eligibility_loss_until_release(
        self,
        committed_user: uuid.UUID,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        assigner = await db_session_factory()
        lifecycle = await db_session_factory()
        await stabilize_acting_user(assigner, committed_user)

        blocked = asyncio.create_task(
            lifecycle.execute(
                select(User.id)
                .where(User.id == committed_user)
                .with_for_update(key_share=True)
            )
        )
        await assert_lock_wait(blocked, waiter=lifecycle, blocked_by=assigner)

        await assigner.rollback()
        await asyncio.wait_for(blocked, timeout=5)
        await lifecycle.rollback()

    async def test_two_assignment_paths_share_the_user(
        self,
        committed_user: uuid.UUID,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        first = await db_session_factory()
        second = await db_session_factory()
        await stabilize_acting_user(first, committed_user)

        stabilized = await asyncio.wait_for(
            stabilize_acting_user(second, committed_user), timeout=5
        )

        assert stabilized.id == committed_user
        await first.rollback()
        await second.rollback()


# ---------------------------------------------------------------------------
# auto_assign_actor()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAutoAssignActor:
    async def test_system_actor_is_skipped(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        assert await auto_assign_actor(ticket, None, db_session) is False

        assert ticket.assignee_id is None
        assert ticket.status == TicketStatus.NEW
        assert await ticket_events(db_session, ticket) == []

    async def test_already_assigned_ticket_is_skipped(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        owner = await va_user()
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await cveless(ticket_factory, assignee_id=owner.id)

        assert await auto_assign_actor(ticket, actor, db_session) is False

        assert ticket.assignee_id == owner.id
        assert await ticket_events(db_session, ticket) == []

    @pytest.mark.parametrize(
        ("active", "roles"),
        [
            pytest.param(False, (Role.VULNERABILITY_ANALYST,), id="inactive-va"),
            pytest.param(True, (Role.RESTRICTED_ANALYST,), id="restricted-analyst"),
            pytest.param(True, (), id="no-role"),
        ],
    )
    async def test_ineligible_actor_is_skipped(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        active: bool,
        roles: tuple[Role, ...],
    ) -> None:
        actor = await stabilize_acting_user(
            db_session, (await va_user(active=active, roles=roles)).id
        )
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        assert await auto_assign_actor(ticket, actor, db_session) is False
        assert await auto_assign_actor(ticket, actor, db_session, force=True) is False

        assert ticket.assignee_id is None
        assert ticket.status == TicketStatus.NEW
        assert await ticket_events(db_session, ticket) == []

    async def test_unchanged_assignee_with_force_is_a_no_op(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await cveless(ticket_factory, assignee_id=actor.id)

        assert await auto_assign_actor(ticket, actor, db_session, force=True) is False

        assert await ticket_events(db_session, ticket) == []

    async def test_assigns_unassigned_gate_zone_ticket_without_status_change(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)

        assert await auto_assign_actor(ticket, actor, db_session) is True

        assert ticket.assignee_id == actor.id
        assert ticket.status == TicketStatus.ANALYZED
        assert await ticket_events(db_session, ticket) == [
            EventRow("assignment", actor.id, None, actor.username, None, None)
        ]

    async def test_new_ticket_is_promoted_after_the_assignment_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        assert await auto_assign_actor(ticket, actor, db_session) is True

        assert ticket.status == TicketStatus.ANALYSIS
        assert await ticket_events(db_session, ticket) == [
            EventRow("assignment", actor.id, None, actor.username, None, None),
            status_event("New", "Analysis"),
        ]

    async def test_force_reassigns_with_previous_username(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        previous = await va_user(active=False)
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await lock_ticket(
            db_session, await cveless(ticket_factory, assignee_id=previous.id)
        )

        with StatementRecorder(db_session) as recorder:
            assert (
                await auto_assign_actor(ticket, actor, db_session, force=True) is True
            )

        # One unlocked previous-assignee username observation, no lock.
        assert len(recorder.selects_from('"user"')) == 1
        assert recorder.row_locks() == []

        assert ticket.assignee_id == actor.id
        assert await ticket_events(db_session, ticket) == [
            EventRow(
                "assignment", actor.id, previous.username, actor.username, None, None
            )
        ]

    async def test_never_reconciles_even_when_gates_are_met(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        tree: TreeBuilder,
    ) -> None:
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        await auto_assign_actor(ticket, actor, db_session)

        assert ticket.status == TicketStatus.ANALYSIS
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_performs_no_user_query_or_lock_after_the_ticket_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        actor = await stabilize_acting_user(db_session, (await va_user()).id)
        ticket = await lock_ticket(
            db_session, await cveless(ticket_factory, status=TicketStatus.NEW)
        )

        with StatementRecorder(db_session) as recorder:
            assert await auto_assign_actor(ticket, actor, db_session) is True

        assert recorder.selects_from('"user"') == []
        assert recorder.selects_from("user_role") == []
        assert recorder.row_locks() == []

    async def test_unstabilized_actor_is_a_contract_violation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        user = await va_user()
        db_session.expire(user, ["roles"])
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="stabilize_acting_user"),
        ):
            await auto_assign_actor(ticket, user, db_session)

        assert recorder.statements == []
        assert ticket.assignee_id is None

    async def test_audit_failure_rolls_back_assignment_and_promotion(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        actor_id = (await va_user()).id
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)
        original = TicketAuditLog.log_event
        calls = 0

        async def failing(*args: Any, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected audit failure")
            await original(*args, **kwargs)

        async with rollback_test_scope(db_session):
            actor = await stabilize_acting_user(db_session, actor_id)
            monkeypatch.setattr(TicketAuditLog, "log_event", failing)
            with pytest.raises(RuntimeError, match="injected"):
                await auto_assign_actor(ticket, actor, db_session)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert ticket.assignee_id is None
        assert ticket.status == TicketStatus.NEW
        assert await ticket_events(db_session, ticket) == []


# ---------------------------------------------------------------------------
# reconcile_ticket_status(): step 1 guards
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestReconcileGuards:
    async def test_new_ticket_is_skipped_without_query_or_event(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        with StatementRecorder(db_session) as recorder:
            assert await _reconcile(db_session, ticket) is TicketStatus.NEW

        assert recorder.statements == []
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_assigned_new_ticket_logs_the_code_path_warning(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        assignee = await va_user()
        ticket = await cveless(
            ticket_factory, status=TicketStatus.NEW, assignee_id=assignee.id
        )

        with caplog.at_level("WARNING"):
            assert await _reconcile(db_session, ticket) is TicketStatus.NEW

        records = _service_event_fields(caplog, "ticket_new_status_with_assignee")
        assert len(records) == 1
        assert records[0]["ticket_id"] == str(ticket.id)
        assert records[0]["assignee_id"] == str(assignee.id)
        assert records[0]["level"] == "warning"
        assert ticket.assignee_id == assignee.id
        assert ticket.status == TicketStatus.NEW
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_unassigned_new_ticket_logs_nothing(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.NEW)

        with caplog.at_level("WARNING"):
            await _reconcile(db_session, ticket)

        assert _service_event_fields(caplog, "ticket_new_status_with_assignee") == []

    @pytest.mark.parametrize("status", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    async def test_manual_zone_ticket_is_a_contract_violation(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        status: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status)

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(ValueError, match="manual-zone"),
        ):
            await _reconcile(db_session, ticket)

        assert recorder.statements == []
        assert ticket.status == status
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()


# ---------------------------------------------------------------------------
# reconcile_ticket_status(): gate predicates and Deterministic Gate Edge Cases
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestStructuralGate:
    async def test_no_track_keeps_analysis(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYZED)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

    @pytest.mark.parametrize(
        "exclusion",
        [
            pytest.param({"package_excluded": True}, id="package-excluded"),
            pytest.param({"track_excluded": True}, id="track-excluded"),
        ],
    )
    async def test_excluded_track_leaves_m_and_a(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        exclusion: dict[str, bool],
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED, **exclusion)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

    async def test_excluded_analysis_track_does_not_block(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.ANALYSIS, track_excluded=True)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    async def test_all_eol_tree_resolves_by_empty_quantification(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.ANALYSIS, products=(Prod(eol=True),))
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(eol=True),))

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    async def test_track_without_products_counts_for_m_only(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.ANALYSIS, products=())

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    async def test_actionable_analysis_track_blocks_analyzed(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.RESOLVED)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        await tree(ticket, status=PackageStatus.ANALYSIS)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

    async def test_non_actionable_analysis_track_does_not_block(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(eol=True), Prod(excluded=True)),
        )
        await tree(ticket, status=PackageStatus.AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYZED

    async def test_product_exclusion_keeps_track_actionable_with_another_product(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(
            ticket,
            status=PackageStatus.ANALYSIS,
            products=(Prod(excluded=True), Prod()),
        )

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

    async def test_missing_lifecycle_data_is_actionable(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(
            ticket, status=PackageStatus.ANALYSIS, products=(Prod(lifecycle=False),)
        )

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS


@pytest.mark.integration
class TestResolutionCompleteness:
    @pytest.mark.parametrize(
        "status", [PackageStatus.NOT_AFFECTED, PackageStatus.WONT_FIX]
    )
    async def test_clause_a_final_decisions_resolve(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        status: PackageStatus,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=status, products=(Prod(),))

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    @pytest.mark.parametrize(
        ("products", "expected"),
        [
            pytest.param((Prod(),), TicketStatus.ANALYZED, id="unreleased-eligible"),
            pytest.param((Prod(released=True),), TicketStatus.RESOLVED, id="released"),
            pytest.param(
                (Prod(released=True), Prod()), TicketStatus.ANALYZED, id="partial"
            ),
            pytest.param(
                (Prod(eligible=False),), TicketStatus.RESOLVED, id="vacuous-no-aep"
            ),
            pytest.param(
                (Prod(released=True), Prod(eligible=False)),
                TicketStatus.RESOLVED,
                id="ineligible-unreleased-ignored",
            ),
            pytest.param(
                (Prod(released=True), Prod(eol=True)),
                TicketStatus.RESOLVED,
                id="eol-unreleased-ignored",
            ),
            pytest.param(
                (Prod(released=True), Prod(excluded=True)),
                TicketStatus.RESOLVED,
                id="excluded-unreleased-ignored",
            ),
        ],
    )
    async def test_clause_b_fixed_with_cve_requires_release_of_aep(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        products: tuple[Prod, ...],
        expected: TicketStatus,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=PackageStatus.FIXED, products=products)

        assert await _reconcile(db_session, ticket) is expected

    async def test_clause_b_cveless_fixed_ignores_release(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        track = await tree(ticket, status=PackageStatus.FIXED, products=(Prod(),))

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED
        released = (
            await db_session.execute(
                select(TicketPackageProduct.released_at).where(
                    TicketPackageProduct.ticket_package_track_id == track.id
                )
            )
        ).scalar_one()
        assert released is None

    @pytest.mark.parametrize(
        ("products", "expected"),
        [
            pytest.param((Prod(),), TicketStatus.ANALYZED, id="eligible-actionable"),
            pytest.param(
                (Prod(eligible=False),), TicketStatus.RESOLVED, id="all-ineligible"
            ),
            pytest.param(
                (Prod(eligible=False, override=True),),
                TicketStatus.RESOLVED,
                id="override-false-removes-from-aep",
            ),
            pytest.param(
                (Prod(eligible=True, override=True),),
                TicketStatus.ANALYZED,
                id="override-true-stays-in-aep",
            ),
            pytest.param(
                (Prod(eol=True), Prod(eligible=False)),
                TicketStatus.RESOLVED,
                id="eligible-only-eol",
            ),
            pytest.param(
                (Prod(excluded=True), Prod(eligible=False)),
                TicketStatus.RESOLVED,
                id="eligible-only-excluded",
            ),
        ],
    )
    async def test_clause_c_affected_resolves_without_aep(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        products: tuple[Prod, ...],
        expected: TicketStatus,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=PackageStatus.AFFECTED, products=products)

        assert await _reconcile(db_session, ticket) is expected

    async def test_every_actionable_track_must_be_complete(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        await tree(ticket, status=PackageStatus.AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYZED

    async def test_eol_product_under_affected_track_restores_on_other_date(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=PackageStatus.AFFECTED, products=(Prod(eol=True),))

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED
        # Before the Product's General Support end it is actionable again.
        assert (
            await _reconcile(
                db_session, ticket, evaluation_date=BEFORE_EVAL - timedelta(days=1)
            )
            is TicketStatus.ANALYZED
        )


@pytest.mark.integration
class TestSeverityAndSuseGates:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            pytest.param(Severity.NONE, TicketStatus.RESOLVED, id="none-label"),
            pytest.param(None, TicketStatus.ANALYSIS, id="sql-null"),
        ],
    )
    async def test_cveless_manual_severity(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        severity: Severity | None,
        expected: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, severity=severity)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is expected

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            pytest.param(Severity.NONE, TicketStatus.RESOLVED, id="none-label"),
            pytest.param(None, TicketStatus.ANALYSIS, id="sql-null"),
        ],
    )
    async def test_cve_severity(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        severity: Severity | None,
        expected: TicketStatus,
    ) -> None:
        ticket = await cve_ticket(severity=severity)
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is expected

    @pytest.mark.parametrize("version", list(CVSSVersion))
    async def test_each_accepted_suse_version_alone_satisfies_the_gate(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        version: CVSSVersion,
    ) -> None:
        ticket = await cve_ticket(suse_versions=(version,))
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    async def test_external_only_assessments_do_not_satisfy_the_gate(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
    ) -> None:
        ticket = await cve_ticket(
            suse_versions=(), external_versions=tuple(CVSSVersion)
        )
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

    async def test_default_version_suse_is_not_required(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        system_setting_factory: Callable[..., Awaitable[Any]],
    ) -> None:
        await system_setting_factory(key="default_cvss_version", value="4.0")
        ticket = await cve_ticket(
            suse_versions=(CVSSVersion.V2_0,), external_versions=(CVSSVersion.V4_0,)
        )
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

    async def test_cveless_ticket_has_no_suse_gate(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        ticket = await cveless(ticket_factory)
        await tree(ticket, status=PackageStatus.AFFECTED)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYZED


# ---------------------------------------------------------------------------
# reconcile_ticket_status(): transitions, events, and date
# ---------------------------------------------------------------------------


GATE_STATUSES = (TicketStatus.ANALYSIS, TicketStatus.ANALYZED, TicketStatus.RESOLVED)


@pytest.mark.integration
class TestTransitions:
    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (current, target)
            for current in GATE_STATUSES
            for target in GATE_STATUSES
            if current is not target
        ],
    )
    async def test_transition_creates_one_system_status_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        current: TicketStatus,
        target: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=current)
        await tree_for(target, ticket, tree)

        assert await _reconcile(db_session, ticket) is target

        assert await ticket_events(db_session, ticket) == [
            status_event(current.value, target.value)
        ]
        persisted = (
            await db_session.execute(
                select(Ticket.status).where(Ticket.id == ticket.id)
            )
        ).scalar_one()
        assert persisted == target

    @pytest.mark.parametrize("status", GATE_STATUSES)
    async def test_no_op_evaluation_creates_no_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        status: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=status)
        await tree_for(status, ticket, tree)

        assert await _reconcile(db_session, ticket) is status
        assert await _reconcile(db_session, ticket) is status

        assert await ticket_events(db_session, ticket) == []

    async def test_one_evaluation_date_across_a_utc_midnight(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        product_factory: Callable[..., Awaitable[Product]],
        ticket_package_product_factory: Callable[..., Awaitable[TicketPackageProduct]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        day = date(2026, 12, 31)
        instants = iter(
            [
                datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
                datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC),
            ]
        )
        calls = 0

        def clock() -> datetime:
            nonlocal calls
            calls += 1
            return next(instants)

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        ticket = await cveless(ticket_factory)
        # General Support ends on `day`: actionable on `day`, EOL the next day.
        track = await tree(ticket, status=PackageStatus.AFFECTED, products=())
        product = await product_factory(general_support_end_date=day)
        await ticket_package_product_factory(
            ticket_package_track_id=track.id, product_id=product.id
        )

        with StatementRecorder(db_session) as recorder:
            await reconcile_ticket_status(ticket, db_session)

        assert ticket.status == TicketStatus.ANALYZED
        assert calls == 1
        dates = {
            value
            for params in recorder.parameters
            for value in (params.values() if isinstance(params, dict) else params)
            if isinstance(value, date) and not isinstance(value, datetime)
        }
        assert dates == {day}

    async def test_supplied_evaluation_date_is_not_recaptured(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def clock() -> datetime:
            raise AssertionError("the supplied date must be reused")

        monkeypatch.setattr(ticket_mutations, "_utc_now", clock)
        ticket = await cveless(ticket_factory)

        await reconcile_ticket_status(ticket, db_session, evaluation_date=EVAL)

    async def test_acquires_no_lock_and_reads_no_audit_history(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(active=False)
        ticket = await cve_ticket(status=TicketStatus.RESOLVED)
        ticket.assignee_id = assignee.id
        await tree(ticket, status=PackageStatus.AFFECTED)
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            assert await _reconcile(db_session, ticket) is TicketStatus.ANALYZED

        assert recorder.row_locks() == []
        assert recorder.selects_from("ticket_audit_event") == []
        assert ticket.assignee_id is None


# ---------------------------------------------------------------------------
# reconcile_ticket_status(): assignment-eligibility sanitation
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAssignmentSanitation:
    @pytest.mark.parametrize(
        ("active", "roles", "reason"),
        [
            pytest.param(
                False, (Role.VULNERABILITY_ANALYST,), "inactive assignee", id="inactive"
            ),
            pytest.param(
                True,
                (Role.RESTRICTED_ANALYST,),
                "vulnerability_analyst role removed",
                id="active-without-va",
            ),
            pytest.param(False, (), "inactive assignee", id="both-invalid-precedence"),
        ],
    )
    @pytest.mark.parametrize("result", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED])
    async def test_ineligible_assignee_is_unassigned(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        caplog: pytest.LogCaptureFixture,
        active: bool,
        roles: tuple[Role, ...],
        reason: str,
        result: TicketStatus,
    ) -> None:
        assignee = await va_user(active=active, roles=roles)
        ticket = await cveless(ticket_factory, status=result, assignee_id=assignee.id)
        await tree_for(result, ticket, tree)

        with caplog.at_level("WARNING"):
            assert await _reconcile(db_session, ticket) is result

        assert ticket.assignee_id is None
        assert await ticket_events(db_session, ticket) == [
            unassigned_event(assignee.username, reason)
        ]
        records = _service_event_fields(caplog, "ticket_assignee_sanitized")
        assert len(records) == 1
        assert {k: records[0][k] for k in ("ticket_id", "user_id", "reason")} == {
            "ticket_id": str(ticket.id),
            "user_id": str(assignee.id),
            "reason": reason,
        }
        assert assignee.username not in str(records[0])

    async def test_eligible_assignee_is_preserved(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(
            roles=(Role.RESTRICTED_ANALYST, Role.VULNERABILITY_ANALYST)
        )
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS

        assert ticket.assignee_id == assignee.id
        assert await ticket_events(db_session, ticket) == []

    async def test_resolved_result_retains_ineligible_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(active=False, roles=())
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        assert await _reconcile(db_session, ticket) is TicketStatus.RESOLVED

        assert ticket.assignee_id == assignee.id
        assert await ticket_events(db_session, ticket) == [
            status_event("Analysis", "Resolved")
        ]

    async def test_sanitation_event_precedes_the_final_status_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(active=False)
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=assignee.id
        )
        await tree_for(TicketStatus.ANALYZED, ticket, tree)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYZED

        assert await ticket_events(db_session, ticket) == [
            unassigned_event(assignee.username, "inactive assignee"),
            status_event("Resolved", "Analyzed"),
        ]

    async def test_observes_current_role_origins_without_user_lock(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user()
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)
        # The final VA origin disappears after the assignee was loaded.
        await db_session.execute(
            delete(UserRole).where(UserRole.user_id == assignee.id)
        )

        with StatementRecorder(db_session) as recorder:
            await _reconcile(db_session, ticket)

        assert ticket.assignee_id is None
        assert recorder.row_locks() == []
        assert recorder.selects_from("ticket_audit_event") == []


# ---------------------------------------------------------------------------
# reconcile_ticket_status(): previous_status and convergence registration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPreviousStatus:
    @pytest.mark.parametrize("source", [TicketStatus.IGNORED, TicketStatus.DUPLICATED])
    @pytest.mark.parametrize("result", GATE_STATUSES)
    async def test_manual_zone_exit_records_semantic_transition(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        source: TicketStatus,
        result: TicketStatus,
    ) -> None:
        # The public exit workflow has prepared the Analysis floor.
        ticket = await cveless(ticket_factory, status=TicketStatus.ANALYSIS)
        await tree_for(result, ticket, tree)

        assert await _reconcile(db_session, ticket, previous_status=source) is result

        assert await ticket_events(db_session, ticket) == [
            status_event(source.value, result.value)
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_exit_to_resolved_retains_ineligible_assignee(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(active=False)
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)
        await tree_for(TicketStatus.RESOLVED, ticket, tree)

        await _reconcile(db_session, ticket, previous_status=TicketStatus.IGNORED)

        assert ticket.assignee_id == assignee.id
        assert await ticket_events(db_session, ticket) == [
            status_event("Ignored", "Resolved")
        ]

    async def test_exit_with_sanitation_orders_events(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        va_user: VAUser,
    ) -> None:
        assignee = await va_user(roles=())
        ticket = await cveless(ticket_factory, assignee_id=assignee.id)

        await _reconcile(db_session, ticket, previous_status=TicketStatus.DUPLICATED)

        assert await ticket_events(db_session, ticket) == [
            unassigned_event(assignee.username, "vulnerability_analyst role removed"),
            status_event("Duplicated", "Analysis"),
        ]

    async def test_exit_needs_no_cve_lock(
        self,
        db_session: AsyncSession,
        cve_ticket: Callable[..., Awaitable[Ticket]],
        tree: TreeBuilder,
    ) -> None:
        ticket = await cve_ticket()
        await tree(ticket, status=PackageStatus.NOT_AFFECTED)
        ticket = await lock_ticket(db_session, ticket)

        with StatementRecorder(db_session) as recorder:
            await _reconcile(db_session, ticket, previous_status=TicketStatus.IGNORED)

        assert ticket.status == TicketStatus.RESOLVED
        assert recorder.row_locks() == []


@pytest.mark.integration
class TestConvergenceRegistration:
    @pytest.mark.parametrize("result", [TicketStatus.ANALYSIS, TicketStatus.ANALYZED])
    async def test_resolved_regression_registers(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        result: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=TicketStatus.RESOLVED)
        await tree_for(result, ticket, tree)

        await _reconcile(db_session, ticket)

        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    @pytest.mark.parametrize(
        ("current", "result"),
        [
            (TicketStatus.RESOLVED, TicketStatus.RESOLVED),
            (TicketStatus.ANALYSIS, TicketStatus.ANALYZED),
            (TicketStatus.ANALYSIS, TicketStatus.RESOLVED),
            (TicketStatus.ANALYZED, TicketStatus.RESOLVED),
            (TicketStatus.ANALYZED, TicketStatus.ANALYSIS),
            (TicketStatus.ANALYSIS, TicketStatus.ANALYSIS),
        ],
    )
    async def test_other_evaluations_do_not_register(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        current: TicketStatus,
        result: TicketStatus,
    ) -> None:
        ticket = await cveless(ticket_factory, status=current)
        await tree_for(result, ticket, tree)

        assert await _reconcile(db_session, ticket) is result

        assert pending_ticket_convergence_effects(db_session) == ()

    async def test_repeated_reconciliation_registers_one_effect_in_order(
        self, db_session: AsyncSession, ticket_factory: TicketFactory
    ) -> None:
        first = await cveless(ticket_factory)
        second = await cveless(ticket_factory)

        await _reconcile(db_session, second, previous_status=TicketStatus.IGNORED)
        await _reconcile(db_session, first, previous_status=TicketStatus.DUPLICATED)
        await _reconcile(db_session, second, previous_status=TicketStatus.IGNORED)

        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(second.id),
            TicketConvergenceEffect(first.id),
        )

    async def test_registration_adds_no_statement_or_event(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        # Registration is in-memory: beyond the gate evaluation, an exit issues
        # only its status-change audit INSERT.
        ticket = await cveless(ticket_factory)
        await tree_for(TicketStatus.ANALYSIS, ticket, tree)

        with StatementRecorder(db_session) as recorder:
            await _reconcile(db_session, ticket, previous_status=TicketStatus.IGNORED)

        writes = [
            s
            for s in recorder.statements
            if not s.lstrip().upper().startswith("SELECT")
        ]
        assert len(writes) == 1
        assert writes[0].lstrip().upper().startswith("INSERT INTO TICKET_AUDIT_EVENT")
        assert len(recorder.statements) == 2
        assert [e.event_type for e in await ticket_events(db_session, ticket)] == [
            "status_change"
        ]
        assert pending_ticket_convergence_effects(db_session) == (
            TicketConvergenceEffect(ticket.id),
        )

    async def test_audit_failure_rolls_back_status_assignee_and_events(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
        va_user: VAUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        assignee_id = (await va_user(active=False)).id
        ticket = await cveless(
            ticket_factory, status=TicketStatus.RESOLVED, assignee_id=assignee_id
        )
        await tree_for(TicketStatus.ANALYZED, ticket, tree)
        original = TicketAuditLog.log_event
        calls = 0

        async def failing(*args: Any, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected audit failure")
            await original(*args, **kwargs)

        async with rollback_test_scope(db_session):
            monkeypatch.setattr(TicketAuditLog, "log_event", failing)
            with pytest.raises(RuntimeError, match="injected"):
                await _reconcile(db_session, ticket)
        monkeypatch.undo()

        await db_session.refresh(ticket)
        assert ticket.status == TicketStatus.RESOLVED
        assert ticket.assignee_id == assignee_id
        assert await ticket_events(db_session, ticket) == []
        assert pending_ticket_convergence_effects(db_session) == ()
        assert calls == 2

    async def test_gate_observes_only_the_ticket_own_tree(
        self,
        db_session: AsyncSession,
        ticket_factory: TicketFactory,
        tree: TreeBuilder,
    ) -> None:
        other = await cveless(ticket_factory)
        await tree(other, status=PackageStatus.NOT_AFFECTED)
        ticket = await cveless(ticket_factory)

        assert await _reconcile(db_session, ticket) is TicketStatus.ANALYSIS
        assert other.status == TicketStatus.ANALYSIS
        total = (
            await db_session.execute(
                select(func.count())
                .select_from(TicketAuditEvent)
                .where(TicketAuditEvent.ticket_id == other.id)
            )
        ).scalar_one()
        assert total == 0
