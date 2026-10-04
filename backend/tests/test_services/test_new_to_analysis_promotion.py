"""Architectural Test Requirement 4 of docs/features/tickets/ticket-service.md:
`New -> Analysis` promotion coverage.

Every code path that sets `assignee_id` on a `New` Ticket produces exactly
one system `status_change` (`old_value = "New"`, `new_value = "Analysis"`,
`user_id = NULL`) immediately after its `assignment` event
(ticket-service.md, `assign_ticket` step 9; ticket-mutations.md,
Auto-Assignment Rule and `auto_assign_actor()` step 7; tickets.md,
Architectural Invariant). The paths are `assign_ticket()` (explicit
assignment) and every existing consumer mutation that reaches
`auto_assign_actor()`, including the six package-tree exclusion and
restoration operations (package-service.md, Exclusion and restoration
operations, step 7), a user-attributed, record-creating
`add_package_records()` call (package-service.md, `add_package_records()`
step 9), and a consumer `add_package_to_ticket()` call by an active VA,
which reaches the assignment through that delegated boundary
(package-service.md, Auto-Assignment Rule). For the manual-zone entries
`ignore_ticket()` and `mark_as_duplicate()`, the acting-user entry
transition (`Analysis -> Ignored` or `Analysis -> Duplicated`) follows the
promotion (tickets.md,
Auto-Assignment on Unassigned Tickets), so the promotion is the only
system `status_change` and precedes that entry transition.

This module is a thin guard over the path list only: every other property
of each path (complete event sequences, reconciliation, rollback, races)
is proven in the path's owning module. Package addition is covered here at
both the `add_package_records()` and the `add_package_to_ticket()` level;
the orchestrator call resolves its package through the in-process SMELT fake
of `tests/support/package_addition.py`.

Expected values are transcribed from the specifications, never computed
with the module under test.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.enums import (
    PackageStatus,
    Scope,
    Severity,
    TicketPriority,
    TicketStatus,
)
from app.models.cve import CVE
from app.services.package_service import set_product_eligibility, set_track_status
from app.services.ticket_mutations import set_severity_manual
from app.services.ticket_service import (
    assign_ticket,
    associate_cve,
    ignore_ticket,
    mark_as_duplicate,
    set_priority_override,
)
from app.services.ticket_visibility import TicketCaller
from tests.support.cvss_chain import DEFAULT_VERSION
from tests.support.package_addition import PackageSmelt, add, codestream, publish
from tests.support.package_exclusion import Direction, Level, change, gate_world
from tests.support.package_records import add_records, catalog_product
from tests.support.package_records import target as resolved_track
from tests.support.product_eligibility import only_occurrence
from tests.support.smelt import SMELT_TEST_API_URL
from tests.support.suse_cvss import V31_CRITICAL, delete_assessment, upsert
from tests.support.ticket_mutations import (
    EVAL,
    EventRow,
    TicketFactory,
    TreeBuilder,
    VAUser,
    status_event,
    ticket_events,
)

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `va_user` and `tree` fixtures."""

Factory = Callable[..., Awaitable[Any]]

PROMOTION = status_event(TicketStatus.NEW.value, TicketStatus.ANALYSIS.value)

PATHS = [
    "assign_ticket",
    "set_severity_manual",
    "upsert_cvss_assessment",
    "delete_cvss_assessment",
    "associate_cve",
    "set_priority_override",
    "ignore_ticket",
    "mark_as_duplicate",
    "set_track_status",
    "set_product_eligibility",
    "soft_delete_ticket_package",
    "soft_delete_ticket_package_track",
    "soft_delete_ticket_package_product",
    "restore_ticket_package",
    "restore_ticket_package_track",
    "restore_ticket_package_product",
    "add_package_records",
    "add_package_to_ticket",
]

MARKER_PATHS = {
    "soft_delete_ticket_package": (Level.PACKAGE, Direction.EXCLUDE),
    "soft_delete_ticket_package_track": (Level.TRACK, Direction.EXCLUDE),
    "soft_delete_ticket_package_product": (Level.PRODUCT, Direction.EXCLUDE),
    "restore_ticket_package": (Level.PACKAGE, Direction.RESTORE),
    "restore_ticket_package_track": (Level.TRACK, Direction.RESTORE),
    "restore_ticket_package_product": (Level.PRODUCT, Direction.RESTORE),
}
"""The direct-marker operations, invoked through
`tests.support.package_exclusion.change()` by `Level` and `Direction`."""


@pytest.mark.integration
@pytest.mark.parametrize("path", PATHS)
async def test_assignment_of_a_new_ticket_is_followed_by_one_promotion(
    db_session: AsyncSession,
    ticket_factory: TicketFactory,
    cve_factory: Callable[..., Awaitable[CVE]],
    cve_cvss_assessment_factory: Factory,
    system_setting_factory: Factory,
    va_user: VAUser,
    tree: TreeBuilder,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    actor = await va_user()
    caller = TicketCaller.authenticated(actor.id, Scope.ALL)
    assignee = actor
    entry: list[EventRow] = []
    match path:
        case "assign_ticket":
            assignee = await va_user()
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            await assign_ticket(
                db_session,
                ticket_id=ticket.id,
                assignee=str(assignee.id),
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case "set_severity_manual":
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            await set_severity_manual(
                db_session,
                ticket_id=ticket.id,
                severity=Severity.HIGH,
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case "upsert_cvss_assessment":
            cve = await cve_factory()
            ticket = await ticket_factory(status=TicketStatus.NEW.value, cve_id=cve.id)
            await upsert(
                db_session,
                cve.id,
                V31_CRITICAL.canonical,
                actor,
                default_cvss_version=DEFAULT_VERSION,
            )
        case "delete_cvss_assessment":
            cve = await cve_factory(severity=Severity.CRITICAL.value)
            await cve_cvss_assessment_factory(
                cve_id=cve.id, provider_name="SUSE", **V31_CRITICAL.columns()
            )
            ticket = await ticket_factory(
                status=TicketStatus.NEW.value, cve_id=cve.id, priority_auto="P2"
            )
            await delete_assessment(
                db_session,
                cve.id,
                V31_CRITICAL.version,
                actor,
                default_cvss_version=DEFAULT_VERSION,
            )
        case "associate_cve":
            await system_setting_factory(
                key="default_cvss_version", value=DEFAULT_VERSION
            )
            cve = await cve_factory()
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            await associate_cve(
                db_session,
                ticket_id=ticket.id,
                cve_id=cve.cve_id,
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case "set_priority_override":
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            await set_priority_override(
                db_session,
                ticket_id=ticket.id,
                priority=TicketPriority.P1,
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case "ignore_ticket":
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            await ignore_ticket(
                db_session,
                ticket_id=ticket.id,
                acting_user_id=actor.id,
                caller=caller,
            )
            entry = [
                EventRow(
                    "status_change",
                    actor.id,
                    TicketStatus.ANALYSIS.value,
                    TicketStatus.IGNORED.value,
                    None,
                    None,
                )
            ]
        case "mark_as_duplicate":
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            target = await ticket_factory(status=TicketStatus.ANALYSIS.value)
            await mark_as_duplicate(
                db_session,
                ticket_id=ticket.id,
                duplicate_of_id=target.id,
                acting_user_id=actor.id,
                caller=caller,
            )
            entry = [
                EventRow(
                    "status_change",
                    actor.id,
                    TicketStatus.ANALYSIS.value,
                    TicketStatus.DUPLICATED.value,
                    None,
                    None,
                )
            ]
        case "set_track_status":
            # CVE-less with no resolved severity: the effective `analysis ->
            # affected` change leaves the promoted Ticket in `Analysis`
            # (tickets.md, Gate: Analysis -> Analyzed), so no gate
            # `status_change` follows the promotion.
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            track = await tree(ticket, status=PackageStatus.ANALYSIS)
            await set_track_status(
                db_session,
                ticket_id=ticket.id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                status=PackageStatus.AFFECTED,
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case "set_product_eligibility":
            # The same CVE-less Ticket without a resolved severity: the
            # effective override leaves the promoted Ticket in `Analysis`.
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            track = await tree(ticket, status=PackageStatus.ANALYSIS)
            occurrence = await only_occurrence(db_session, track)
            await set_product_eligibility(
                db_session,
                ticket_id=ticket.id,
                package_id=track.ticket_package_id,
                track_id=track.id,
                ticket_package_product_id=occurrence.id,
                eligible=False,
                acting_user_id=actor.id,
                caller=caller,
                evaluation_date=EVAL,
            )
        case _ if path in MARKER_PATHS:
            # The same CVE-less Ticket without a resolved severity, plus an
            # untouched included `analysis` track: before and after the
            # effective marker change an undecided actionable track remains,
            # so the promoted Ticket stays in `Analysis` (tickets.md, Gate:
            # Analysis -> Analyzed) and no gate `status_change` follows. A
            # restore seeds only the target's direct marker.
            level, direction = MARKER_PATHS[path]
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            occurrence = await gate_world(
                db_session,
                tree,
                ticket,
                level,
                direction,
                other=PackageStatus.ANALYSIS,
            )
            await change(db_session, level, direction, occurrence, actor)
        case "add_package_records":
            # The same CVE-less Ticket without a resolved severity: the new
            # `analysis` track leaves the promoted Ticket in `Analysis`, so
            # `package_added` is followed by no gate `status_change`.
            await system_setting_factory(
                key="default_cvss_version", value=DEFAULT_VERSION
            )
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            product = await catalog_product(db_session)
            await add_records(
                db_session,
                ticket.id,
                "fictional-libexample",
                [resolved_track("Fictional:Product:15-SP7:Update", product)],
                actor=actor,
            )
        case "add_package_to_ticket":
            # The same world as `add_package_records`, with the package
            # resolved through SMELT and the Product in the current catalog
            # snapshot; a system call of the same function never assigns
            # (tests/test_services/test_add_package_to_ticket.py).
            monkeypatch.setattr(settings, "smelt_api_url", SMELT_TEST_API_URL)
            await system_setting_factory(
                key="default_cvss_version", value=DEFAULT_VERSION
            )
            ticket = await ticket_factory(status=TicketStatus.NEW.value)
            product = await catalog_product(db_session)
            await publish(db_session, product)
            await add(
                db_session,
                ticket.id,
                "fictional-libexample",
                PackageSmelt.ok(
                    codestream("Fictional:Product:15-SP7:Update", "SLE_15", product.cpe)
                ),
                actor=actor,
            )
        case _:
            raise AssertionError(path)

    events = await ticket_events(db_session, ticket)
    assignment = EventRow("assignment", actor.id, None, assignee.username, None, None)
    assert [e for e in events if e.event_type == "assignment"] == [assignment]
    assert [e for e in events if e.event_type == "status_change"] == [
        PROMOTION,
        *entry,
    ]
    position = events.index(assignment)
    assert events[position + 1] == PROMOTION
