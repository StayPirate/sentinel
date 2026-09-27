"""Persist one shared deadline-matrix case as real database rows.

Builds, through the model factory fixtures, exactly the persisted evidence
a `tests.support.deadline_matrix.DeadlineCase` describes: one Ticket (with
a CVE carrying the case severity, or CVE-less with `severity_manual`), one
package, one track, its Product occurrences, and its IBS request actions.
Both persistence-backed consumers of the matrix use it: the package-tree
projection test and the SQL/pure parity test. Expectations are never
computed here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Final

import pytest

from app.models.ticket import Ticket
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_track import TicketPackageTrack
from tests.support.deadline_matrix import DeadlineCase

Factory = Callable[..., Awaitable[Any]]

EXCLUDED_AT: Final = datetime(2026, 3, 11, 9, 0, tzinfo=UTC)
RELEASED_AT: Final = datetime(2026, 3, 12, 16, 45, 30, 250000, tzinfo=UTC)
GS_PAST: Final = date(2020, 1, 1)
"""General Support end making a Product `eol` on every matrix evaluation date."""
GS_FUTURE: Final = date(2030, 1, 1)
"""General Support end keeping a Product in General Support on every matrix date."""

PERSISTED_INPUT_FIELDS: Final = frozenset(
    {
        "severity",
        "ticket_status",
        "ticket_has_cve",
        "workflow_type",
        "track_status",
        "delivery_status",
        "package_excluded",
        "track_excluded",
        "products",
        "requests",
        "created_at",
    }
)
"""`DeadlineCase` input fields that `DeadlineWorld.build()` persists.

The only other input, `evaluation_instant`, is a read parameter. A
structural test asserts this set plus `evaluation_instant` covers every
input field, so a new evidence field cannot be silently ignored by the
persistence-backed consumers."""

_FACTORIES: Final = (
    "ticket_factory",
    "cve_factory",
    "product_factory",
    "ticket_package_factory",
    "ticket_package_track_factory",
    "ticket_package_product_factory",
    "ibs_request_factory",
    "ibs_request_action_factory",
    "ibs_request_action_track_factory",
)


@dataclass(frozen=True, slots=True)
class PersistedCase:
    """The rows persisted for one case."""

    ticket: Ticket
    package: TicketPackage
    track: TicketPackageTrack


class DeadlineWorld:
    """Builds matrix cases with the model factory fixtures."""

    def __init__(self, factories: dict[str, Factory]) -> None:
        self._f = factories

    @classmethod
    def from_request(cls, request: pytest.FixtureRequest) -> DeadlineWorld:
        """Resolve the required factory fixtures of the requesting test."""
        return cls({name: request.getfixturevalue(name) for name in _FACTORIES})

    def factory(self, name: str) -> Factory:
        """One of the resolved factory fixtures, for ad hoc rows."""
        return self._f[name]

    async def build(
        self, case: DeadlineCase, *, ticket: Ticket | None = None
    ) -> PersistedCase:
        """Persist `case`; with `ticket`, add its package to that Ticket.

        Reusing a Ticket adds another package and track under it; the
        Ticket-level inputs of `case` must then match the Ticket's.
        """
        if ticket is None:
            ticket = await self._ticket(case)
        package = await self._f["ticket_package_factory"](
            ticket_id=ticket.id,
            deleted_at=EXCLUDED_AT if case.package_excluded else None,
        )
        track = await self._f["ticket_package_track_factory"](
            ticket_package_id=package.id,
            workflow_type=case.workflow_type.value,
            status=case.track_status.value,
            delivery_status=case.delivery_status.value,
            deleted_at=EXCLUDED_AT if case.track_excluded else None,
        )
        for spec in case.products:
            product = await self._f["product_factory"](
                general_support_end_date=GS_PAST if spec.eol else GS_FUTURE
            )
            await self._f["ticket_package_product_factory"](
                ticket_package_track_id=track.id,
                product_id=product.id,
                eligible=spec.eligible,
                released_at=RELEASED_AT if spec.released else None,
                deleted_at=EXCLUDED_AT if spec.excluded else None,
            )
        for evidence in case.requests:
            request = await self._f["ibs_request_factory"](state=evidence.state.value)
            action = await self._f["ibs_request_action_factory"](
                ibs_request_id=request.id, action_type=evidence.action_type.value
            )
            link: dict[str, Any] = {"ibs_request_action_id": action.id}
            if evidence.correlated:
                link["ticket_package_track_id"] = track.id
            # Without a track id the factory links a fresh unrelated track.
            await self._f["ibs_request_action_track_factory"](**link)
        return PersistedCase(ticket=ticket, package=package, track=track)

    async def _ticket(self, case: DeadlineCase) -> Ticket:
        severity = case.severity.value if case.severity is not None else None
        common = {"status": case.ticket_status.value, "created_at": case.created_at}
        if case.ticket_has_cve:
            cve = await self._f["cve_factory"](severity=severity)
            ticket: Ticket = await self._f["ticket_factory"](cve_id=cve.id, **common)
        else:
            ticket = await self._f["ticket_factory"](severity_manual=severity, **common)
        return ticket
