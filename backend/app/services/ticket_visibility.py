"""Canonical Ticket visibility predicate and request-resolved caller information.

`docs/features/identity/rbac.md` (Scope and Confidential Ticket
Visibility) is the single normative definition of Ticket visibility; this
module is its only implementation. Every consumer-facing service
(`ticket_service`, `package_service`, `ticket_mutations`, and the Ticket
audit read) applies `ticket_visibility_condition()` inside its own
PostgreSQL selection rather than defining another predicate or filtering
in Python (`docs/features/tickets/ticket-service.md`, Caller category and
Ticket accessibility).

The module imports only Models and Core, so every Ticket-domain service
can import it without an import cycle.

`TicketCaller` is the plain service-layer value that carries the
request-resolved caller: anonymous, or an authenticated user ID plus the
effective scope resolved once for the request
(`docs/features/identity/rbac.md`, Optional Principal to Caller
Context). Thin API dependencies build it; services never import API
types. Trusted internal or system workflows are not consumer callers and
never pass a `TicketCaller`; in particular they are never represented as
`ANONYMOUS_CALLER`.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import ColumnElement, and_, exists, false, or_, select, true

from app.core.enums import Scope
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer


@dataclass(frozen=True, slots=True)
class TicketCaller:
    """The consumer caller of a Ticket-derived operation.

    Either anonymous (`user_id` and `scope` both `None`) or authenticated
    (`user_id` and `scope` both set). Use `ANONYMOUS_CALLER` or
    `TicketCaller.authenticated()`; any other combination raises
    `ValueError`.
    """

    user_id: UUID | None = None
    scope: Scope | None = None

    def __post_init__(self) -> None:
        if (self.user_id is None) != (self.scope is None):
            raise ValueError(
                "TicketCaller requires both user_id and scope, or neither."
            )

    @classmethod
    def authenticated(cls, user_id: UUID, scope: Scope) -> TicketCaller:
        """Build the caller for an authenticated user and effective scope."""
        return cls(user_id=user_id, scope=scope)

    @property
    def is_anonymous(self) -> bool:
        """Whether the caller has no authenticated identity."""
        return self.user_id is None


ANONYMOUS_CALLER = TicketCaller()
"""The caller of a request that selected no credential."""


def ticket_visibility_condition(caller: TicketCaller) -> ColumnElement[bool]:
    """Return the canonical visibility predicate as a condition on `Ticket`.

    The result is a SQL boolean expression correlated to the `Ticket`
    entity of the enclosing statement, for use in its `WHERE` clause or
    in a CTE that selects from `Ticket`. Branches (rbac.md, Scope and
    Confidential Ticket Visibility), each independently sufficient:

    1. `Ticket.is_confidential IS FALSE`;
    2. the caller's effective scope is `all`;
    3. an explicit `TicketAccessGrant` for the caller on the Ticket;
    4. a `TicketPackageMaintainer` association of the caller under a
       `TicketPackage` of the Ticket whose `deleted_at IS NULL`.

    Branch 2 is resolved in Python from the request-resolved scope, so a
    scope-`all` caller yields `TRUE` with no subquery. An anonymous
    caller yields exactly branch 1: no grant or maintainer subquery is
    built because there is no caller identity. Track and Product
    exclusion, lifecycle, affectedness, eligibility, delivery, and Ticket
    status are deliberately absent. Pure: builds an expression and
    performs no I/O.
    """
    not_confidential = Ticket.is_confidential.is_(false())
    if caller.user_id is None:
        return not_confidential
    if caller.scope is Scope.ALL:
        return true()

    has_grant = exists(
        select(TicketAccessGrant.ticket_id).where(
            TicketAccessGrant.ticket_id == Ticket.id,
            TicketAccessGrant.user_id == caller.user_id,
        )
    ).correlate(Ticket)
    maintains_included_package = exists(
        select(TicketPackageMaintainer.id)
        .join(
            TicketPackage,
            TicketPackage.id == TicketPackageMaintainer.ticket_package_id,
        )
        .where(
            and_(
                TicketPackage.ticket_id == Ticket.id,
                TicketPackageMaintainer.user_id == caller.user_id,
                TicketPackage.deleted_at.is_(None),
            )
        )
    ).correlate(Ticket)
    return or_(not_confidential, has_grant, maintains_included_package)
