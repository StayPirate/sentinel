"""Resolved Ticket severity as a reusable SQL expression.

Single SQL owner of the canonical Ticket severity cascade of
`docs/features/tickets/tickets.md` (Severity Resolution > Resolution
Rules): a Ticket with a CVE uses the CVE-owned `CVE.severity`; a Ticket
without a CVE uses `Ticket.severity_manual`; otherwise the severity is
SQL `NULL` (unresolved). The `None` label (resolved score exactly 0.0) is
a stored value distinct from SQL `NULL` and passes through unchanged.

Ticket reads resolve severity through this expression exactly once per
Ticket and use the same value for projection, filtering, sorting, and
deadline derivation. The expression is Category B: building it performs
no I/O, write, audit, or lock.

This module imports only Models and Core, so `package_service`,
`ticket_service`, and the Ticket-level deadline expressions can use it
without a dependency cycle.
"""

from __future__ import annotations

from sqlalchemy import ColumnElement, case, select
from sqlalchemy.orm.util import AliasedClass

from app.models.cve import CVE
from app.models.ticket import Ticket


def resolved_severity_expression(
    ticket: type[Ticket] | AliasedClass[Ticket] = Ticket,
) -> ColumnElement[str | None]:
    """Build the resolved-severity expression of `ticket`.

    `ticket` is the `Ticket` entity or an alias of it in the enclosing
    statement. The expression yields the stored PascalCase `Severity`
    value string or `NULL`: when `ticket.cve_id IS NOT NULL`, the
    associated CVE's `severity` (read through a correlated scalar
    subquery, so the enclosing statement needs no CVE join and is never
    multiplied); otherwise `ticket.severity_manual`.

    Usable in `SELECT`, `WHERE`, and `ORDER BY`. Raises no exception.
    """
    cve_severity = (
        select(CVE.severity)
        .where(CVE.id == ticket.cve_id)
        .correlate(ticket)
        .scalar_subquery()
    )
    severity: ColumnElement[str | None] = case(
        (ticket.cve_id.is_not(None), cve_severity),
        else_=ticket.severity_manual,
    )
    return severity
