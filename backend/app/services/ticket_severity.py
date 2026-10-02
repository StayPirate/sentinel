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

`severity_rank_expression()` is the single SQL owner of the semantic
severity sort rank (`docs/api-spec.md`, Semantic Sort Fields), shared by
every list that sorts by a stored severity value (the Ticket list and the
CVE list).

This module imports only Models and Core, so `package_service`,
`ticket_service`, `cve_service`, and the Ticket-level deadline
expressions can use it without a dependency cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from sqlalchemy import ColumnElement, case, select
from sqlalchemy.orm.util import AliasedClass

from app.core.enums import Severity
from app.models.cve import CVE
from app.models.ticket import Ticket

# Semantic ranks (docs/api-spec.md, Semantic Sort Fields). SQL `NULL` is
# not ranked, so it sorts last under Nullable Sort Field Ordering.
_SEVERITY_RANK: Final[Mapping[str, int]] = {
    Severity.NONE.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


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


def severity_rank_expression(
    severity: ColumnElement[str | None],
) -> ColumnElement[int | None]:
    """Map a stored PascalCase `Severity` value expression to its rank.

    `None` (resolved score 0.0) ranks 0 up to `Critical` at 4. SQL `NULL`
    (unresolved) and any unrecognized stored value yield `NULL`, which the
    caller orders last in both directions (`docs/api-spec.md`, Nullable
    Sort Field Ordering). Raises no exception.
    """
    rank: ColumnElement[int | None] = case(dict(_SEVERITY_RANK), value=severity)
    return rank
