"""The single UUID-or-username matching condition on `User`.

Leaf module of the user domain: it imports only Models and SQLAlchemy and
must never import another service. It exists so that shared infrastructure
imported by `user_service` itself (for example `BaseAuditLog`, reached through
`user_service` -> `identity_audit_log` -> `base_audit_log`) can reuse the
matching rules without a dependency cycle. `user_service` re-exports
`user_identifier_condition()` as the public user-domain boundary described in
`docs/features/identity/user-service.md` (Read Operations,
`resolve_user_identifier()`); consumers outside that cycle import it from
`user_service`.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import ColumnElement

from app.models.user import User


def user_identifier_condition(identifier: str) -> ColumnElement[bool]:
    """Build the UUID-or-username matching condition on `User`.

    Category B query builder: the single owner of the identifier
    matching rules of `docs/api-spec.md` (User Identifier Resolution)
    and `docs/features/identity/user-service.md`
    (`resolve_user_identifier()`), in the composable form a consumer
    embeds in its own statement (for example
    `Ticket.assignee_id.in_(select(User.id).where(...))`) so that rows,
    totals, and resolved users derive from one PostgreSQL observation.

    Q1: `identifier` is the raw value supplied by a caller.

    Q3: if `identifier` parses as a UUID, the condition is
    `User.id = <uuid>`; otherwise it is the exact, case-sensitive
    `User.username = identifier`. At most one User matches. Builds an
    expression only: performs no I/O.

    Q6: infallible. Absence is not an error: the consumer's selection
    simply matches no row.
    """
    try:
        user_id = UUID(identifier)
    except ValueError:
        return User.username == identifier
    return User.id == user_id
