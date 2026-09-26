"""Ticket audit trail service.

See `docs/features/tickets/ticket-audit-log.md` for the full
specification: the Event Type Contract, the Canonical Automatic Comment
Vocabulary, and the `detail` JSONB Schema Contract enforced by
`TicketAuditLog.log_event()`. Shared audit rules (registry, flush
before return, no commit, exception propagation) are defined in
`docs/features/platform/audit-trail-infrastructure.md`.

`log_event()` validates in this fixed order and raises `ValueError` at
the first violation, before any row is added or flushed:

1. `event_type` is a `TicketAuditEventType` member.
2. `detail` shape: `NULL`, or a non-empty mapping (an empty mapping is
   invalid; callers pass `None`).
3. `detail` schema for the event type:
   - `priority_changed`: a user actor requires exactly
     `{"override_action": "set" | "changed" | "cleared"}`; the system
     actor requires `NULL`.
   - Other event types listed in the schema contract require a mapping
     with every required key, no undocumented key, and string values;
     `product_eligibility_changed` additionally enforces its closed
     `reason` set and the conditional `override_action`.
   - Every other event type requires `NULL`.
4. `detail` size: at most 4096 UTF-8 bytes of the deterministic compact
   serialization (sorted keys, `ensure_ascii=False`, `,`/`:` separators,
   no non-finite numbers), measured only after schema validation.
5. `comment`: the one exact canonical value allowed for the event type
   and its context, or `NULL` where that context requires `NULL`. The
   context is derived from the event's own fields:
   - `ticket_created`: a user actor requires `Ticket created manually`;
     the system actor requires `CVE ingested from {label}` with a
     canonical `CVESourceType` label.
   - `package_added`: a user actor requires `NULL`; the system actor
     requires one of the three automatic workflow comments.
   - `assignment`: a user actor requires `NULL`; the system actor
     (system unassignment) requires exactly
     `Unassigned from {old_value}: {reason}` with a closed reason.
   - `status_change`: the system `New -> Ignored` transition (automatic
     only for CVE rejection) requires `CVE rejected`; every other
     transition requires `NULL`.
   - Every other event type requires `NULL`.
6. Insert through `BaseAuditLog.log_event()`, which flushes in the
   caller's transaction, never commits, and propagates database
   exceptions unchanged.

Actor and `old_value`/`new_value` population per event type remain the
responsibility of the owning mutation service; this module validates
only the actor-dependent `detail` and `comment` rules above.

`list_ticket_events()` is the consumer-facing Ticket audit read
(ticket-audit-log.md, Service Contract > `list_ticket_events()`). It
selects the accessible parent Ticket, the filtered events, their total,
the requested page, and the current actor profiles in one SQL statement,
so every part of the result derives from one PostgreSQL snapshot.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Final

from sqlalchemy import Text, cast, false, func, or_, select, true
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.enums import CVESourceType, TicketAuditEventType, TicketStatus
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id, parse_ticket_id
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services.base_audit_log import BaseAuditLog
from app.services.ticket_visibility import TicketCaller, ticket_visibility_condition

# ---------------------------------------------------------------------------
# Canonical Automatic Comment Vocabulary (ticket-audit-log.md)
# ---------------------------------------------------------------------------

MANUAL_TICKET_CREATED_COMMENT: Final = "Ticket created manually"

# Exhaustive `ticket_created` audit label per CVE source, keyed by Enum
# member (cve-service.md, `upsert_cve()` parameter `source`). The comment
# is exactly `CVE ingested from {label}`.
CVE_SOURCE_AUDIT_LABELS: Final[Mapping[CVESourceType, str]] = {
    CVESourceType.NVD: "NVD",
    CVESourceType.MITRE: "MITRE",
    CVESourceType.KERNEL: "Linux Kernel CNA",
    CVESourceType.REDHAT: "Red Hat",
    CVESourceType.GHSA: "GitHub Advisory Database",
    CVESourceType.OSV: "OSV",
    CVESourceType.KEV: "CISA KEV",
    CVESourceType.EPSS: "FIRST.org EPSS",
}

CVE_REJECTED_COMMENT: Final = "CVE rejected"

PACKAGE_ADDED_AUTOMATIC_COMMENTS: Final = frozenset(
    {"CVE package resolution", "Product catalog backfill", "Ticket convergence"}
)

# Closed `{reason}` vocabulary of `Unassigned from {username}: {reason}`.
UNASSIGNMENT_REASONS: Final = frozenset(
    {
        "user deactivated",
        "vulnerability_analyst role removed",
        "vulnerability_analyst role removed by external sync",
        "vulnerability_analyst role removed after role mapping deletion",
        "inactive assignee",
    }
)

_CVE_INGESTED_COMMENTS: Final = frozenset(
    f"CVE ingested from {label}" for label in CVE_SOURCE_AUDIT_LABELS.values()
)

# ---------------------------------------------------------------------------
# detail JSONB Schema Contract (ticket-audit-log.md)
# ---------------------------------------------------------------------------

_MAX_DETAIL_BYTES: Final = 4096

_TRACK_SUBJECT: Final = frozenset({"track", "package"})
_PRODUCT_SUBJECT: Final = _TRACK_SUBJECT | {"product_name", "product_cpe"}
_REFERENCE_SUBJECT: Final = frozenset({"url"})

# Required keys of every event type whose `detail` is a fixed-key mapping
# of string values. `priority_changed` is validated separately because
# its presence depends on the actor. Event types absent from this
# mapping (and not `priority_changed`) MUST have `detail = NULL`.
_REQUIRED_DETAIL_KEYS: Final[Mapping[TicketAuditEventType, frozenset[str]]] = {
    TicketAuditEventType.TRACK_STATUS_CHANGED: _TRACK_SUBJECT,
    TicketAuditEventType.TRACK_EXCLUDED: _TRACK_SUBJECT,
    TicketAuditEventType.TRACK_RESTORED: _TRACK_SUBJECT,
    TicketAuditEventType.PRODUCT_RELEASED: _PRODUCT_SUBJECT | {"advisory_id"},
    TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED: _PRODUCT_SUBJECT | {"reason"},
    TicketAuditEventType.PRODUCT_EXCLUDED: _PRODUCT_SUBJECT,
    TicketAuditEventType.PRODUCT_RESTORED: _PRODUCT_SUBJECT,
    TicketAuditEventType.REFERENCE_TYPE_CHANGED: _REFERENCE_SUBJECT,
    TicketAuditEventType.REFERENCE_TITLE_CHANGED: _REFERENCE_SUBJECT,
    TicketAuditEventType.REFERENCE_DESCRIPTION_CHANGED: _REFERENCE_SUBJECT,
    TicketAuditEventType.DUPLICATE_TARGET_CHANGED: frozenset({"triggered_by_ticket"}),
    TicketAuditEventType.PACKAGE_MAINTAINER_ADDED: frozenset({"package"}),
}

ELIGIBILITY_REASONS: Final = frozenset(
    {"reactive_ltss", "threshold", "reactivation", "cvss", "va_override"}
)
OVERRIDE_ACTIONS: Final = frozenset({"set", "changed", "cleared"})

_VA_OVERRIDE_REASON: Final = "va_override"
_OVERRIDE_ACTION_KEY: Final = "override_action"


def _validate_detail_shape(detail: object) -> None:
    if detail is None:
        return
    if not isinstance(detail, Mapping):
        raise ValueError("detail must be a JSON object mapping or None")
    if not detail:
        raise ValueError("detail must not be empty; use None instead")


def _check_keys(
    event_type: TicketAuditEventType,
    detail: Mapping[str, object],
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    unknown = set(detail) - required - optional
    if unknown:
        raise ValueError(
            f"detail contains undocumented keys for event type '{event_type}': "
            f"{sorted(map(str, unknown))}"
        )
    missing = required - set(detail)
    if missing:
        raise ValueError(
            f"detail is missing required keys for event type '{event_type}': "
            f"{sorted(missing)}"
        )
    for key, value in detail.items():
        if not isinstance(value, str):
            raise ValueError(f"detail.{key} must be a string")


def _validate_override_action(value: object) -> None:
    if value not in OVERRIDE_ACTIONS:
        raise ValueError(
            f"detail.override_action must be one of {sorted(OVERRIDE_ACTIONS)}, "
            f"got {value!r}"
        )


def _validate_priority_changed_detail(
    user_id: uuid.UUID | None, detail: Mapping[str, object] | None
) -> None:
    event_type = TicketAuditEventType.PRIORITY_CHANGED
    if user_id is None:
        if detail is not None:
            raise ValueError(
                "detail must be NULL for an automatic (system) priority_changed event"
            )
        return
    if detail is None:
        raise ValueError(
            "detail with override_action is required for a user-attributed "
            "priority_changed event"
        )
    _check_keys(event_type, detail, frozenset({_OVERRIDE_ACTION_KEY}))
    _validate_override_action(detail[_OVERRIDE_ACTION_KEY])


def _validate_eligibility_conditionals(detail: Mapping[str, object]) -> None:
    reason = detail["reason"]
    if reason not in ELIGIBILITY_REASONS:
        raise ValueError(
            f"detail.reason must be one of {sorted(ELIGIBILITY_REASONS)}, "
            f"got {reason!r}"
        )
    if reason == _VA_OVERRIDE_REASON:
        if _OVERRIDE_ACTION_KEY not in detail:
            raise ValueError(
                "detail.override_action is required when detail.reason is 'va_override'"
            )
        _validate_override_action(detail[_OVERRIDE_ACTION_KEY])
    elif _OVERRIDE_ACTION_KEY in detail:
        raise ValueError(
            "detail.override_action must be absent when detail.reason is not "
            "'va_override'"
        )


def _validate_detail_schema(
    event_type: TicketAuditEventType,
    user_id: uuid.UUID | None,
    detail: Mapping[str, object] | None,
) -> None:
    if event_type is TicketAuditEventType.PRIORITY_CHANGED:
        _validate_priority_changed_detail(user_id, detail)
        return

    required = _REQUIRED_DETAIL_KEYS.get(event_type)
    if required is None:
        if detail is not None:
            raise ValueError(f"detail must be NULL for event type '{event_type}'")
        return
    if detail is None:
        raise ValueError(f"detail is required for event type '{event_type}'")

    if event_type is TicketAuditEventType.PRODUCT_ELIGIBILITY_CHANGED:
        _check_keys(
            event_type, detail, required, optional=frozenset({_OVERRIDE_ACTION_KEY})
        )
        _validate_eligibility_conditionals(detail)
    else:
        _check_keys(event_type, detail, required)


def _serialized_detail_size(detail: Mapping[str, object]) -> int:
    """UTF-8 byte length of the deterministic compact serialization.

    The serialization is used solely for measurement; the persisted
    value is the original mapping.
    """
    serialized = json.dumps(
        dict(detail),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return len(serialized.encode("utf-8"))


def _check_detail_size(detail: Mapping[str, object]) -> None:
    size = _serialized_detail_size(detail)
    if size > _MAX_DETAIL_BYTES:
        raise ValueError(
            f"detail payload of {size} bytes exceeds the {_MAX_DETAIL_BYTES} byte limit"
        )


def _allowed_comments(
    event_type: TicketAuditEventType,
    user_id: uuid.UUID | None,
    old_value: str | None,
    new_value: str | None,
) -> frozenset[str | None]:
    """The exact `comment` values allowed for this event and context."""
    is_system = user_id is None
    if event_type is TicketAuditEventType.TICKET_CREATED:
        return (
            frozenset(_CVE_INGESTED_COMMENTS)
            if is_system
            else frozenset({MANUAL_TICKET_CREATED_COMMENT})
        )
    if event_type is TicketAuditEventType.PACKAGE_ADDED:
        return (
            frozenset(PACKAGE_ADDED_AUTOMATIC_COMMENTS)
            if is_system
            else frozenset({None})
        )
    if event_type is TicketAuditEventType.ASSIGNMENT:
        if not is_system:
            return frozenset({None})
        if old_value is None:
            # System unassignment always names the cleared assignee; with
            # no previous username no canonical comment exists.
            return frozenset()
        return frozenset(
            f"Unassigned from {old_value}: {reason}" for reason in UNASSIGNMENT_REASONS
        )
    if (
        event_type is TicketAuditEventType.STATUS_CHANGE
        and is_system
        and old_value == TicketStatus.NEW.value
        and new_value == TicketStatus.IGNORED.value
    ):
        return frozenset({CVE_REJECTED_COMMENT})
    return frozenset({None})


def _validate_comment(
    event_type: TicketAuditEventType,
    user_id: uuid.UUID | None,
    old_value: str | None,
    new_value: str | None,
    comment: str | None,
) -> None:
    if comment not in _allowed_comments(event_type, user_id, old_value, new_value):
        actor = "system" if user_id is None else "user"
        raise ValueError(
            f"comment {comment!r} is not the canonical value for event type "
            f"'{event_type}' with a {actor} actor"
        )


class TicketAuditLog(BaseAuditLog):
    """Audit trail for Ticket lifecycle and mutation events.

    See `docs/features/tickets/ticket-audit-log.md`. Every Ticket
    mutation creates its events only through `log_event()`.
    """

    name = "ticket"
    description = "Ticket lifecycle and mutation events"
    model_class = TicketAuditEvent

    @classmethod
    async def log_event(  # type: ignore[override]
        cls,
        session: AsyncSession,
        *,
        ticket_id: uuid.UUID,
        event_type: TicketAuditEventType,
        user_id: uuid.UUID | None,
        old_value: str | None = None,
        new_value: str | None = None,
        comment: str | None = None,
        detail: Mapping[str, str] | None = None,
    ) -> None:
        """Create one `TicketAuditEvent` in the caller's transaction.

        Validates `event_type`, the `detail` schema and size, and the
        canonical `comment` in the order documented in the module
        docstring. Every violation raises `ValueError` before any row
        is added or flushed. On success, flushes the pending insert
        before returning and never commits or rolls back; database
        exceptions (for example an unknown `ticket_id` or `user_id`)
        propagate unchanged. Each call creates a new event, so callers
        invoke it only for an effective mutation.
        """
        if not isinstance(event_type, TicketAuditEventType):
            raise ValueError(
                f"event_type must be a TicketAuditEventType member, got {event_type!r}"
            )
        _validate_detail_shape(detail)
        _validate_detail_schema(event_type, user_id, detail)
        if detail is not None:
            _check_detail_size(detail)
        _validate_comment(event_type, user_id, old_value, new_value, comment)

        await super().log_event(
            session,
            ticket_id=ticket_id,
            event_type=event_type.value,
            user_id=user_id,
            old_value=old_value,
            new_value=new_value,
            comment=comment,
            detail=dict(detail) if detail is not None else None,
        )


# ---------------------------------------------------------------------------
# Ticket audit read (ticket-audit-log.md, Service Contract >
# `list_ticket_events()`)
# ---------------------------------------------------------------------------

MAX_PER_PAGE: Final = 100
"""Largest accepted `per_page` (docs/api-spec.md, Pagination)."""

_LIKE_ESCAPE: Final = "\\"


@dataclass(frozen=True, slots=True)
class TicketEventActor:
    """The current profile of a non-null event actor (api-spec.md, User
    References in Responses): resolved from the current `User` row, never
    an event-time snapshot."""

    id: uuid.UUID
    username: str
    full_name: str | None
    active: bool


@dataclass(frozen=True, slots=True)
class TicketEventItem:
    """One Ticket audit event projection.

    `ticket_id` is the parent's public `SNTL-{n}` identifier, never the
    internal Ticket UUID. `actor` is `None` for a system event.
    """

    id: uuid.UUID
    ticket_id: str
    event_type: str
    old_value: str | None
    new_value: str | None
    comment: str | None
    detail: dict[str, Any] | None
    created_at: datetime
    actor: TicketEventActor | None


@dataclass(frozen=True, slots=True)
class TicketEventPage:
    """One page of Ticket audit events and the total of filtered events."""

    items: tuple[TicketEventItem, ...]
    total: int
    page: int
    per_page: int


def _literal_substring_pattern(term: str) -> str:
    """Build an `ILIKE` pattern matching `term` as a literal substring.

    Backslash is escaped first, so the escapes added for `%` and `_`
    are not themselves doubled. Used with `ESCAPE '\\'`.
    """
    escaped = (
        term.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", f"{_LIKE_ESCAPE}%")
        .replace("_", f"{_LIKE_ESCAPE}_")
    )
    return f"%{escaped}%"


async def list_ticket_events(
    db: AsyncSession,
    *,
    ticket_id: str,
    caller: TicketCaller,
    event_types: Collection[TicketAuditEventType] | None = None,
    actor: str | None = None,
    search: str | None = None,
    from_date: date | datetime | None = None,
    to_date: date | datetime | None = None,
    page: int = 1,
    per_page: int = 20,
) -> TicketEventPage:
    """List the audit events of one accessible Ticket.

    Category B read (ticket-audit-log.md, Service Contract >
    `list_ticket_events()`; API > List Ticket Events).

    Q1: `ticket_id` is the public `SNTL-{n}` locator and `caller` the
    request-resolved caller information. `event_types` is `None` when
    the filter was not supplied, or the valid members of a supplied
    filter — an empty collection means every supplied value was invalid.
    `actor` is `system`, a User UUID, or an exact username. `search` is
    the raw text filter. `from_date`/`to_date` are inclusive bounds
    interpreted in UTC. `page` is positive and `per_page` is 1-100.

    Q3: in one SQL statement, and therefore one PostgreSQL snapshot:
    1. select the parent Ticket by `sequence_id` under the canonical
       visibility predicate, before any event filter;
    2. apply the event-type filter with OR semantics; a supplied but
       empty filter matches nothing;
    3. apply `actor` through `TicketAuditLog.filter_by_actor()`; an
       unknown actor matches nothing;
    4. trim `search` once; when non-empty, match it as a literal
       case-insensitive substring (`%`, `_`, and backslash are literal)
       of `comment`, `old_value`, `new_value`, or `detail::text`;
    5. apply the date bounds through `TicketAuditLog.apply_date_filters()`;
       different filters compose with AND;
    6. count the filtered events and select the requested page ordered by
       `created_at DESC, id DESC`;
    7. project each event with the parent's `SNTL-{n}` and the current
       actor profile, or `None` for a system event.
    Creates no event, acquires no lock, and never commits or rolls back.

    Q4: returns the page items, the filtered total, and the echoed
    `page`/`per_page`. A page beyond the last is empty with the correct
    total. The filters never join a one-to-many relation, so the total
    counts each event once.

    Q6: raises `TicketNotFoundError` for a malformed locator (including a
    Ticket UUID), a missing Ticket, or an inaccessible Ticket, never an
    empty page. Raises `ValueError` before any query for `page < 1` or
    `per_page` outside 1-100. Database exceptions propagate unchanged.
    """
    if page < 1:
        raise ValueError("page must be at least 1")
    if not 1 <= per_page <= MAX_PER_PAGE:
        raise ValueError(f"per_page must be between 1 and {MAX_PER_PAGE}")
    sequence_id = parse_ticket_id(ticket_id)
    if sequence_id is None:
        raise TicketNotFoundError()

    parent = (
        select(
            Ticket.id.label("ticket_id"),
            Ticket.sequence_id.label("sequence_id"),
        )
        .where(Ticket.sequence_id == sequence_id, ticket_visibility_condition(caller))
        .cte("parent")
    )

    events = select(
        TicketAuditEvent.id,
        TicketAuditEvent.event_type,
        TicketAuditEvent.old_value,
        TicketAuditEvent.new_value,
        TicketAuditEvent.comment,
        TicketAuditEvent.detail,
        TicketAuditEvent.created_at,
        TicketAuditEvent.user_id,
    ).join(parent, TicketAuditEvent.ticket_id == parent.c.ticket_id)
    if event_types is not None:
        values = [event_type.value for event_type in event_types]
        events = events.where(
            TicketAuditEvent.event_type.in_(values) if values else false()
        )
    events = TicketAuditLog.filter_by_actor(events, actor)
    normalized_search = search.strip() if search is not None else ""
    if normalized_search:
        pattern = _literal_substring_pattern(normalized_search)
        events = events.where(
            or_(
                TicketAuditEvent.comment.ilike(pattern, escape=_LIKE_ESCAPE),
                TicketAuditEvent.old_value.ilike(pattern, escape=_LIKE_ESCAPE),
                TicketAuditEvent.new_value.ilike(pattern, escape=_LIKE_ESCAPE),
                cast(TicketAuditEvent.detail, Text).ilike(pattern, escape=_LIKE_ESCAPE),
            )
        )
    events = TicketAuditLog.apply_date_filters(events, from_date, to_date)
    filtered = events.cte("filtered")

    total = select(func.count().label("total")).select_from(filtered).cte("total")
    page_rows = (
        select(filtered)
        .order_by(filtered.c.created_at.desc(), filtered.c.id.desc())
        .limit(per_page)
        .offset((page - 1) * per_page)
        .cte("page")
    )
    actor_user = aliased(User, name="actor_user")
    statement = (
        select(
            parent.c.sequence_id,
            total.c.total,
            page_rows.c.id.label("event_id"),
            page_rows.c.event_type,
            page_rows.c.old_value,
            page_rows.c.new_value,
            page_rows.c.comment,
            page_rows.c.detail,
            page_rows.c.created_at,
            actor_user.id.label("actor_id"),
            actor_user.username.label("actor_username"),
            actor_user.full_name.label("actor_full_name"),
            actor_user.active.label("actor_active"),
        )
        .select_from(parent)
        .join(total, true())
        .outerjoin(page_rows, true())
        .outerjoin(actor_user, actor_user.id == page_rows.c.user_id)
        .order_by(page_rows.c.created_at.desc(), page_rows.c.id.desc())
    )
    rows = (await db.execute(statement)).all()
    if not rows:
        raise TicketNotFoundError()

    public_ticket_id = format_ticket_id(rows[0].sequence_id)
    items = tuple(
        TicketEventItem(
            id=row.event_id,
            ticket_id=public_ticket_id,
            event_type=row.event_type,
            old_value=row.old_value,
            new_value=row.new_value,
            comment=row.comment,
            detail=row.detail,
            created_at=row.created_at,
            actor=(
                TicketEventActor(
                    id=row.actor_id,
                    username=row.actor_username,
                    full_name=row.actor_full_name,
                    active=row.actor_active,
                )
                if row.actor_id is not None
                else None
            ),
        )
        for row in rows
        if row.event_id is not None
    )
    return TicketEventPage(
        items=items, total=rows[0].total, page=page, per_page=per_page
    )
