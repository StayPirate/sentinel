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
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, TicketAuditEventType, TicketStatus
from app.models.ticket_audit_event import TicketAuditEvent
from app.services.base_audit_log import BaseAuditLog

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
