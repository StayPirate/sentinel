"""Tests for the Ticket audit trail service
(backend/app/services/ticket_audit_log.py).

See docs/features/tickets/ticket-audit-log.md for the contract under
test: the Event Type Contract (`comment`/`detail` columns), the
Canonical Automatic Comment Vocabulary, the `detail` JSONB Schema
Contract with its conditional keys and 4096-byte serialization rule,
and Implementation Guidelines 3, 5, and 6. The flush / no-commit /
exception-propagation guarantees come from
docs/features/platform/audit-trail-infrastructure.md (Atomicity).

It also covers the consumer read `list_ticket_events()`
(ticket-audit-log.md, Service Contract > `list_ticket_events()`;
Testing Requirements 22 and 26) against the Ticket Accessibility matrix
in docs/features/platform/testing-strategy.md, including the
independent-session races.

Per-mutation event sequences, actors, and no-event assertions belong
to the owning mutation services and are not tested here.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import delete, event, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, Role, Scope, TicketAuditEventType
from app.core.exceptions import TicketNotFoundError
from app.core.identifiers import format_ticket_id
from app.core.permissions import get_effective_scope
from app.models.ticket import Ticket
from app.models.ticket_access_grant import TicketAccessGrant
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.ticket_package import TicketPackage
from app.models.ticket_package_maintainer import TicketPackageMaintainer
from app.models.user import User
from app.models.user_role import UserRole
from app.services import base_audit_log, user_service
from app.services.ticket_audit_log import (
    CVE_SOURCE_AUDIT_LABELS,
    TicketAuditLog,
    TicketEventActor,
    _literal_substring_pattern,
    _serialized_detail_size,
    list_ticket_events,
)
from app.services.ticket_service import resolve_ticket_locator
from app.services.ticket_visibility import ANONYMOUS_CALLER, TicketCaller
from tests.support.database import rollback_test_scope

# No module-level `pytestmark`: pytest marks accumulate rather than
# override, so every class below carries its own explicit marker
# (mirrors tests/test_services/test_identity_audit_log.py).

_USERNAME = "fictional.analyst"
_TRACK: dict[str, str] = {
    "track": "SUSE:SLE-15-SP6:Update",
    "package": "fictional-package",
}
_PRODUCT: dict[str, str] = {
    **_TRACK,
    "product_name": "Fictional Linux 15 SP6",
    "product_cpe": "cpe:/o:fictional:linux:15:sp6",
}
_REFERENCE_URL = "https://bugzilla.example.com/show_bug.cgi?id=12345"

_ELIGIBILITY_REASONS = ("reactive_ltss", "threshold", "reactivation", "cvss")
_OVERRIDE_ACTIONS = ("set", "changed", "cleared")
_AUTOMATIC_PACKAGE_COMMENTS = (
    "CVE package resolution",
    "Product catalog backfill",
    "Ticket convergence",
)
_UNASSIGNMENT_REASONS = (
    "user deactivated",
    "vulnerability_analyst role removed",
    "vulnerability_analyst role removed by external sync",
    "vulnerability_analyst role removed after role mapping deletion",
    "inactive assignee",
)
_EXPECTED_SOURCE_LABELS = {
    CVESourceType.NVD: "NVD",
    CVESourceType.MITRE: "MITRE",
    CVESourceType.KERNEL: "Linux Kernel CNA",
    CVESourceType.REDHAT: "Red Hat",
    CVESourceType.GHSA: "GitHub Advisory Database",
    CVESourceType.OSV: "OSV",
    CVESourceType.KEV: "CISA KEV",
    CVESourceType.EPSS: "FIRST.org EPSS",
}

# Every exact non-NULL comment of the canonical vocabulary, used to prove
# that NULL-only event types reject each of them.
_ALL_CANONICAL_COMMENTS = (
    "Ticket created manually",
    *(f"CVE ingested from {label}" for label in _EXPECTED_SOURCE_LABELS.values()),
    *_AUTOMATIC_PACKAGE_COMMENTS,
    "CVE rejected",
    *(f"Unassigned from {_USERNAME}: {reason}" for reason in _UNASSIGNMENT_REASONS),
)


@dataclass(frozen=True)
class _Case:
    """One `log_event()` payload; `system=True` means `user_id = None`."""

    event_type: TicketAuditEventType
    system: bool = False
    old_value: str | None = None
    new_value: str | None = None
    comment: str | None = None
    detail: dict[str, str] | None = None

    def kwargs(self, ticket_id: uuid.UUID, user_id: uuid.UUID) -> dict[str, Any]:
        return {
            "ticket_id": ticket_id,
            "event_type": self.event_type,
            "user_id": None if self.system else user_id,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "comment": self.comment,
            "detail": self.detail,
        }


_T = TicketAuditEventType

# One canonical payload per event type, following the Event Type
# Contract. Additional context variants are tested separately.
_CANONICAL: dict[TicketAuditEventType, _Case] = {
    _T.STATUS_CHANGE: _Case(_T.STATUS_CHANGE, old_value="New", new_value="Analysis"),
    _T.ASSIGNMENT: _Case(_T.ASSIGNMENT, new_value=_USERNAME),
    _T.DUPLICATE_SET: _Case(_T.DUPLICATE_SET, new_value="SNTL-41"),
    _T.DUPLICATE_REMOVED: _Case(_T.DUPLICATE_REMOVED, old_value="SNTL-41"),
    _T.DUPLICATE_TARGET_CHANGED: _Case(
        _T.DUPLICATE_TARGET_CHANGED,
        system=True,
        old_value="SNTL-41",
        new_value="SNTL-43",
        detail={"triggered_by_ticket": "SNTL-44"},
    ),
    _T.PACKAGE_ADDED: _Case(_T.PACKAGE_ADDED, new_value="fictional-package"),
    _T.PACKAGE_MAINTAINER_ADDED: _Case(
        _T.PACKAGE_MAINTAINER_ADDED,
        system=True,
        new_value="fictional.maintainer",
        detail={"package": "fictional-package"},
    ),
    _T.PACKAGE_EXCLUDED: _Case(_T.PACKAGE_EXCLUDED, old_value="fictional-package"),
    _T.PACKAGE_RESTORED: _Case(_T.PACKAGE_RESTORED, new_value="fictional-package"),
    _T.TRACK_STATUS_CHANGED: _Case(
        _T.TRACK_STATUS_CHANGED,
        old_value="AFFECTED",
        new_value="NOT_AFFECTED",
        detail=dict(_TRACK),
    ),
    _T.TRACK_EXCLUDED: _Case(
        _T.TRACK_EXCLUDED, old_value=_TRACK["track"], detail=dict(_TRACK)
    ),
    _T.TRACK_RESTORED: _Case(
        _T.TRACK_RESTORED, new_value=_TRACK["track"], detail=dict(_TRACK)
    ),
    _T.PRODUCT_RELEASED: _Case(
        _T.PRODUCT_RELEASED,
        system=True,
        new_value="2026-09-01T10:00:00Z",
        detail={**_PRODUCT, "advisory_id": "SUSE-SU-2026:1234-1"},
    ),
    _T.PRODUCT_EXCLUDED: _Case(
        _T.PRODUCT_EXCLUDED,
        old_value=_PRODUCT["product_name"],
        detail=dict(_PRODUCT),
    ),
    _T.PRODUCT_RESTORED: _Case(
        _T.PRODUCT_RESTORED,
        new_value=_PRODUCT["product_name"],
        detail=dict(_PRODUCT),
    ),
    _T.TICKET_CREATED: _Case(_T.TICKET_CREATED, comment="Ticket created manually"),
    _T.CVE_ASSOCIATED: _Case(_T.CVE_ASSOCIATED, new_value="CVE-2026-0001"),
    _T.SEVERITY_CHANGED: _Case(_T.SEVERITY_CHANGED, system=True, new_value="High"),
    _T.PRIORITY_CHANGED: _Case(_T.PRIORITY_CHANGED, system=True, new_value="P2"),
    _T.CVSS_ASSESSMENT_CHANGED: _Case(
        _T.CVSS_ASSESSMENT_CHANGED,
        new_value="SUSE v3.1 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
    ),
    _T.PRODUCT_ELIGIBILITY_CHANGED: _Case(
        _T.PRODUCT_ELIGIBILITY_CHANGED,
        system=True,
        old_value="false",
        new_value="true",
        detail={**_PRODUCT, "reason": "threshold"},
    ),
    _T.CONFIDENTIALITY_CHANGED: _Case(
        _T.CONFIDENTIALITY_CHANGED, old_value="false", new_value="true"
    ),
    _T.COORDINATED_RELEASE_CHANGED: _Case(
        _T.COORDINATED_RELEASE_CHANGED, new_value="2026-10-06T14:00:00Z"
    ),
    _T.ACCESS_GRANT_ADDED: _Case(_T.ACCESS_GRANT_ADDED, new_value=_USERNAME),
    _T.ACCESS_GRANT_REMOVED: _Case(_T.ACCESS_GRANT_REMOVED, old_value=_USERNAME),
    _T.REFERENCE_ADDED: _Case(_T.REFERENCE_ADDED, new_value=_REFERENCE_URL),
    _T.REFERENCE_DELETED: _Case(_T.REFERENCE_DELETED, old_value=_REFERENCE_URL),
    _T.REFERENCE_URL_CHANGED: _Case(
        _T.REFERENCE_URL_CHANGED,
        old_value=_REFERENCE_URL,
        new_value="https://bugzilla.example.com/show_bug.cgi?id=67890",
    ),
    _T.REFERENCE_TYPE_CHANGED: _Case(
        _T.REFERENCE_TYPE_CHANGED,
        old_value="advisory",
        new_value="patch",
        detail={"url": _REFERENCE_URL},
    ),
    _T.REFERENCE_TITLE_CHANGED: _Case(
        _T.REFERENCE_TITLE_CHANGED,
        new_value="Fictional advisory title",
        detail={"url": _REFERENCE_URL},
    ),
    _T.REFERENCE_DESCRIPTION_CHANGED: _Case(
        _T.REFERENCE_DESCRIPTION_CHANGED,
        old_value="Old fictional description",
        detail={"url": _REFERENCE_URL},
    ),
}

# Event types whose canonical payload carries a fixed-key `detail`
# mapping (all but `priority_changed`, which depends on the actor).
_DETAIL_TYPES = [t for t, case in _CANONICAL.items() if case.detail is not None]
# Event types whose `detail` MUST always be NULL.
_NULL_DETAIL_TYPES = [
    t
    for t, case in _CANONICAL.items()
    if case.detail is None and t != _T.PRIORITY_CHANGED
]
# Event types whose `comment` MUST be NULL in every context.
_NULL_COMMENT_TYPES = [
    t
    for t in TicketAuditEventType
    if t not in {_T.TICKET_CREATED, _T.PACKAGE_ADDED, _T.ASSIGNMENT, _T.STATUS_CHANGE}
]

_PRIORITY_OVERRIDE = _Case(
    _T.PRIORITY_CHANGED,
    old_value="P3",
    new_value="P1",
    detail={"override_action": "set"},
)


def _ids(value: object) -> str:
    return str(value)


def _mock_session() -> MagicMock:
    session = MagicMock(spec=AsyncSession)
    session.flush = AsyncMock()
    return session


async def _accept(case: _Case) -> MagicMock:
    """Call `log_event()` on a mock session and assert one flushed insert."""
    session = _mock_session()
    await TicketAuditLog.log_event(session, **case.kwargs(uuid.uuid4(), uuid.uuid4()))
    session.add.assert_called_once()
    session.flush.assert_awaited_once()
    return session


async def _reject(case: _Case, match: str) -> None:
    """Assert `ValueError` before any row is added or flushed."""
    session = _mock_session()
    with pytest.raises(ValueError, match=match):
        await TicketAuditLog.log_event(
            session, **case.kwargs(uuid.uuid4(), uuid.uuid4())
        )
    session.add.assert_not_called()
    session.flush.assert_not_called()
    session.commit.assert_not_called()


def _spec_size(detail: dict[str, str]) -> int:
    """Independent re-statement of the specified measurement rule."""
    return len(
        json.dumps(
            detail, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )


def _padded(case: _Case, key: str, target_bytes: int, unit: str = "a") -> _Case:
    """Return `case` with `detail[key]` padded to `target_bytes` in total.

    `unit` must be a single code point; the remainder that is not a
    multiple of its UTF-8 width is filled with ASCII `a`.
    """
    assert case.detail is not None
    base = _spec_size({**case.detail, key: ""})
    room = target_bytes - base
    width = len(unit.encode("utf-8"))
    value = unit * (room // width) + "a" * (room % width)
    detail = {**case.detail, key: value}
    assert _spec_size(detail) == target_bytes
    return replace(case, detail=detail)


# ---------------------------------------------------------------------------
# Registration and vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistration:
    def test_registered_under_ticket_name(self) -> None:
        assert base_audit_log.AUDIT_LOG_REGISTRY["ticket"] is TicketAuditLog

    def test_binds_to_ticket_audit_event_model(self) -> None:
        assert TicketAuditLog.model_class is TicketAuditEvent

    def test_description(self) -> None:
        assert TicketAuditLog.description == "Ticket lifecycle and mutation events"

    def test_cve_source_audit_labels_are_exact_and_exhaustive(self) -> None:
        assert dict(CVE_SOURCE_AUDIT_LABELS) == _EXPECTED_SOURCE_LABELS
        assert set(CVE_SOURCE_AUDIT_LABELS) == set(CVESourceType)

    def test_canonical_cases_cover_all_31_event_types(self) -> None:
        assert set(_CANONICAL) == set(TicketAuditEventType)
        assert len(_CANONICAL) == 31


# ---------------------------------------------------------------------------
# Accepted canonical payloads (persisted)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCanonicalPayloadsPersisted:
    @pytest.mark.parametrize("event_type", list(_CANONICAL), ids=_ids)
    async def test_canonical_payload_persists_one_event_with_exact_fields(
        self,
        db_session: AsyncSession,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
        event_type: TicketAuditEventType,
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()
        case = _CANONICAL[event_type]

        await TicketAuditLog.log_event(db_session, **case.kwargs(ticket.id, actor.id))

        rows = (
            (
                await db_session.execute(
                    select(TicketAuditEvent).where(
                        TicketAuditEvent.ticket_id == ticket.id
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.event_type == event_type.value
        assert row.user_id == (None if case.system else actor.id)
        assert row.old_value == case.old_value
        assert row.new_value == case.new_value
        assert row.comment == case.comment
        assert row.detail == case.detail
        assert row.created_at is not None

    async def test_user_priority_override_persists_actor_and_override_action(
        self,
        db_session: AsyncSession,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()

        await TicketAuditLog.log_event(
            db_session, **_PRIORITY_OVERRIDE.kwargs(ticket.id, actor.id)
        )

        row = (
            await db_session.execute(
                select(TicketAuditEvent).where(TicketAuditEvent.ticket_id == ticket.id)
            )
        ).scalar_one()
        assert row.event_type == "priority_changed"
        assert row.user_id == actor.id
        assert (row.old_value, row.new_value) == ("P3", "P1")
        assert row.comment is None
        assert row.detail == {"override_action": "set"}

    async def test_read_only_mapping_detail_is_persisted_as_plain_object(
        self,
        db_session: AsyncSession,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()

        await TicketAuditLog.log_event(
            db_session,
            ticket_id=ticket.id,
            event_type=_T.TRACK_EXCLUDED,
            user_id=actor.id,
            old_value=_TRACK["track"],
            detail=MappingProxyType(dict(_TRACK)),
        )

        row = (
            await db_session.execute(
                select(TicketAuditEvent).where(TicketAuditEvent.ticket_id == ticket.id)
            )
        ).scalar_one()
        await db_session.refresh(row)
        assert row.detail == _TRACK


# ---------------------------------------------------------------------------
# event_type
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestEventTypeValidation:
    async def test_raw_string_event_type_rejected(self) -> None:
        session = _mock_session()
        with pytest.raises(ValueError, match="TicketAuditEventType member"):
            await TicketAuditLog.log_event(
                session,
                ticket_id=uuid.uuid4(),
                event_type="status_change",  # type: ignore[arg-type]
                user_id=uuid.uuid4(),
                old_value="New",
                new_value="Analysis",
            )
        session.add.assert_not_called()
        session.flush.assert_not_called()


# ---------------------------------------------------------------------------
# detail schema
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDetailSchema:
    @pytest.mark.parametrize(
        ("event_type", "key"),
        [(t, key) for t in _DETAIL_TYPES for key in sorted(_CANONICAL[t].detail or {})],
        ids=_ids,
    )
    async def test_missing_required_key_rejected(
        self, event_type: TicketAuditEventType, key: str
    ) -> None:
        case = _CANONICAL[event_type]
        assert case.detail is not None
        detail = {k: v for k, v in case.detail.items() if k != key}
        # Removing the only key of a single-key schema leaves an empty
        # mapping, which the shape rule rejects first.
        match = "missing required keys" if detail else "use None instead"
        await _reject(replace(case, detail=detail), match)

    @pytest.mark.parametrize("event_type", _DETAIL_TYPES, ids=_ids)
    async def test_undocumented_key_rejected(
        self, event_type: TicketAuditEventType
    ) -> None:
        case = _CANONICAL[event_type]
        assert case.detail is not None
        detail = {**case.detail, "ticket_package_product_id": "fictional"}
        await _reject(replace(case, detail=detail), "undocumented keys")

    @pytest.mark.parametrize("event_type", _DETAIL_TYPES, ids=_ids)
    async def test_null_detail_rejected_where_required(
        self, event_type: TicketAuditEventType
    ) -> None:
        await _reject(
            replace(_CANONICAL[event_type], detail=None), "detail is required"
        )

    @pytest.mark.parametrize("event_type", _DETAIL_TYPES, ids=_ids)
    async def test_non_string_value_rejected(
        self, event_type: TicketAuditEventType
    ) -> None:
        case = _CANONICAL[event_type]
        assert case.detail is not None
        key = sorted(case.detail)[0]
        detail: dict[str, Any] = {**case.detail, key: 42}
        await _reject(replace(case, detail=detail), f"detail.{key} must be a string")

    @pytest.mark.parametrize("event_type", _NULL_DETAIL_TYPES, ids=_ids)
    async def test_non_null_detail_rejected_where_null_required(
        self, event_type: TicketAuditEventType
    ) -> None:
        case = replace(_CANONICAL[event_type], detail={"package": "fictional-package"})
        await _reject(case, "detail must be NULL")

    @pytest.mark.parametrize(
        "event_type", [_T.TRACK_EXCLUDED, _T.STATUS_CHANGE], ids=_ids
    )
    async def test_empty_mapping_rejected(
        self, event_type: TicketAuditEventType
    ) -> None:
        await _reject(replace(_CANONICAL[event_type], detail={}), "use None instead")

    @pytest.mark.parametrize("value", [["track", "package"], "track"], ids=_ids)
    async def test_non_mapping_detail_rejected(self, value: object) -> None:
        case = replace(_CANONICAL[_T.TRACK_EXCLUDED], detail=value)  # type: ignore[arg-type]
        await _reject(case, "JSON object mapping")

    async def test_non_string_key_rejected_as_undocumented(self) -> None:
        detail: dict[Any, str] = {**_TRACK, 1: "x"}
        case = replace(_CANONICAL[_T.TRACK_EXCLUDED], detail=detail)
        await _reject(case, "undocumented keys")


@pytest.mark.unit
class TestProductEligibilityConditionals:
    """`reason` is closed; `override_action` is required exactly when
    `reason = va_override` and then limited to set/changed/cleared."""

    _BASE = _CANONICAL[_T.PRODUCT_ELIGIBILITY_CHANGED]

    def _with(self, **detail: str) -> _Case:
        return replace(self._BASE, detail={**_PRODUCT, **detail})

    @pytest.mark.parametrize("reason", _ELIGIBILITY_REASONS)
    async def test_automatic_reason_without_override_action_accepted(
        self, reason: str
    ) -> None:
        await _accept(self._with(reason=reason))

    @pytest.mark.parametrize(
        ("reason", "action"),
        [(r, a) for r in _ELIGIBILITY_REASONS for a in _OVERRIDE_ACTIONS],
        ids=_ids,
    )
    async def test_automatic_reason_with_override_action_rejected(
        self, reason: str, action: str
    ) -> None:
        await _reject(
            self._with(reason=reason, override_action=action), "must be absent"
        )

    @pytest.mark.parametrize("action", _OVERRIDE_ACTIONS)
    async def test_va_override_with_valid_override_action_accepted(
        self, action: str
    ) -> None:
        case = replace(
            self._with(reason="va_override", override_action=action),
            system=False,
            old_value="true",
            new_value="true",
        )
        session = await _accept(case)
        instance = session.add.call_args.args[0]
        assert instance.detail["override_action"] == action

    async def test_va_override_without_override_action_rejected(self) -> None:
        await _reject(self._with(reason="va_override"), "override_action is required")

    @pytest.mark.parametrize("action", ["SET", "removed", ""])
    async def test_va_override_with_invalid_override_action_rejected(
        self, action: str
    ) -> None:
        await _reject(
            self._with(reason="va_override", override_action=action),
            "override_action must be one of",
        )

    @pytest.mark.parametrize("reason", ["manual", "THRESHOLD", "lifecycle", ""])
    async def test_reason_outside_closed_set_rejected(self, reason: str) -> None:
        await _reject(self._with(reason=reason), "detail.reason must be one of")

    async def test_non_string_override_action_rejected(self) -> None:
        detail: dict[str, Any] = {
            **_PRODUCT,
            "reason": "va_override",
            "override_action": True,
        }
        await _reject(replace(self._BASE, detail=detail), "must be a string")


@pytest.mark.unit
class TestPriorityChangedActorRule:
    """User actor requires `{"override_action": ...}`; system requires NULL."""

    async def test_system_event_with_null_detail_accepted(self) -> None:
        await _accept(_CANONICAL[_T.PRIORITY_CHANGED])

    @pytest.mark.parametrize("action", _OVERRIDE_ACTIONS)
    async def test_system_event_with_override_detail_rejected(
        self, action: str
    ) -> None:
        case = replace(
            _CANONICAL[_T.PRIORITY_CHANGED], detail={"override_action": action}
        )
        await _reject(case, "must be NULL for an automatic")

    @pytest.mark.parametrize("action", _OVERRIDE_ACTIONS)
    async def test_user_event_with_each_override_action_accepted(
        self, action: str
    ) -> None:
        await _accept(replace(_PRIORITY_OVERRIDE, detail={"override_action": action}))

    async def test_user_event_with_equal_old_and_new_values_accepted(self) -> None:
        await _accept(
            replace(
                _PRIORITY_OVERRIDE,
                old_value="P2",
                new_value="P2",
                detail={"override_action": "cleared"},
            )
        )

    async def test_user_event_with_null_detail_rejected(self) -> None:
        await _reject(replace(_PRIORITY_OVERRIDE, detail=None), "is required")

    async def test_user_event_with_empty_detail_rejected(self) -> None:
        await _reject(replace(_PRIORITY_OVERRIDE, detail={}), "use None instead")

    @pytest.mark.parametrize("action", ["SET", "removed", ""])
    async def test_user_event_with_invalid_override_action_rejected(
        self, action: str
    ) -> None:
        await _reject(
            replace(_PRIORITY_OVERRIDE, detail={"override_action": action}),
            "override_action must be one of",
        )

    async def test_user_event_with_extra_key_rejected(self) -> None:
        detail = {"override_action": "set", "reason": "va_override"}
        await _reject(replace(_PRIORITY_OVERRIDE, detail=detail), "undocumented keys")

    async def test_user_event_with_wrong_key_rejected(self) -> None:
        detail = {"action": "set"}
        await _reject(replace(_PRIORITY_OVERRIDE, detail=detail), "undocumented keys")


# ---------------------------------------------------------------------------
# detail size
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDetailSize:
    _MAINTAINER = _CANONICAL[_T.PACKAGE_MAINTAINER_ADDED]
    _RELEASED = _CANONICAL[_T.PRODUCT_RELEASED]

    async def test_exactly_4096_bytes_accepted(self) -> None:
        await _accept(_padded(self._MAINTAINER, "package", 4096))

    async def test_4097_bytes_rejected(self) -> None:
        await _reject(
            _padded(self._MAINTAINER, "package", 4097), "4097 bytes exceeds the 4096"
        )

    @pytest.mark.parametrize("unit", ["é", "漢", "🔒"])
    async def test_multibyte_payload_measured_in_utf8_bytes(self, unit: str) -> None:
        # Accepting 4096 bytes of multi-byte content also proves
        # `ensure_ascii=False`: `\\uXXXX` escapes would exceed the limit.
        at_limit = _padded(self._MAINTAINER, "package", 4096, unit)
        assert at_limit.detail is not None
        assert len(at_limit.detail["package"]) < 4096
        await _accept(at_limit)
        await _reject(
            _padded(self._MAINTAINER, "package", 4097, unit), "exceeds the 4096"
        )

    async def test_measurement_uses_compact_separators(self) -> None:
        case = _padded(self._RELEASED, "advisory_id", 4096)
        assert case.detail is not None
        assert len(json.dumps(case.detail, ensure_ascii=False).encode()) > 4096
        await _accept(case)

    @pytest.mark.parametrize("target", [4096, 4097])
    async def test_measurement_is_independent_of_key_order(self, target: int) -> None:
        case = _padded(self._RELEASED, "advisory_id", target)
        assert case.detail is not None
        reversed_detail = dict(reversed(list(case.detail.items())))
        assert list(reversed_detail) != list(case.detail)
        assert _serialized_detail_size(case.detail) == target
        assert _serialized_detail_size(reversed_detail) == target
        for detail in (case.detail, reversed_detail):
            candidate = replace(case, detail=detail)
            if target == 4096:
                await _accept(candidate)
            else:
                await _reject(candidate, "exceeds the 4096")

    async def test_schema_is_validated_before_size(self) -> None:
        oversized = _padded(self._MAINTAINER, "package", 5000)
        assert oversized.detail is not None
        detail = {**oversized.detail, "unexpected": "x"}
        await _reject(replace(oversized, detail=detail), "undocumented keys")


# ---------------------------------------------------------------------------
# comment
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCommentValidation:
    @pytest.mark.parametrize("event_type", list(_CANONICAL), ids=_ids)
    async def test_free_text_comment_rejected(
        self, event_type: TicketAuditEventType
    ) -> None:
        case = replace(_CANONICAL[event_type], comment="Fictional analyst note")
        await _reject(case, "is not the canonical value")

    @pytest.mark.parametrize("event_type", _NULL_COMMENT_TYPES, ids=_ids)
    async def test_null_only_event_type_rejects_every_canonical_comment(
        self, event_type: TicketAuditEventType
    ) -> None:
        for comment in _ALL_CANONICAL_COMMENTS:
            await _reject(
                replace(_CANONICAL[event_type], comment=comment),
                "is not the canonical value",
            )

    async def test_detail_error_takes_precedence_over_comment_error(self) -> None:
        case = replace(
            _CANONICAL[_T.TRACK_EXCLUDED], detail=None, comment="Fictional note"
        )
        await _reject(case, "detail is required")


@pytest.mark.unit
class TestTicketCreatedComment:
    _BASE = _CANONICAL[_T.TICKET_CREATED]

    async def test_manual_creation_comment_accepted(self) -> None:
        await _accept(self._BASE)

    @pytest.mark.parametrize(
        "comment", [None, "CVE ingested from NVD", "ticket created manually"]
    )
    async def test_manual_creation_other_comment_rejected(
        self, comment: str | None
    ) -> None:
        await _reject(replace(self._BASE, comment=comment), "is not the canonical")

    @pytest.mark.parametrize("label", list(_EXPECTED_SOURCE_LABELS.values()))
    async def test_ingestion_comment_for_each_canonical_label_accepted(
        self, label: str
    ) -> None:
        await _accept(
            replace(self._BASE, system=True, comment=f"CVE ingested from {label}")
        )

    @pytest.mark.parametrize(
        "comment",
        [
            None,
            "Ticket created manually",
            "CVE ingested from nvd",
            "CVE ingested from Fictional Source",
            "CVE ingested from NVD ",
        ],
    )
    async def test_ingestion_other_comment_rejected(self, comment: str | None) -> None:
        await _reject(
            replace(self._BASE, system=True, comment=comment), "is not the canonical"
        )


@pytest.mark.unit
class TestPackageAddedComment:
    _BASE = _CANONICAL[_T.PACKAGE_ADDED]

    async def test_user_facing_addition_with_null_comment_accepted(self) -> None:
        await _accept(self._BASE)

    @pytest.mark.parametrize("comment", _AUTOMATIC_PACKAGE_COMMENTS)
    async def test_user_facing_addition_with_automatic_comment_rejected(
        self, comment: str
    ) -> None:
        await _reject(replace(self._BASE, comment=comment), "is not the canonical")

    @pytest.mark.parametrize("comment", _AUTOMATIC_PACKAGE_COMMENTS)
    async def test_automatic_addition_with_each_workflow_comment_accepted(
        self, comment: str
    ) -> None:
        await _accept(replace(self._BASE, system=True, comment=comment))

    @pytest.mark.parametrize(
        "comment", [None, "cve package resolution", "Package resolution"]
    )
    async def test_automatic_addition_with_other_comment_rejected(
        self, comment: str | None
    ) -> None:
        await _reject(
            replace(self._BASE, system=True, comment=comment), "is not the canonical"
        )


@pytest.mark.unit
class TestAssignmentComment:
    _BASE = _CANONICAL[_T.ASSIGNMENT]
    _UNASSIGN = _Case(_T.ASSIGNMENT, system=True, old_value=_USERNAME)

    async def test_user_assignment_with_null_comment_accepted(self) -> None:
        await _accept(self._BASE)

    async def test_user_assignment_with_unassignment_comment_rejected(self) -> None:
        case = replace(
            self._BASE,
            old_value=_USERNAME,
            comment=f"Unassigned from {_USERNAME}: user deactivated",
        )
        await _reject(case, "is not the canonical")

    @pytest.mark.parametrize("reason", _UNASSIGNMENT_REASONS)
    async def test_system_unassignment_with_each_closed_reason_accepted(
        self, reason: str
    ) -> None:
        await _accept(
            replace(self._UNASSIGN, comment=f"Unassigned from {_USERNAME}: {reason}")
        )

    @pytest.mark.parametrize(
        "comment",
        [
            None,
            "Unassigned from other.analyst: user deactivated",
            f"Unassigned from {_USERNAME}: role changed",
            f"Unassigned from {_USERNAME}: user deactivated.",
            f"unassigned from {_USERNAME}: user deactivated",
        ],
    )
    async def test_system_unassignment_with_other_comment_rejected(
        self, comment: str | None
    ) -> None:
        await _reject(replace(self._UNASSIGN, comment=comment), "is not the canonical")

    @pytest.mark.parametrize(
        "comment", [None, "Unassigned from None: user deactivated"]
    )
    async def test_system_assignment_without_previous_username_rejected(
        self, comment: str | None
    ) -> None:
        case = replace(self._UNASSIGN, old_value=None, comment=comment)
        await _reject(case, "is not the canonical")


@pytest.mark.unit
class TestStatusChangeComment:
    _REJECTION = _Case(
        _T.STATUS_CHANGE,
        system=True,
        old_value="New",
        new_value="Ignored",
        comment="CVE rejected",
    )

    async def test_system_new_to_ignored_with_cve_rejected_accepted(self) -> None:
        await _accept(self._REJECTION)

    async def test_system_new_to_ignored_with_null_comment_rejected(self) -> None:
        await _reject(replace(self._REJECTION, comment=None), "is not the canonical")

    async def test_user_new_to_ignored_with_null_comment_accepted(self) -> None:
        await _accept(replace(self._REJECTION, system=False, comment=None))

    async def test_user_new_to_ignored_with_cve_rejected_rejected(self) -> None:
        await _reject(replace(self._REJECTION, system=False), "is not the canonical")

    @pytest.mark.parametrize(
        ("old_value", "new_value"),
        [("Analysis", "Ignored"), ("New", "Analysis"), ("Ignored", "New")],
    )
    async def test_cve_rejected_outside_system_new_to_ignored_rejected(
        self, old_value: str, new_value: str
    ) -> None:
        case = replace(self._REJECTION, old_value=old_value, new_value=new_value)
        await _reject(case, "is not the canonical")

    async def test_system_gate_transition_with_null_comment_accepted(self) -> None:
        await _accept(
            replace(
                self._REJECTION,
                old_value="Analysis",
                new_value="Analyzed",
                comment=None,
            )
        )


# ---------------------------------------------------------------------------
# Transaction contract
# ---------------------------------------------------------------------------


async def _event_count(session: AsyncSession, ticket_id: uuid.UUID) -> int:
    return (
        await session.execute(
            select(func.count())
            .select_from(TicketAuditEvent)
            .where(TicketAuditEvent.ticket_id == ticket_id)
        )
    ).scalar_one()


@pytest.mark.integration
class TestTransactionContract:
    async def test_accepted_event_is_flushed_once_and_not_committed(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "flush", flush_spy)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await TicketAuditLog.log_event(
            db_session, **_CANONICAL[_T.TICKET_CREATED].kwargs(ticket.id, actor.id)
        )

        flush_spy.assert_awaited_once()
        commit_spy.assert_not_called()
        assert await _event_count(db_session, ticket.id) == 1

    async def test_caller_rollback_removes_the_flushed_event(
        self,
        db_session: AsyncSession,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        ticket_id = (await ticket_factory()).id
        actor_id = (await user_factory()).id

        async with rollback_test_scope(db_session):
            await TicketAuditLog.log_event(
                db_session,
                **_CANONICAL[_T.CONFIDENTIALITY_CHANGED].kwargs(ticket_id, actor_id),
            )
            assert await _event_count(db_session, ticket_id) == 1

        assert await _event_count(db_session, ticket_id) == 0
        assert await db_session.get(Ticket, ticket_id) is not None

    @pytest.mark.parametrize(
        ("case", "match"),
        [
            (replace(_CANONICAL[_T.TRACK_EXCLUDED], detail=None), "detail is required"),
            (
                replace(_CANONICAL[_T.STATUS_CHANGE], comment="Fictional note"),
                "is not the canonical value",
            ),
            (
                _padded(_CANONICAL[_T.PACKAGE_MAINTAINER_ADDED], "package", 4097),
                "exceeds the 4096",
            ),
        ],
        ids=["detail", "comment", "size"],
    )
    async def test_rejection_persists_nothing_and_does_not_flush(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        ticket_factory: Callable[..., Awaitable[Ticket]],
        user_factory: Callable[..., Awaitable[User]],
        case: _Case,
        match: str,
    ) -> None:
        ticket = await ticket_factory()
        actor = await user_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        with pytest.raises(ValueError, match=match):
            await TicketAuditLog.log_event(
                db_session, **case.kwargs(ticket.id, actor.id)
            )

        flush_spy.assert_not_called()
        assert len(db_session.new) == 0
        assert await _event_count(db_session, ticket.id) == 0

    async def test_unknown_ticket_id_propagates_integrity_error(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        actor = await user_factory()

        with pytest.raises(IntegrityError):
            await TicketAuditLog.log_event(
                db_session,
                **_CANONICAL[_T.TICKET_CREATED].kwargs(uuid.uuid4(), actor.id),
            )

    async def test_unknown_user_id_propagates_integrity_error(
        self,
        db_session: AsyncSession,
        ticket_factory: Callable[..., Awaitable[Ticket]],
    ) -> None:
        ticket = await ticket_factory()

        with pytest.raises(IntegrityError):
            await TicketAuditLog.log_event(
                db_session,
                **_CANONICAL[_T.TICKET_CREATED].kwargs(ticket.id, uuid.uuid4()),
            )


# ---------------------------------------------------------------------------
# list_ticket_events() — consumer read
# ---------------------------------------------------------------------------

_Factory = Callable[..., Awaitable[Any]]
_BASE_TIME = datetime(2026, 3, 15, 10, 30, tzinfo=UTC)


def _sntl(ticket: Ticket) -> str:
    return format_ticket_id(ticket.sequence_id)


def _restricted(user: User) -> TicketCaller:
    return TicketCaller.authenticated(user.id, Scope.NON_CONFIDENTIAL)


async def _page_ids(db: AsyncSession, ticket: Ticket, **kwargs: Any) -> list[uuid.UUID]:
    result = await list_ticket_events(
        db, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER, **kwargs
    )
    return [item.id for item in result.items]


@pytest.mark.unit
class TestLiteralSubstringPattern:
    @pytest.mark.parametrize(
        ("term", "pattern"),
        [
            ("plain", "%plain%"),
            ("100%", "%100\\%%"),
            ("a_b", "%a\\_b%"),
            ("C:\\x", "%C:\\\\x%"),
            ("\\%", "%\\\\\\%%"),
        ],
    )
    def test_escapes_like_metacharacters(self, term: str, pattern: str) -> None:
        assert _literal_substring_pattern(term) == pattern


@pytest.mark.unit
class TestListTicketEventsInputGuards:
    @pytest.mark.parametrize(
        ("page", "per_page"),
        [(0, 20), (-1, 20), (1, 0), (1, 101)],
    )
    async def test_out_of_range_pagination_raises_before_query(
        self, page: int, per_page: int
    ) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(ValueError, match="page"):
            await list_ticket_events(
                db,
                ticket_id="SNTL-1",
                caller=ANONYMOUS_CALLER,
                page=page,
                per_page=per_page,
            )

        db.execute.assert_not_awaited()

    @pytest.mark.parametrize(
        "locator",
        ["sntl-1", " SNTL-1", "SNTL-01", "SNTL-2147483648", str(uuid.uuid4())],
    )
    async def test_malformed_locator_raises_before_query(self, locator: str) -> None:
        db = AsyncMock(spec=AsyncSession)

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(db, ticket_id=locator, caller=ANONYMOUS_CALLER)

        db.execute.assert_not_awaited()

    async def test_database_error_propagates(self) -> None:
        db = AsyncMock(spec=AsyncSession)
        failure = OperationalError("SELECT 1", {}, Exception("connection lost"))
        db.execute.side_effect = failure

        with pytest.raises(OperationalError) as excinfo:
            await list_ticket_events(db, ticket_id="SNTL-1", caller=ANONYMOUS_CALLER)

        assert excinfo.value is failure


@pytest.mark.integration
class TestListTicketEventsProjection:
    async def test_returns_events_newest_first_with_public_ticket_id(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actor: User = await user_factory(full_name="Fictional Analyst")
        older = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            old_value="New",
            new_value="Analysis",
            created_at=_BASE_TIME,
        )
        newer = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="priority_changed",
            user_id=actor.id,
            old_value="P3",
            new_value="P1",
            detail={"override_action": "set"},
            created_at=_BASE_TIME + timedelta(minutes=5),
        )

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER
        )

        assert (result.total, result.page, result.per_page) == (2, 1, 20)
        first, second = result.items
        assert first.id == newer.id
        assert first.ticket_id == _sntl(ticket)
        assert first.event_type == "priority_changed"
        assert (first.old_value, first.new_value) == ("P3", "P1")
        assert first.detail == {"override_action": "set"}
        assert first.created_at == _BASE_TIME + timedelta(minutes=5)
        assert first.actor == TicketEventActor(
            id=actor.id,
            username=actor.username,
            full_name="Fictional Analyst",
            active=True,
        )
        assert second.id == older.id
        assert second.actor is None
        assert second.comment is None
        assert str(ticket.id) not in {first.ticket_id, second.ticket_id}

    async def test_actor_is_the_current_user_profile(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actor: User = await user_factory(username="fictional.before")
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
        actor.username = "fictional.after"
        actor.full_name = None
        actor.active = False
        await db_session.flush()

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER
        )

        assert result.items[0].actor == TicketEventActor(
            id=actor.id, username="fictional.after", full_name=None, active=False
        )

    async def test_accessible_ticket_without_events_returns_empty_page(
        self, db_session: AsyncSession, ticket_factory: _Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER
        )

        assert result.items == ()
        assert result.total == 0

    async def test_read_creates_no_event_and_adds_nothing_to_the_session(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)

        await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER
        )

        assert not db_session.new
        assert not db_session.dirty
        assert await _event_count(db_session, ticket.id) == 1

    async def test_read_is_one_statement(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """Parent accessibility, events, actors, total, and page come
        from one statement, hence one PostgreSQL snapshot (umbrella #646
        decision B4). Also bounds the work independently of page size."""
        ticket: Ticket = await ticket_factory()
        for _ in range(3):
            actor = await user_factory()
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=actor.id)
        caller = _restricted(await user_factory())
        statements: list[str] = []

        def _record(*args: Any) -> None:
            statements.append(args[2])

        sync_engine = db_session.bind.engine.sync_engine
        event.listen(sync_engine, "before_cursor_execute", _record)
        try:
            await list_ticket_events(
                db_session,
                ticket_id=_sntl(ticket),
                caller=caller,
                actor="system",
                search="x",
                from_date=date(2020, 1, 1),
            )
        finally:
            event.remove(sync_engine, "before_cursor_execute", _record)

        assert len(statements) == 1
        (statement,) = statements
        for cte in ("parent AS", "filtered AS", "total AS", "page AS"):
            assert cte in statement
        assert '"user" AS actor_user' in statement

    async def test_parent_scope_can_use_the_ticket_id_index(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)
        captured: list[tuple[str, Any]] = []

        def _record(*args: Any) -> None:
            captured.append((args[2], args[3]))

        sync_engine = db_session.bind.engine.sync_engine
        event.listen(sync_engine, "before_cursor_execute", _record)
        try:
            await list_ticket_events(
                db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER
            )
        finally:
            event.remove(sync_engine, "before_cursor_execute", _record)
        statement, parameters = captured[0]

        connection = await db_session.connection()
        await connection.exec_driver_sql("SET LOCAL enable_seqscan = off")
        plan = await connection.exec_driver_sql(f"EXPLAIN {statement}", parameters)

        assert "ix_ticket_audit_event_ticket_id" in "\n".join(
            row[0] for row in plan.all()
        )


@pytest.mark.integration
class TestListTicketEventsPagination:
    async def test_equal_timestamps_are_ordered_by_id_desc_across_pages(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        events = [
            await ticket_audit_event_factory(ticket_id=ticket.id, created_at=_BASE_TIME)
            for _ in range(5)
        ]
        expected = sorted((e.id for e in events), reverse=True)

        pages = [
            await _page_ids(db_session, ticket, page=page, per_page=2)
            for page in (1, 2, 3)
        ]

        assert [len(page) for page in pages] == [2, 2, 1]
        assert [event_id for page in pages for event_id in page] == expected

    async def test_created_at_orders_before_id(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        # The later-created (higher UUIDv7) event carries the older timestamp.
        newest = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=_BASE_TIME + timedelta(hours=1)
        )
        oldest = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=_BASE_TIME
        )

        assert await _page_ids(db_session, ticket) == [newest.id, oldest.id]

    async def test_page_beyond_the_last_is_empty_with_the_total(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for _ in range(3):
            await ticket_audit_event_factory(ticket_id=ticket.id)

        result = await list_ticket_events(
            db_session,
            ticket_id=_sntl(ticket),
            caller=ANONYMOUS_CALLER,
            page=3,
            per_page=2,
        )

        assert result.items == ()
        assert (result.total, result.page, result.per_page) == (3, 3, 2)

    async def test_maximum_page_is_accepted(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)

        result = await list_ticket_events(
            db_session,
            ticket_id=_sntl(ticket),
            caller=ANONYMOUS_CALLER,
            page=2_147_483_647,
            per_page=100,
        )

        assert result.items == ()
        assert result.total == 1


@pytest.mark.integration
class TestListTicketEventsFilters:
    async def test_event_type_filter_uses_or_semantics(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        status = await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="status_change"
        )
        assignment = await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="assignment"
        )
        await ticket_audit_event_factory(
            ticket_id=ticket.id, event_type="ticket_created"
        )

        ids = await _page_ids(
            db_session,
            ticket,
            event_types=[
                TicketAuditEventType.STATUS_CHANGE,
                TicketAuditEventType.ASSIGNMENT,
            ],
        )

        assert set(ids) == {status.id, assignment.id}

    async def test_omitted_event_type_filter_returns_every_event(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        for event_type in ("status_change", "assignment"):
            await ticket_audit_event_factory(ticket_id=ticket.id, event_type=event_type)

        assert len(await _page_ids(db_session, ticket, event_types=None)) == 2

    async def test_supplied_but_empty_event_type_filter_returns_empty_page(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER, event_types=[]
        )

        assert result.items == ()
        assert result.total == 0

    async def test_actor_filter_forms(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        alice: User = await user_factory(username="fictional.alice")
        bob: User = await user_factory(username="fictional.bob")
        system_event = await ticket_audit_event_factory(ticket_id=ticket.id)
        alice_event = await ticket_audit_event_factory(
            ticket_id=ticket.id, user_id=alice.id
        )
        await ticket_audit_event_factory(ticket_id=ticket.id, user_id=bob.id)

        assert await _page_ids(db_session, ticket, actor="system") == [system_event.id]
        assert await _page_ids(db_session, ticket, actor=str(alice.id)) == [
            alice_event.id
        ]
        assert await _page_ids(db_session, ticket, actor="fictional.alice") == [
            alice_event.id
        ]
        assert await _page_ids(db_session, ticket, actor="Fictional.Alice") == []

    @pytest.mark.parametrize("actor", ["fictional.nobody", str(uuid.uuid4())])
    async def test_unknown_actor_returns_empty_page_for_accessible_ticket(
        self,
        actor: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id)

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER, actor=actor
        )

        assert (result.items, result.total) == ((), 0)

    @pytest.mark.parametrize("field", ["comment", "old_value", "new_value", "detail"])
    async def test_search_matches_each_declared_field_case_insensitively(
        self,
        field: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        value: Any = (
            {"product_name": "Fictional Linux"}
            if field == "detail"
            else ("Fictional Linux")
        )
        match = await ticket_audit_event_factory(ticket_id=ticket.id, **{field: value})
        await ticket_audit_event_factory(ticket_id=ticket.id, **{field: None})

        assert await _page_ids(db_session, ticket, search="  fictional LINUX ") == [
            match.id
        ]

    @pytest.mark.parametrize("search", [None, "", "   \t "])
    async def test_absent_or_blank_search_applies_no_filter(
        self,
        search: str | None,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        await ticket_audit_event_factory(ticket_id=ticket.id, new_value="a")
        await ticket_audit_event_factory(ticket_id=ticket.id)

        assert len(await _page_ids(db_session, ticket, search=search)) == 2

    @pytest.mark.parametrize(
        ("literal", "decoy"),
        [("100%", "1000"), ("a_b", "axb"), ("C:\\tmp", "C:tmp")],
    )
    async def test_search_metacharacters_are_literal(
        self,
        literal: str,
        decoy: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        match = await ticket_audit_event_factory(ticket_id=ticket.id, new_value=literal)
        await ticket_audit_event_factory(ticket_id=ticket.id, new_value=decoy)

        assert await _page_ids(db_session, ticket, search=literal) == [match.id]

    async def test_date_bounds_are_inclusive_utc(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        before = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            created_at=datetime(2026, 3, 14, 23, 59, 59, tzinfo=UTC),
        )
        start = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=datetime(2026, 3, 15, 0, 0, tzinfo=UTC)
        )
        end = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            created_at=datetime(2026, 3, 16, 23, 59, 59, 999999, tzinfo=UTC),
        )
        after = await ticket_audit_event_factory(
            ticket_id=ticket.id, created_at=datetime(2026, 3, 17, 0, 0, tzinfo=UTC)
        )

        assert await _page_ids(
            db_session, ticket, from_date=date(2026, 3, 15), to_date=date(2026, 3, 16)
        ) == [end.id, start.id]
        assert await _page_ids(db_session, ticket, to_date=date(2026, 3, 14)) == [
            before.id
        ]
        assert (
            await _page_ids(
                db_session,
                ticket,
                from_date=datetime.fromisoformat("2026-03-17T02:00:00"),  # naive = UTC
            )
            == []
        )
        assert await _page_ids(
            db_session,
            ticket,
            from_date=datetime.fromisoformat("2026-03-17T02:00:00+02:00"),
        ) == [after.id]

    async def test_different_filters_compose_with_and(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory()
        actor: User = await user_factory()
        target = await ticket_audit_event_factory(
            ticket_id=ticket.id,
            event_type="status_change",
            user_id=actor.id,
            new_value="Analysis",
            created_at=_BASE_TIME,
        )
        for overrides in (
            {"event_type": "assignment"},
            {"user_id": None},
            {"new_value": "Resolved"},
            {"created_at": _BASE_TIME - timedelta(days=30)},
        ):
            values: dict[str, Any] = {
                "event_type": "status_change",
                "user_id": actor.id,
                "new_value": "Analysis",
                "created_at": _BASE_TIME,
                **overrides,
            }
            await ticket_audit_event_factory(ticket_id=ticket.id, **values)

        result = await list_ticket_events(
            db_session,
            ticket_id=_sntl(ticket),
            caller=ANONYMOUS_CALLER,
            event_types=[TicketAuditEventType.STATUS_CHANGE],
            actor=str(actor.id),
            search="analysis",
            from_date=date(2026, 3, 1),
        )

        assert [item.id for item in result.items] == [target.id]
        assert result.total == 1


@pytest.mark.integration
class TestListTicketEventsAccessibility:
    async def test_mixed_visibility_returns_only_the_requested_ticket_events(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        user: User = await user_factory()
        granted: Ticket = await ticket_factory(is_confidential=True)
        hidden: Ticket = await ticket_factory(is_confidential=True)
        public: Ticket = await ticket_factory()
        await ticket_access_grant_factory(ticket_id=granted.id, user_id=user.id)
        own = await ticket_audit_event_factory(ticket_id=granted.id)
        await ticket_audit_event_factory(ticket_id=hidden.id)
        await ticket_audit_event_factory(ticket_id=public.id)

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(granted), caller=_restricted(user)
        )

        assert [item.id for item in result.items] == [own.id]
        assert result.total == 1
        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(
                db_session, ticket_id=_sntl(hidden), caller=_restricted(user)
            )

    @pytest.mark.parametrize("branch", ["scope_all", "grant", "maintainer"])
    async def test_each_visibility_branch_exposes_the_audit_list(
        self,
        branch: str,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        caller = _restricted(user)
        if branch == "scope_all":
            caller = TicketCaller.authenticated(user.id, Scope.ALL)
        elif branch == "grant":
            await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        else:
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )
        await ticket_audit_event_factory(ticket_id=ticket.id)

        result = await list_ticket_events(
            db_session, ticket_id=_sntl(ticket), caller=caller
        )

        assert result.total == 1

    async def test_losing_the_final_visibility_path_denies_the_list(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory()
        package: TicketPackage = await ticket_package_factory(ticket_id=ticket.id)
        await ticket_package_maintainer_factory(
            ticket_package_id=package.id, user_id=user.id
        )
        await ticket_audit_event_factory(ticket_id=ticket.id)
        package.deleted_at = datetime.now(UTC)
        await db_session.flush()

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(
                db_session, ticket_id=_sntl(ticket), caller=_restricted(user)
            )

    @pytest.mark.parametrize(
        "filters",
        [
            {},
            {"event_types": []},
            {"event_types": [TicketAuditEventType.ASSIGNMENT]},
            {"actor": "fictional.nobody"},
            {"actor": "system"},
            {"search": "no-such-text"},
            {"from_date": date(2099, 1, 1)},
            {"page": 99},
        ],
        ids=[
            "no-filter",
            "all-invalid-event-type",
            "event-type",
            "unknown-actor",
            "system-actor",
            "search",
            "date",
            "beyond-last-page",
        ],
    )
    async def test_inaccessible_ticket_is_not_found_before_any_filter(
        self,
        filters: dict[str, Any],
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        ticket: Ticket = await ticket_factory(is_confidential=True)
        await ticket_audit_event_factory(ticket_id=ticket.id)
        caller = _restricted(await user_factory())

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(
                db_session, ticket_id=_sntl(ticket), caller=caller, **filters
            )

    @pytest.mark.parametrize("kind", ["missing", "uuid"])
    async def test_missing_ticket_and_uuid_locator_are_not_found(
        self, kind: str, db_session: AsyncSession, ticket_factory: _Factory
    ) -> None:
        ticket: Ticket = await ticket_factory()
        locator = "SNTL-2147483647" if kind == "missing" else str(ticket.id)

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(
                db_session, ticket_id=locator, caller=ANONYMOUS_CALLER
            )

    async def test_fan_out_does_not_duplicate_events_or_inflate_total(
        self,
        db_session: AsyncSession,
        ticket_factory: _Factory,
        user_factory: _Factory,
        ticket_access_grant_factory: _Factory,
        ticket_package_factory: _Factory,
        ticket_package_maintainer_factory: _Factory,
        ticket_audit_event_factory: _Factory,
    ) -> None:
        """Several qualifying visibility paths and repeated actors never
        multiply event rows."""
        ticket: Ticket = await ticket_factory(is_confidential=True)
        user: User = await user_factory(username="fictional.fanout")
        await ticket_access_grant_factory(ticket_id=ticket.id, user_id=user.id)
        for _ in range(3):
            package = await ticket_package_factory(ticket_id=ticket.id)
            await ticket_package_maintainer_factory(
                ticket_package_id=package.id, user_id=user.id
            )
            await ticket_package_maintainer_factory(ticket_package_id=package.id)
        for _ in range(4):
            await ticket_audit_event_factory(ticket_id=ticket.id, user_id=user.id)

        for actor in (None, "fictional.fanout"):
            result = await list_ticket_events(
                db_session,
                ticket_id=_sntl(ticket),
                caller=_restricted(user),
                actor=actor,
            )
            assert result.total == 4
            assert len({item.id for item in result.items}) == 4


# ---------------------------------------------------------------------------
# list_ticket_events() — independent-session races
# ---------------------------------------------------------------------------


class _CommittedWorld:
    """Commits fixture rows through an independent session and deletes
    them at teardown in FK-safe order (testing-strategy.md, Concurrency
    Testing: committed data is not rolled back by the fixture)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.ticket_ids: list[uuid.UUID] = []
        self.user_ids: list[uuid.UUID] = []

    async def user(self, *, role: Role | None = None) -> User:
        n = len(self.user_ids) + 1
        user = User(
            username=f"fictional.race{n}.{uuid.uuid4().hex[:8]}",
            email=f"race{n}.{uuid.uuid4().hex[:8]}@example.com",
            password_hash="$2b$12$" + "a" * 53,
        )
        self.session.add(user)
        await self.session.flush()
        self.user_ids.append(user.id)
        if role is not None:
            self.session.add(UserRole(user_id=user.id, role=role.value))
        await self.session.commit()
        return user

    async def ticket(self, *, is_confidential: bool, events: int = 2) -> Ticket:
        ticket = Ticket(is_confidential=is_confidential)
        self.session.add(ticket)
        await self.session.flush()
        self.ticket_ids.append(ticket.id)
        for _ in range(events):
            self.session.add(
                TicketAuditEvent(ticket_id=ticket.id, event_type="status_change")
            )
        await self.session.commit()
        return ticket

    async def cleanup(self) -> None:
        await self.session.rollback()
        packages = select(TicketPackage.id).where(
            TicketPackage.ticket_id.in_(self.ticket_ids)
        )
        for statement in (
            delete(TicketAuditEvent).where(
                TicketAuditEvent.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id.in_(self.ticket_ids)
            ),
            delete(TicketPackageMaintainer).where(
                TicketPackageMaintainer.ticket_package_id.in_(packages)
            ),
            delete(TicketPackage).where(TicketPackage.ticket_id.in_(self.ticket_ids)),
            delete(Ticket).where(Ticket.id.in_(self.ticket_ids)),
            delete(UserRole).where(UserRole.user_id.in_(self.user_ids)),
            delete(User).where(User.id.in_(self.user_ids)),
        ):
            await self.session.execute(statement)
        await self.session.commit()


@pytest.fixture
async def committed_world(
    db_session_factory: Callable[[], Awaitable[AsyncSession]],
) -> AsyncIterator[_CommittedWorld]:
    world = _CommittedWorld(await db_session_factory())
    try:
        yield world
    finally:
        await world.cleanup()


async def _commit(session: AsyncSession, *statements: Any) -> None:
    for statement in statements:
        await session.execute(statement)
    await session.commit()


@pytest.mark.integration
class TestListTicketEventsRaces:
    """Session R performs the preliminary SNTL resolution, session W then
    commits a visibility change, and R performs the protected selection.
    The steps run in a fixed order on independent connections, so the
    interleaving is deterministic. An implementation that listed events
    without re-applying visibility after the preliminary decision would
    return rows and fail these tests."""

    async def test_confidentiality_set_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=False)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            update(Ticket).where(Ticket.id == ticket.id).values(is_confidential=True),
        )

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(reader, ticket_id=_sntl(ticket), caller=caller)

    async def test_grant_revoked_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=True)
        committed_world.session.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await committed_world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            delete(TicketAccessGrant).where(
                TicketAccessGrant.ticket_id == ticket.id,
                TicketAccessGrant.user_id == user.id,
            ),
        )

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(reader, ticket_id=_sntl(ticket), caller=caller)

    async def test_last_maintained_package_excluded_after_preliminary_resolution(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=True)
        package = TicketPackage(ticket_id=ticket.id, package_name="fictional-race-pkg")
        committed_world.session.add(package)
        await committed_world.session.flush()
        committed_world.session.add(
            TicketPackageMaintainer(ticket_package_id=package.id, user_id=user.id)
        )
        await committed_world.session.commit()
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        await resolve_ticket_locator(reader, _sntl(ticket), caller)
        await _commit(
            writer,
            update(TicketPackage)
            .where(TicketPackage.id == package.id)
            .values(deleted_at=datetime.now(UTC)),
        )

        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(reader, ticket_id=_sntl(ticket), caller=caller)

    async def test_count_and_page_come_from_one_view(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """Events committed after a preliminary resolution are observed by
        the later protected read, in its page and total alike. Page/total
        coherence itself follows from the single statement proven by
        `test_read_is_one_statement`."""
        ticket = await committed_world.ticket(is_confidential=False, events=2)
        reader = await db_session_factory()
        writer = await db_session_factory()

        before = await list_ticket_events(
            reader, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER, per_page=100
        )
        await resolve_ticket_locator(reader, _sntl(ticket), ANONYMOUS_CALLER)
        writer.add_all(
            TicketAuditEvent(ticket_id=ticket.id, event_type="assignment")
            for _ in range(3)
        )
        await writer.commit()
        after = await list_ticket_events(
            reader, ticket_id=_sntl(ticket), caller=ANONYMOUS_CALLER, per_page=100
        )

        assert (before.total, len(before.items)) == (2, 2)
        assert (after.total, len(after.items)) == (5, 5)

    async def test_visibility_acquired_after_a_denial_is_observed_whole(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        user = await committed_world.user()
        granter = await committed_world.user()
        ticket = await committed_world.ticket(is_confidential=True, events=3)
        reader = await db_session_factory()
        writer = await db_session_factory()
        caller = _restricted(user)

        with pytest.raises(TicketNotFoundError):
            await resolve_ticket_locator(reader, _sntl(ticket), caller)
        writer.add(
            TicketAccessGrant(
                ticket_id=ticket.id, user_id=user.id, granted_by_id=granter.id
            )
        )
        await writer.commit()
        result = await list_ticket_events(
            reader, ticket_id=_sntl(ticket), caller=caller
        )

        assert (result.total, len(result.items)) == (3, 3)

    async def test_concurrent_role_change_does_not_alter_the_resolved_caller(
        self,
        committed_world: _CommittedWorld,
        db_session_factory: Callable[[], Awaitable[AsyncSession]],
    ) -> None:
        """The caller's scope is resolved once per request; a committed
        role removal applies to the next resolution, not to the in-flight
        request (rbac.md, Optional Principal to Caller Context)."""
        user = await committed_world.user(role=Role.VULNERABILITY_ANALYST)
        ticket = await committed_world.ticket(is_confidential=True)
        reader = await db_session_factory()
        writer = await db_session_factory()
        in_flight = TicketCaller.authenticated(
            user.id,
            get_effective_scope(await user_service.get_user_roles(reader, user.id)),
        )

        await _commit(writer, delete(UserRole).where(UserRole.user_id == user.id))
        result = await list_ticket_events(
            reader, ticket_id=_sntl(ticket), caller=in_flight
        )
        next_request = TicketCaller.authenticated(
            user.id,
            get_effective_scope(await user_service.get_user_roles(reader, user.id)),
        )

        assert in_flight.scope is Scope.ALL
        assert result.total == 2
        assert next_request.scope is Scope.NON_CONFIDENTIAL
        with pytest.raises(TicketNotFoundError):
            await list_ticket_events(
                reader, ticket_id=_sntl(ticket), caller=next_request
            )
