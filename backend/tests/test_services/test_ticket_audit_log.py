"""Tests for the Ticket audit trail service
(backend/app/services/ticket_audit_log.py).

See docs/features/tickets/ticket-audit-log.md for the contract under
test: the Event Type Contract (`comment`/`detail` columns), the
Canonical Automatic Comment Vocabulary, the `detail` JSONB Schema
Contract with its conditional keys and 4096-byte serialization rule,
and Implementation Guidelines 3, 5, and 6. The flush / no-commit /
exception-propagation guarantees come from
docs/features/platform/audit-trail-infrastructure.md (Atomicity).

Per-mutation event sequences, actors, and no-event assertions belong
to the owning mutation services and are not tested here.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CVESourceType, TicketAuditEventType
from app.models.ticket import Ticket
from app.models.ticket_audit_event import TicketAuditEvent
from app.models.user import User
from app.services import base_audit_log
from app.services.ticket_audit_log import (
    CVE_SOURCE_AUDIT_LABELS,
    TicketAuditLog,
    _serialized_detail_size,
)
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
