"""Tests for the identity audit trail service
(backend/app/services/identity_audit_log.py).

See docs/features/identity/identity-audit-log.md for the contract
under test: the `IdentityAuditEventType` field contract, the `detail`
JSONB Schema Contract, the deterministic validation order, and the
512-code-point / 4096-byte limits.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IdentityAuditEventType
from app.models.identity_audit_event import IdentityAuditEvent
from app.models.user import User
from app.services import base_audit_log
from app.services.identity_audit_log import (
    IdentityAuditLog,
    _measure_and_check_detail_size,
    list_events,
    list_user_events,
)

# No module-level `pytestmark` here: pytest marks accumulate rather than
# override, so a blanket module marker combined with a class-level
# `@pytest.mark.unit` (below) would tag the same test with both `unit`
# and `integration` — pulling structural-only tests into the integration
# tier as well. Every class below carries its own explicit marker
# instead.


@pytest.mark.unit
class TestRegistration:
    def test_registered_under_identity_name(self) -> None:
        assert base_audit_log.AUDIT_LOG_REGISTRY["identity"] is IdentityAuditLog

    def test_binds_to_identity_audit_event_model(self) -> None:
        assert IdentityAuditLog.model_class is IdentityAuditEvent

    def test_description(self) -> None:
        assert IdentityAuditLog.description == (
            "User lifecycle, roles, API keys, and role mappings"
        )


# Each entry: (event_type, kwargs_builder) where kwargs_builder receives
# (actor_user, target_user) and returns the full log_event() kwargs for
# a minimal, valid invocation of that event type.
_HappyPathCase = tuple[IdentityAuditEventType, Callable[[User, User], dict[str, Any]]]


def _happy_path_cases() -> list[_HappyPathCase]:
    key_id = str(uuid.uuid4())
    return [
        (
            IdentityAuditEventType.USER_CREATED,
            lambda actor, target: {
                "user_id": None,
                "target_user_id": target.id,
                "new_value": "jdoe",
            },
        ),
        (
            IdentityAuditEventType.USER_DEACTIVATED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "active",
                "new_value": "inactive",
                "detail": {"reason": "manual_deactivation"},
            },
        ),
        (
            IdentityAuditEventType.USER_REACTIVATED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "inactive",
                "new_value": "active",
            },
        ),
        (
            IdentityAuditEventType.PASSWORD_RESET,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
            },
        ),
        (
            IdentityAuditEventType.ROLE_ADDED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "new_value": "admin",
            },
        ),
        (
            IdentityAuditEventType.ROLE_REMOVED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "admin",
            },
        ),
        (
            IdentityAuditEventType.ROLE_MAPPING_CREATED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": None,
                "new_value": "SecurityTeam -> admin",
                "detail": {
                    "group_name": "SecurityTeam",
                    "role": "admin",
                    "affected_users": 5,
                },
            },
        ),
        (
            IdentityAuditEventType.ROLE_MAPPING_DELETED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": None,
                "old_value": "SecurityTeam -> admin",
                "detail": {
                    "group_name": "SecurityTeam",
                    "role": "admin",
                    "affected_users": 3,
                },
            },
        ),
        (
            IdentityAuditEventType.USERNAME_CHANGED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "jdoe",
                "new_value": "jdoe2",
            },
        ),
        (
            IdentityAuditEventType.API_KEY_CREATED,
            lambda actor, target: {
                "user_id": target.id,
                "target_user_id": target.id,
                "new_value": "ci-pipeline",
                "detail": {"key_id": key_id},
            },
        ),
        (
            IdentityAuditEventType.API_KEY_REVOKED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "ci-pipeline",
                "detail": {"key_id": key_id},
            },
        ),
        (
            IdentityAuditEventType.EMAIL_CHANGED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": "old@example.com",
                "new_value": "new@example.com",
            },
        ),
        (
            IdentityAuditEventType.FULL_NAME_CHANGED,
            lambda actor, target: {
                "user_id": actor.id,
                "target_user_id": target.id,
                "old_value": None,
                "new_value": "Alice Smith",
            },
        ),
        (
            IdentityAuditEventType.MANAGER_CHANGED,
            lambda actor, target: {
                "user_id": None,
                "target_user_id": target.id,
                "old_value": None,
                "new_value": "bwilson",
            },
        ),
    ]


@pytest.mark.parametrize(
    ("event_type", "kwargs_builder"),
    _happy_path_cases(),
    ids=[case[0].value for case in _happy_path_cases()],
)
@pytest.mark.integration
class TestHappyPathAllEventTypes:
    async def test_creates_exactly_one_event_with_correct_fields(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
        kwargs_builder: Callable[[User, User], dict[str, Any]],
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        kwargs = kwargs_builder(actor, target)

        await IdentityAuditLog.log_event(db_session, event_type=event_type, **kwargs)

        rows = (
            (
                await db_session.execute(
                    select(IdentityAuditEvent).where(
                        IdentityAuditEvent.event_type == event_type.value
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        event = rows[0]
        assert event.user_id == kwargs["user_id"]
        assert event.target_user_id == kwargs["target_user_id"]
        assert event.old_value == kwargs.get("old_value")
        assert event.new_value == kwargs.get("new_value")
        assert event.detail == kwargs.get("detail")


@pytest.mark.integration
class TestEventTypeValidation:
    async def test_raw_string_event_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="IdentityAuditEventType"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type="user_created",  # type: ignore[arg-type]
                user_id=None,
                target_user_id=target.id,
                new_value="jdoe",
            )


@pytest.mark.integration
class TestFieldPresenceValidation:
    """Asymmetric/notable field-presence cases not otherwise obvious from
    the exhaustive `TestFieldRuleRejectionMatrix` below. The full
    required/forbidden matrix for every event type is covered there —
    this class holds only the success-path and cross-field cases that
    the matrix (single-field mutation) cannot express."""

    async def test_api_key_created_actor_and_target_may_differ(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """log_event() only requires both user_id and target_user_id to
        be non-NULL for api_key_created; it does not enforce actor ==
        target. That coherence (actor = owner = target) is guaranteed
        by `api_key_service.create_key()` deriving both from the same
        parameter — a caller obligation, not a log_event() invariant."""
        actor = await user_factory()
        target = await user_factory()

        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.API_KEY_CREATED,
            user_id=actor.id,
            target_user_id=target.id,
            new_value="ci-pipeline",
            detail={"key_id": str(uuid.uuid4())},
        )

        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "api_key_created"
                )
            )
        ).scalar_one()
        assert row.user_id == actor.id
        assert row.target_user_id == target.id


# Every required/forbidden field entry from the IdentityAuditEventType
# field contract in `docs/features/identity/identity-audit-log.md`.
# Deliberately independent of `app.services.identity_audit_log._FIELD_RULES`
# — it is transcribed from the specification, not imported from the
# implementation, so this matrix catches a rule that drifts from the
# documented contract instead of merely re-asserting the code against
# itself. `optional` fields are omitted: they never trigger a rejection.
_FIELD_RULE_REJECTIONS: dict[IdentityAuditEventType, dict[str, str]] = {
    IdentityAuditEventType.USER_CREATED: {
        "target_user_id": "required",
        "old_value": "forbidden",
        "new_value": "required",
    },
    IdentityAuditEventType.USER_DEACTIVATED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "required",
    },
    IdentityAuditEventType.USER_REACTIVATED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "required",
    },
    IdentityAuditEventType.PASSWORD_RESET: {
        "target_user_id": "required",
        "old_value": "forbidden",
        "new_value": "forbidden",
    },
    IdentityAuditEventType.ROLE_ADDED: {
        "target_user_id": "required",
        "old_value": "forbidden",
        "new_value": "required",
    },
    IdentityAuditEventType.ROLE_REMOVED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "forbidden",
    },
    # role_mapping_created/deleted are intrinsically administrator-only
    # events: user_id (the actor) is required — there is no system-sync
    # equivalent that could omit it.
    IdentityAuditEventType.ROLE_MAPPING_CREATED: {
        "user_id": "required",
        "target_user_id": "forbidden",
        "old_value": "forbidden",
        "new_value": "required",
    },
    IdentityAuditEventType.ROLE_MAPPING_DELETED: {
        "user_id": "required",
        "target_user_id": "forbidden",
        "old_value": "required",
        "new_value": "forbidden",
    },
    IdentityAuditEventType.USERNAME_CHANGED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "required",
    },
    IdentityAuditEventType.API_KEY_CREATED: {
        "user_id": "required",
        "target_user_id": "required",
        "old_value": "forbidden",
        "new_value": "required",
    },
    IdentityAuditEventType.API_KEY_REVOKED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "forbidden",
    },
    IdentityAuditEventType.EMAIL_CHANGED: {
        "target_user_id": "required",
        "old_value": "required",
        "new_value": "required",
    },
    IdentityAuditEventType.FULL_NAME_CHANGED: {
        "target_user_id": "required",
    },
    # manager_changed is intrinsically system-only: user_id (the actor)
    # must be NULL — manager assignment is always derived from external
    # sync, never a human action.
    IdentityAuditEventType.MANAGER_CHANGED: {
        "user_id": "forbidden",
        "target_user_id": "required",
    },
}

_HAPPY_PATH_BY_TYPE: dict[
    IdentityAuditEventType, Callable[[User, User], dict[str, Any]]
] = dict(_happy_path_cases())


def _rejection_matrix_cases() -> list[tuple[IdentityAuditEventType, str, str]]:
    """One case per (event_type, field_name, rule) combination in
    `_FIELD_RULE_REJECTIONS` — every required/forbidden field the
    contract defines across all 14 event types."""
    return [
        (event_type, field_name, rule)
        for event_type, fields in _FIELD_RULE_REJECTIONS.items()
        for field_name, rule in fields.items()
    ]


@pytest.mark.integration
@pytest.mark.parametrize(
    ("event_type", "field_name", "rule"),
    _rejection_matrix_cases(),
    ids=[f"{case[0].value}-{case[1]}-{case[2]}" for case in _rejection_matrix_cases()],
)
class TestFieldRuleRejectionMatrix:
    """Exhaustive required/forbidden coverage: every entry of
    `_FIELD_RULE_REJECTIONS` is exercised by starting from a valid,
    happy-path invocation for the event type (all other fields and
    `detail`, if any, remain valid) and mutating only the field under
    test — isolating the rejection to that single field. Every
    rejection must also leave zero persisted events."""

    async def test_violating_the_rule_is_rejected_and_persists_nothing(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
        field_name: str,
        rule: str,
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))

        if rule == "required":
            kwargs[field_name] = None
        else:  # forbidden
            if field_name in ("user_id", "target_user_id"):
                kwargs[field_name] = actor.id
            else:
                kwargs[field_name] = "unexpected"

        with pytest.raises(ValueError, match=field_name):
            await IdentityAuditLog.log_event(
                db_session, event_type=event_type, **kwargs
            )

        rows = (
            (
                await db_session.execute(
                    select(IdentityAuditEvent).where(
                        IdentityAuditEvent.event_type == event_type.value
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows == []


@pytest.mark.integration
class TestDetailValidation:
    @pytest.mark.parametrize(
        "event_type",
        [IdentityAuditEventType.PASSWORD_RESET, IdentityAuditEventType.MANAGER_CHANGED],
        ids=["password_reset", "manager_changed"],
    )
    async def test_event_type_without_detail_support_rejects_non_null(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
    ) -> None:
        """Both event types absent from `_DETAIL_SCHEMAS` — `detail`
        must be NULL for either."""
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))
        kwargs["detail"] = {"source": "external_sync"}
        with pytest.raises(ValueError, match="does not support a detail payload"):
            await IdentityAuditLog.log_event(
                db_session, event_type=event_type, **kwargs
            )

    @pytest.mark.parametrize(
        "event_type",
        [
            IdentityAuditEventType.USER_DEACTIVATED,
            IdentityAuditEventType.ROLE_MAPPING_CREATED,
            IdentityAuditEventType.ROLE_MAPPING_DELETED,
            IdentityAuditEventType.API_KEY_CREATED,
            IdentityAuditEventType.API_KEY_REVOKED,
        ],
        ids=[
            "user_deactivated",
            "role_mapping_created",
            "role_mapping_deleted",
            "api_key_created",
            "api_key_revoked",
        ],
    )
    async def test_event_type_requiring_detail_rejects_null(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
    ) -> None:
        """Every `require_present=True` event type rejects `detail=None`."""
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))
        kwargs["detail"] = None
        with pytest.raises(ValueError, match="requires a detail payload"):
            await IdentityAuditLog.log_event(
                db_session, event_type=event_type, **kwargs
            )

    async def test_non_mapping_detail_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="JSON object"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.USER_CREATED,
                user_id=None,
                target_user_id=target.id,
                new_value="jdoe",
                detail=["not", "a", "mapping"],  # type: ignore[arg-type]
            )

    async def test_empty_detail_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="empty"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.USER_CREATED,
                user_id=None,
                target_user_id=target.id,
                new_value="jdoe",
                detail={},
            )

    async def test_unknown_key_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="unsupported keys"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.USER_CREATED,
                user_id=None,
                target_user_id=target.id,
                new_value="jdoe",
                detail={"unexpected_key": "value"},
            )

    async def test_missing_required_key_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        with pytest.raises(ValueError, match="missing required keys"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={"group_name": "SecurityTeam", "role": "admin"},
            )

    async def test_source_wrong_literal_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="external_sync"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.USER_CREATED,
                user_id=None,
                target_user_id=target.id,
                new_value="jdoe",
                detail={"source": "manual"},
            )

    @pytest.mark.parametrize(
        "event_type",
        [IdentityAuditEventType.ROLE_ADDED, IdentityAuditEventType.ROLE_REMOVED],
        ids=["role_added", "role_removed"],
    )
    async def test_mapping_without_source_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
    ) -> None:
        """`role_added` and `role_removed` share the same paired
        `source`/`mapping` schema; both must reject `mapping` alone."""
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))
        kwargs["detail"] = {"mapping": "SecurityTeam"}
        with pytest.raises(ValueError, match="must be provided together"):
            await IdentityAuditLog.log_event(
                db_session, event_type=event_type, **kwargs
            )

    @pytest.mark.parametrize(
        "event_type",
        [IdentityAuditEventType.ROLE_ADDED, IdentityAuditEventType.ROLE_REMOVED],
        ids=["role_added", "role_removed"],
    )
    async def test_source_without_mapping_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))
        kwargs["detail"] = {"source": "external_sync"}
        with pytest.raises(ValueError, match="must be provided together"):
            await IdentityAuditLog.log_event(
                db_session, event_type=event_type, **kwargs
            )

    @pytest.mark.parametrize(
        "event_type",
        [IdentityAuditEventType.ROLE_ADDED, IdentityAuditEventType.ROLE_REMOVED],
        ids=["role_added", "role_removed"],
    )
    async def test_source_and_mapping_together_accepted(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        event_type: IdentityAuditEventType,
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        kwargs = dict(_HAPPY_PATH_BY_TYPE[event_type](actor, target))
        kwargs["detail"] = {"source": "external_sync", "mapping": "SecurityTeam"}
        await IdentityAuditLog.log_event(db_session, event_type=event_type, **kwargs)
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == event_type.value
                )
            )
        ).scalar_one()
        assert row.detail == {"source": "external_sync", "mapping": "SecurityTeam"}

    async def test_reason_wrong_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="reason"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_REVOKED,
                user_id=None,
                target_user_id=target.id,
                old_value="ci-pipeline",
                detail={"key_id": str(uuid.uuid4()), "reason": 12345},
            )

    async def test_group_name_wrong_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        with pytest.raises(ValueError, match="group_name"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={"group_name": 123, "role": "admin", "affected_users": 5},
            )

    async def test_role_key_wrong_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        with pytest.raises(ValueError, match=r"detail\.role"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={"group_name": "SecurityTeam", "role": 123, "affected_users": 5},
            )

    async def test_affected_users_wrong_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        with pytest.raises(ValueError, match="affected_users"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={
                    "group_name": "SecurityTeam",
                    "role": "admin",
                    "affected_users": "5",
                },
            )

    async def test_affected_users_boolean_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """A boolean is not an integer for this contract (detail JSONB
        Schema Contract, Notes) — bool is a subclass of int in Python."""
        admin = await user_factory()
        with pytest.raises(ValueError, match="affected_users"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={
                    "group_name": "SecurityTeam",
                    "role": "admin",
                    "affected_users": True,
                },
            )

    async def test_affected_users_negative_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        admin = await user_factory()
        with pytest.raises(ValueError, match="affected_users"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_MAPPING_CREATED,
                user_id=admin.id,
                target_user_id=None,
                new_value="SecurityTeam -> admin",
                detail={
                    "group_name": "SecurityTeam",
                    "role": "admin",
                    "affected_users": -1,
                },
            )

    async def test_key_id_invalid_uuid_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="key_id"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_CREATED,
                user_id=target.id,
                target_user_id=target.id,
                new_value="ci-pipeline",
                detail={"key_id": "not-a-uuid"},
            )

    async def test_key_id_non_canonical_uppercase_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        non_canonical = str(uuid.uuid4()).upper()
        with pytest.raises(ValueError, match="key_id"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_CREATED,
                user_id=target.id,
                target_user_id=target.id,
                new_value="ci-pipeline",
                detail={"key_id": non_canonical},
            )

    async def test_key_id_non_string_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="key_id"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_CREATED,
                user_id=target.id,
                target_user_id=target.id,
                new_value="ci-pipeline",
                detail={"key_id": 12345},
            )

    async def test_mapping_wrong_type_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        with pytest.raises(ValueError, match="mapping"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.ROLE_ADDED,
                user_id=None,
                target_user_id=target.id,
                new_value="admin",
                detail={"source": "external_sync", "mapping": 123},
            )


@pytest.mark.integration
class TestOldNewValueTruncation:
    async def test_value_within_limit_is_not_truncated(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        value = "a" * 512
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value=value,
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "user_created"
                )
            )
        ).scalar_one()
        assert row.new_value == value
        assert len(row.new_value) == 512

    async def test_value_over_limit_is_truncated_to_512_codepoints(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        value = "a" * 600
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value=value,
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "user_created"
                )
            )
        ).scalar_one()
        assert row.new_value == "a" * 512
        assert len(row.new_value) == 512

    async def test_multibyte_astral_characters_truncated_by_codepoint(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Each emoji below is a single Unicode code point outside the
        BMP (astral plane), encoded as a UTF-8 4-byte sequence and a
        UTF-16 surrogate pair. Truncation must count code points, not
        UTF-16 code units or bytes."""
        target = await user_factory()
        value = "\U0001f600" * 600  # 😀 repeated 600 times
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value=value,
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "user_created"
                )
            )
        ).scalar_one()
        assert row.new_value == "\U0001f600" * 512
        assert len(row.new_value) == 512

    async def test_old_value_within_limit_is_not_truncated(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Mirrors `test_value_within_limit_is_not_truncated` (which
        covers `new_value`) for `old_value`, completing boundary
        coverage at exactly 512 code points for both fields."""
        target = await user_factory()
        value = "b" * 512
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USERNAME_CHANGED,
            user_id=None,
            target_user_id=target.id,
            old_value=value,
            new_value="jdoe2",
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "username_changed"
                )
            )
        ).scalar_one()
        assert row.old_value == value
        assert len(row.old_value) == 512

    async def test_old_value_over_limit_is_truncated_to_512_codepoints(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """`old_value` follows the same 512-code-point truncation as
        `new_value` — exercised here via `username_changed`, whose
        contract requires both `old_value` and `new_value`."""
        target = await user_factory()
        value = "b" * 600
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USERNAME_CHANGED,
            user_id=None,
            target_user_id=target.id,
            old_value=value,
            new_value="jdoe2",
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "username_changed"
                )
            )
        ).scalar_one()
        assert row.old_value == "b" * 512
        assert len(row.old_value) == 512

    async def test_old_value_multibyte_astral_characters_truncated_by_codepoint(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        value = "\U0001f600" * 600  # 😀 repeated 600 times
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USERNAME_CHANGED,
            user_id=None,
            target_user_id=target.id,
            old_value=value,
            new_value="jdoe2",
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "username_changed"
                )
            )
        ).scalar_one()
        assert row.old_value == "\U0001f600" * 512
        assert len(row.old_value) == 512

    async def test_none_remains_none(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.PASSWORD_RESET,
            user_id=None,
            target_user_id=target.id,
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "password_reset"
                )
            )
        ).scalar_one()
        assert row.old_value is None
        assert row.new_value is None


def _serialized_detail_size(detail: dict[str, Any]) -> int:
    """Mirror the production serialization exactly, for constructing
    precise byte-boundary test fixtures (see
    `IdentityAuditLog.log_event()`, `_measure_and_check_detail_size`)."""
    serialized = json.dumps(
        detail,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return len(serialized.encode("utf-8"))


@pytest.mark.integration
class TestDetailSizeBoundary:
    async def test_exactly_4096_bytes_accepted(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        key_id = str(uuid.uuid4())
        overhead = _serialized_detail_size({"key_id": key_id, "reason": ""})
        padding = "a" * (4096 - overhead)
        detail = {"key_id": key_id, "reason": padding}
        assert _serialized_detail_size(detail) == 4096

        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.API_KEY_REVOKED,
            user_id=None,
            target_user_id=target.id,
            old_value="ci-pipeline",
            detail=detail,
        )
        row = (
            await db_session.execute(
                select(IdentityAuditEvent).where(
                    IdentityAuditEvent.event_type == "api_key_revoked"
                )
            )
        ).scalar_one()
        assert row.detail == detail

    async def test_4097_bytes_rejected(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        key_id = str(uuid.uuid4())
        overhead = _serialized_detail_size({"key_id": key_id, "reason": ""})
        padding = "a" * (4097 - overhead)
        detail = {"key_id": key_id, "reason": padding}
        assert _serialized_detail_size(detail) == 4097

        with pytest.raises(ValueError, match="4096"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_REVOKED,
                user_id=None,
                target_user_id=target.id,
                old_value="ci-pipeline",
                detail=detail,
            )

        rows = (
            (
                await db_session.execute(
                    select(IdentityAuditEvent).where(
                        IdentityAuditEvent.event_type == "api_key_revoked"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert rows == []

    async def test_multibyte_utf8_boundary_measured_in_bytes(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        """Each '€' character encodes to 3 UTF-8 bytes but is a single
        Python `str` character — the size limit must be measured in
        encoded bytes, not characters."""
        target = await user_factory()
        key_id = str(uuid.uuid4())
        overhead = _serialized_detail_size({"key_id": key_id, "reason": ""})
        remaining = 4096 - overhead
        char_count = remaining // 3
        padding = "\u20ac" * char_count  # '€', 3 bytes each in UTF-8
        detail = {"key_id": key_id, "reason": padding}
        size = _serialized_detail_size(detail)
        assert size <= 4096

        # Accepted at or under the boundary.
        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.API_KEY_REVOKED,
            user_id=None,
            target_user_id=target.id,
            old_value="ci-pipeline",
            detail=detail,
        )

        # One more '€' pushes at least 3 bytes past any remaining slack,
        # guaranteeing the limit is exceeded.
        over_detail = {"key_id": key_id, "reason": padding + "\u20ac" * 10}
        with pytest.raises(ValueError, match="4096"):
            await IdentityAuditLog.log_event(
                db_session,
                event_type=IdentityAuditEventType.API_KEY_REVOKED,
                user_id=None,
                target_user_id=target.id,
                old_value="ci-pipeline-2",
                detail=over_detail,
            )


@pytest.mark.integration
class TestNoCommit:
    async def test_does_not_commit(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        commit_spy = AsyncMock(wraps=db_session.commit)
        monkeypatch.setattr(db_session, "commit", commit_spy)

        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value="jdoe",
        )

        commit_spy.assert_not_called()

    async def test_flushes_within_the_caller_transaction(
        self,
        db_session: AsyncSession,
        monkeypatch: pytest.MonkeyPatch,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()
        flush_spy = AsyncMock(wraps=db_session.flush)
        monkeypatch.setattr(db_session, "flush", flush_spy)

        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value="jdoe",
        )

        flush_spy.assert_called_once()


@pytest.mark.integration
class TestRollbackAtomicity:
    async def test_rollback_removes_the_flushed_audit_event(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
    ) -> None:
        target = await user_factory()

        await IdentityAuditLog.log_event(
            db_session,
            event_type=IdentityAuditEventType.USER_CREATED,
            user_id=None,
            target_user_id=target.id,
            new_value="jdoe",
        )
        rows = (await db_session.execute(select(IdentityAuditEvent))).scalars().all()
        assert len(rows) == 1

        await db_session.rollback()

        rows_after = (
            (await db_session.execute(select(IdentityAuditEvent))).scalars().all()
        )
        assert rows_after == []


@pytest.mark.unit
class TestMeasureAndCheckDetailSizeInternal:
    """Direct unit tests for the private
    `_measure_and_check_detail_size()` helper, covering the defensive
    JSON-encoding-failure branch that `log_event()`'s own schema
    validation makes unreachable through the public API (every
    documented `detail` value is a `str` or non-boolean `int`, both
    always JSON-serializable). The identity-audit-log.md contract
    explicitly lists "JSON encoding failure" among the conditions that
    raise `ValueError`, so this branch is exercised directly."""

    def test_unserializable_value_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="failed to serialize"):
            _measure_and_check_detail_size({"key_id": {1, 2, 3}})  # type: ignore[dict-item]

    def test_within_limit_does_not_raise(self) -> None:
        _measure_and_check_detail_size({"key_id": "a" * 10})


# ---------------------------------------------------------------------------
# list_events() / list_user_events() — read/query boundary
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestListEvents:
    """`list_events()` — the admin identity audit log query
    (`docs/features/identity/identity-audit-log.md`, List Identity
    Audit Events)."""

    async def test_empty_database_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_events(db_session)

        assert page.items == []
        assert page.total == 0

    async def test_actor_and_target_user_are_eagerly_loaded(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory(username="adminactor")
        target = await user_factory(username="targetuser")
        await identity_audit_event_factory(
            event_type="role_added",
            user_id=actor.id,
            target_user_id=target.id,
            new_value="admin",
        )

        page = await list_events(db_session)

        (event,) = page.items
        assert event.actor is not None
        assert event.actor.username == "adminactor"
        assert event.target_user is not None
        assert event.target_user.username == "targetuser"

    async def test_system_event_has_null_actor(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", user_id=None, target_user_id=target.id
        )

        page = await list_events(db_session)

        (event,) = page.items
        assert event.actor is None

    async def test_null_target_configuration_event_is_included(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        await identity_audit_event_factory(
            event_type="role_mapping_created",
            user_id=actor.id,
            target_user_id=None,
        )

        page = await list_events(db_session)

        (event,) = page.items
        assert event.target_user is None

    async def test_event_type_filter_or_semantics(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="role_removed", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="username_changed", target_user_id=target.id
        )

        page = await list_events(
            db_session,
            event_types=[
                IdentityAuditEventType.ROLE_ADDED,
                IdentityAuditEventType.ROLE_REMOVED,
            ],
        )

        event_types = {event.event_type for event in page.items}
        assert event_types == {"role_added", "role_removed"}
        assert page.total == 2

    async def test_actor_filter_by_uuid(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        other_actor = await user_factory()
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="role_added", user_id=other_actor.id, target_user_id=target.id
        )

        page = await list_events(db_session, actor=str(actor.id))

        assert page.total == 1
        assert page.items[0].user_id == actor.id

    async def test_actor_filter_by_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory(username="filteractor")
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )

        page = await list_events(db_session, actor="filteractor")

        assert page.total == 1

    async def test_actor_filter_by_system_literal(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory()
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", user_id=None, target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )

        page = await list_events(db_session, actor="system")

        assert page.total == 1
        assert page.items[0].user_id is None

    async def test_actor_filter_unknown_uuid_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_events(db_session, actor=str(uuid.uuid4()))

        assert page.items == []
        assert page.total == 0

    async def test_actor_filter_unknown_username_returns_empty_page(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_events(db_session, actor="no-such-actor")

        assert page.items == []
        assert page.total == 0

    async def test_target_user_filter_by_uuid(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        other_target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=other_target.id
        )

        page = await list_events(db_session, target_user=str(target.id))

        assert page.total == 1
        assert page.items[0].target_user_id == target.id

    async def test_target_user_filter_by_username(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory(username="filtertarget")
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )

        page = await list_events(db_session, target_user="filtertarget")

        assert page.total == 1

    async def test_target_user_filter_unknown_returns_empty_page_not_error(
        self, db_session: AsyncSession
    ) -> None:
        page = await list_events(db_session, target_user="no-such-target")

        assert page.items == []
        assert page.total == 0

    @pytest.mark.parametrize(
        ("identifier_key", "expected_owner"),
        [
            ("shared_uuid", "id_owner"),
            ("shared_uuid_upper", "id_owner"),
            ("plain_uuid", "plain"),
            ("plain_username", "plain"),
            ("plain_username_upper", None),
            ("unknown_uuid", None),
            ("unknown_username", None),
        ],
    )
    async def test_target_user_and_actor_share_identifier_matching(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
        identifier_key: str,
        expected_owner: str | None,
    ) -> None:
        """Both filters apply the single user-domain matching policy
        (`docs/features/identity/user-service.md`,
        `resolve_user_identifier()`): a username shaped like another
        user's ID selects that ID owner, because a UUID-parsable value is
        always matched by `User.id`."""
        # Letter-leading, so its text is also a format-valid username.
        shared = uuid.UUID("a" + uuid.uuid4().hex[1:])
        users = {
            "id_owner": await user_factory(id=shared, username="parity.idowner"),
            "name_owner": await user_factory(username=str(shared)),
            "plain": await user_factory(username="parity.plain"),
        }
        bystander = await user_factory()
        for user in users.values():
            await identity_audit_event_factory(
                event_type="role_added", user_id=user.id, target_user_id=bystander.id
            )
            await identity_audit_event_factory(
                event_type="role_added", user_id=None, target_user_id=user.id
            )
        identifier = {
            "shared_uuid": str(shared),
            "shared_uuid_upper": str(shared).upper(),
            "plain_uuid": str(users["plain"].id),
            "plain_username": "parity.plain",
            "plain_username_upper": "PARITY.PLAIN",
            "unknown_uuid": str(uuid.uuid4()),
            "unknown_username": "no-such-user",
        }[identifier_key]
        expected: set[uuid.UUID] = (
            set() if expected_owner is None else {users[expected_owner].id}
        )

        by_actor = await list_events(db_session, actor=identifier)
        by_target = await list_events(db_session, target_user=identifier)

        assert {event.user_id for event in by_actor.items} == expected
        assert {event.target_user_id for event in by_target.items} == expected
        assert len(by_actor.items) == by_actor.total == len(expected)
        assert len(by_target.items) == by_target.total == len(expected)

    async def test_date_range_is_inclusive(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        boundary = datetime(2026, 5, 13, 10, 0, 0, tzinfo=UTC)
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id, created_at=boundary
        )

        page = await list_events(db_session, from_date=boundary, to_date=boundary)

        assert page.total == 1

    async def test_combined_filters(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        actor = await user_factory(username="combinedactor")
        target = await user_factory(username="combinedtarget")
        await identity_audit_event_factory(
            event_type="role_added", user_id=actor.id, target_user_id=target.id
        )
        await identity_audit_event_factory(
            event_type="role_removed", user_id=actor.id, target_user_id=target.id
        )

        page = await list_events(
            db_session,
            event_types=[IdentityAuditEventType.ROLE_ADDED],
            actor="combinedactor",
            target_user="combinedtarget",
        )

        assert page.total == 1
        assert page.items[0].event_type == "role_added"

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id
        )

        page = await list_events(db_session, page=2, per_page=20)

        assert page.items == []
        assert page.total == 1

    async def test_fixed_ordering_newest_first(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        older = await identity_audit_event_factory(
            event_type="user_created",
            target_user_id=target.id,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=target.id,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        page = await list_events(db_session)

        assert [event.id for event in page.items] == [newer.id, older.id]

    async def test_tie_break_by_id_descending_for_equal_timestamps(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        target = await user_factory()
        same_time = datetime(2026, 5, 1, tzinfo=UTC)
        first = await identity_audit_event_factory(
            event_type="user_created", target_user_id=target.id, created_at=same_time
        )
        second = await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=target.id,
            created_at=same_time,
        )
        expected_order = sorted([first.id, second.id], reverse=True)

        page = await list_events(db_session)

        assert [event.id for event in page.items] == expected_order


@pytest.mark.integration
class TestListUserEvents:
    """`list_user_events()` — the self-service identity audit log query
    (`docs/features/identity/identity-audit-log.md`, List My Identity
    Audit Events)."""

    async def test_only_returns_events_targeting_the_given_user(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        other_user = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=user.id
        )
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=other_user.id
        )

        page = await list_user_events(db_session, user_id=user.id)

        assert page.total == 1
        assert page.items[0].target_user_id == user.id

    async def test_excludes_null_target_events(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=user.id
        )
        await identity_audit_event_factory(
            event_type="role_mapping_created", target_user_id=None
        )

        page = await list_user_events(db_session, user_id=user.id)

        assert page.total == 1

    async def test_event_type_filter(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        await identity_audit_event_factory(
            event_type="role_added", target_user_id=user.id
        )
        await identity_audit_event_factory(
            event_type="username_changed", target_user_id=user.id
        )

        page = await list_user_events(
            db_session,
            user_id=user.id,
            event_types=[IdentityAuditEventType.ROLE_ADDED],
        )

        assert page.total == 1
        assert page.items[0].event_type == "role_added"

    async def test_date_range_is_inclusive(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        boundary = datetime(2026, 5, 13, 10, 0, 0, tzinfo=UTC)
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=user.id, created_at=boundary
        )
        outside = boundary - timedelta(days=1)
        await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=user.id,
            created_at=outside,
        )

        page = await list_user_events(
            db_session, user_id=user.id, from_date=boundary, to_date=boundary
        )

        assert page.total == 1

    async def test_page_beyond_last_page_returns_empty_with_correct_total(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        await identity_audit_event_factory(
            event_type="user_created", target_user_id=user.id
        )

        page = await list_user_events(db_session, user_id=user.id, page=2, per_page=20)

        assert page.items == []
        assert page.total == 1

    async def test_fixed_ordering_newest_first(
        self,
        db_session: AsyncSession,
        user_factory: Callable[..., Awaitable[User]],
        identity_audit_event_factory: Callable[..., Awaitable[IdentityAuditEvent]],
    ) -> None:
        user = await user_factory()
        older = await identity_audit_event_factory(
            event_type="user_created",
            target_user_id=user.id,
            created_at=datetime(2026, 5, 1, tzinfo=UTC),
        )
        newer = await identity_audit_event_factory(
            event_type="username_changed",
            target_user_id=user.id,
            created_at=datetime(2026, 5, 2, tzinfo=UTC),
        )

        page = await list_user_events(db_session, user_id=user.id)

        assert [event.id for event in page.items] == [newer.id, older.id]
