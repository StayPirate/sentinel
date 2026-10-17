"""Integration tests for the identity Alembic migration chain.

Exercises the real migration files from the empty base through revision
``4e3e94583e96`` and verifies the identity tables, constraints, and indexes
owned by ``docs/data-model.md``. See ``tests/test_migrations/conftest.py`` for
the dedicated PostgreSQL database and synchronous Alembic command boundary.
"""

from __future__ import annotations

from typing import Any, TypedDict

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_REVISION = "4e3e94583e96"
_IDENTITY_TABLES = {
    "user",
    "user_role",
    "session",
    "api_key",
    "identity_audit_event",
}


class _SchemaFacts(TypedDict):
    tables: set[str]
    user_checks: set[str]
    user_role_checks: set[str]
    session_indexes: dict[str, dict[str, Any]]
    api_key_checks: set[str]
    api_key_indexes: dict[str, dict[str, Any]]
    identity_audit_event_indexes: dict[str, dict[str, Any]]


async def _inspect_schema(database_url: str) -> _SchemaFacts:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> _SchemaFacts:
                inspector = inspect(sync_conn)
                tables = set(inspector.get_table_names())

                def _checks(table_name: str) -> set[str]:
                    if table_name not in tables:
                        return set()
                    return {
                        constraint["name"]
                        for constraint in inspector.get_check_constraints(table_name)
                    }

                def _indexes(table_name: str) -> dict[str, dict[str, Any]]:
                    if table_name not in tables:
                        return {}
                    return {
                        index["name"]: index
                        for index in inspector.get_indexes(table_name)
                    }

                return {
                    "tables": tables,
                    "user_checks": _checks("user"),
                    "user_role_checks": _checks("user_role"),
                    "session_indexes": _indexes("session"),
                    "api_key_checks": _checks("api_key"),
                    "api_key_indexes": _indexes("api_key"),
                    "identity_audit_event_indexes": _indexes("identity_audit_event"),
                }

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _inspect(database_url: str) -> _SchemaFacts:
    return run_sync(_inspect_schema(database_url))


def _assert_identity_schema(facts: _SchemaFacts) -> None:
    assert facts["tables"] >= _IDENTITY_TABLES
    assert "chk_user_auth_exclusive" in facts["user_checks"]
    assert "chk_user_role_role_valid" in facts["user_role_checks"]

    session_index = facts["session_indexes"]["ix_session_user_id_is_active"]
    assert session_index["column_names"] == ["user_id", "is_active"]

    assert "chk_api_key_hash_is_sha256_hex" in facts["api_key_checks"]
    api_key_index = facts["api_key_indexes"]["ix_api_key_user_id_revoked_at"]
    assert api_key_index["column_names"] == ["user_id", "revoked_at"]

    active_name_index = facts["api_key_indexes"]["uq_api_key_user_id_name_active"]
    assert active_name_index["column_names"] == ["user_id", "name"]
    assert active_name_index["unique"] is True
    predicate = str(active_name_index["dialect_options"]["postgresql_where"])
    assert "revoked_at IS NULL" in predicate

    assert {
        "ix_identity_audit_event_created_at",
        "ix_identity_audit_event_target_user_id",
        "ix_identity_audit_event_user_id",
    } <= facts["identity_audit_event_indexes"].keys()


@pytest.mark.integration
class TestIdentityMigrations:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _REVISION)
        _assert_identity_schema(_inspect(alembic_test_database_url))

        command.downgrade(cfg, "base")
        downgraded = _inspect(alembic_test_database_url)
        assert _IDENTITY_TABLES.isdisjoint(downgraded["tables"])

        command.upgrade(cfg, _REVISION)
        _assert_identity_schema(_inspect(alembic_test_database_url))
