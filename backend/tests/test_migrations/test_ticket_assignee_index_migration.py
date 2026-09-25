"""Integration tests for the Ticket assignee index Alembic migration
(backend/alembic/versions/b3996908657f_add_ticket_assignee_index.py).

Verifies that upgrading from the previous head adds exactly the non-unique,
non-partial `ix_ticket_assignee_id` B-tree index on `ticket.assignee_id`
documented in `docs/data-model.md` (Ticket, Indexes), leaving the existing
partial `ix_ticket_duplicate_of_id` index untouched. Downgrade removes only
the new index, and re-upgrade restores it.

`alembic check` is deliberately not invoked in-process: `command.check()`
compares against `Base.metadata` of the current process, which already
contains the test-only `tests.support.audit_models.SampleAuditEvent` table
and would report it as spurious drift. The CI "Check Alembic migration
drift" step (`.github/workflows/ci.yml`) runs `alembic check` from a clean
process against the same migration chain.

See `tests/test_migrations/conftest.py` for the shared Alembic test
infrastructure (dedicated database fixture, isolated config helper).
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import command
from app.config import settings
from tests.test_migrations.conftest import isolated_alembic_config, run_sync

_PREVIOUS_HEAD = "e7c553292d65"
_REVISION = "b3996908657f"

_DUPLICATE_OF_INDEX = ("ix_ticket_duplicate_of_id", ("duplicate_of_id",))
_ASSIGNEE_INDEX = ("ix_ticket_assignee_id", ("assignee_id",))


async def _ticket_standalone_indexes_async(database_url: str) -> list[dict[str, Any]]:
    engine = create_async_engine(database_url)
    try:
        async with engine.connect() as conn:

            def _sync_inspect(sync_conn: Any) -> list[dict[str, Any]]:
                # Indexes backing a unique constraint are reported with
                # `duplicates_constraint`; anything else is standalone.
                return [
                    dict(index)
                    for index in inspect(sync_conn).get_indexes("ticket")
                    if not index.get("duplicates_constraint")
                ]

            return await conn.run_sync(_sync_inspect)
    finally:
        await engine.dispose()


def _ticket_standalone_indexes(database_url: str) -> dict[str, dict[str, Any]]:
    indexes = run_sync(_ticket_standalone_indexes_async(database_url))
    return {index["name"]: index for index in indexes}


def _assert_previous_head(indexes: dict[str, dict[str, Any]]) -> None:
    assert set(indexes) == {_DUPLICATE_OF_INDEX[0]}
    _assert_duplicate_of_index_unchanged(indexes)


def _assert_upgraded(indexes: dict[str, dict[str, Any]]) -> None:
    assert set(indexes) == {_DUPLICATE_OF_INDEX[0], _ASSIGNEE_INDEX[0]}
    _assert_duplicate_of_index_unchanged(indexes)

    assignee = indexes[_ASSIGNEE_INDEX[0]]
    assert tuple(assignee["column_names"]) == _ASSIGNEE_INDEX[1]
    assert assignee["unique"] is False
    assert "postgresql_where" not in assignee["dialect_options"]


def _assert_duplicate_of_index_unchanged(indexes: dict[str, dict[str, Any]]) -> None:
    duplicate_of = indexes[_DUPLICATE_OF_INDEX[0]]
    assert tuple(duplicate_of["column_names"]) == _DUPLICATE_OF_INDEX[1]
    assert duplicate_of["unique"] is False
    assert (
        duplicate_of["dialect_options"]["postgresql_where"]
        == "(duplicate_of_id IS NOT NULL)"
    )


@pytest.mark.integration
class TestTicketAssigneeIndexMigration:
    def test_upgrade_downgrade_reupgrade_cycle(
        self,
        alembic_test_database_url: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(settings, "database_url", alembic_test_database_url)
        cfg = isolated_alembic_config()

        command.upgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous_head(_ticket_standalone_indexes(alembic_test_database_url))

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(_ticket_standalone_indexes(alembic_test_database_url))

        command.downgrade(cfg, _PREVIOUS_HEAD)
        _assert_previous_head(_ticket_standalone_indexes(alembic_test_database_url))

        command.upgrade(cfg, _REVISION)
        _assert_upgraded(_ticket_standalone_indexes(alembic_test_database_url))
