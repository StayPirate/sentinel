"""Minimal OCI artifact probes for Celery worker command and broker delivery."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from tests.image.conftest import IsolatedComposeStack

_TASK_EFFECT_SCRIPT = """
import asyncio
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.celery_app import celery_app
from app.database import async_session_factory, engine
from app.models.session import Session
from app.models.user import User


async def seed() -> uuid.UUID:
    session_id = uuid.uuid4()
    async with async_session_factory() as db:
        user = User(
            username=f"smoke-{session_id.hex[:8]}",
            email=f"smoke-{session_id.hex[:8]}@example.test",
            external_id=uuid.uuid4(),
        )
        db.add(user)
        await db.flush()
        db.add(
            Session(
                id=session_id,
                user_id=user.id,
                expires_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
        await db.commit()
    return session_id


async def session_exists(session_id: uuid.UUID) -> bool:
    async with async_session_factory() as db:
        result = await db.execute(select(Session.id).where(Session.id == session_id))
        return result.scalar_one_or_none() is not None


async def main() -> None:
    try:
        session_id = await seed()
        assert await session_exists(session_id), "seed session not visible before task"
        celery_app.send_task("cleanup_sessions")

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if not await session_exists(session_id):
                print("TASK-EFFECT-OK")
                return
            await asyncio.sleep(1)
        raise SystemExit("expired session was not cleaned up within the poll window")
    finally:
        await engine.dispose()


asyncio.run(main())
"""


@pytest.mark.image
def test_worker_registers_representative_production_tasks_only(
    celery_node_inspect: Callable[[str, str, str], Any],
) -> None:
    registered_tasks = celery_node_inspect("worker", "celery", "registered")
    assert "cleanup_sessions" in registered_tasks
    assert "run_fetcher" in registered_tasks


@pytest.mark.image
def test_broker_delivery_produces_durable_result_in_disposable_stack(
    isolated_compose_stack: IsolatedComposeStack,
) -> None:
    """Use a worker-only application topology and discard all resulting state."""
    result = isolated_compose_stack.up("services: {}\n", "worker")
    assert result.returncode == 0, (
        f"disposable worker stack failed to become ready "
        f"(stdout={result.stdout!r}, stderr={result.stderr!r})"
    )

    effect = isolated_compose_stack.exec(
        "worker", "python", "-c", _TASK_EFFECT_SCRIPT, timeout=40.0
    )
    assert effect.returncode == 0, (
        f"broker delivery check failed (stdout={effect.stdout!r}, "
        f"stderr={effect.stderr!r})"
    )
    assert "TASK-EFFECT-OK" in effect.stdout


@pytest.mark.image
def test_unsupported_worker_pool_fails_before_consuming_tasks(
    isolated_compose_stack: IsolatedComposeStack,
) -> None:
    override = (
        "services:\n"
        "  worker:\n"
        "    command:\n"
        "      - celery\n"
        "      - -A\n"
        "      - app.celery_app\n"
        "      - worker\n"
        "      - --pool=solo\n"
        "      - --loglevel=info\n"
    )

    result = isolated_compose_stack.up(override, "worker")
    assert result.returncode != 0, (
        "unsupported worker unexpectedly became ready: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    isolated_compose_stack.wait_until_exited("worker")

    state = isolated_compose_stack.service_state("worker")
    assert state.returncode == 0, state.stderr
    assert state.stdout.strip().startswith("exited|"), state.stdout
    assert not state.stdout.strip().endswith("|0"), state.stdout

    logs = isolated_compose_stack.logs("worker")
    assert "worker_startup_failed" in logs
    assert "worker_pool_validation" in logs
    assert "worker_startup_completed" not in logs
