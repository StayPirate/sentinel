"""OCI artifact probes for the packaged Alembic migration chain.

Focused migration tests own exhaustive schema, constraint, index, downgrade,
and re-upgrade coverage. These checks verify only that the packaged migration
files reach the expected head and seed, report no Alembic drift, and gate every
runtime role on failure. Shared-image non-root execution is verified in
``test_image_build.py``.

See ``docs/features/platform/testing-strategy.md`` (Artifact-Risk Rule).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

import pytest

from tests.image.conftest import IsolatedComposeStack

_HEAD_AND_SEED_CHECK_SCRIPT = """
import asyncio

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text

from app.database import engine


async def main() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    expected_head = script.get_current_head()
    async with engine.connect() as conn:
        version_result = await conn.execute(
            text("SELECT version_num FROM alembic_version")
        )
        version = version_result.scalar_one()
        seed = (
            await conn.execute(
                text(
                    "SELECT value FROM system_setting "
                    "WHERE key = 'default_cvss_version'"
                )
            )
        ).scalar_one_or_none()
    assert version == expected_head, (version, expected_head)
    assert seed == "3.1", seed
    print("MIGRATION-HEAD-AND-SEED-OK")
    await engine.dispose()


asyncio.run(main())
"""


@pytest.mark.image
def test_packaged_migrations_reach_head_seed_without_drift(
    compose_exec: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
    result = compose_exec("api", "python", "-c", _HEAD_AND_SEED_CHECK_SCRIPT)
    assert result.returncode == 0, (
        f"migration head/seed check failed (rc={result.returncode}): "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "MIGRATION-HEAD-AND-SEED-OK" in result.stdout
    drift = compose_exec("api", "alembic", "check")
    assert drift.returncode == 0, (
        f"alembic check failed (rc={drift.returncode}): "
        f"stdout={drift.stdout!r} stderr={drift.stderr!r}"
    )


@pytest.mark.image
def test_failed_migration_prevents_every_runtime_role_from_starting(
    isolated_compose_stack: IsolatedComposeStack,
) -> None:
    """A disposable failed migration gates API, worker, Git worker, and Beat."""
    override = (
        "services:\n"
        "  api:\n"
        "    ports: !reset []\n"
        "  migrate:\n"
        '    command: ["alembic", "upgrade", '
        '"nonexistent_revision_id_smoke_test"]\n'
    )

    result = isolated_compose_stack.up(override, "api", "worker", "git-worker", "beat")
    assert result.returncode != 0, (
        f"expected non-zero exit when migrate fails "
        f"(stdout={result.stdout!r} stderr={result.stderr!r})"
    )

    migrate = isolated_compose_stack.service_state("migrate")
    assert migrate.returncode == 0, migrate.stderr
    assert migrate.stdout.strip().startswith("exited|"), migrate.stdout
    assert not migrate.stdout.strip().endswith("|0"), migrate.stdout
    migrate_logs = isolated_compose_stack.logs("migrate")
    assert "Can't locate revision identified by" in migrate_logs, migrate_logs
    assert "nonexistent_revision_id_smoke_test" in migrate_logs, migrate_logs

    for service in ("api", "worker", "git-worker", "beat"):
        state = isolated_compose_stack.service_state(service)
        assert state.returncode == 0, state.stderr
        assert not state.stdout.strip().startswith("running|"), (
            f"{service} unexpectedly started after migration failure: {state.stdout!r}"
        )
