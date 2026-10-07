"""Fetcher config bootstrap — idempotent `FetcherConfig` auto-creation.

See `docs/features/platform/fetcher-infrastructure.md` (Data Model —
FetcherConfig) for the full specification this module implements:
transaction contract, concurrency safety, empty-registry behavior, and
the "no audit event" guarantee.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.fetcher_config import FetcherConfig
from app.services.base_fetcher import FETCHER_REGISTRY


async def bootstrap_fetcher_configs(db: AsyncSession) -> None:
    """Idempotently ensure a `FetcherConfig` row exists for every
    registered fetcher.

    Executes a single batch `INSERT ... ON CONFLICT (fetcher_name) DO
    NOTHING` for every fetcher currently in `FETCHER_REGISTRY`, using
    each fetcher's own `default_request_delay` and the column defaults
    for every other field. Never modifies an existing row — an
    administrator-modified `FetcherConfig` (schedule override,
    disabled, custom run_timeout/request_delay/custom_settings) is
    always preserved. Flushes so database errors surface at this
    boundary. Never commits or rolls back — the caller's startup
    workflow (FastAPI lifespan, worker handler, Beat handler) owns the
    transaction.

    If `FETCHER_REGISTRY` is empty, still issues a bounded `SELECT`
    against `fetcher_config` instead of returning without touching the
    database — this preserves the fail-fast startup contract
    (`docs/deployment.md`, Startup Ordering): the process must fail if
    PostgreSQL or the table schema is unavailable, regardless of how
    many fetchers are currently registered.

    Creates no `FetcherAuditEvent` under any condition — this is
    idempotent initialization, not an administrative configuration
    change. Concurrent callers are safe: at most one insert succeeds
    per fetcher name, and every successful caller observes a completed
    insert or conflict before returning. Database availability,
    missing-table/schema, constraint, and flush failures propagate
    unchanged — this function does not catch, retry, or return partial
    success.
    """
    if not FETCHER_REGISTRY:
        await db.execute(select(FetcherConfig.fetcher_name).limit(1))
        await db.flush()
        return

    # Only `fetcher_name` and `request_delay` are set explicitly — every
    # other column (`enabled`, `schedule_override`, `run_timeout`,
    # `custom_settings`) is left for SQLAlchemy's Column-level defaults
    # to populate. This is a Core-level mechanism (not ORM-specific) that
    # applies correctly to a multi-row VALUES insert: each omitted column
    # receives its `FetcherConfig` mapped_column default independently
    # per row, verified empirically against PostgreSQL.
    stmt = (
        pg_insert(FetcherConfig)
        .values(
            [
                {
                    "fetcher_name": fetcher.name,
                    "request_delay": fetcher.default_request_delay,
                }
                for fetcher in FETCHER_REGISTRY.values()
            ]
        )
        .on_conflict_do_nothing(index_elements=["fetcher_name"])
    )
    await db.execute(stmt)
    await db.flush()
