"""RedBeat schedule construction, upsert/delete, startup reconciliation,
and PATCH post-commit propagation.

See `docs/features/platform/fetcher-infrastructure.md` (Celery Beat
Schedule Synchronization) for the full specification this module
implements: effective schedule resolution, redbeat entry structure and
options, startup reconciliation steps, and the PostgreSQL-master /
redbeat-slave architecture. See
`docs/features/platform/fetcher-operations.md` (RedBeat Post-Commit
Propagation) for `propagate_config_update()`'s contract.

`upsert_fetcher_entry`, `delete_fetcher_entry`, and
`reconcile_beat_schedule` are called by the Beat startup handler
(`app/tasks/beat_startup.py`) — worker processes never write redbeat
entries (see "Who Writes Where" in the owning spec).
`propagate_config_update()` is called by the
`PATCH /api/v1/fetchers/{fetcher_name}/config` endpoint's post-commit
callback (`app/api/v1/fetchers.py`) — the API server process is the
other redbeat writer (see "Who Writes Where"). All writers use the
`redbeat.RedBeatSchedulerEntry` public API exclusively; no raw Redis
key is ever constructed by this module (see `docs/conventions.md`,
Redis Key Conventions). Enumeration of the full stored schedule
(`_iter_all_entries`) uses the shape confirmed by RedBeat's own
maintainer as the supported way to list every entry — see
https://github.com/sibson/redbeat/issues/155 — since
`RedBeatScheduler.schedule` is a due-now query, not a full-schedule
accessor.

All public functions in this module propagate exceptions from the
underlying redbeat/Redis client (typically `redis.exceptions.RedisError`)
and from `celery.schedules.crontab.from_string` (`ValueError` on an
invalid cron expression) uncaught. No function in this module creates
audit events. `reconcile_beat_schedule` is idempotent: re-running it
with unchanged PostgreSQL/registry state reproduces the same redbeat
state. `propagate_config_update()` is not idempotent in the general
sense — each call applies the specific `action` requested by the
caller — but calling it twice with the same arguments reproduces the
same redbeat state (both `upsert_fetcher_entry` and
`delete_fetcher_entry` are themselves idempotent).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from math import floor
from typing import Any, Literal, Protocol

import structlog
from celery import Celery
from celery.schedules import crontab
from redbeat import RedBeatSchedulerEntry
from redbeat.schedulers import ensure_conf, get_redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FetcherRunTriggeredBy
from app.models.fetcher_config import FetcherConfig
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher

logger = structlog.get_logger(__name__)

# Celery task name every redbeat fetcher entry is registered under (see
# fetcher-infrastructure.md, Celery Integration). Reconciliation step 4
# uses it as a strict pre-filter to protect static/framework entries.
_RUN_FETCHER_TASK_NAME = "run_fetcher"


class _ScheduleConfigLike(Protocol):
    """Structural type for the two `FetcherConfig` attributes needed to
    build a redbeat entry: `schedule_override` and `run_timeout`.

    `_effective_schedule`, `_effective_options`, `_build_entry`, and
    `upsert_fetcher_entry` accept this Protocol instead of the concrete
    `FetcherConfig` ORM type so they can also be called with a
    lightweight, detached snapshot — see `_ConfigSnapshot` and
    `propagate_config_update()` below, used by the PATCH endpoint's
    post-commit callback (`docs/features/platform/fetcher-operations.md`,
    RedBeat Post-Commit Propagation). `FetcherConfig` itself satisfies
    this Protocol structurally; no change to its own definition or to
    the startup-reconciliation call sites is needed. Declared as
    read-only `@property` members (rather than plain attribute
    annotations) so a frozen (read-only) dataclass like
    `_ConfigSnapshot` can satisfy the Protocol structurally — a plain
    attribute annotation requires a settable member, which
    `_ConfigSnapshot`'s frozen fields are not.
    """

    @property
    def schedule_override(self) -> str | None: ...

    @property
    def run_timeout(self) -> int: ...


@dataclass(frozen=True)
class ReconciliationSummary:
    """Outcome counters for one full startup reconciliation pass.

    `written`: number of enabled, registered fetchers whose entry was
    created or overwritten (step 2). `disabled_removed`: number of
    entries actually deleted for a registered-but-disabled fetcher
    (step 3) — a disabled fetcher with no pre-existing entry
    contributes 0, not 1. `deregistered_removed`: number of entries
    deleted in step 4, whether removed for being deregistered or
    corrupted (both are removed for the same underlying reason: they
    do not belong to a currently enabled, registered fetcher).
    """

    written: int
    disabled_removed: int
    deregistered_removed: int


def _effective_schedule(
    fetcher: type[BaseFetcher], config: _ScheduleConfigLike
) -> crontab:
    """Resolve and parse the effective cron schedule for `fetcher`.

    `config.schedule_override` wins when set; otherwise
    `fetcher.default_schedule`. Raises `ValueError` (from
    `crontab.from_string`) if the effective value is not a valid
    5-field cron expression — this propagates uncaught to the caller,
    which fails the entire reconciliation pass (see
    fetcher-infrastructure.md, Startup Reconciliation step 2).
    """
    raw = config.schedule_override or fetcher.default_schedule
    return crontab.from_string(raw)


def effective_task_time_limits(run_timeout: int) -> dict[str, int]:
    """Derive the `time_limit`/`soft_time_limit` Celery task options from
    `run_timeout`, per the formulas in fetcher-infrastructure.md (Redbeat
    Entry Structure, Options field) and fetcher-operations.md
    (`trigger_fetcher`, Celery Publication): `time_limit = max(5,
    run_timeout)`, `soft_time_limit = max(1, floor(run_timeout * 0.95))`.

    Shared by `_effective_options()` below (RedBeat schedule entries) and
    `app.services.fetcher_operations.trigger_fetcher()` (manual trigger
    publication) so both call sites derive the same values from a single
    formula.
    """
    return {
        "time_limit": max(5, run_timeout),
        "soft_time_limit": max(1, floor(run_timeout * 0.95)),
    }


def _effective_options(
    fetcher: type[BaseFetcher], config: _ScheduleConfigLike
) -> dict[str, Any]:
    """Build the `apply_async()` options dict for `fetcher`'s redbeat entry.

    Always includes `time_limit` and `soft_time_limit` (see
    `effective_task_time_limits`). Includes `queue` only when
    `fetcher.queue` is not `None`.
    """
    options: dict[str, Any] = dict(effective_task_time_limits(config.run_timeout))
    if fetcher.queue is not None:
        options["queue"] = fetcher.queue
    return options


def _build_entry(
    celery_app: Celery, fetcher: type[BaseFetcher], config: _ScheduleConfigLike
) -> RedBeatSchedulerEntry:
    """Construct the canonical, unsaved redbeat entry for `fetcher`.

    See fetcher-infrastructure.md (Redbeat Entry Structure) for the
    exact shape: the entry name equals `fetcher.name`, the task is
    always `"run_fetcher"`, and kwargs identify the fetcher and mark
    the trigger origin as `"schedule"`.
    """
    return RedBeatSchedulerEntry(
        name=fetcher.name,
        task=_RUN_FETCHER_TASK_NAME,
        schedule=_effective_schedule(fetcher, config),
        args=[],
        kwargs={
            "fetcher_name": fetcher.name,
            "triggered_by": FetcherRunTriggeredBy.SCHEDULE.value,
        },
        options=_effective_options(fetcher, config),
        enabled=True,
        app=celery_app,
    )


def upsert_fetcher_entry(
    celery_app: Celery, fetcher: type[BaseFetcher], config: _ScheduleConfigLike
) -> None:
    """Create or unconditionally overwrite `fetcher`'s canonical redbeat entry.

    Calls `RedBeatSchedulerEntry.save()` (create-if-missing upsert),
    then `reschedule(now)` so `due_at` is always computed relative to
    the current time rather than inheriting a stale `last_run_at` that
    `save()` alone would preserve — redbeat's `save()` uses `HSETNX`
    for the meta hash, so a pre-existing entry's `last_run_at` survives
    an unqualified `save()` call. This matches
    fetcher-infrastructure.md (Startup Reconciliation step 2): "Runs
    missed during Beat downtime are not retroactively triggered."
    Propagates any `RedisError` from the underlying client uncaught.
    """
    entry = _build_entry(celery_app, fetcher, config)
    entry.save()
    entry.reschedule(datetime.now(UTC))


def fetcher_entry_key(celery_app: Celery, fetcher_name: str) -> str:
    """Return the redbeat key of `fetcher_name`'s canonical entry.

    Calls `ensure_conf()` first because
    `RedBeatSchedulerEntry.generate_key()` reads `app.redbeat_conf`
    without initializing it, unlike the library's other entry points.
    It raises `AttributeError` in a process where no earlier redbeat call
    has run, such as a freshly started API or CLI process (see
    https://github.com/sibson/redbeat/issues/345). Performs no Redis I/O.

    Also used by `app.services.fetcher_operations` to read `next_run_at`.
    """
    ensure_conf(celery_app)
    key: str = RedBeatSchedulerEntry.generate_key(celery_app, fetcher_name)
    return key


def delete_fetcher_entry(celery_app: Celery, fetcher_name: str) -> bool:
    """Delete `fetcher_name`'s canonical redbeat entry if it exists.

    Returns `True` if an entry existed and was deleted, `False` if no
    entry existed (no-op) — existence is checked via
    `RedBeatSchedulerEntry.from_key()` first, since
    `RedBeatSchedulerEntry.delete()` itself has no return value and
    silently no-ops on a missing key (its underlying `zrem`/`delete`
    Redis calls are idempotent). Propagates any `RedisError` uncaught.
    """
    key = fetcher_entry_key(celery_app, fetcher_name)
    try:
        RedBeatSchedulerEntry.from_key(key, app=celery_app)
    except KeyError:
        return False
    RedBeatSchedulerEntry(name=fetcher_name, app=celery_app).delete()
    return True


@dataclass(frozen=True)
class _ConfigSnapshot:
    """Minimal `_ScheduleConfigLike` snapshot carrying only the two
    post-mutation values needed to build a redbeat entry — no ORM
    reference, so it remains valid across the PATCH endpoint's commit
    boundary (`docs/conventions.md`, Transaction Hygiene Rules)."""

    schedule_override: str | None
    run_timeout: int


def propagate_config_update(
    celery_app: Celery,
    *,
    fetcher_name: str,
    action: Literal["delete", "upsert"],
    schedule_override: str | None = None,
    run_timeout: int = 0,
) -> None:
    """Apply one post-commit redbeat propagation step for a single PATCH.

    Called by the `PATCH /api/v1/fetchers/{fetcher_name}/config`
    endpoint's post-commit callback
    (`app.services.fetcher_operations.update_fetcher_config()` builds
    the descriptor this function consumes) — see
    `docs/features/platform/fetcher-operations.md` (RedBeat Post-Commit
    Propagation) for the precedence rules. The caller has already
    resolved which single `action` applies; this function does not
    re-evaluate precedence.

    `action="delete"` removes the canonical entry unconditionally
    (idempotent — see `delete_fetcher_entry`). `action="upsert"` looks
    up `fetcher_name` in `FETCHER_REGISTRY` — guaranteed present,
    since `update_fetcher_config()` rejects any mutation on a
    deregistered fetcher before a propagation descriptor is ever built
    — and creates/overwrites its canonical entry using the caller-
    supplied, already-resolved post-mutation `schedule_override` and
    `run_timeout` (not re-read from the database — the caller computed
    the effective post-PATCH state under its own `FetcherConfig` row
    lock).

    Propagates any `RedisError` from the underlying client uncaught —
    the caller is responsible for catching it, logging a WARNING, and
    preserving the already-committed PostgreSQL state, per the section
    above.
    """
    if action == "delete":
        delete_fetcher_entry(celery_app, fetcher_name)
        return

    fetcher = FETCHER_REGISTRY[fetcher_name]
    snapshot = _ConfigSnapshot(
        schedule_override=schedule_override, run_timeout=run_timeout
    )
    upsert_fetcher_entry(celery_app, fetcher, snapshot)


def _iter_all_entries(celery_app: Celery) -> list[RedBeatSchedulerEntry]:
    """Load every entry currently stored in redbeat's schedule sorted set.

    Uses the supported enumeration shape — `ensure_conf()` +
    `get_redis()` + `zrange()` over `redbeat_conf.schedule_key`, then
    `RedBeatSchedulerEntry.from_key()` per key — the one redbeat's
    maintainer confirmed as the supported way to list the whole
    schedule (`RedBeatScheduler.schedule` is a due-now query, not an
    accessor for the full stored schedule — see upstream
    sibson/redbeat#155). No raw Redis key string is constructed:
    `schedule_key` and the per-entry keys stored in the sorted set are
    both read through redbeat's own config/`RedBeatSchedulerEntry`
    objects, never assembled from a hardcoded prefix.

    A sorted-set member whose backing hash is missing by the time
    `from_key()` reads it (the two are separate Redis reads, so a gap
    between them is possible in principle) is treated as orphaned: it
    is removed from the sorted set and skipped, mirroring the
    self-healing behavior of redbeat's own due-task query
    (`RedBeatScheduler.schedule`, which performs the same
    zrange + from_key + zrem-on-KeyError sequence) — see
    https://github.com/sibson/redbeat/blob/d55325e653c124c52778c78accc8279450e7cc8f/redbeat/schedulers.py#L564-L570.
    None of Sentinel's own writes (`upsert_fetcher_entry`,
    `delete_fetcher_entry`) can produce this state — both rely on a
    single atomic `redis-py` pipeline (`transaction=True`, the
    default) that updates the hash and the sorted-set member together
    — so this path is only reachable through direct Redis
    manipulation outside Sentinel's control.
    """
    conf = ensure_conf(celery_app)
    redis_client = get_redis(celery_app)
    keys = redis_client.zrange(conf.schedule_key, 0, -1)
    entries: list[RedBeatSchedulerEntry] = []
    for key in keys:
        try:
            entries.append(RedBeatSchedulerEntry.from_key(key, app=celery_app))
        except KeyError:
            logger.warning("redbeat_orphaned_schedule_member_removed", key=key)
            redis_client.zrem(conf.schedule_key, key)
            continue
    return entries


async def reconcile_beat_schedule(
    db: AsyncSession, celery_app: Celery
) -> ReconciliationSummary:
    """Full startup reconciliation of the redbeat schedule against
    PostgreSQL + `FETCHER_REGISTRY`.

    Implements Reconciliation Steps 1-5 in
    fetcher-infrastructure.md (Startup Reconciliation). Called once, by
    the Beat startup handler, after `bootstrap_fetcher_configs()` has
    committed and the redbeat distributed lock has been confirmed
    acquired.

    Step 1: queries every `FetcherConfig` row in one `SELECT`. Every
    fetcher in `FETCHER_REGISTRY` is expected to already have a row —
    `bootstrap_fetcher_configs()` runs immediately before this function
    in the Beat startup sequence. A missing row is treated as a bug in
    that ordering, not a condition this function tolerates: it raises
    `RuntimeError` immediately.

    Step 2: for every registered fetcher with `config.enabled = True`,
    unconditionally upserts its canonical entry (`upsert_fetcher_entry`).

    Step 3: for every registered fetcher with `config.enabled = False`,
    deletes its canonical entry if present (`delete_fetcher_entry`).

    Step 4: enumerates the entire redbeat schedule
    (`_iter_all_entries`). The task-name pre-filter is applied first —
    an entry whose `task` is not `"run_fetcher"` is skipped
    unconditionally without ever reading its `kwargs`, protecting
    static/framework entries regardless of their shape. For a
    `run_fetcher`-tasked entry: if `kwargs["fetcher_name"]` is missing,
    not a string, empty, or does not match the entry's own `name` (a
    non-canonical alias — see fetcher-infrastructure.md, Reconciliation
    Steps, step 4), the entry is treated as corrupted, deleted, and
    logged at WARNING. If `fetcher_name` matches the entry's own name
    but is absent from `FETCHER_REGISTRY`, the entry is deregistered,
    deleted, and logged at INFO. An entry that passes both checks
    (registered, canonical name) is left untouched by step 4 — steps
    2-3 and step 4 target disjoint entry sets by construction (registry
    membership).

    Step 5: logs one INFO summary with the three counters.

    Idempotent: re-running with unchanged PostgreSQL/registry state
    reproduces the exact same redbeat state (step 2 unconditionally
    overwrites; step 3/4 deletions are no-ops when nothing matches).

    Raises:
        RuntimeError: a registered fetcher has no `FetcherConfig` row
            (bootstrap ordering bug).
        ValueError: a fetcher's effective schedule is not a valid
            5-field cron expression.
        redis.exceptions.RedisError (or any other exception from the
            underlying redbeat/Redis client): propagates immediately —
            fail-on-first-error semantics per fetcher-infrastructure.md
            (Startup Failure: Redis Error During Reconciliation).
        Exception: any database error from the step-1 `SELECT`
            propagates per Startup Failure: PostgreSQL Unreachable.

    In every failure case, the caller (the Beat startup handler) logs
    CRITICAL and exits — this function performs no error handling of
    its own beyond the fail-on-first-error propagation above.
    """
    result = await db.execute(select(FetcherConfig))
    configs_by_name = {c.fetcher_name: c for c in result.scalars().all()}

    written = 0
    disabled_removed = 0
    for name, fetcher in FETCHER_REGISTRY.items():
        config = configs_by_name.get(name)
        if config is None:
            raise RuntimeError(
                f"No FetcherConfig row for registered fetcher '{name}' during "
                "reconciliation — bootstrap_fetcher_configs() must run first"
            )
        if config.enabled:
            upsert_fetcher_entry(celery_app, fetcher, config)
            written += 1
        elif delete_fetcher_entry(celery_app, name):
            disabled_removed += 1

    deregistered_removed = 0
    for entry in _iter_all_entries(celery_app):
        if entry.task != _RUN_FETCHER_TASK_NAME:
            continue

        kwargs = entry.kwargs if isinstance(entry.kwargs, dict) else {}
        fetcher_name = kwargs.get("fetcher_name")

        if not fetcher_name or fetcher_name != entry.name:
            logger.warning("redbeat_corrupted_entry_removed", entry_name=entry.name)
            entry.delete()
            deregistered_removed += 1
            continue

        if fetcher_name not in FETCHER_REGISTRY:
            logger.info("redbeat_deregistered_entry_removed", fetcher_name=fetcher_name)
            entry.delete()
            deregistered_removed += 1

    logger.info(
        "beat_schedule_reconciliation_complete",
        written=written,
        disabled_removed=disabled_removed,
        deregistered_removed=deregistered_removed,
    )
    return ReconciliationSummary(
        written=written,
        disabled_removed=disabled_removed,
        deregistered_removed=deregistered_removed,
    )
