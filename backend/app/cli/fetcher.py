"""`sentinel fetcher` command group: list and config (read-only diagnostics).

See `docs/features/platform/fetcher-operations.md` (CLI Commands) for the
authoritative per-command contract (parameters, exact output, ordering,
error messages, exit codes) this module implements, and
`docs/features/platform/cli-infrastructure.md` for the shared bootstrap,
session, and error-mapping mechanism it builds on.

Module-level imports are intentionally limited to Core-layer modules and
third-party libraries that do not instantiate `Settings` — `app.celery_app`
(which imports `app.config`, builds the Celery singleton, and imports
`app.services.fetcher_discovery` as a side effect) and
`app.services.fetcher_operations` are imported lazily, inside each
command's own workflow, after `app.cli._runtime.bootstrap()` has already
validated `Settings`. Mirrors `app.cli.manage_user`'s and
`app.cli.api_key`'s module docstring rationale — `--help` at every level
must never load application settings or open a database/Redis connection.

Both commands are read-only: they delegate to the `fetcher_operations`
service module for data retrieval and issue no commit, no flush, and no
audit event. All mutations (trigger, enable/disable, configuration
changes) are done exclusively through the API — see
`docs/features/platform/fetcher-operations.md` (CLI Commands).
"""

from __future__ import annotations

import asyncio
import json
import math
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import click

from app.cli._runtime import bootstrap, get_session_factory
from app.core.enums import FetcherRunStatus

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.services.fetcher_operations import (
        FetcherConfigResult,
        FetcherListItem,
        FetcherRunSummary,
    )

_LIST_HEADERS = ("Name", "Enabled", "Last Run", "Status", "Settings")
_DEREGISTERED_HEADERS = ("Name", "Last Run", "Status")


@click.group("fetcher")
def fetcher_group() -> None:
    """Read-only diagnostic access to the fetcher infrastructure.

    This group callback is intentionally a no-op — see
    `app.cli.manage_user.manage_user_group`'s identical docstring
    rationale: Click invokes a group's own callback before creating its
    child command's context, including for a child's own `--help`, so
    bootstrap logic cannot live here.
    """


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


@fetcher_group.command("list")
def list_command() -> None:
    """List all fetchers (registered and deregistered) with their
    current state.

    See `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher list`) for the full behavioral contract.
    """
    bootstrap()

    items = asyncio.run(_list_flow(get_session_factory()))
    click.echo(_render_fetcher_list(items))


async def _list_flow(
    session_factory: async_sessionmaker[AsyncSession],
) -> list[FetcherListItem]:
    """Read every fetcher via `fetcher_operations.list_fetchers()`.

    Read-only: opens a session, delegates the query, and issues no
    commit — see `docs/features/platform/cli-infrastructure.md`
    (Database Session Management). `has_manage_fetchers=False`: this
    command never surfaces `triggered_by_user` (no admin-capability
    concept applies to a local shell invocation, and the rendered table
    does not display that field regardless).
    """
    from app.celery_app import celery_app
    from app.services import fetcher_operations

    async with session_factory() as db:
        return await fetcher_operations.list_fetchers(
            db, has_manage_fetchers=False, celery_app=celery_app
        )


def _render_fetcher_list(items: list[FetcherListItem]) -> str:
    """Render the `fetcher list` output: a registered-fetchers table,
    followed by a deregistered-fetchers table (only when at least one
    deregistered fetcher exists) — see
    `docs/features/platform/fetcher-operations.md` (`sentinel fetcher
    list`, Output, Ordering)."""
    now = datetime.now(UTC)
    registered = sorted(
        (item for item in items if item.registered),
        key=lambda item: item.fetcher_name,
    )
    deregistered = sorted(
        (item for item in items if not item.registered),
        key=lambda item: item.fetcher_name,
    )

    sections = [
        _render_table(
            _LIST_HEADERS,
            [_render_registered_row(item, now) for item in registered],
        )
    ]
    if deregistered:
        sections.append("")
        sections.append("Deregistered (historical data only):")
        sections.append(
            _render_table(
                _DEREGISTERED_HEADERS,
                [_render_deregistered_row(item, now) for item in deregistered],
            )
        )
    return "\n".join(sections)


def _render_registered_row(
    item: FetcherListItem, now: datetime
) -> tuple[str, str, str, str, str]:
    return (
        item.fetcher_name,
        "yes" if item.enabled else "no",
        _format_last_run(item.last_run),
        _render_run_status(item.last_run, now),
        _render_settings_count(item.custom_settings_count),
    )


def _render_deregistered_row(
    item: FetcherListItem, now: datetime
) -> tuple[str, str, str]:
    return (
        item.fetcher_name,
        _format_last_run(item.last_run),
        _render_run_status(item.last_run, now),
    )


def _render_settings_count(count: int) -> str:
    return "—" if count == 0 else f"{count} custom"


def _format_last_run(run: FetcherRunSummary | None) -> str:
    """`created_at` in `YYYY-MM-DD HH:MM UTC` — not `started_at`, so a
    `queued` run (whose `started_at` is `None`) is still displayed. `—`
    if no runs exist."""
    if run is None:
        return "—"
    return run.created_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _render_run_status(run: FetcherRunSummary | None, now: datetime) -> str:
    """Render the Status column for one fetcher's last run — see
    `docs/features/platform/fetcher-operations.md` (`sentinel fetcher
    list`, Status column) for the full precedence and formatting rules.

    `run.stale` is the shared `is_run_stale()` result already computed
    by the service — this function never re-derives staleness from the
    elapsed time it renders, so its threshold logic can never drift
    from the API's own.
    """
    if run is None:
        return "never run"
    if run.status == FetcherRunStatus.QUEUED.value:
        elapsed = (now - run.created_at).total_seconds()
        suffix = ", stale?" if run.stale else ""
        return f"queued ({_format_duration(elapsed)} elapsed{suffix})"
    if run.status == FetcherRunStatus.RUNNING.value:
        # `started_at` is always set for a `running` row; the fallback
        # to `created_at` only guards a theoretically inconsistent row.
        started = run.started_at if run.started_at is not None else run.created_at
        elapsed = (now - started).total_seconds()
        suffix = ", stale?" if run.stale else ""
        return f"running ({_format_duration(elapsed)} elapsed{suffix})"
    if run.duration_seconds is not None:
        return f"{run.status} ({_format_duration(run.duration_seconds)})"
    return run.status


def _format_duration(seconds: float) -> str:
    """Render a duration as `Xs` (<60s), `Xm Ys` (<60m), or `Xh Ym`
    (>=60m), always rounded down to the nearest whole unit — see
    `docs/features/platform/fetcher-operations.md` (`sentinel fetcher
    list`, Status column, Elapsed formatting). Negative input (clock
    skew) is clamped to zero."""
    total_seconds = max(0, math.floor(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _render_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    """Render a fixed-width table (header + rows), two-space column
    separator, no truncation. Duplicated from the near-identical
    `_render_key_table`/`_render_list_table` in `app.cli.api_key`/
    `app.cli.manage_user` rather than shared — see `api_key`'s
    `_format_utc` docstring for the identical rationale (an
    unnecessary coupling for a small, self-contained function)."""
    all_rows = [headers, *rows]
    widths = [max(len(row[i]) for row in all_rows) for i in range(len(headers))]
    lines = [
        "  ".join(row[i].ljust(widths[i]) for i in range(len(headers))).rstrip()
        for row in all_rows
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


@fetcher_group.command("config")
@click.argument(
    "name",
    help="Fetcher name, registered or deregistered (e.g. sync_nvd_cves).",
)
def config_command(name: str) -> None:
    """Display the full configuration of a fetcher, including custom
    settings with their current values, defaults, and descriptions.

    See `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher config`) for the full behavioral contract.
    """
    bootstrap()

    config = asyncio.run(_config_flow(get_session_factory(), name))
    click.echo(_render_fetcher_config(config))


async def _config_flow(
    session_factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> FetcherConfigResult:
    """Look up `fetcher_name` via `fetcher_operations.get_fetcher_config()`.

    Read-only: opens a session, delegates the query, and issues no
    commit. Translates `FetcherNotFoundError` into the command's exact
    not-found message and exit code.
    """
    import app.services.fetcher_discovery  # noqa: F401  (populates FETCHER_REGISTRY)
    from app.services import fetcher_operations
    from app.services.fetcher_operations import FetcherNotFoundError

    async with session_factory() as db:
        try:
            return await fetcher_operations.get_fetcher_config(
                db, fetcher_name=fetcher_name
            )
        except FetcherNotFoundError:
            click.echo(f"Error: Fetcher '{fetcher_name}' not found.", err=True)
            raise SystemExit(1) from None


def _render_fetcher_config(config: FetcherConfigResult) -> str:
    """Render the `fetcher config` output — see
    `docs/features/platform/fetcher-operations.md` (`sentinel fetcher
    config`) for the full behavioral contract.

    A fetcher is deregistered when `default_schedule is None` — see
    `app.services.fetcher_operations.FetcherConfigResult`'s own
    docstring ("`default_schedule` and `settings_schema` are `None` for
    a deregistered fetcher"). This avoids a second, redundant registry
    lookup in the CLI layer.
    """
    deregistered = config.default_schedule is None

    lines = [
        f"Fetcher: {config.fetcher_name} (deregistered)"
        if deregistered
        else f"Fetcher: {config.fetcher_name}",
        f"Enabled: {'yes' if config.enabled else 'no'}",
    ]

    if deregistered:
        override_display = config.schedule_override or "—"
        lines.append(f"Schedule override: {override_display}")
    else:
        suffix = "override" if config.schedule_override is not None else "default"
        lines.append(f"Schedule: {config.effective_schedule} ({suffix})")

    lines.append(f"Timeout: {config.run_timeout}s")
    lines.append(f"Request delay: {_format_scalar(config.request_delay)}s")
    lines.append("")

    if deregistered:
        lines.extend(_render_deregistered_settings(config.custom_settings))
    else:
        lines.extend(
            _render_registered_settings(config.custom_settings, config.settings_schema)
        )

    return "\n".join(lines)


def _render_registered_settings(
    custom_settings: dict[str, Any], settings_schema: dict[str, Any] | None
) -> list[str]:
    """Render the "Custom settings:"/"Orphaned settings" sections for a
    registered fetcher — see `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher config`, Ordering of custom settings, Value
    display, Value rendering)."""
    if settings_schema is None:
        return ["No custom settings available for this fetcher."]

    properties: dict[str, Any] = settings_schema.get("properties", {})
    defs: dict[str, Any] = settings_schema.get("$defs", {})

    lines: list[str] = []
    if properties:
        lines.append("Custom settings:")
        for key in sorted(properties):
            resolved_prop = _resolve_schema_property(properties[key], defs)
            lines.extend(_render_setting_line(key, resolved_prop, custom_settings))

    orphaned_keys = sorted(key for key in custom_settings if key not in properties)
    if orphaned_keys:
        if lines:
            lines.append("")
        lines.append("Orphaned settings (no longer in schema):")
        for key in orphaned_keys:
            lines.append(f"  {key} = {_format_scalar(custom_settings[key])}")

    return lines if lines else ["No custom settings available for this fetcher."]


def _render_deregistered_settings(custom_settings: dict[str, Any]) -> list[str]:
    """Render the raw custom-settings snapshot for a deregistered
    fetcher — see `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher config`, Deregistered output differences)."""
    if not custom_settings:
        return ["No custom settings stored."]
    lines = ["Custom settings (schema unavailable — raw stored values):"]
    for key in sorted(custom_settings):
        lines.append(f"  {key} = {_format_scalar(custom_settings[key])}")
    return lines


def _resolve_schema_property(
    prop: dict[str, Any], defs: dict[str, Any]
) -> dict[str, Any]:
    """Resolve a single-level local `$ref` (Pydantic's representation
    for an Enum-typed field) against the schema's `$defs`.

    Pydantic keeps `default`/`description` on the referencing property
    itself and moves `enum`/`type` into the `$defs` entry — verified
    directly against `Settings.model_json_schema()` output for an
    Enum-typed field. The referenced entry is merged first so the
    property's own keys (in particular `default`/`description`) take
    precedence."""
    ref = prop.get("$ref")
    if ref is None:
        return prop
    key = ref.rsplit("/", 1)[-1]
    resolved = dict(defs.get(key, {}))
    resolved.update({k: v for k, v in prop.items() if k != "$ref"})
    return resolved


def _render_setting_line(
    key: str, prop: dict[str, Any], custom_settings: dict[str, Any]
) -> list[str]:
    """Render one custom-setting entry (value line + optional
    description line) — see `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher config`, Value display). `range` is shown only
    when the schema declares both a `minimum` and a `maximum`
    (Pydantic's JSON Schema representation of `ge`/`le`), per the
    spec's explicit scoping to `ge`/`le` constraints."""
    explicit = key in custom_settings
    default = prop.get("default")
    value = custom_settings[key] if explicit else default

    metadata_parts = [f"default: {_format_scalar(default)}" if explicit else "default"]
    if "minimum" in prop and "maximum" in prop:
        low = _format_scalar(prop["minimum"])
        high = _format_scalar(prop["maximum"])
        metadata_parts.append(f"range: {low}\u2013{high}")
    choices = prop.get("enum")
    if choices is not None:
        metadata_parts.append(
            "choices: " + ", ".join(_format_scalar(choice) for choice in choices)
        )

    lines = [f"  {key} = {_format_scalar(value)}  ({', '.join(metadata_parts)})"]
    description = prop.get("description")
    if description:
        lines.append(f"    {description}")
    return lines


def _format_scalar(value: Any) -> str:
    """Render a scalar in its natural display form — see
    `docs/features/platform/fetcher-operations.md` (`sentinel fetcher
    config`, Value rendering). A collection (list/dict) is not expected
    as a custom-setting value; if one is encountered (e.g. a raw
    orphaned key predating a schema change), it is rendered as
    deterministic JSON rather than Python's `repr()`."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
