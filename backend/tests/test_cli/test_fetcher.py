"""Tests for `sentinel fetcher list/config`.

See `docs/features/platform/fetcher-operations.md` (CLI Commands) for the
authoritative per-command contract exercised here. Pure rendering helpers
are unit-tested directly against dataclass values (deterministic, no
wall-clock dependency). Integration tests exercise the full
`CliRunner`-invoked commands against the real PostgreSQL test database
via `cli_session_factory` (see docs/features/platform/testing-strategy.md,
Sync Entry-Point Tests) — mirrors `test_api_key.py`'s module docstring
rationale: setup data is inserted directly through `cli_session_factory`
rather than through `db_session`-based factories, which run on a
separate connection/event loop.

`FETCHER_REGISTRY` is snapshotted/restored around every test in this
file, mirroring `tests/test_services/test_fetcher_operations.py`'s
`_isolated_registry` fixture — the CLI delegates directly to the same
service functions tested there, so registry manipulation follows the
identical pattern.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Generator
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal, cast
from uuid import uuid4

import pytest
from celery import Celery
from click.testing import CliRunner, Result
from pydantic import BaseModel, Field
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.cli.fetcher as fetcher_module
from app.cli import cli
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import FETCHER_REGISTRY, BaseFetcher
from app.services.fetcher_operations import (
    FetcherConfigResult,
    FetcherListItem,
    FetcherRunSummary,
)


def _invoke(args: list[str], input: str | None = None) -> Result:
    """Invoke the raw `cli` group with `standalone_mode=False`, mirroring
    exactly how production's `main()` invokes it — see the identical
    helper in `test_main.py`/`test_manage_user.py`/`test_api_key.py`."""
    return CliRunner().invoke(cli, args, input=input, standalone_mode=False)


def _inject_session_factory(
    monkeypatch: pytest.MonkeyPatch,
    factory: async_sessionmaker[AsyncSession],
) -> None:
    monkeypatch.setattr(fetcher_module, "get_session_factory", lambda: factory)


def _inject_celery_app(monkeypatch: pytest.MonkeyPatch, celery_app: Celery) -> None:
    """Point the lazily-imported `from app.celery_app import celery_app`
    statement inside `_list_flow()` at the isolated test Celery/Redis
    app, mirroring `test_api/test_fetchers.py`'s `_patch_celery_app`
    fixture (which patches the same singleton for the API router)."""
    import app.celery_app as celery_app_module

    monkeypatch.setattr(celery_app_module, "celery_app", celery_app)


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this
    file — mirrors `tests/test_services/test_fetcher_operations.py`."""
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


def _register(*stubs: type[Any]) -> None:
    """Replace `FETCHER_REGISTRY` with exactly the given stub classes."""
    FETCHER_REGISTRY.clear()
    for stub in stubs:
        FETCHER_REGISTRY[stub.name] = stub


# ---------------------------------------------------------------------------
# Stub fetcher classes (deliberately NOT `BaseFetcher` subclasses — see
# `test_fetcher_operations.py`, Test Independence)
# ---------------------------------------------------------------------------


class _Mode(StrEnum):
    FAST = "fast"
    SLOW = "slow"


class _RichSettings(BaseModel):
    """Exercises range (`ge`/`le`), an Enum field (`$ref`/`$defs`
    resolution), a `Literal` field (inline `enum`), a float, and a
    bool — see `docs/features/platform/fetcher-operations.md`
    (`sentinel fetcher config`, Value display)."""

    results_per_page: int = Field(
        default=2000, ge=100, le=2000, description="Number of CVE records per API page."
    )
    mode: _Mode = Field(default=_Mode.FAST, description="Sync mode.")
    fmt: Literal["json", "xml"] = Field(default="json")
    ratio: float = Field(default=1.5, ge=0.0, le=10.0)
    verbose: bool = Field(default=False)


class _NoSettingsFetcherStub:
    name = "test_cli_no_settings"
    description = "Stub fetcher without custom settings"
    default_schedule = "0 3 * * *"
    queue: str | None = None
    Settings: type[BaseModel] | None = None


class _RichFetcherStub:
    name = "test_cli_rich_settings"
    description = "Stub fetcher with rich custom settings"
    default_schedule = "0 4 * * *"
    queue: str | None = None
    Settings = _RichSettings


_NoSettingsFetcher = cast("type[BaseFetcher]", _NoSettingsFetcherStub)
_RichFetcher = cast("type[BaseFetcher]", _RichFetcherStub)


# ---------------------------------------------------------------------------
# Direct-insert helpers (bypass `fetcher_operations`/`fetcher_bootstrap`
# entirely — mirrors `test_api_key.py`'s `_create_user_directly`)
# ---------------------------------------------------------------------------


async def _create_fetcher_config_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    fetcher_name: str,
    enabled: bool = True,
    schedule_override: str | None = None,
    run_timeout: int = 3600,
    request_delay: float = 0,
    custom_settings: dict[str, Any] | None = None,
) -> FetcherConfig:
    async with factory() as db:
        config = FetcherConfig(
            fetcher_name=fetcher_name,
            enabled=enabled,
            schedule_override=schedule_override,
            run_timeout=run_timeout,
            request_delay=request_delay,
            custom_settings=custom_settings or {},
        )
        db.add(config)
        await db.commit()
        return config


async def _create_fetcher_run_directly(
    factory: async_sessionmaker[AsyncSession],
    *,
    fetcher_name: str,
    status: str,
    created_at: datetime | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
    duration_seconds: float | None = None,
    triggered_by: str = "schedule",
    hard_time_limit_seconds: int | None = None,
) -> FetcherRun:
    async with factory() as db:
        kwargs: dict[str, Any] = {
            "fetcher_name": fetcher_name,
            "status": status,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration_seconds,
            "triggered_by": triggered_by,
            "hard_time_limit_seconds": hard_time_limit_seconds,
        }
        if created_at is not None:
            kwargs["created_at"] = created_at
        run = FetcherRun(**kwargs)
        db.add(run)
        await db.commit()
        return run


@pytest.fixture
def cleanup_fetchers_by_name(
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> Generator[Callable[..., None]]:
    """Return a function that marks fetcher names for FK-safe deletion
    at teardown — mirrors `cleanup_users_by_username` (conftest.py)."""
    pending: set[str] = set()

    def _mark(*names: str) -> None:
        pending.update(names)

    yield _mark

    if not pending:
        return

    async def _cleanup() -> None:
        async with cli_session_factory() as db:
            await db.execute(
                delete(FetcherRun).where(FetcherRun.fetcher_name.in_(pending))
            )
            await db.execute(
                delete(FetcherConfig).where(FetcherConfig.fetcher_name.in_(pending))
            )
            await db.commit()

    asyncio.run(_cleanup())


def _run_summary(
    *,
    status: str,
    created_at: datetime,
    started_at: datetime | None = None,
    duration_seconds: float | None = None,
    stale: bool = False,
) -> FetcherRunSummary:
    """Build a `FetcherRunSummary` for deterministic, wall-clock-free
    rendering tests — the `stale` field is supplied directly rather
    than derived, since `is_run_stale()` itself is tested in
    `test_fetcher_execution.py`."""
    return FetcherRunSummary(
        id=uuid4(),
        fetcher_name="stub",
        created_at=created_at,
        started_at=started_at,
        finished_at=None,
        duration_seconds=duration_seconds,
        status=status,
        items_succeeded=0,
        items_created=0,
        items_updated=0,
        items_failed=0,
        error_message=None,
        triggered_by="schedule",
        triggered_by_user=None,
        stale=stale,
    )


def _list_item(
    *,
    fetcher_name: str,
    registered: bool,
    enabled: bool = True,
    custom_settings_count: int = 0,
    last_run: FetcherRunSummary | None = None,
) -> FetcherListItem:
    return FetcherListItem(
        fetcher_name=fetcher_name,
        registered=registered,
        description="stub" if registered else None,
        enabled=enabled,
        effective_schedule="0 3 * * *" if registered else None,
        schedule_is_override=False if registered else None,
        default_schedule="0 3 * * *" if registered else None,
        cve_source_type=None,
        next_run_at=None,
        custom_settings_count=custom_settings_count,
        last_run=last_run,
    )


_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Unit: _format_duration
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "0s"),
        (5, "5s"),
        (59, "59s"),
        (59.9, "59s"),
        (60, "1m 0s"),
        (90, "1m 30s"),
        (3599, "59m 59s"),
        (3600, "1h 0m"),
        (3725, "1h 2m"),
        (-5, "0s"),
    ],
)
def test_format_duration(seconds: float, expected: str) -> None:
    assert fetcher_module._format_duration(seconds) == expected


# ---------------------------------------------------------------------------
# Unit: _format_last_run
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_format_last_run_none_renders_em_dash() -> None:
    assert fetcher_module._format_last_run(None) == "—"


@pytest.mark.unit
def test_format_last_run_uses_created_at_minute_precision() -> None:
    run = _run_summary(status="success", created_at=_NOW, duration_seconds=45.0)
    assert fetcher_module._format_last_run(run) == "2026-01-01 12:00 UTC"


# ---------------------------------------------------------------------------
# Unit: _render_settings_count
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("count", "expected"), [(0, "—"), (1, "1 custom"), (2, "2 custom")]
)
def test_render_settings_count(count: int, expected: str) -> None:
    assert fetcher_module._render_settings_count(count) == expected


# ---------------------------------------------------------------------------
# Unit: _render_run_status
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_run_status_none_is_never_run() -> None:
    assert fetcher_module._render_run_status(None, _NOW) == "never run"


@pytest.mark.unit
def test_render_run_status_queued_not_stale() -> None:
    run = _run_summary(
        status="queued", created_at=_NOW - timedelta(seconds=5), stale=False
    )
    assert fetcher_module._render_run_status(run, _NOW) == "queued (5s elapsed)"


@pytest.mark.unit
def test_render_run_status_queued_stale_matches_spec_example() -> None:
    run = _run_summary(
        status="queued", created_at=_NOW - timedelta(minutes=11, seconds=2), stale=True
    )
    assert (
        fetcher_module._render_run_status(run, _NOW)
        == "queued (11m 2s elapsed, stale?)"
    )


@pytest.mark.unit
def test_render_run_status_running_not_stale() -> None:
    run = _run_summary(
        status="running",
        created_at=_NOW - timedelta(minutes=2),
        started_at=_NOW - timedelta(minutes=1, seconds=30),
        stale=False,
    )
    assert fetcher_module._render_run_status(run, _NOW) == "running (1m 30s elapsed)"


@pytest.mark.unit
def test_render_run_status_running_stale_matches_spec_example() -> None:
    run = _run_summary(
        status="running",
        created_at=_NOW - timedelta(hours=1, minutes=2),
        started_at=_NOW - timedelta(hours=1, minutes=2),
        stale=True,
    )
    assert fetcher_module._render_run_status(run, _NOW) == (
        "running (1h 2m elapsed, stale?)"
    )


@pytest.mark.unit
def test_render_run_status_running_uses_started_at_not_created_at() -> None:
    """Elapsed is computed from `started_at`, not `created_at` — a
    `queued -> running` transition can leave a gap between the two."""
    run = _run_summary(
        status="running",
        created_at=_NOW - timedelta(minutes=10),
        started_at=_NOW - timedelta(seconds=5),
        stale=False,
    )
    assert fetcher_module._render_run_status(run, _NOW) == "running (5s elapsed)"


@pytest.mark.unit
@pytest.mark.parametrize("status", ["success", "failure", "partial"])
def test_render_run_status_terminal_with_duration(status: str) -> None:
    run = _run_summary(status=status, created_at=_NOW, duration_seconds=135.0)
    assert fetcher_module._render_run_status(run, _NOW) == f"{status} (2m 15s)"


@pytest.mark.unit
def test_render_run_status_failure_without_duration_shown_alone() -> None:
    """A `queued -> failure` pre-adoption run has no `duration_seconds`
    — shown as `failure` alone, per `sentinel fetcher list` (Status
    column, case 3)."""
    run = _run_summary(status="failure", created_at=_NOW, duration_seconds=None)
    assert fetcher_module._render_run_status(run, _NOW) == "failure"


# ---------------------------------------------------------------------------
# Unit: _render_table
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_table_empty_rows_renders_header_only() -> None:
    table = fetcher_module._render_table(("A", "BB"), [])
    assert table == "A  BB"


@pytest.mark.unit
def test_render_table_dynamic_column_widths_no_truncation() -> None:
    long_name = "a" * 64
    table = fetcher_module._render_table(("Name", "Status"), [(long_name, "yes")])
    lines = table.splitlines()
    assert long_name in lines[1]
    assert lines[1].startswith(long_name)


# ---------------------------------------------------------------------------
# Unit: _format_scalar
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "null"),
        (True, "true"),
        (False, "false"),
        (500, "500"),
        (1.5, "1.5"),
        (0.0, "0"),
        (10.0, "10"),
        ("api_url", "api_url"),
        ("", ""),
    ],
)
def test_format_scalar_natural_forms(value: Any, expected: str) -> None:
    assert fetcher_module._format_scalar(value) == expected


@pytest.mark.unit
def test_format_scalar_collection_falls_back_to_deterministic_json() -> None:
    assert fetcher_module._format_scalar({"b": 1, "a": 2}) == '{"a":2,"b":1}'


# ---------------------------------------------------------------------------
# Unit: _resolve_schema_property
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_schema_property_no_ref_passthrough() -> None:
    prop = {"type": "integer", "default": 5}
    assert fetcher_module._resolve_schema_property(prop, {}) == prop


@pytest.mark.unit
def test_resolve_schema_property_resolves_ref_merging_default_and_description() -> None:
    prop = {"$ref": "#/$defs/Mode", "default": "fast", "description": "Sync mode."}
    defs = {"Mode": {"enum": ["fast", "slow"], "type": "string", "title": "Mode"}}
    resolved = fetcher_module._resolve_schema_property(prop, defs)
    assert resolved["enum"] == ["fast", "slow"]
    assert resolved["default"] == "fast"
    assert resolved["description"] == "Sync mode."
    assert "$ref" not in resolved


# ---------------------------------------------------------------------------
# Unit: _render_setting_line
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_setting_line_explicit_value_with_range() -> None:
    prop = {
        "default": 2000,
        "minimum": 100,
        "maximum": 2000,
        "description": "Number of CVE records per API page.",
    }
    lines = fetcher_module._render_setting_line(
        "results_per_page", prop, {"results_per_page": 500}
    )
    assert lines == [
        "  results_per_page = 500  (default: 2000, range: 100\u20132000)",
        "    Number of CVE records per API page.",
    ]


@pytest.mark.unit
def test_render_setting_line_default_value_no_description() -> None:
    prop = {"default": False}
    lines = fetcher_module._render_setting_line("verbose", prop, {})
    assert lines == ["  verbose = false  (default)"]


@pytest.mark.unit
def test_render_setting_line_choices() -> None:
    prop = {"default": "json", "enum": ["json", "xml"]}
    lines = fetcher_module._render_setting_line("fmt", prop, {})
    assert lines == ["  fmt = json  (default, choices: json, xml)"]


# ---------------------------------------------------------------------------
# Unit: _render_registered_settings / _render_deregistered_settings
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_registered_settings_no_schema() -> None:
    assert fetcher_module._render_registered_settings({}, None) == [
        "No custom settings available for this fetcher."
    ]


@pytest.mark.unit
def test_render_registered_settings_no_orphans_omits_orphan_section() -> None:
    """Every stored key is recognized by the schema — no `"Orphaned
    settings"` section is rendered."""
    schema = _RichSettings.model_json_schema()
    lines = fetcher_module._render_registered_settings(
        {"results_per_page": 500}, schema
    )
    assert "Orphaned settings (no longer in schema):" not in lines


@pytest.mark.unit
def test_render_registered_settings_empty_properties_with_orphan() -> None:
    """A `Settings` model declaring zero fields (edge case) with a
    stored raw key renders only the orphaned-settings section, with no
    leading blank line (`lines` was empty when entering that block)."""
    schema: dict[str, Any] = {"properties": {}}
    lines = fetcher_module._render_registered_settings({"legacy_orphan": "raw"}, schema)
    assert lines == [
        "Orphaned settings (no longer in schema):",
        "  legacy_orphan = raw",
    ]


@pytest.mark.unit
def test_render_registered_settings_alphabetical_with_orphan() -> None:
    schema = _RichSettings.model_json_schema()
    custom_settings = {"results_per_page": 500, "legacy_orphan": "raw"}
    lines = fetcher_module._render_registered_settings(custom_settings, schema)
    assert lines[0] == "Custom settings:"
    orphan_header_index = lines.index("Orphaned settings (no longer in schema):")
    # Recognized keys alphabetical: fmt, mode, ratio, results_per_page, verbose.
    setting_lines = [
        line
        for line in lines[:orphan_header_index]
        if line.startswith("  ") and "=" in line
    ]
    keys_in_order = [line.strip().split(" = ")[0] for line in setting_lines]
    assert keys_in_order == ["fmt", "mode", "ratio", "results_per_page", "verbose"]
    assert "  legacy_orphan = raw" in lines


@pytest.mark.unit
def test_render_deregistered_settings_empty() -> None:
    assert fetcher_module._render_deregistered_settings({}) == [
        "No custom settings stored."
    ]


@pytest.mark.unit
def test_render_deregistered_settings_alphabetical_raw_values() -> None:
    lines = fetcher_module._render_deregistered_settings({"zeta": 1, "alpha": "value"})
    assert lines == [
        "Custom settings (schema unavailable — raw stored values):",
        "  alpha = value",
        "  zeta = 1",
    ]


# ---------------------------------------------------------------------------
# Unit: _render_fetcher_config (full assembly)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_fetcher_config_registered_default_schedule_no_settings() -> None:
    config = FetcherConfigResult(
        fetcher_name="sync_nvd_cves",
        enabled=True,
        schedule_override=None,
        default_schedule="0 */6 * * *",
        effective_schedule="0 */6 * * *",
        run_timeout=3600,
        request_delay=0,
        custom_settings={},
        settings_schema=None,
        updated_at=_NOW,
    )
    output = fetcher_module._render_fetcher_config(config)
    assert output == (
        "Fetcher: sync_nvd_cves\n"
        "Enabled: yes\n"
        "Schedule: 0 */6 * * * (default)\n"
        "Timeout: 3600s\n"
        "Request delay: 0s\n"
        "\n"
        "No custom settings available for this fetcher."
    )


@pytest.mark.unit
def test_render_fetcher_config_registered_schedule_override_suffix() -> None:
    config = FetcherConfigResult(
        fetcher_name="sync_redhat_cves",
        enabled=True,
        schedule_override="0 */2 * * *",
        default_schedule="0 3 * * *",
        effective_schedule="0 */2 * * *",
        run_timeout=3600,
        request_delay=2.5,
        custom_settings={},
        settings_schema=None,
        updated_at=_NOW,
    )
    output = fetcher_module._render_fetcher_config(config)
    assert "Schedule: 0 */2 * * * (override)" in output
    assert "Request delay: 2.5s" in output


@pytest.mark.unit
def test_render_fetcher_config_deregistered_with_settings() -> None:
    config = FetcherConfigResult(
        fetcher_name="old_fetcher",
        enabled=True,
        schedule_override="0 */6 * * *",
        default_schedule=None,
        effective_schedule="0 */6 * * *",
        run_timeout=3600,
        request_delay=0,
        custom_settings={"results_per_page": 500},
        settings_schema=None,
        updated_at=_NOW,
    )
    output = fetcher_module._render_fetcher_config(config)
    assert output == (
        "Fetcher: old_fetcher (deregistered)\n"
        "Enabled: yes\n"
        "Schedule override: 0 */6 * * *\n"
        "Timeout: 3600s\n"
        "Request delay: 0s\n"
        "\n"
        "Custom settings (schema unavailable — raw stored values):\n"
        "  results_per_page = 500"
    )


@pytest.mark.unit
def test_render_fetcher_config_deregistered_no_override_and_no_settings() -> None:
    config = FetcherConfigResult(
        fetcher_name="old_fetcher",
        enabled=False,
        schedule_override=None,
        default_schedule=None,
        effective_schedule=None,
        run_timeout=3600,
        request_delay=0,
        custom_settings={},
        settings_schema=None,
        updated_at=_NOW,
    )
    output = fetcher_module._render_fetcher_config(config)
    assert "Schedule override: —" in output
    assert "Enabled: no" in output
    assert output.endswith("No custom settings stored.")


# ---------------------------------------------------------------------------
# Unit: _render_fetcher_list (full assembly, ordering/sections)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_render_fetcher_list_sections_ordering_and_omission() -> None:
    items = [
        _list_item(fetcher_name="zz_registered", registered=True),
        _list_item(fetcher_name="aa_registered", registered=True),
        _list_item(fetcher_name="zz_deregistered", registered=False),
        _list_item(fetcher_name="aa_deregistered", registered=False),
    ]
    output = fetcher_module._render_fetcher_list(items)
    lines = output.splitlines()

    # Registered table: header + aa_registered + zz_registered (alphabetical).
    assert lines[0].startswith("Name")
    assert "aa_registered" in lines[1]
    assert "zz_registered" in lines[2]

    dereg_header_index = lines.index("Deregistered (historical data only):")
    dereg_lines = lines[dereg_header_index + 1 :]
    assert "aa_deregistered" in dereg_lines[1]
    assert "zz_deregistered" in dereg_lines[2]


@pytest.mark.unit
def test_render_fetcher_list_omits_deregistered_section_when_empty() -> None:
    items = [_list_item(fetcher_name="only_registered", registered=True)]
    output = fetcher_module._render_fetcher_list(items)
    assert "Deregistered" not in output


@pytest.mark.unit
def test_render_fetcher_list_never_run_and_enabled_column() -> None:
    items = [
        _list_item(fetcher_name="a", registered=True, enabled=False, last_run=None)
    ]
    output = fetcher_module._render_fetcher_list(items)
    assert "never run" in output
    data_line = output.splitlines()[1]
    assert data_line.split()[1] == "no"


# ---------------------------------------------------------------------------
# Integration: `fetcher list`
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_list_registered_fetcher_without_config_shows_defaults(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    celery_test_app: Celery,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _inject_celery_app(monkeypatch, celery_test_app)
    _register(_NoSettingsFetcher)

    result = _invoke(["fetcher", "list"])
    assert result.exit_code == 0, result.output
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert lines[0].startswith("Name")
    assert _NoSettingsFetcher.name in lines[1]
    assert "never run" in lines[1]
    assert "Deregistered" not in result.stdout


@pytest.mark.integration
def test_list_shows_registered_and_deregistered_sections_ordered(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    celery_test_app: Celery,
    cleanup_fetchers_by_name: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _inject_celery_app(monkeypatch, celery_test_app)
    _register(_NoSettingsFetcher, _RichFetcher)

    deregistered_name = "test_cli_deregistered_zz"
    cleanup_fetchers_by_name(deregistered_name, _RichFetcher.name)
    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory, fetcher_name=deregistered_name
        )
    )
    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory,
            fetcher_name=_RichFetcher.name,
            custom_settings={"results_per_page": 500},
        )
    )

    result = _invoke(["fetcher", "list"])
    assert result.exit_code == 0, result.output

    lines = result.stdout.splitlines()
    dereg_index = lines.index("Deregistered (historical data only):")
    registered_block = "\n".join(lines[:dereg_index])
    deregistered_block = "\n".join(lines[dereg_index:])

    assert _NoSettingsFetcher.name in registered_block
    assert _RichFetcher.name in registered_block
    assert "1 custom" in registered_block
    assert deregistered_name in deregistered_block
    assert _NoSettingsFetcher.name not in deregistered_block


@pytest.mark.integration
def test_list_status_reflects_real_run_records(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    celery_test_app: Celery,
    cleanup_fetchers_by_name: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _inject_celery_app(monkeypatch, celery_test_app)
    _register(_NoSettingsFetcher)
    cleanup_fetchers_by_name(_NoSettingsFetcher.name)

    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory, fetcher_name=_NoSettingsFetcher.name
        )
    )
    asyncio.run(
        _create_fetcher_run_directly(
            cli_session_factory,
            fetcher_name=_NoSettingsFetcher.name,
            status="success",
            started_at=datetime.now(UTC) - timedelta(seconds=45),
            finished_at=datetime.now(UTC),
            duration_seconds=45.0,
        )
    )

    result = _invoke(["fetcher", "list"])
    assert result.exit_code == 0, result.output
    data_line = next(
        line for line in result.stdout.splitlines() if _NoSettingsFetcher.name in line
    )
    assert "success (45s)" in data_line


@pytest.mark.integration
def test_list_issues_no_database_commit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    celery_test_app: Celery,
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _inject_celery_app(monkeypatch, celery_test_app)
    _register(_NoSettingsFetcher)

    original_commit = AsyncSession.commit

    async def _fail_commit(self: AsyncSession) -> None:
        raise AssertionError("fetcher list must not commit")

    monkeypatch.setattr(AsyncSession, "commit", _fail_commit)

    result = _invoke(["fetcher", "list"])
    assert result.exit_code == 0, result.output

    monkeypatch.setattr(AsyncSession, "commit", original_commit)


# ---------------------------------------------------------------------------
# Integration: `fetcher config`
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_config_unknown_fetcher_exits_one(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)

    result = _invoke(["fetcher", "config", "does-not-exist-at-all"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "Error: Fetcher 'does-not-exist-at-all' not found."
    assert result.stdout == ""


@pytest.mark.integration
def test_config_registered_with_settings_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_fetchers_by_name: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _register(_RichFetcher)
    cleanup_fetchers_by_name(_RichFetcher.name)

    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory,
            fetcher_name=_RichFetcher.name,
            custom_settings={"results_per_page": 500, "legacy_orphan": "raw"},
        )
    )

    result = _invoke(["fetcher", "config", _RichFetcher.name])
    assert result.exit_code == 0, result.output
    assert f"Fetcher: {_RichFetcher.name}" in result.stdout
    assert "Schedule: 0 4 * * * (default)" in result.stdout
    assert (
        "results_per_page = 500  (default: 2000, range: 100\u20132000)" in result.stdout
    )
    assert "mode = fast  (default, choices: fast, slow)" in result.stdout
    assert "Orphaned settings (no longer in schema):" in result.stdout
    assert "legacy_orphan = raw" in result.stdout


@pytest.mark.integration
def test_config_deregistered_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_fetchers_by_name: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    name = "test_cli_config_deregistered"
    cleanup_fetchers_by_name(name)

    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory,
            fetcher_name=name,
            schedule_override="0 5 * * *",
            custom_settings={"raw_key": "raw_value"},
        )
    )

    result = _invoke(["fetcher", "config", name])
    assert result.exit_code == 0, result.output
    assert f"Fetcher: {name} (deregistered)" in result.stdout
    assert "Schedule override: 0 5 * * *" in result.stdout
    assert "schema unavailable" in result.stdout
    assert "raw_key = raw_value" in result.stdout


@pytest.mark.integration
def test_config_issues_no_database_commit(
    monkeypatch: pytest.MonkeyPatch,
    cli_session_factory: async_sessionmaker[AsyncSession],
    cleanup_fetchers_by_name: Callable[..., None],
) -> None:
    _inject_session_factory(monkeypatch, cli_session_factory)
    _register(_NoSettingsFetcher)
    cleanup_fetchers_by_name(_NoSettingsFetcher.name)
    asyncio.run(
        _create_fetcher_config_directly(
            cli_session_factory, fetcher_name=_NoSettingsFetcher.name
        )
    )

    original_commit = AsyncSession.commit

    async def _fail_commit(self: AsyncSession) -> None:
        raise AssertionError("fetcher config must not commit")

    monkeypatch.setattr(AsyncSession, "commit", _fail_commit)

    result = _invoke(["fetcher", "config", _NoSettingsFetcher.name])
    assert result.exit_code == 0, result.output

    monkeypatch.setattr(AsyncSession, "commit", original_commit)
