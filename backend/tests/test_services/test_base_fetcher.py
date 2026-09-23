"""Tests for the generic BaseFetcher lifecycle, registry, and HTTP
client integration (backend/app/services/base_fetcher.py).

See `docs/features/platform/fetcher-infrastructure.md` for the
contract under test: import-time class validation
(`__init_subclass__`), the `run()` lifecycle (9 phases), the
finalization status precedence, error message sanitization, the
custom Settings schema, and the BaseFetcher HTTP client integration.

Import-time validation, metrics, `get_setting()`, and the HTTP client
lazy property are unit tests (no DB, no network). The `run()`
lifecycle requires committed, independently-visible database state —
`BaseFetcher.run()` opens its own sessions internally via the
module-level `async_session_factory` reference in `base_fetcher`,
which is monkeypatched to `real_session_factory` (bound to the test
engine) by the `fetcher_lifecycle` fixture below. Rows created through
that fixture are real commits, not covered by the per-test savepoint
rollback — teardown deletes them explicitly.
"""

from __future__ import annotations

import dataclasses
import itertools
import warnings
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
import structlog.contextvars as ctxvars
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.base_fetcher as base_fetcher_module
from app.models.fetcher_audit_event import FetcherAuditEvent
from app.models.fetcher_config import FetcherConfig
from app.models.fetcher_run import FetcherRun
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    FetcherConfigError,
    FetcherError,
    FetcherRunConfig,
    get_catch_up_fetchers,
)
from app.services.http_client import create_http_client

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry() -> Generator[None]:
    """Snapshot/restore `FETCHER_REGISTRY` around every test in this file.

    Most tests below define throwaway `BaseFetcher` subclasses inside
    the test body, mutating the shared, module-level registry via
    `__init_subclass__`. Without this fixture, those registrations
    would leak into later tests — see
    `docs/features/platform/testing-strategy.md` (Test Independence).
    """
    original = dict(FETCHER_REGISTRY)
    yield
    FETCHER_REGISTRY.clear()
    FETCHER_REGISTRY.update(original)


def _make_config(
    *,
    hard_time_limit_seconds: int = 3600,
    request_delay: float = 0,
    custom_settings: dict[str, Any] | None = None,
) -> FetcherRunConfig:
    return FetcherRunConfig(
        hard_time_limit_seconds=hard_time_limit_seconds,
        request_delay=request_delay,
        custom_settings=custom_settings or {},
    )


@pytest_asyncio.fixture
async def fetcher_lifecycle(
    real_session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncGenerator[Callable[..., Awaitable[tuple[str, UUID]]]]:
    """Create a committed `FetcherConfig` + `FetcherRun` (status=
    'running') pair, ready for `BaseFetcher.run()`, and redirect
    `base_fetcher`'s internal session factory to the test database.

    `BaseFetcher.run()` opens its own independent sessions (settings,
    cursor load, execution, finalization) via the module-level
    `async_session_factory` reference in `app.services.base_fetcher` —
    normally bound to the production engine. This fixture monkeypatches
    that reference to `real_session_factory` so `run()`'s internal
    sessions target the test database, and commits the
    `FetcherConfig`/`FetcherRun` rows that the atomic run acquisition
    protocol (`app.services.fetcher_execution`) would normally have
    committed before delegating to `run()`.

    Returns an async callable `(**overrides) -> (fetcher_name, run_id)`.
    Unlike `fetcher_config_factory`/`fetcher_run_factory` (rollback-
    scoped `db_session`), rows created here are real commits — teardown
    deletes every row this fixture created (and any additional
    same-fetcher_name rows a test seeds directly), in FK-safe order.
    """
    monkeypatch.setattr(
        base_fetcher_module, "async_session_factory", real_session_factory
    )

    created_fetcher_names: list[str] = []
    counter = itertools.count(1)

    async def _create(
        *,
        custom_settings: dict[str, Any] | None = None,
        run_timeout: int = 3600,
        request_delay: float = 0,
        schedule_override: str | None = None,
        enabled: bool = True,
        started_at: datetime | None = None,
    ) -> tuple[str, UUID]:
        n = next(counter)
        fetcher_name = f"test_lifecycle_fetcher_{n}"
        async with real_session_factory() as session:
            config = FetcherConfig(
                fetcher_name=fetcher_name,
                enabled=enabled,
                schedule_override=schedule_override,
                run_timeout=run_timeout,
                request_delay=request_delay,
                custom_settings=custom_settings or {},
            )
            session.add(config)
            run = FetcherRun(
                fetcher_name=fetcher_name,
                started_at=started_at or datetime.now(UTC),
                status="running",
                triggered_by="schedule",
            )
            session.add(run)
            await session.commit()
            run_id = run.id
        created_fetcher_names.append(fetcher_name)
        return fetcher_name, run_id

    try:
        yield _create
    finally:
        if created_fetcher_names:
            async with real_session_factory() as session:
                await session.execute(
                    delete(FetcherAuditEvent).where(
                        FetcherAuditEvent.fetcher_name.in_(created_fetcher_names)
                    )
                )
                await session.execute(
                    delete(FetcherRun).where(
                        FetcherRun.fetcher_name.in_(created_fetcher_names)
                    )
                )
                await session.execute(
                    delete(FetcherConfig).where(
                        FetcherConfig.fetcher_name.in_(created_fetcher_names)
                    )
                )
                await session.commit()


async def _seed_finished_run(
    real_session_factory: async_sessionmaker[AsyncSession],
    *,
    fetcher_name: str,
    status: str,
    started_at: datetime,
    cursor: dict[str, Any] | None = None,
) -> None:
    """Seed an additional, already-finished `FetcherRun` row for
    `fetcher_name`, used by previous-cursor selection tests to build a
    run history alongside the "current" row `fetcher_lifecycle` creates.
    """
    async with real_session_factory() as session:
        session.add(
            FetcherRun(
                fetcher_name=fetcher_name,
                started_at=started_at,
                finished_at=started_at + timedelta(seconds=1),
                status=status,
                triggered_by="schedule",
                cursor=cursor,
            )
        )
        await session.commit()


async def _get_run(
    real_session_factory: async_sessionmaker[AsyncSession], run_id: UUID
) -> FetcherRun:
    async with real_session_factory() as session:
        run = await session.get(FetcherRun, run_id)
        assert run is not None
        return run


async def _get_config(
    real_session_factory: async_sessionmaker[AsyncSession], fetcher_name: str
) -> FetcherConfig:
    async with real_session_factory() as session:
        config = await session.get(FetcherConfig, fetcher_name)
        assert config is not None
        return config


async def _execute_stub(self: BaseFetcher, session: AsyncSession) -> None:
    pass


# ---------------------------------------------------------------------------
# FetcherRunConfig
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestFetcherRunConfig:
    def test_snapshot_contains_only_the_three_consumed_fields(self) -> None:
        """`FetcherRunConfig` carries only the fields `execute()` consumes
        (see `fetcher-infrastructure.md`, "Runtime Configuration
        Snapshot"). `enabled`, `schedule_override`, and `fetcher_name`
        must never reappear on this snapshot — identity is available via
        `BaseFetcher.name` instead."""
        field_names = {f.name for f in dataclasses.fields(FetcherRunConfig)}
        assert field_names == {
            "hard_time_limit_seconds",
            "request_delay",
            "custom_settings",
        }

    def test_fields_are_readonly(self) -> None:
        config = _make_config()
        with pytest.raises(AttributeError):
            config.hard_time_limit_seconds = 1800  # type: ignore[misc]

    def test_custom_settings_is_defensively_copied(self) -> None:
        source = {"a": 1}
        config = _make_config(custom_settings=source)
        source["a"] = 999
        assert config.custom_settings == {"a": 1}


# ---------------------------------------------------------------------------
# Registry auto-registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRegistryAutoRegistration:
    def test_concrete_subclass_registers_by_name(self) -> None:
        class SyncOne(BaseFetcher):
            name = "sync_registry_one"
            description = "Test fetcher"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_registry_one"] is SyncOne

    def test_duplicate_name_raises_and_identifies_both_classes(self) -> None:
        class SyncDupBase(BaseFetcher):
            name = "sync_registry_dup"
            description = "First"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        with pytest.raises(TypeError, match="SyncDupBase") as exc_info:

            class SyncDupOther(BaseFetcher):
                name = "sync_registry_dup"
                description = "Second"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

        assert "SyncDupOther" in str(exc_info.value)
        assert FETCHER_REGISTRY["sync_registry_dup"] is SyncDupBase

    def test_abstract_intermediate_class_does_not_register(self) -> None:
        class AbstractMiddle(BaseFetcher):
            abstract = True

        assert not hasattr(AbstractMiddle, "name") or "AbstractMiddle" not in {
            cls.__name__ for cls in FETCHER_REGISTRY.values()
        }

    def test_concrete_subclass_of_abstract_intermediate_registers(self) -> None:
        class AbstractMiddle(BaseFetcher):
            abstract = True
            description = "Intermediate"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        class ConcreteChild(AbstractMiddle):
            name = "sync_registry_child"

        assert FETCHER_REGISTRY["sync_registry_child"] is ConcreteChild

    def test_invalid_definition_does_not_leak_partial_registry_state(self) -> None:
        with pytest.raises(TypeError):

            class SyncInvalid(BaseFetcher):
                name = "sync_registry_invalid"
                description = "x"
                default_schedule = "not a cron"

                async def execute(self, session: AsyncSession) -> None:
                    pass

        assert "sync_registry_invalid" not in FETCHER_REGISTRY


# ---------------------------------------------------------------------------
# Import-time validation — name
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNameValidation:
    @pytest.mark.parametrize(
        "bad_name",
        ["Sync-Bad", "1sync_bad", "SyncBad", "sync bad", ""],
    )
    def test_invalid_pattern_raises(self, bad_name: str) -> None:
        with pytest.raises(TypeError, match="name"):

            class BadName(BaseFetcher):
                name = bad_name
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_name_exceeding_100_chars_raises(self) -> None:
        with pytest.raises(TypeError, match="100 characters"):

            class TooLong(BaseFetcher):
                name = "sync_" + "a" * 100
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_name_exactly_100_chars_is_accepted(self) -> None:
        name = "sync_" + "a" * 95
        assert len(name) == 100

        exact_length_cls = type(
            "ExactLength",
            (BaseFetcher,),
            {
                "name": name,
                "description": "x",
                "default_schedule": "0 * * * *",
                "execute": _execute_stub,
            },
        )

        assert FETCHER_REGISTRY[name] is exact_length_cls


# ---------------------------------------------------------------------------
# Import-time validation — description, schedule, request_delay, queue
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestDescriptionValidation:
    def test_empty_description_raises(self) -> None:
        with pytest.raises(TypeError, match="description"):

            class BadDescription(BaseFetcher):
                name = "sync_empty_description"
                description = ""
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_whitespace_only_description_raises(self) -> None:
        with pytest.raises(TypeError, match="description"):

            class BadDescription(BaseFetcher):
                name = "sync_whitespace_description"
                description = "   "
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass


@pytest.mark.unit
class TestScheduleValidation:
    def test_valid_cron_registers(self) -> None:
        class ValidCron(BaseFetcher):
            name = "sync_valid_cron"
            description = "x"
            default_schedule = "0 */6 * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_valid_cron"] is ValidCron

    def test_non_string_schedule_raises(self) -> None:
        with pytest.raises(TypeError, match="must be a string"):

            class NonStringSchedule(BaseFetcher):
                name = "sync_non_string_schedule"
                description = "x"
                default_schedule = None  # type: ignore[assignment]

                async def execute(self, session: AsyncSession) -> None:
                    pass

    @pytest.mark.parametrize(
        "bad_schedule", ["not a cron", "0 */6 * *", "60 * * * *", "* * * * * *"]
    )
    def test_invalid_cron_raises(self, bad_schedule: str) -> None:
        with pytest.raises(TypeError, match="cron"):

            class BadCron(BaseFetcher):
                name = "sync_bad_cron_case"
                description = "x"
                default_schedule = bad_schedule

                async def execute(self, session: AsyncSession) -> None:
                    pass


@pytest.mark.unit
class TestRequestDelayValidation:
    @pytest.mark.parametrize("delay", [0, 300, 0.0, 150.5])
    def test_valid_delay_registers(self, delay: float) -> None:
        class ValidDelay(BaseFetcher):
            name = f"sync_valid_delay_{str(delay).replace('.', '_')}"
            description = "x"
            default_schedule = "0 * * * *"
            default_request_delay = delay

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY[ValidDelay.name] is ValidDelay

    @pytest.mark.parametrize("delay", [-1, 301, -0.5])
    def test_out_of_range_delay_raises(self, delay: float) -> None:
        with pytest.raises(TypeError, match="default_request_delay"):

            class BadDelay(BaseFetcher):
                name = "sync_bad_delay_case"
                description = "x"
                default_schedule = "0 * * * *"
                default_request_delay = delay

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_boolean_delay_raises(self) -> None:
        with pytest.raises(TypeError, match="default_request_delay"):

            class BoolDelay(BaseFetcher):
                name = "sync_bool_delay"
                description = "x"
                default_schedule = "0 * * * *"
                default_request_delay = True

                async def execute(self, session: AsyncSession) -> None:
                    pass


@pytest.mark.unit
class TestQueueValidation:
    def test_none_queue_registers(self) -> None:
        class NoneQueue(BaseFetcher):
            name = "sync_none_queue"
            description = "x"
            default_schedule = "0 * * * *"
            queue = None

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_none_queue"] is NoneQueue

    def test_valid_queue_registers(self) -> None:
        class ValidQueue(BaseFetcher):
            name = "sync_valid_queue"
            description = "x"
            default_schedule = "0 * * * *"
            queue = "git"

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_valid_queue"] is ValidQueue

    def test_empty_string_queue_raises(self) -> None:
        with pytest.raises(TypeError, match="queue"):

            class EmptyQueue(BaseFetcher):
                name = "sync_empty_queue"
                description = "x"
                default_schedule = "0 * * * *"
                queue = ""

                async def execute(self, session: AsyncSession) -> None:
                    pass


# ---------------------------------------------------------------------------
# Import-time validation — execute()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExecuteValidation:
    def test_missing_execute_raises(self) -> None:
        with pytest.raises(TypeError, match="execute"):

            class NoExecute(BaseFetcher):
                name = "sync_no_execute"
                description = "x"
                default_schedule = "0 * * * *"

    def test_inherited_execute_from_intermediate_class_is_accepted(self) -> None:
        class AbstractMiddle(BaseFetcher):
            abstract = True
            description = "x"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        class ConcreteChild(AbstractMiddle):
            name = "sync_inherited_execute"

        assert FETCHER_REGISTRY["sync_inherited_execute"] is ConcreteChild

    def test_non_coroutine_execute_raises(self) -> None:
        with pytest.raises(TypeError, match="async"):

            class SyncExecute(BaseFetcher):
                name = "sync_sync_execute"
                description = "x"
                default_schedule = "0 * * * *"

                def execute(self, session: AsyncSession) -> None:  # type: ignore[override]
                    pass


# ---------------------------------------------------------------------------
# Import-time validation — Settings
# ---------------------------------------------------------------------------


class _Choice(StrEnum):
    ONE = "one"
    TWO = "two"


class _Level(IntEnum):
    LOW = 1
    HIGH = 2


@pytest.mark.unit
class TestSettingsValidation:
    def test_no_settings_declared_registers(self) -> None:
        class NoSettings(BaseFetcher):
            name = "sync_no_settings"
            description = "x"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert NoSettings.Settings is None

    def test_settings_not_a_basemodel_subclass_raises(self) -> None:
        with pytest.raises(TypeError, match="BaseModel"):

            class BadSettingsType(BaseFetcher):
                name = "sync_bad_settings_type"
                description = "x"
                default_schedule = "0 * * * *"
                Settings = dict  # type: ignore[assignment]

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_missing_model_config_raises(self) -> None:
        with pytest.raises(TypeError, match="model_config"):

            class MissingModelConfig(BaseFetcher):
                name = "sync_missing_model_config"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    x: int = 5

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_extra_not_ignore_raises(self) -> None:
        with pytest.raises(TypeError, match="model_config"):

            class ExtraForbid(BaseFetcher):
                name = "sync_extra_forbid"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="forbid", validate_default=True)
                    x: int = 5

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_validate_default_false_raises(self) -> None:
        with pytest.raises(TypeError, match="model_config"):

            class NoValidateDefault(BaseFetcher):
                name = "sync_no_validate_default"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=False)
                    x: int = 5

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_required_field_raises(self) -> None:
        with pytest.raises(TypeError, match="default value"):

            class RequiredField(BaseFetcher):
                name = "sync_required_field"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=True)
                    required_field: int

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_non_snake_case_field_name_raises(self) -> None:
        with pytest.raises(TypeError, match="snake_case"):

            class BadFieldName(BaseFetcher):
                name = "sync_bad_field_name"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=True)
                    BadUpper: int = 5

                async def execute(self, session: AsyncSession) -> None:
                    pass

    @pytest.mark.parametrize(
        "good_type",
        [int, float, str, bool],
    )
    def test_scalar_type_registers(self, good_type: type) -> None:
        field_default: Any = {
            int: 1,
            float: 1.0,
            str: "x",
            bool: True,
        }[good_type]

        class Settings(BaseModel):
            model_config = ConfigDict(extra="ignore", validate_default=True)
            value: good_type = field_default  # type: ignore[valid-type]

        class ScalarFetcher(BaseFetcher):
            name = f"sync_scalar_{good_type.__name__}"
            description = "x"
            default_schedule = "0 * * * *"
            locals()["Settings"] = Settings

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY[ScalarFetcher.name] is ScalarFetcher

    def test_literal_of_scalars_registers(self) -> None:
        class LiteralFetcher(BaseFetcher):
            name = "sync_literal_settings"
            description = "x"
            default_schedule = "0 * * * *"

            class Settings(BaseModel):
                model_config = ConfigDict(extra="ignore", validate_default=True)
                output_format: Literal["json", "xml"] = "json"

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_literal_settings"] is LiteralFetcher

    def test_str_enum_registers(self) -> None:
        class StrEnumFetcher(BaseFetcher):
            name = "sync_str_enum_settings"
            description = "x"
            default_schedule = "0 * * * *"

            class Settings(BaseModel):
                model_config = ConfigDict(extra="ignore", validate_default=True)
                choice: _Choice = _Choice.ONE

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_str_enum_settings"] is StrEnumFetcher

    def test_int_enum_registers(self) -> None:
        class IntEnumFetcher(BaseFetcher):
            name = "sync_int_enum_settings"
            description = "x"
            default_schedule = "0 * * * *"

            class Settings(BaseModel):
                model_config = ConfigDict(extra="ignore", validate_default=True)
                level: _Level = _Level.LOW

            async def execute(self, session: AsyncSession) -> None:
                pass

        assert FETCHER_REGISTRY["sync_int_enum_settings"] is IntEnumFetcher

    def test_list_field_raises(self) -> None:
        with pytest.raises(TypeError, match="scalar"):

            class ListField(BaseFetcher):
                name = "sync_list_field"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=True)
                    items: list[int] = Field(default_factory=list)

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_nested_model_field_raises(self) -> None:
        class _Nested(BaseModel):
            x: int = 1

        with pytest.raises(TypeError, match="scalar"):

            class NestedField(BaseFetcher):
                name = "sync_nested_field"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=True)
                    nested: _Nested = Field(default_factory=_Nested)

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_invalid_default_raises_at_registration(self) -> None:
        """Pydantic's `validate_default=True` only validates a default
        against its own constraints when the model is instantiated, not
        at class body execution — `_validate_settings_class()` forces
        this check at import time by instantiating with no overrides."""
        with pytest.raises(TypeError, match="invalid default"):

            class BadDefault(BaseFetcher):
                name = "sync_invalid_default"
                description = "x"
                default_schedule = "0 * * * *"

                class Settings(BaseModel):
                    model_config = ConfigDict(extra="ignore", validate_default=True)
                    value: int = Field(default=-1, ge=0)

                async def execute(self, session: AsyncSession) -> None:
                    pass

        assert "sync_invalid_default" not in FETCHER_REGISTRY


# ---------------------------------------------------------------------------
# Abstract stub methods (BaseFetcher itself, never a registered fetcher)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAbstractStubs:
    async def test_execute_stub_raises_not_implemented_error(self) -> None:
        with pytest.raises(NotImplementedError, match="must implement execute"):
            await BaseFetcher().execute(session=None)  # type: ignore[arg-type]

    async def test_catch_up_stub_raises_not_implemented_error(self) -> None:
        with pytest.raises(NotImplementedError, match="does not implement catch_up"):
            await BaseFetcher().catch_up(
                ticket_id="00000000-0000-0000-0000-000000000001",
                session=None,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Import-time validation — catch_up
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCatchUpSignatureValidation:
    def test_correct_signature_registers(self) -> None:
        class GoodCatchUp(BaseFetcher):
            name = "detect_good_catch_up"
            description = "x"
            default_schedule = "0 * * * *"
            participates_in_catch_up = True

            async def execute(self, session: AsyncSession) -> None:
                pass

            async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
                return None

        assert FETCHER_REGISTRY["detect_good_catch_up"] is GoodCatchUp

    def test_wrong_parameter_names_raises(self) -> None:
        with pytest.raises(TypeError, match="catch_up"):

            class BadParams(BaseFetcher):
                name = "detect_bad_params"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                async def catch_up(self, wrong: str) -> None:  # type: ignore[override]
                    return None

    def test_non_coroutine_catch_up_raises(self) -> None:
        with pytest.raises(TypeError, match="async"):

            class SyncCatchUp(BaseFetcher):
                name = "detect_sync_catch_up"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                def catch_up(  # type: ignore[override]
                    self, ticket_id: str, session: AsyncSession
                ) -> None:
                    return None

    def test_wrong_ticket_id_annotation_raises(self) -> None:
        with pytest.raises(TypeError, match="ticket_id"):

            class BadTicketIdType(BaseFetcher):
                name = "detect_bad_ticket_id_type"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                async def catch_up(  # type: ignore[override]
                    self, ticket_id: int, session: AsyncSession
                ) -> None:
                    return None

    def test_wrong_session_annotation_raises(self) -> None:
        with pytest.raises(TypeError, match="session"):

            class BadSessionType(BaseFetcher):
                name = "detect_bad_session_type"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                async def catch_up(  # type: ignore[override]
                    self, ticket_id: str, session: str
                ) -> None:
                    return None

    def test_wrong_return_annotation_raises(self) -> None:
        with pytest.raises(TypeError, match="return None"):

            class BadReturn(BaseFetcher):
                name = "detect_bad_return"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                async def catch_up(  # type: ignore[override]
                    self, ticket_id: str, session: AsyncSession
                ) -> bool:
                    return True


@pytest.mark.unit
class TestCatchUpParticipationConsistency:
    def test_participates_true_without_implementation_raises(self) -> None:
        with pytest.raises(TypeError, match="participates_in_catch_up"):

            class NoImpl(BaseFetcher):
                name = "detect_participates_no_impl"
                description = "x"
                default_schedule = "0 * * * *"
                participates_in_catch_up = True

                async def execute(self, session: AsyncSession) -> None:
                    pass

    def test_implementation_defined_without_flag_warns(self) -> None:
        with pytest.warns(UserWarning, match="participates_in_catch_up"):

            class MismatchFlag(BaseFetcher):
                name = "detect_mismatch_flag"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

                async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
                    return None

        assert FETCHER_REGISTRY["detect_mismatch_flag"] is MismatchFlag

    def test_no_catch_up_and_flag_false_registers_silently(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")

            class Plain(BaseFetcher):
                name = "sync_plain_no_catch_up"
                description = "x"
                default_schedule = "0 * * * *"

                async def execute(self, session: AsyncSession) -> None:
                    pass

        assert FETCHER_REGISTRY["sync_plain_no_catch_up"] is Plain


@pytest.mark.unit
class TestGetCatchUpFetchers:
    def test_returns_only_participating_fetchers(self) -> None:
        class Participating(BaseFetcher):
            name = "detect_participating_example"
            description = "x"
            default_schedule = "0 * * * *"
            participates_in_catch_up = True

            async def execute(self, session: AsyncSession) -> None:
                pass

            async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
                return None

        class NonParticipating(BaseFetcher):
            name = "sync_non_participating_example"
            description = "x"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        result = get_catch_up_fetchers()
        assert result.get("detect_participating_example") is Participating
        assert "sync_non_participating_example" not in result

    def test_computed_fresh_from_current_registry(self) -> None:
        assert "not_yet_registered" not in get_catch_up_fetchers()

        class NewlyRegistered(BaseFetcher):
            name = "detect_newly_registered"
            description = "x"
            default_schedule = "0 * * * *"
            participates_in_catch_up = True

            async def execute(self, session: AsyncSession) -> None:
                pass

            async def catch_up(self, ticket_id: str, session: AsyncSession) -> None:
                return None

        assert "detect_newly_registered" in get_catch_up_fetchers()


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


_METRIC_HELPERS: tuple[str, ...] = (
    "record_succeeded",
    "record_failed",
    "record_created",
    "record_updated",
)


@pytest.mark.unit
class TestMetrics:
    def _fetcher(self) -> BaseFetcher:
        class MetricsFetcher(BaseFetcher):
            name = "sync_metrics_example"
            description = "x"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        return MetricsFetcher()

    def _counters(self, fetcher: BaseFetcher) -> tuple[int, int, int, int]:
        return (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        )

    def _populated(self) -> tuple[BaseFetcher, tuple[int, int, int, int]]:
        fetcher = self._fetcher()
        fetcher.record_succeeded(count=2)
        fetcher.record_created(count=3)
        fetcher.record_updated(count=4)
        fetcher.record_failed(count=5)
        return fetcher, self._counters(fetcher)

    def test_record_succeeded_default_increments_by_one(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_succeeded()
        assert fetcher._succeeded == 1

    def test_record_succeeded_with_count(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_succeeded(count=5)
        assert fetcher._succeeded == 5

    def test_record_created_default_increments_by_one(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_created()
        assert fetcher._created == 1

    def test_record_created_with_count(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_created(count=5)
        assert fetcher._created == 5

    def test_record_updated_increments(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_updated(count=3)
        assert fetcher._updated == 3

    def test_record_updated_default_increments_by_one(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_updated()
        assert fetcher._updated == 1

    def test_record_failed_increments(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_failed(count=2)
        assert fetcher._failed == 2

    def test_record_failed_default_increments_by_one(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_failed()
        assert fetcher._failed == 1

    @pytest.mark.parametrize("method_name", _METRIC_HELPERS)
    def test_zero_count_is_a_noop(self, method_name: str) -> None:
        fetcher = self._fetcher()
        getattr(fetcher, method_name)(count=0)
        assert self._counters(fetcher) == (0, 0, 0, 0)

    @pytest.mark.parametrize("method_name", _METRIC_HELPERS)
    def test_negative_count_raises_value_error_without_mutating(
        self, method_name: str
    ) -> None:
        fetcher, before = self._populated()
        with pytest.raises(ValueError, match="must be >= 0"):
            getattr(fetcher, method_name)(count=-1)
        assert self._counters(fetcher) == before

    @pytest.mark.parametrize("method_name", _METRIC_HELPERS)
    @pytest.mark.parametrize("bad_count", [True, False, 1.0, 1.5, "1", None])
    def test_non_integer_count_raises_type_error_without_mutating(
        self, method_name: str, bad_count: Any
    ) -> None:
        fetcher, before = self._populated()
        with pytest.raises(TypeError):
            getattr(fetcher, method_name)(count=bad_count)
        assert self._counters(fetcher) == before

    def test_repeated_positive_calls_are_additive(self) -> None:
        fetcher = self._fetcher()
        fetcher.record_succeeded(count=2)
        fetcher.record_succeeded(count=3)
        assert fetcher._succeeded == 5


# ---------------------------------------------------------------------------
# get_setting()
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetSetting:
    def _fetcher_cls(self) -> type[BaseFetcher]:
        class SettingsFetcher(BaseFetcher):
            name = "sync_get_setting_example"
            description = "x"
            default_schedule = "0 * * * *"

            class Settings(BaseModel):
                model_config = ConfigDict(extra="ignore", validate_default=True)
                page_size: int = Field(default=100, ge=1, le=1000)

            async def execute(self, session: AsyncSession) -> None:
                pass

        return SettingsFetcher

    def test_no_settings_declared_raises_key_error(self) -> None:
        class NoSettingsFetcher(BaseFetcher):
            name = "sync_get_setting_none"
            description = "x"
            default_schedule = "0 * * * *"

            async def execute(self, session: AsyncSession) -> None:
                pass

        with pytest.raises(KeyError):
            NoSettingsFetcher().get_setting("anything")

    def test_unknown_key_raises_key_error(self) -> None:
        fetcher = self._fetcher_cls()()
        with pytest.raises(KeyError):
            fetcher.get_setting("unknown_key")

    def test_default_used_when_no_instance_populated(self) -> None:
        fetcher = self._fetcher_cls()()
        assert fetcher.get_setting("page_size") == 100

    def test_stored_override_takes_precedence(self) -> None:
        fetcher_cls = self._fetcher_cls()
        fetcher = fetcher_cls()
        assert fetcher_cls.Settings is not None
        fetcher._settings_instance = fetcher_cls.Settings.model_validate(
            {"page_size": 50}
        )
        assert fetcher.get_setting("page_size") == 50


# ---------------------------------------------------------------------------
# HTTP client lazy property
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestHttpClientLazyProperty:
    def _fetcher_cls(self, **options: Any) -> type[BaseFetcher]:
        class HttpFetcher(BaseFetcher):
            name = "sync_http_client_example"
            description = "x"
            default_schedule = "0 * * * *"
            http_client_options = options

            async def execute(self, session: AsyncSession) -> None:
                pass

        return HttpFetcher

    def test_not_created_until_first_access(self) -> None:
        fetcher = self._fetcher_cls()()
        assert fetcher._http_client is None

    def test_created_lazily_on_first_access(self) -> None:
        fetcher = self._fetcher_cls()()
        client = fetcher.http_client
        assert isinstance(client, httpx.AsyncClient)
        assert fetcher._http_client is client

    def test_reused_within_the_same_instance(self) -> None:
        fetcher = self._fetcher_cls()()
        first = fetcher.http_client
        second = fetcher.http_client
        assert first is second

    def test_options_passed_through_to_factory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def _spy(name: str, **kwargs: Any) -> httpx.AsyncClient:
            captured["name"] = name
            captured.update(kwargs)
            return create_http_client(name, **kwargs)

        monkeypatch.setattr(base_fetcher_module, "create_http_client", _spy)
        fetcher = self._fetcher_cls(timeout=httpx.Timeout(5.0))()
        _ = fetcher.http_client
        assert captured["name"] == "sync_http_client_example"
        assert captured["timeout"] == httpx.Timeout(5.0)

    async def test_teardown_closes_and_resets_to_none(self) -> None:
        fetcher = self._fetcher_cls()()
        _ = fetcher.http_client
        await fetcher._teardown_http_client()
        assert fetcher._http_client is None

    async def test_teardown_is_a_no_op_when_never_accessed(self) -> None:
        fetcher = self._fetcher_cls()()
        await fetcher._teardown_http_client()
        assert fetcher._http_client is None

    async def test_teardown_suppresses_aclose_failure_and_logs_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        fetcher = self._fetcher_cls()()
        client = fetcher.http_client

        async def _failing_aclose() -> None:
            raise RuntimeError("boom")

        monkeypatch.setattr(client, "aclose", _failing_aclose)
        with caplog.at_level("WARNING"):
            await fetcher._teardown_http_client()
        assert fetcher._http_client is None
        assert "fetcher_http_client_close_failed" in caplog.text


# ---------------------------------------------------------------------------
# run() lifecycle — integration
# ---------------------------------------------------------------------------


def _fetcher_class(
    fetcher_name: str,
    execute_body: Callable[[BaseFetcher, AsyncSession], Awaitable[None]],
    **class_attrs: Any,
) -> type[BaseFetcher]:
    async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
        await execute_body(self, session)

    attrs: dict[str, Any] = {
        "name": fetcher_name,
        "description": "Lifecycle test fetcher",
        "default_schedule": "0 * * * *",
        "execute": _execute,
    }
    attrs.update(class_attrs)
    return type(fetcher_name.title().replace("_", ""), (BaseFetcher,), attrs)


@pytest.mark.integration
class TestRunLifecycleStatus:
    async def test_success_with_zero_metrics(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "success"
        assert run.items_succeeded == 0
        assert run.items_created == 0
        assert run.items_updated == 0
        assert run.items_failed == 0
        assert run.error_message is None

    async def test_success_with_terminal_units_and_durable_effects(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Successful terminal units plus create/update effects and no
        failure are `success`; `items_succeeded` is independent of the
        durable-effect counters (docs/features/platform/
        fetcher-infrastructure.md, Outcome and effect accounting)."""
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(count=5)
            self.record_created(count=3)
            self.record_updated(count=2)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "success"
        assert run.items_succeeded == 5
        assert run.items_created == 3
        assert run.items_updated == 2
        assert run.items_failed == 0

    async def test_partial_when_some_units_succeed_and_some_fail(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """`partial` is derived exclusively from terminal outcomes; a
        successful unchanged unit (no create/update effect) still counts
        as a success (fetcher-infrastructure.md, Status determination
        precedence, rule 3)."""
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(count=2)
            self.record_failed(count=1)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "partial"
        assert run.items_succeeded == 2
        assert run.items_created == 0
        assert run.items_failed == 1

    async def test_committed_effect_with_failed_unit_and_no_success_is_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """A committed create/update effect never substitutes for a
        successful terminal outcome: with zero successes the run is
        `failure` even though `items_created` is positive
        (fetcher-infrastructure.md, Status determination precedence,
        rule 2, and `testing-strategy.md`, Regression combinations)."""
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_created(count=1)
            self.record_failed(count=1)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "All 1 items failed"
        assert run.items_succeeded == 0
        assert run.items_created == 1
        assert run.items_failed == 1

    async def test_all_items_failed_is_failure_without_raising(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_failed(count=4)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        # Must not raise: failure is recorded on the FetcherRun, not as
        # a propagated exception.
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "All 4 items failed"
        assert run.items_succeeded == 0
        assert run.error_detail is None
        assert run.error_traceback is None

    async def test_run_level_exception_preserves_all_four_counters(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """An escaping run-level exception forces `failure` regardless of
        counters, while preserving them for diagnostics
        (fetcher-infrastructure.md, Finalization, rule 1)."""
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(count=3)
            self.record_created(count=2)
            self.record_updated(count=1)
            self.record_failed(count=4)
            raise FetcherError("upstream failed")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(FetcherError):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.items_succeeded == 3
        assert run.items_created == 2
        assert run.items_updated == 1
        assert run.items_failed == 4

    async def test_execute_exception_propagates_and_records_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            raise FetcherError("Failed to reach upstream")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(FetcherError, match="Failed to reach upstream"):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Failed to reach upstream"

    async def test_metrics_reset_across_multiple_run_calls_on_same_instance(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Every counter resets before each run, including reuse after a
        prior success, a per-item failure, and an escaping exception
        (testing-strategy.md, Per-run reset)."""
        fetcher_name, run_id_1 = await fetcher_lifecycle()

        async def _seed_run() -> UUID:
            async with real_session_factory() as session:
                run = FetcherRun(
                    fetcher_name=fetcher_name,
                    started_at=datetime.now(UTC),
                    status="running",
                    triggered_by="schedule",
                )
                session.add(run)
                await session.commit()
                return run.id

        run_id_2 = await _seed_run()
        run_id_3 = await _seed_run()
        run_id_4 = await _seed_run()

        call_count = 0

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                self.record_succeeded(count=5)
                self.record_created(count=4)
                self.record_updated(count=3)
                self.record_failed(count=2)
            elif call_count == 2:
                self.record_succeeded(count=1)
                self.record_failed(count=1)
            elif call_count == 3:
                self.record_succeeded(count=1)
                self.record_created(count=1)
                raise FetcherError("boom")

        # Same underlying instance reused for every run.
        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        instance = fetcher_cls()
        await instance.run(run_id=run_id_1, config=_make_config())
        await instance.run(run_id=run_id_2, config=_make_config())
        with pytest.raises(FetcherError):
            await instance.run(run_id=run_id_3, config=_make_config())
        await instance.run(run_id=run_id_4, config=_make_config())

        run_1 = await _get_run(real_session_factory, run_id_1)
        assert (
            run_1.items_succeeded,
            run_1.items_created,
            run_1.items_updated,
            run_1.items_failed,
        ) == (5, 4, 3, 2)
        run_2 = await _get_run(real_session_factory, run_id_2)
        assert (run_2.items_succeeded, run_2.items_failed) == (1, 1)
        run_3 = await _get_run(real_session_factory, run_id_3)
        assert (run_3.items_succeeded, run_3.items_created) == (1, 1)
        run_4 = await _get_run(real_session_factory, run_id_4)
        assert (
            run_4.items_succeeded,
            run_4.items_created,
            run_4.items_updated,
            run_4.items_failed,
        ) == (0, 0, 0, 0)

    async def test_active_run_row_exposes_zero_counters_during_execution(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Counters are never written before finalization: an independent
        session observing the adopted row during `execute()` still reads
        `running` with all four counters at their zero defaults
        (testing-strategy.md, Diagnostics and persistence: "tests must
        prove no live progress writes occur")."""
        fetcher_name, run_id = await fetcher_lifecycle()
        observed: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(count=3)
            self.record_created(count=2)
            self.record_updated(count=1)
            self.record_failed(count=1)
            async with real_session_factory() as independent:
                row = await independent.get(FetcherRun, run_id)
                assert row is not None
                observed["status"] = row.status
                observed["items"] = (
                    row.items_succeeded,
                    row.items_created,
                    row.items_updated,
                    row.items_failed,
                )

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert observed["status"] == "running"
        assert observed["items"] == (0, 0, 0, 0)

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "partial"
        assert run.items_succeeded == 3
        assert run.items_created == 2
        assert run.items_updated == 1
        assert run.items_failed == 1


@pytest.mark.integration
class TestRunLifecycleCursor:
    async def test_no_previous_run_yields_none(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["previous_cursor"] = self.previous_cursor

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["previous_cursor"] is None

    async def test_latest_success_cursor_is_picked(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        now = datetime.now(UTC)
        await _seed_finished_run(
            real_session_factory,
            fetcher_name=fetcher_name,
            status="success",
            started_at=now - timedelta(hours=2),
            cursor={"checkpoint": "old"},
        )
        await _seed_finished_run(
            real_session_factory,
            fetcher_name=fetcher_name,
            status="success",
            started_at=now - timedelta(hours=1),
            cursor={"checkpoint": "new"},
        )

        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["previous_cursor"] = self.previous_cursor

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["previous_cursor"] == {"checkpoint": "new"}

    async def test_latest_partial_cursor_is_picked(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        now = datetime.now(UTC)
        await _seed_finished_run(
            real_session_factory,
            fetcher_name=fetcher_name,
            status="partial",
            started_at=now - timedelta(hours=1),
            cursor={"checkpoint": "partial-value"},
        )

        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["previous_cursor"] = self.previous_cursor

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["previous_cursor"] == {"checkpoint": "partial-value"}

    async def test_failure_and_running_runs_are_ignored(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        now = datetime.now(UTC)
        await _seed_finished_run(
            real_session_factory,
            fetcher_name=fetcher_name,
            status="success",
            started_at=now - timedelta(hours=3),
            cursor={"checkpoint": "real"},
        )
        await _seed_finished_run(
            real_session_factory,
            fetcher_name=fetcher_name,
            status="failure",
            started_at=now - timedelta(hours=1),
            cursor={"checkpoint": "should-be-ignored"},
        )

        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["previous_cursor"] = self.previous_cursor

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["previous_cursor"] == {"checkpoint": "real"}

    async def test_valid_cursor_is_persisted_on_success(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self._cursor = {"page": 3}

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.cursor == {"page": 3}

    async def test_cursor_is_persisted_on_partial(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(count=1)
            self.record_failed(count=1)
            self._cursor = {"page": 7}

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "partial"
        assert run.items_succeeded == 1
        assert run.cursor == {"page": 7}

    async def test_no_cursor_persisted_when_execute_raises(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self._cursor = {"page": 1}
            raise FetcherError("boom")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(FetcherError):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.cursor is None

    async def test_no_cursor_persisted_when_all_items_failed(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self._cursor = {"page": 1}
            self.record_failed(count=1)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.cursor is None

    async def test_no_cursor_persisted_for_effect_only_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """A committed effect with zero successes and one failure is
        `failure`, so the cursor is not advanced even though a durable
        create effect exists (fetcher-infrastructure.md, Cursor
        persistence)."""
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self._cursor = {"page": 9}
            self.record_created(count=1)
            self.record_failed(count=1)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.items_succeeded == 0
        assert run.items_created == 1
        assert run.cursor is None

    async def test_non_serializable_cursor_absorbs_into_failure_without_raising(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        class _Unserializable:
            pass

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self._cursor = {"bad": _Unserializable()}

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        # Must not raise.
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Cursor serialization failed"
        assert run.error_detail is not None
        assert run.error_traceback is not None
        assert run.cursor is None


@pytest.mark.integration
class TestRunLifecycleTiming:
    async def test_duration_is_computed_from_persisted_started_at(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        backdated = datetime.now(UTC) - timedelta(seconds=120)
        fetcher_name, run_id = await fetcher_lifecycle(started_at=backdated)

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.duration_seconds is not None
        assert run.duration_seconds >= 119
        assert run.finished_at is not None


@pytest.mark.integration
class TestRunLifecycleSettings:
    async def test_default_used_when_no_override_stored(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["page_size"] = self.get_setting("page_size")

        class Settings(BaseModel):
            model_config = ConfigDict(extra="ignore", validate_default=True)
            page_size: int = Field(default=100, ge=1, le=1000)

        fetcher_cls = _fetcher_class(fetcher_name, _execute, Settings=Settings)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["page_size"] == 100

    async def test_stored_override_takes_precedence(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle(
            custom_settings={"page_size": 50}
        )
        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["page_size"] = self.get_setting("page_size")

        class Settings(BaseModel):
            model_config = ConfigDict(extra="ignore", validate_default=True)
            page_size: int = Field(default=100, ge=1, le=1000)

        fetcher_cls = _fetcher_class(fetcher_name, _execute, Settings=Settings)
        await fetcher_cls().run(
            run_id=run_id,
            config=_make_config(custom_settings={"page_size": 50}),
        )

        assert captured["page_size"] == 50

    async def test_orphaned_key_is_ignored_silently(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_created(count=1)

        class Settings(BaseModel):
            model_config = ConfigDict(extra="ignore", validate_default=True)
            page_size: int = Field(default=100, ge=1, le=1000)

        fetcher_cls = _fetcher_class(fetcher_name, _execute, Settings=Settings)
        await fetcher_cls().run(
            run_id=run_id,
            config=_make_config(custom_settings={"removed_field": "orphan"}),
        )

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "success"

    async def test_invalid_stored_settings_raises_config_error_and_records_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle(
            custom_settings={"page_size": -5}
        )

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pytest.fail("execute() must not run when settings validation fails")

        class Settings(BaseModel):
            model_config = ConfigDict(extra="ignore", validate_default=True)
            page_size: int = Field(default=100, ge=1, le=1000)

        fetcher_cls = _fetcher_class(fetcher_name, _execute, Settings=Settings)
        with pytest.raises(FetcherConfigError) as exc_info:
            await fetcher_cls().run(
                run_id=run_id,
                config=_make_config(custom_settings={"page_size": -5}),
            )
        assert fetcher_name in str(exc_info.value)
        assert "page_size" not in str(exc_info.value)

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message is not None
        assert "update via the API" in run.error_message
        assert run.error_detail is not None
        assert "page_size" in run.error_detail
        assert run.error_traceback is not None


@pytest.mark.integration
class TestRunLifecyclePreExecutionFailure:
    async def test_previous_cursor_load_exception_finalizes_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pytest.fail("execute() must not run when cursor loading fails")

        async def _load_previous_cursor(
            self: BaseFetcher, fetcher_name: str
        ) -> dict[str, Any] | None:
            raise ValueError("previous cursor query failed")

        fetcher_cls = _fetcher_class(
            fetcher_name,
            _execute,
            _load_previous_cursor=_load_previous_cursor,
        )
        with pytest.raises(ValueError, match="previous cursor query failed"):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert run.error_detail == "previous cursor query failed"
        assert run.error_traceback is not None
        assert "ValueError" in run.error_traceback
        assert run.finished_at is not None
        assert run.duration_seconds is not None

    async def test_non_validation_settings_exception_finalizes_failure(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pytest.fail("execute() must not run when settings construction fails")

        def _build_settings_instance(
            self: BaseFetcher, custom_settings: dict[str, Any]
        ) -> BaseModel | None:
            raise RuntimeError("settings construction failed")

        fetcher_cls = _fetcher_class(
            fetcher_name,
            _execute,
            _build_settings_instance=_build_settings_instance,
        )
        with pytest.raises(RuntimeError, match="settings construction failed"):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        run = await _get_run(real_session_factory, run_id)
        assert run.status == "failure"
        assert run.error_message == "Unexpected error"
        assert run.error_detail == "settings construction failed"
        assert run.error_traceback is not None
        assert "RuntimeError" in run.error_traceback
        assert run.finished_at is not None
        assert run.duration_seconds is not None


@pytest.mark.integration
class TestRunLifecycleExecutionSessionContract:
    async def test_explicit_commit_inside_execute_is_visible_afterward(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            config = await session.get(FetcherConfig, fetcher_name)
            assert config is not None
            config.enabled = False
            await session.commit()

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        config = await _get_config(real_session_factory, fetcher_name)
        assert config.enabled is False

    async def test_uncommitted_work_is_discarded_on_normal_return(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            config = await session.get(FetcherConfig, fetcher_name)
            assert config is not None
            config.enabled = False
            # Deliberately no commit.

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        config = await _get_config(real_session_factory, fetcher_name)
        assert config.enabled is True

    async def test_rollback_on_exception_discards_mutation(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            config = await session.get(FetcherConfig, fetcher_name)
            assert config is not None
            config.enabled = False
            await session.flush()
            raise FetcherError("boom after mutation")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(FetcherError):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        config = await _get_config(real_session_factory, fetcher_name)
        assert config.enabled is True


@pytest.mark.integration
class TestRunLifecycleFinalizationFailure:
    async def test_missing_run_row_raises_and_does_not_mask_success(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, _run_id = await fetcher_lifecycle()
        bogus_run_id = uuid4()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(RuntimeError, match="not found during finalization"):
            await fetcher_cls().run(run_id=bogus_run_id, config=_make_config())

    async def test_missing_run_row_chains_original_execution_exception(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, _run_id = await fetcher_lifecycle()
        bogus_run_id = uuid4()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            raise FetcherError("original execution failure")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(RuntimeError) as exc_info:
            await fetcher_cls().run(run_id=bogus_run_id, config=_make_config())
        assert isinstance(exc_info.value.__cause__, FetcherError)
        assert "original execution failure" in str(exc_info.value.__cause__)

    async def test_missing_run_row_logs_critical_with_identifying_fields(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        fetcher_name, _run_id = await fetcher_lifecycle()
        bogus_run_id = uuid4()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with (
            caplog.at_level("CRITICAL"),
            pytest.raises(RuntimeError, match="not found during finalization"),
        ):
            await fetcher_cls().run(run_id=bogus_run_id, config=_make_config())

        assert "fetcher_finalization_failed" in caplog.text
        assert fetcher_name in caplog.text
        assert str(bogus_run_id) in caplog.text

    async def test_null_started_at_raises_and_does_not_mask_success(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """`run()` must only ever be invoked on an already-adopted run
        (`started_at` populated) — see
        `docs/features/platform/fetcher-infrastructure.md`
        (`BaseFetcher.run()` Parameters). A violation of this
        precondition (a `queued` run reaching finalization) fails
        loudly rather than computing a nonsensical duration."""
        fetcher_name, run_id = await fetcher_lifecycle()
        async with real_session_factory() as session:
            run = await session.get(FetcherRun, run_id)
            assert run is not None
            run.started_at = None
            run.status = "queued"
            await session.commit()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(RuntimeError, match="has no started_at during"):
            await fetcher_cls().run(run_id=run_id, config=_make_config())


@pytest.mark.integration
class TestRunLifecycleAuditTrail:
    async def test_run_creates_no_fetcher_audit_event(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_created(count=1)

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        async with real_session_factory() as session:
            result = await session.execute(
                select(FetcherAuditEvent).where(
                    FetcherAuditEvent.fetcher_name == fetcher_name
                )
            )
            assert result.scalars().all() == []


# ---------------------------------------------------------------------------
# Error sanitization
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestSanitizeErrorHelper:
    """Direct unit tests for the private `_sanitize_error()` helper —
    covers the defensive branch (`httpx.HTTPStatusError` with a status
    code below 400) that no legitimate `raise_for_status()` call can
    produce, but which the function still handles safely."""

    def test_http_status_error_below_400_maps_to_unexpected_error(self) -> None:
        request = httpx.Request("GET", "https://example.internal/api")
        response = httpx.Response(200, request=request)
        exc = httpx.HTTPStatusError("Unusual", request=request, response=response)

        message, detail = base_fetcher_module._sanitize_error(
            exc, hard_time_limit_seconds=3600, fetcher_name="sync_example", processed=0
        )

        assert message == "Unexpected error"
        assert detail is not None


@pytest.mark.integration
class TestErrorSanitization:
    async def _run_with_exception(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
        exc: BaseException,
    ) -> FetcherRun:
        fetcher_name, run_id = await fetcher_lifecycle()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            raise exc

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(type(exc)):
            await fetcher_cls().run(run_id=run_id, config=_make_config())
        return await _get_run(real_session_factory, run_id)

    async def test_fetcher_error_with_cause_exposes_cause_in_detail_only(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        try:
            raise FetcherError("Failed to connect to upstream") from ValueError(
                "internal host db.internal.example unreachable"
            )
        except FetcherError as exc:
            run = await self._run_with_exception(
                fetcher_lifecycle, real_session_factory, exc
            )
        assert run.error_message == "Failed to connect to upstream"
        assert run.error_detail is not None
        assert "db.internal.example" in run.error_detail
        assert "db.internal.example" not in (run.error_message or "")

    async def test_fetcher_error_without_cause_has_null_detail(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run = await self._run_with_exception(
            fetcher_lifecycle,
            real_session_factory,
            FetcherError("Pre-flight guard failed"),
        )
        assert run.error_message == "Pre-flight guard failed"
        assert run.error_detail is None

    async def test_network_error_maps_to_unreachable_message(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        exc = httpx.ConnectError("Connection refused to build.suse.de")
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, exc
        )
        assert run.error_message == "External service unreachable"
        assert run.error_detail is not None
        assert "build.suse.de" not in (run.error_message or "")

    async def test_timeout_maps_to_unreachable_message(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        exc = httpx.ReadTimeout("Timed out")
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, exc
        )
        assert run.error_message == "External service unreachable"

    async def test_http_4xx_maps_to_rejected_message(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        request = httpx.Request("GET", "https://example.internal/api")
        response = httpx.Response(403, request=request)
        exc = httpx.HTTPStatusError("Forbidden", request=request, response=response)
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, exc
        )
        assert run.error_message == "External service rejected request"
        assert run.error_detail is not None
        assert "example.internal" not in (run.error_message or "")

    async def test_http_5xx_maps_to_server_error_message(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        request = httpx.Request("GET", "https://example.internal/api")
        response = httpx.Response(503, request=request)
        exc = httpx.HTTPStatusError(
            "Service Unavailable", request=request, response=response
        )
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, exc
        )
        assert run.error_message == "External service returned server error"

    async def test_soft_time_limit_exceeded_maps_to_timeout_message(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Matches the exact template mandated by `fetcher-infrastructure.md`
        (Error Message Sanitization, BaseFetcher fallback), including the
        items-processed count and fetcher name. Uses a live
        `FetcherConfig.run_timeout` (1800) deliberately different from
        the snapshot's `hard_time_limit_seconds` (2400) to prove the
        message reports the per-delivery limit, never the live config
        value."""
        fetcher_name, run_id = await fetcher_lifecycle(run_timeout=1800)

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            self.record_succeeded(2)
            self.record_failed(1)
            raise SoftTimeLimitExceeded()

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(SoftTimeLimitExceeded):
            await fetcher_cls().run(
                run_id=run_id,
                config=_make_config(hard_time_limit_seconds=2400),
            )
        run = await _get_run(real_session_factory, run_id)

        assert run.error_message == (
            "Execution reached the soft time limit (hard limit for this "
            "run: 2400s; 3 items processed). Review FetcherConfig.run_timeout "
            f"for future runs of fetcher '{fetcher_name}'."
        )
        assert run.items_succeeded == 2
        assert run.items_failed == 1

    async def test_unknown_exception_maps_to_unexpected_error(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, ValueError("some internal detail")
        )
        assert run.error_message == "Unexpected error"
        assert run.error_detail is not None
        assert "some internal detail" in run.error_detail

    async def test_traceback_populated_for_raised_exception(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
        real_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        run = await self._run_with_exception(
            fetcher_lifecycle, real_session_factory, ValueError("boom")
        )
        assert run.error_traceback is not None
        assert "ValueError" in run.error_traceback


# ---------------------------------------------------------------------------
# Logging context (fetcher_run_id)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLoggingContext:
    async def test_fetcher_run_id_bound_during_execute(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        captured: dict[str, Any] = {}

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            captured["context"] = ctxvars.get_contextvars()

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert captured["context"].get("fetcher_run_id") == str(run_id)

    async def test_context_reset_after_successful_run_with_no_prior_context(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        ctxvars.clear_contextvars()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert "fetcher_run_id" not in ctxvars.get_contextvars()

    async def test_context_reset_after_exception(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        ctxvars.clear_contextvars()

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            raise FetcherError("boom")

        fetcher_cls = _fetcher_class(fetcher_name, _execute)
        with pytest.raises(FetcherError):
            await fetcher_cls().run(run_id=run_id, config=_make_config())

        assert "fetcher_run_id" not in ctxvars.get_contextvars()

    async def test_pre_existing_context_is_restored_not_destroyed(
        self,
        fetcher_lifecycle: Callable[..., Awaitable[tuple[str, UUID]]],
    ) -> None:
        fetcher_name, run_id = await fetcher_lifecycle()
        ctxvars.clear_contextvars()
        pre_tokens = ctxvars.bind_contextvars(fetcher_run_id="pre-existing-value")

        async def _execute(self: BaseFetcher, session: AsyncSession) -> None:
            pass

        try:
            fetcher_cls = _fetcher_class(fetcher_name, _execute)
            await fetcher_cls().run(run_id=run_id, config=_make_config())
            assert ctxvars.get_contextvars().get("fetcher_run_id") == (
                "pre-existing-value"
            )
        finally:
            ctxvars.reset_contextvars(**pre_tokens)
