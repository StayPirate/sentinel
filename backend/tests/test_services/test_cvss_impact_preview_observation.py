"""Deadline, observation, and population-boundary tests for
`get_default_cvss_version_impact()`
(backend/app/services/cvss_impact_preview.py).

Owning specifications:

- docs/features/platform/default-cvss-version-operations.md (Preview
  Service steps 3-4; Consistency and Staleness; Timeout and Partial
  Results; Preview Service Exception).
- docs/features/platform/testing-strategy.md (Default-CVSS Impact
  Preview, Integration tests: two observations across units with
  committed changes between reads; population boundary; deadline expiry).

Projection rules are in test_cvss_impact_preview.py. The tests that observe
committed state between page reads run the preview on a session of its own
(`db_session_factory`) and remove every row they commit.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, time
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import delete, event, func, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Severity
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.system_setting import SystemSetting
from app.services import cvss_impact_preview, settings
from app.services.cvss_impact_preview import (
    CVSSPreviewTimeoutError,
    DefaultCVSSVersionImpact,
    get_default_cvss_version_impact,
)
from tests.support.cvss_chain import Assessment, CVEBuilder
from tests.support.database import backend_pid, rollback_test_scope
from tests.support.ticket_mutations import EVAL, StatementRecorder

pytest_plugins = ["tests.support.ticket_mutation_fixtures"]
"""Provides the shared `cve_with` fixture."""

SessionFactory = Callable[[], Awaitable[AsyncSession]]

_PAST_DEADLINE = cvss_impact_preview.PREVIEW_DEADLINE_SECONDS + 1
_MARK_STATEMENT = "ORDER BY cve.id DESC"
"""Fragment identifying the high-water-mark statement."""


@pytest.fixture(autouse=True)
def fixed_evaluation_date(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cvss_impact_preview,
        "_utc_now",
        lambda: datetime.combine(EVAL, time(12, 0), tzinfo=UTC),
    )


@pytest.fixture
async def setting(
    system_setting_factory: Callable[..., Awaitable[SystemSetting]],
) -> SystemSetting:
    return await system_setting_factory(key="default_cvss_version", value="3.1")


class FakeClock:
    """A controlled monotonic clock for the preview deadline."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = 0.0
        monkeypatch.setattr(cvss_impact_preview, "_monotonic", lambda: self.now)

    def expire(self) -> None:
        self.now = _PAST_DEADLINE


def _converging_cve(cve_with: CVEBuilder) -> Awaitable[CVE]:
    """A ticketless CVE whose projected `4.0` severity (`Critical`) differs
    from its persisted `Medium`."""
    return cve_with(
        Assessment("5.0"), Assessment("9.0", version="4.0"), severity=Severity.MEDIUM
    )


async def _statement_timeout(db: AsyncSession) -> str:
    value: str = (await db.execute(text("SHOW statement_timeout"))).scalar_one()
    return value


# ---------------------------------------------------------------------------
# Deadline
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("setting")
class TestDeadline:
    async def test_expiry_at_the_setting_read_raises_and_discards_counts(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        clock = FakeClock(monkeypatch)
        read = settings.get_default_cvss_version

        async def _slow_read(session: AsyncSession) -> str:
            clock.expire()
            return await read(session)

        monkeypatch.setattr(cvss_impact_preview, "get_default_cvss_version", _slow_read)
        await _converging_cve(cve_with)
        await db_session.execute(text("SET LOCAL statement_timeout = '12345ms'"))

        with (
            StatementRecorder(db_session) as recorder,
            pytest.raises(CVSSPreviewTimeoutError),
        ):
            await get_default_cvss_version_impact(db_session, "4.0")

        assert recorder.selects_from("cve") == []
        # A client-side expiry leaves the transaction usable and restores
        # the caller's timeout.
        assert await _statement_timeout(db_session) == "12345ms"

    async def test_expiry_at_the_high_water_mark_statement(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        clock = FakeClock(monkeypatch)
        await _converging_cve(cve_with)
        engine = db_session.get_bind().engine

        def _on_statement(*args: Any) -> None:
            if _MARK_STATEMENT in args[2]:
                clock.expire()

        event.listen(engine, "before_cursor_execute", _on_statement)
        try:
            with (
                StatementRecorder(db_session) as recorder,
                pytest.raises(CVSSPreviewTimeoutError),
            ):
                await get_default_cvss_version_impact(db_session, "4.0")
        finally:
            event.remove(engine, "before_cursor_execute", _on_statement)

        assert [s for s in recorder.statements if _MARK_STATEMENT in s]
        assert [
            s for s in recorder.statements if "LIMIT" in s and "json_agg" in s
        ] == []

    async def test_expiry_after_a_page_discards_its_counts(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The clock passes the deadline while the first page is read: the
        budget check before its projection batch raises, so no partial
        result exists."""
        clock = FakeClock(monkeypatch)
        projected: list[object] = []
        project = cvss_impact_preview._project_unit

        def _spy(*args: Any) -> None:
            projected.append(args[0])
            project(*args)

        monkeypatch.setattr(cvss_impact_preview, "_project_unit", _spy)
        await _converging_cve(cve_with)
        engine = db_session.get_bind().engine

        def _on_statement(*args: Any) -> None:
            if "json_agg" in args[2]:
                clock.expire()

        event.listen(engine, "before_cursor_execute", _on_statement)
        try:
            with pytest.raises(CVSSPreviewTimeoutError):
                await get_default_cvss_version_impact(db_session, "4.0")
        finally:
            event.remove(engine, "before_cursor_execute", _on_statement)

        assert projected == []

    async def test_a_slow_page_is_cancelled_by_postgresql(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Every statement is bounded by the remaining budget: a page that
        would outlive a 0.5 s budget is cancelled server-side
        (`query_canceled`) and surfaces as the timeout. The aborted request
        transaction is left for its owner to roll back."""
        monkeypatch.setattr(cvss_impact_preview, "PREVIEW_DEADLINE_SECONDS", 0.5)
        _slow_pages(monkeypatch, seconds=5)
        await _converging_cve(cve_with)

        async with rollback_test_scope(db_session):
            with pytest.raises(CVSSPreviewTimeoutError) as raised:
                await get_default_cvss_version_impact(db_session, "4.0")

        cause = raised.value.__cause__
        assert isinstance(cause, DBAPIError)
        assert getattr(cause.orig, "sqlstate", None) == "57014"
        # The owner's rollback discarded the transaction-local timeout.
        assert await _statement_timeout(db_session) == "0"

    async def test_a_cancellation_within_the_budget_is_a_database_error(
        self,
        db_session: AsyncSession,
        db_session_factory: SessionFactory,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A `query_canceled` that is not a deadline expiry (here an
        operator's `pg_cancel_backend()`) propagates unchanged."""
        _slow_pages(monkeypatch, seconds=10)
        await _converging_cve(cve_with)
        pid = backend_pid(db_session)
        operator = await db_session_factory()

        async def _cancel_when_sleeping() -> None:
            for _ in range(500):
                waiting = (
                    await operator.execute(
                        text(
                            "SELECT wait_event FROM pg_stat_activity WHERE pid = :pid"
                        ),
                        {"pid": pid},
                    )
                ).scalar_one_or_none()
                await operator.rollback()
                if waiting == "PgSleep":
                    await operator.execute(
                        text("SELECT pg_cancel_backend(:pid)"), {"pid": pid}
                    )
                    await operator.rollback()
                    return
                await asyncio.sleep(0.01)
            raise AssertionError("the page statement never started sleeping")

        async with rollback_test_scope(db_session):
            canceller = asyncio.create_task(_cancel_when_sleeping())
            with pytest.raises(DBAPIError) as raised:
                await get_default_cvss_version_impact(db_session, "4.0")
            await canceller

        assert not isinstance(raised.value, CVSSPreviewTimeoutError)
        assert getattr(raised.value.orig, "sqlstate", None) == "57014"

    async def test_every_statement_after_entry_is_bounded_and_restored(
        self,
        db_session: AsyncSession,
        cve_with: CVEBuilder,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Before the setting read, the high-water mark, and every page the
        transaction-local `statement_timeout` is set to the remaining budget
        (at most 30 s); the caller's value is restored before returning."""
        monkeypatch.setattr(cvss_impact_preview, "_PAGE_SIZE", 1)
        for _ in range(2):
            await _converging_cve(cve_with)
        await db_session.execute(text("SET LOCAL statement_timeout = '12345ms'"))

        with StatementRecorder(db_session) as recorder:
            result = await get_default_cvss_version_impact(db_session, "4.0")

        assert result.cves_evaluated == 2
        kinds = [_kind(s) for s in recorder.statements]
        assert kinds == [
            "read-timeout",
            "bound",
            "setting",
            "bound",
            "mark",
            "bound",
            "page",
            "bound",
            "page",
            "bound",
            "page",
            "bound",
        ]
        bounds = [
            parameters
            for statement, parameters in zip(
                recorder.statements, recorder.parameters, strict=True
            )
            if _kind(statement) == "bound"
        ]
        budgets = [int(_values(parameters)[1]) for parameters in bounds[:-1]]
        assert all(0 < budget <= 30_000 for budget in budgets)
        assert budgets == sorted(budgets, reverse=True)
        assert _values(bounds[-1])[1] == "12345ms"
        assert await _statement_timeout(db_session) == "12345ms"


def _slow_pages(monkeypatch: pytest.MonkeyPatch, *, seconds: float) -> None:
    """Make every page statement sleep server-side for `seconds`."""
    build = cvss_impact_preview._page_statement

    def _slow(*args: Any) -> Any:
        return build(*args).add_columns(func.pg_sleep(seconds).label("slow"))

    monkeypatch.setattr(cvss_impact_preview, "_page_statement", _slow)


def _kind(statement: str) -> str:
    if "current_setting" in statement:
        return "read-timeout"
    if "set_config" in statement:
        return "bound"
    if "system_setting" in statement:
        return "setting"
    if _MARK_STATEMENT in statement:
        return "mark"
    if "json_agg" in statement:
        return "page"
    return statement


def _values(parameters: Any) -> tuple[Any, ...]:
    return tuple(parameters)


# ---------------------------------------------------------------------------
# Observation model and population boundary (committed state)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _committed_population(
    factory: SessionFactory, count: int
) -> AsyncIterator[list[uuid.UUID]]:
    """Commit the setting and `count` converging ticketless CVEs; remove
    every committed row afterwards."""
    seed = await factory()
    seed.add(SystemSetting(key="default_cvss_version", value="3.1"))
    ids: list[uuid.UUID] = []
    for n in range(count):
        cve = CVE(cve_id=f"CVE-2099-9{n:04d}", severity=Severity.MEDIUM.value)
        seed.add(cve)
        await seed.flush()
        ids.append(cve.id)
        for version, score in (("3.1", "5.0"), ("4.0", "9.0")):
            seed.add(_suse(cve.id, version, score))
    await seed.commit()
    try:
        yield ids
    finally:
        await seed.rollback()
        await seed.execute(delete(CVE).where(CVE.cve_id.like("CVE-2099-9%")))
        await seed.execute(
            delete(SystemSetting).where(SystemSetting.key == "default_cvss_version")
        )
        await seed.commit()


def _suse(cve_id: uuid.UUID, version: str, score: str) -> CVECVSSAssessment:
    return CVECVSSAssessment(
        cve_id=cve_id,
        provider_name="SUSE",
        cvss_version=version,
        score=Decimal(score),
        severity="medium",
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )


def _before_bound(
    monkeypatch: pytest.MonkeyPatch,
    call: int,
    action: Callable[[], Awaitable[None]],
) -> None:
    """Run `action` just before the `call`-th bounded statement (1: setting
    read, 2: high-water mark, 3: first page, ...)."""
    original = cvss_impact_preview._set_statement_timeout
    calls = {"n": 0}

    async def _hooked(session: AsyncSession, value: str) -> None:
        calls["n"] += 1
        if calls["n"] == call:
            await action()
        await original(session, value)

    monkeypatch.setattr(cvss_impact_preview, "_set_statement_timeout", _hooked)


class TestCommittedObservation:
    async def test_units_observe_different_committed_states(
        self,
        db_session_factory: SessionFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Consistency and Staleness: between the two page statements an
        independent transaction converges both CVEs' persisted severity.
        The first unit was read before that commit and still projects a
        severity change; the second is read after it and projects none.
        Each unit corresponds to one committed observation."""
        monkeypatch.setattr(cvss_impact_preview, "_PAGE_SIZE", 1)
        async with _committed_population(db_session_factory, 2) as ids:
            writer = await db_session_factory()

            async def _converge() -> None:
                await writer.execute(
                    update(CVE)
                    .where(CVE.id.in_(ids))
                    .values(severity=Severity.CRITICAL.value)
                )
                await writer.commit()

            _before_bound(monkeypatch, 4, _converge)
            reader = await db_session_factory()

            result = await get_default_cvss_version_impact(reader, "4.0")
            await reader.rollback()

        assert result == _impact(cves_evaluated=2, cve_severity_changes=1)

    async def test_high_water_mark_bounds_the_population(
        self,
        db_session_factory: SessionFactory,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A CVE committed after the mark with a greater `id` is excluded.
        A CVE whose `id` is below the mark and that becomes visible during
        the scan may or may not be observed. Neither the mark nor any
        preview state is returned."""
        async with _committed_population(db_session_factory, 1) as ids:
            writer = await db_session_factory()

            async def _insert() -> None:
                late = CVE(cve_id="CVE-2099-98888", severity=Severity.MEDIUM.value)
                below = CVE(
                    id=uuid.UUID(int=1),
                    cve_id="CVE-2099-98889",
                    severity=Severity.MEDIUM.value,
                )
                writer.add_all([late, below])
                await writer.flush()
                assert late.id > ids[0] > below.id
                writer.add_all(
                    [_suse(late.id, "4.0", "9.0"), _suse(below.id, "4.0", "9.0")]
                )
                await writer.commit()

            _before_bound(monkeypatch, 3, _insert)
            reader = await db_session_factory()

            result = await get_default_cvss_version_impact(reader, "4.0")
            await reader.rollback()

        assert result in (
            _impact(cves_evaluated=1, cve_severity_changes=1),
            _impact(cves_evaluated=2, cve_severity_changes=2),
        )
        assert set(DefaultCVSSVersionImpact.__dataclass_fields__) == {
            "observed_default_cvss_version",
            "proposed_default_cvss_version",
            "no_op",
            "cves_evaluated",
            "cve_severity_changes",
            "product_eligibility_changes",
            "product_eligibility_override_skips",
            "resolved_ticket_regressions",
        }


def _impact(**counts: int) -> DefaultCVSSVersionImpact:
    values = {
        "cves_evaluated": 0,
        "cve_severity_changes": 0,
        "product_eligibility_changes": 0,
        "product_eligibility_override_skips": 0,
        "resolved_ticket_regressions": 0,
    }
    values.update(counts)
    return DefaultCVSSVersionImpact(
        observed_default_cvss_version="3.1",
        proposed_default_cvss_version="4.0",
        no_op=False,
        **values,
    )
