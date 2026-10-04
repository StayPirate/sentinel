"""Tests for the database-free on-demand publication
`cve_service.trigger_on_demand_fetch()` and `FetchDispatchResult`
(backend/app/services/cve_service.py).

Owning specifications:

- docs/features/tickets/cve-service.md (Fetch Orchestration:
  `trigger_on_demand_fetch()` — Database-Free Publication and
  `FetchDispatchResult`; Caller Validation Responsibility; CVE Source Status,
  Status values and Redis graceful degradation, for overlay agreement);
- docs/features/platform/fetcher-infrastructure.md (On-Demand Queue
  Routing);
- docs/features/platform/testing-strategy.md (On-Demand CVE Refetch; Redis
  Strategy; Application-Owned Redis Operations);
- issue #799 decisions D3 (token grammar), D5 (marker protocol), D9 (one
  `fetch_pending_marker_unavailable` WARNING per fail-open source), and D10
  (duplicate sources raise `ValueError` before any I/O; code-point order).

Marker tests use the worker Redis database through `redis_client`, which
redirects `cve_service.get_fetch_pending_redis_url`; `RedisError` behavior
replaces the `_new_redis_client` boundary with `ScriptedRedis` instead of
stopping Redis. The broker is never reached: `task_publication.publish_task`
is a recording substitute, or, for the queue-option tests, the real
`publish_task` runs over a substituted `celery_app.send_task`. Publication
needs no PostgreSQL; the overlay-agreement tests commit a CVE and a
`FetcherConfig` row and delete them explicitly at teardown.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from typing import Any, cast
from unittest.mock import MagicMock, call

import pytest
import redis.asyncio as redis_asyncio
from celery.exceptions import (
    OperationalError,  # kombu.exceptions.OperationalError
    SoftTimeLimitExceeded,
)
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError, ResponseError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from structlog.testing import capture_logs

from app.celery_app import celery_app
from app.core.enums import CVESourceDerivedStatus, CVESourceType
from app.services import base_cve_fetcher, cve_service, task_publication
from app.services.base_cve_fetcher import CVEFetchResult, get_fetch_single_fetchers
from app.services.cve_ingest import UpsertAction
from app.services.cve_service import (
    CVEIdFormatError,
    FetchDispatchResult,
    _PendingMarker,
    get_cve_source_status,
    trigger_on_demand_fetch,
)
from app.services.ticket_visibility import ANONYMOUS_CALLER
from tests.support.cve_catch_up import (
    CVEProbe,
    Publications,
    define_cve_fetcher,
    delete_fetcher_rows,
    seed_fetcher_config,
)
from tests.support.fetch_single_cve import (
    MARKER_UNAVAILABLE,
    PENDING_TTL,
    TASK,
    TOKEN_PATTERN,
    NoDatabaseAccess,
    ScriptedRedis,
    assert_private_logs,
    forbid_redis,
    pending_key,
    wait_until_expired,
)
from tests.support.suse_cvss_races import CommittedWorld

SessionFactory = Callable[[], Awaitable[AsyncSession]]
Dispatch = list[tuple[str, str, str | None]]

CVE_ID = "CVE-2099-0001"
NVD_FETCHER = "fictional_nvd_fetcher"
GHSA_FETCHER = "fictional_ghsa_fetcher"
MITRE_FETCHER = "fictional_mitre_fetcher"
OSV_FETCHER = "fictional_osv_fetcher"
REDHAT_FETCHER = "fictional_redhat_fetcher"

_SIGNALS = [
    pytest.param(asyncio.CancelledError, id="cancelled"),
    pytest.param(SoftTimeLimitExceeded, id="soft-time-limit"),
    pytest.param(MemoryError, id="memory-error"),
]


def _publication_kwargs(published: Publications) -> list[dict[str, Any]]:
    return published.published(TASK)


def _failing_for(sources: set[str], error: Exception) -> Callable[..., Awaitable[None]]:
    """A `Publications.before` hook that raises `error` for `sources`."""

    async def before(call_options: dict[str, Any]) -> None:
        if call_options["kwargs"]["source"] in sources:
            raise error

    return before


def _assert_partition(result: FetchDispatchResult, prepared: Sequence[str]) -> None:
    """Four disjoint lists, each in code-point order, covering `prepared`."""
    lists = [
        result.sources_enqueued,
        result.sources_already_pending,
        result.sources_disabled,
        result.sources_failed,
    ]
    for values in lists:
        assert values == sorted(values)
    flat = [source for values in lists for source in values]
    assert len(flat) == len(set(flat))
    assert set(flat) == set(prepared)


@pytest.fixture
def published(monkeypatch: pytest.MonkeyPatch) -> Publications:
    recorder = Publications()
    monkeypatch.setattr(task_publication, "publish_task", recorder)
    return recorder


# ---------------------------------------------------------------------------
# Input guard: no Redis or Celery I/O
# ---------------------------------------------------------------------------

_MALFORMED_CVE_IDS = [
    pytest.param("cve-2099-0001", id="lowercase"),
    pytest.param("CVE-2099-" + "1" * 12, id="overlength-21"),
    pytest.param("", id="empty"),
    pytest.param(" CVE-2099-0001", id="leading-space"),
    pytest.param("CVE-2099-001", id="three-digit-sequence"),
    pytest.param(None, id="none"),
    pytest.param(20990001, id="integer"),
    pytest.param(b"CVE-2099-0001", id="bytes"),
]


@pytest.mark.unit
class TestInputGuard:
    @pytest.mark.parametrize("cve_id", _MALFORMED_CVE_IDS)
    async def test_trigger_malformed_cve_id_raises_format_error_without_any_io(
        self,
        cve_id: object,
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        attempts = forbid_redis(monkeypatch)

        with capture_logs() as logs, pytest.raises(CVEIdFormatError):
            await trigger_on_demand_fetch(
                cast(str, cve_id), [(NVD_FETCHER, "nvd", None)], ["ghsa"]
            )

        assert attempts() == 0
        assert published.calls == []
        assert logs == []

    @pytest.mark.parametrize(
        ("dispatch", "disabled"),
        [
            pytest.param(
                [(NVD_FETCHER, "nvd", None), ("fictional_other", "nvd", None)],
                [],
                id="within-dispatch",
            ),
            pytest.param(
                [(NVD_FETCHER, "nvd", None)],
                ["ghsa", "nvd"],
                id="dispatch-and-disabled",
            ),
            pytest.param([], ["ghsa", "ghsa"], id="within-disabled"),
        ],
    )
    async def test_trigger_duplicate_sources_raise_value_error_before_any_io(
        self,
        dispatch: Dispatch,
        disabled: list[str],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        attempts = forbid_redis(monkeypatch)

        with pytest.raises(ValueError, match="distinct"):
            await trigger_on_demand_fetch(CVE_ID, dispatch, disabled)

        assert attempts() == 0
        assert published.calls == []

    async def test_trigger_only_disabled_sources_performs_no_redis_or_publication(
        self, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts = forbid_redis(monkeypatch)

        result = await trigger_on_demand_fetch(CVE_ID, [], ["osv", "ghsa"])

        assert result == FetchDispatchResult(
            sources_enqueued=[],
            sources_already_pending=[],
            sources_disabled=["ghsa", "osv"],
            sources_failed=[],
        )
        assert attempts() == 0
        assert published.calls == []

    def test_new_marker_token_draws_32_bytes_from_secrets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        drawn: list[int] = []
        real = secrets.token_urlsafe

        def token_urlsafe(nbytes: int) -> str:
            drawn.append(nbytes)
            return real(nbytes)

        monkeypatch.setattr(secrets, "token_urlsafe", token_urlsafe)

        token = cve_service._new_marker_token()

        assert drawn == [32]
        assert TOKEN_PATTERN.fullmatch(token)


# ---------------------------------------------------------------------------
# Token marker writer (worker Redis database)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMarkerWriter:
    async def test_trigger_writes_published_token_under_exact_key_with_600s_ttl(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        result = await trigger_on_demand_fetch(CVE_ID, [(NVD_FETCHER, "nvd", None)])

        assert result.sources_enqueued == ["nvd"]
        [kwargs] = _publication_kwargs(published)
        token = kwargs["token"]
        assert TOKEN_PATTERN.fullmatch(token)
        key = "fetch_pending:CVE-2099-0001:nvd"
        assert await redis_client.keys("*") == [key]
        assert await redis_client.get(key) == token
        ttl = await redis_client.ttl(key)
        assert 0 < ttl <= PENDING_TTL
        pttl = await redis_client.pttl(key)
        assert PENDING_TTL * 1000 - 5000 < pttl <= PENDING_TTL * 1000

    async def test_trigger_sends_set_with_nx_and_ex_600(
        self, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = ScriptedRedis()
        created = client.install(monkeypatch)

        await trigger_on_demand_fetch(
            CVE_ID, [(NVD_FETCHER, "nvd", None), (GHSA_FETCHER, "ghsa", None)]
        )

        assert created == [1]
        assert [key for _, key, _ in client.commands] == [
            pending_key(CVE_ID, "ghsa"),
            pending_key(CVE_ID, "nvd"),
        ]
        assert client.set_options == [{"nx": True, "ex": PENDING_TTL}] * 2
        assert client.values("set") == [
            kwargs["token"] for kwargs in _publication_kwargs(published)
        ]
        assert client.closed == 1

    async def test_trigger_tokens_are_unique_across_sources_and_invocations(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        dispatch: Dispatch = [
            (NVD_FETCHER, "nvd", None),
            (GHSA_FETCHER, "ghsa", None),
            (OSV_FETCHER, "osv", None),
        ]

        await trigger_on_demand_fetch(CVE_ID, dispatch)
        first = {k["source"]: k["token"] for k in _publication_kwargs(published)}
        for source, token in first.items():
            assert await redis_client.get(pending_key(CVE_ID, source)) == token
        await redis_client.delete(*(pending_key(CVE_ID, s) for s in first))
        await trigger_on_demand_fetch(CVE_ID, dispatch)

        tokens = [kwargs["token"] for kwargs in _publication_kwargs(published)]
        assert len(tokens) == 6
        assert len(set(tokens)) == 6
        assert all(TOKEN_PATTERN.fullmatch(token) for token in tokens)

    async def test_trigger_existing_marker_reports_already_pending_untouched(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        existing = pending_key(CVE_ID, "nvd")
        await redis_client.set(existing, "fictional-earlier-owner", ex=300)

        result = await trigger_on_demand_fetch(
            CVE_ID, [(NVD_FETCHER, "nvd", None), (GHSA_FETCHER, "ghsa", None)]
        )

        assert result == FetchDispatchResult(
            sources_enqueued=["ghsa"],
            sources_already_pending=["nvd"],
            sources_disabled=[],
            sources_failed=[],
        )
        assert [k["source"] for k in _publication_kwargs(published)] == ["ghsa"]
        assert await redis_client.get(existing) == "fictional-earlier-owner"
        assert 0 < await redis_client.ttl(existing) <= 300

    async def test_trigger_reinvocation_coalesces_on_the_current_marker(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        dispatch: Dispatch = [(NVD_FETCHER, "nvd", None)]

        first = await trigger_on_demand_fetch(CVE_ID, dispatch)
        second = await trigger_on_demand_fetch(CVE_ID, dispatch)

        assert first.sources_enqueued == ["nvd"]
        assert second.sources_already_pending == ["nvd"]
        assert second.sources_enqueued == []
        [kwargs] = _publication_kwargs(published)
        assert await redis_client.get(pending_key(CVE_ID, "nvd")) == kwargs["token"]

    async def test_marker_expiry_after_a_lost_task_allows_a_new_publication(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        """The task of the first publication never runs (crash or hard
        kill): the TTL recovers, and a later publication owns a new
        marker."""
        dispatch: Dispatch = [(NVD_FETCHER, "nvd", None)]
        key = pending_key(CVE_ID, "nvd")
        await trigger_on_demand_fetch(CVE_ID, dispatch)
        assert (await trigger_on_demand_fetch(CVE_ID, dispatch)).sources_already_pending

        await redis_client.pexpire(key, 1)
        await wait_until_expired(redis_client, key)
        recovered = await trigger_on_demand_fetch(CVE_ID, dispatch)

        assert recovered.sources_enqueued == ["nvd"]
        first, second = (k["token"] for k in _publication_kwargs(published))
        assert first != second
        assert await redis_client.get(key) == second


# ---------------------------------------------------------------------------
# Redis fail-open publication
# ---------------------------------------------------------------------------

SECRET = "redis://cache.example.invalid:6379/0"
"""A connection detail that must never reach a log record."""

_SET_ERRORS = [
    pytest.param(
        lambda: RedisConnectionError(f"fictional refusal: {SECRET}"), id="connection"
    ),
    pytest.param(
        lambda: ResponseError(
            f"OOM command not allowed when used memory > 'maxmemory'. {SECRET}"
        ),
        id="oom-response",
    ),
]


@pytest.mark.unit
class TestRedisFailOpen:
    @pytest.mark.parametrize("make_error", _SET_ERRORS)
    async def test_trigger_set_redis_error_publishes_without_marker_and_logs_once(
        self,
        make_error: Callable[[], RedisError],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        error = make_error()
        client = ScriptedRedis(
            set_results={
                pending_key(CVE_ID, "ghsa"): error,
                pending_key(CVE_ID, "osv"): error,
            }
        )
        client.install(monkeypatch)
        dispatch: Dispatch = [
            (OSV_FETCHER, "osv", None),
            (NVD_FETCHER, "nvd", None),
            (GHSA_FETCHER, "ghsa", None),
        ]

        with capture_logs() as logs:
            result = await trigger_on_demand_fetch(CVE_ID, dispatch)

        assert result.sources_enqueued == ["ghsa", "nvd", "osv"]
        assert result.sources_failed == []
        tokens = [kwargs["token"] for kwargs in _publication_kwargs(published)]
        assert [k["source"] for k in _publication_kwargs(published)] == [
            "ghsa",
            "nvd",
            "osv",
        ]
        assert logs == [
            {
                "event": MARKER_UNAVAILABLE,
                "log_level": "warning",
                "cve_id": CVE_ID,
                "source": source,
                "fetcher_name": fetcher_name,
                "cause": type(error).__name__,
            }
            for source, fetcher_name in (("ghsa", GHSA_FETCHER), ("osv", OSV_FETCHER))
        ]
        assert_private_logs(logs, *tokens, str(error), SECRET)
        assert client.closed == 1

    async def test_trigger_client_close_redis_error_is_suppressed(
        self, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = ScriptedRedis(aclose_error=RedisConnectionError("fictional"))
        client.install(monkeypatch)

        result = await trigger_on_demand_fetch(CVE_ID, [(NVD_FETCHER, "nvd", None)])

        assert result.sources_enqueued == ["nvd"]
        assert client.closed == 1


# ---------------------------------------------------------------------------
# Publication: identity, queue routing, ambiguity, and control signals
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPublication:
    @pytest.mark.usefixtures("isolated_fetcher_registries")
    async def test_trigger_publishes_fetcher_class_identity_and_queue(
        self, published: Publications, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The prepared values of a Git-routed and a default-routed
        test-only class are published as `fetch_single_cve` with exactly
        the four payload fields; `queue` reaches `publish_task()` as given."""
        client = ScriptedRedis()
        client.install(monkeypatch)
        git = define_cve_fetcher(source=CVESourceType.MITRE, fetcher_queue="git")
        default = define_cve_fetcher(source=CVESourceType.NVD)
        registry = get_fetch_single_fetchers()
        dispatch: Dispatch = [
            (cls.name, cls.cve_source_type.value, cls.queue)
            for cls in (registry["mitre"], registry["nvd"])
        ]

        result = await trigger_on_demand_fetch(CVE_ID, dispatch)

        assert result.sources_enqueued == ["mitre", "nvd"]
        tokens = client.values("set")
        assert published.calls == [
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": git.name,
                    "cve_id": CVE_ID,
                    "source": "mitre",
                    "token": tokens[0],
                },
                "queue": "git",
            },
            {
                "task_name": TASK,
                "kwargs": {
                    "fetcher_name": default.name,
                    "cve_id": CVE_ID,
                    "source": "nvd",
                    "token": tokens[1],
                },
                "queue": None,
            },
        ]

    async def test_trigger_real_publish_task_omits_none_queue_and_preserves_git(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = ScriptedRedis()
        client.install(monkeypatch)
        send_task = MagicMock()
        monkeypatch.setattr(celery_app, "send_task", send_task)

        await trigger_on_demand_fetch(
            CVE_ID, [(MITRE_FETCHER, "mitre", "git"), (NVD_FETCHER, "nvd", None)]
        )

        mitre_token, nvd_token = client.values("set")
        assert send_task.call_args_list == [
            call(
                TASK,
                kwargs={
                    "fetcher_name": MITRE_FETCHER,
                    "cve_id": CVE_ID,
                    "source": "mitre",
                    "token": mitre_token,
                },
                ignore_result=True,
                queue="git",
            ),
            call(
                TASK,
                kwargs={
                    "fetcher_name": NVD_FETCHER,
                    "cve_id": CVE_ID,
                    "source": "nvd",
                    "token": nvd_token,
                },
                ignore_result=True,
            ),
        ]
        assert "queue" not in send_task.call_args_list[1].kwargs

    @pytest.mark.parametrize(
        "make_error",
        [
            pytest.param(
                lambda: OperationalError(f"fictional broker refusal {SECRET}"),
                id="kombu-operational",
            ),
            pytest.param(lambda: RuntimeError("fictional failure"), id="runtime"),
            pytest.param(lambda: TypeError("fictional serialization"), id="type"),
        ],
    )
    async def test_trigger_publication_exception_reports_failed_and_continues(
        self,
        make_error: Callable[[], Exception],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = ScriptedRedis()
        client.install(monkeypatch)
        published.before = _failing_for({"ghsa"}, make_error())

        with capture_logs() as logs:
            result = await trigger_on_demand_fetch(
                CVE_ID, [(NVD_FETCHER, "nvd", None), (GHSA_FETCHER, "ghsa", None)]
            )

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd"],
            sources_already_pending=[],
            sources_disabled=[],
            sources_failed=["ghsa"],
        )
        assert [k["source"] for k in _publication_kwargs(published)] == ["ghsa", "nvd"]
        # The owned marker is never deleted because publication raised.
        assert [name for name, _, _ in client.commands] == ["set", "set"]
        # D9: the caller owns the `sources_failed` log.
        assert logs == []

    @pytest.mark.parametrize("make_signal", _SIGNALS)
    async def test_trigger_control_signal_propagates_and_closes_the_client(
        self,
        make_signal: Callable[[], BaseException],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        client = ScriptedRedis()
        client.install(monkeypatch)
        signal = make_signal()

        async def before(call_options: dict[str, Any]) -> None:
            raise signal

        published.before = before

        with pytest.raises(type(signal)) as raised:
            await trigger_on_demand_fetch(
                CVE_ID, [(GHSA_FETCHER, "ghsa", None), (NVD_FETCHER, "nvd", None)]
            )

        assert raised.value is signal
        assert len(published.calls) == 1
        assert client.closed == 1


@pytest.mark.integration
class TestPublicationWithRedis:
    async def test_failed_publication_retains_the_owned_marker(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        published.before = _failing_for(
            {"ghsa"}, OperationalError("fictional broker refusal")
        )

        result = await trigger_on_demand_fetch(
            CVE_ID, [(GHSA_FETCHER, "ghsa", None), (NVD_FETCHER, "nvd", None)]
        )

        assert result.sources_failed == ["ghsa"]
        assert result.sources_enqueued == ["nvd"]
        tokens = {k["source"]: k["token"] for k in _publication_kwargs(published)}
        for source in ("ghsa", "nvd"):
            key = pending_key(CVE_ID, source)
            assert await redis_client.get(key) == tokens[source]
            assert 0 < await redis_client.ttl(key) <= PENDING_TTL

    async def test_trigger_performs_no_database_access(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        """Every outcome (enqueued, already pending, failed, disabled) runs
        without a SQL statement or a pool checkout of any engine."""
        await redis_client.set(pending_key(CVE_ID, "mitre"), "fictional-owner")
        published.before = _failing_for({"osv"}, RuntimeError("fictional"))

        with NoDatabaseAccess() as observed:
            result = await trigger_on_demand_fetch(
                CVE_ID,
                [
                    (OSV_FETCHER, "osv", None),
                    (NVD_FETCHER, "nvd", None),
                    (MITRE_FETCHER, "mitre", "git"),
                ],
                ["ghsa"],
            )

        assert observed.statements == []
        assert observed.checkouts == 0
        assert result == FetchDispatchResult(
            sources_enqueued=["nvd"],
            sources_already_pending=["mitre"],
            sources_disabled=["ghsa"],
            sources_failed=["osv"],
        )


# ---------------------------------------------------------------------------
# FetchDispatchResult
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFetchDispatchResult:
    async def test_result_lists_are_disjoint_ordered_and_cover_the_prepared_set(
        self, redis_client: redis_asyncio.Redis, published: Publications
    ) -> None:
        """Input in reverse order; one source already pending, two failing
        publication, two disabled. Publication runs in code-point order and
        disabled sources get no Redis or Celery I/O."""
        await redis_client.set(pending_key(CVE_ID, "mitre"), "fictional-owner")
        published.before = _failing_for({"redhat", "ghsa"}, RuntimeError("x"))
        dispatch: Dispatch = [
            (REDHAT_FETCHER, "redhat", None),
            (OSV_FETCHER, "osv", None),
            (NVD_FETCHER, "nvd", None),
            (MITRE_FETCHER, "mitre", "git"),
            (GHSA_FETCHER, "ghsa", None),
        ]
        disabled = ["kernel", "epss"]

        result = await trigger_on_demand_fetch(CVE_ID, dispatch, disabled)

        assert result == FetchDispatchResult(
            sources_enqueued=["nvd", "osv"],
            sources_already_pending=["mitre"],
            sources_disabled=["epss", "kernel"],
            sources_failed=["ghsa", "redhat"],
        )
        _assert_partition(result, [s for _, s, _ in dispatch] + disabled)
        assert [k["source"] for k in _publication_kwargs(published)] == [
            "ghsa",
            "nvd",
            "osv",
            "redhat",
        ]
        for source in disabled:
            assert await redis_client.exists(pending_key(CVE_ID, source)) == 0


@pytest.mark.unit
def test_dispatch_result_is_a_service_dataclass_with_four_list_fields() -> None:
    result = FetchDispatchResult([], [], [], [])

    assert list(FetchDispatchResult.__dataclass_fields__) == [
        "sources_enqueued",
        "sources_already_pending",
        "sources_disabled",
        "sources_failed",
    ]
    with pytest.raises(AttributeError):
        result.sources_failed = ["nvd"]  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Agreement with the source-status overlay (#751 reader)
# ---------------------------------------------------------------------------


@pytest.fixture
async def world(db_session_factory: SessionFactory) -> AsyncIterator[CommittedWorld]:
    created = CommittedWorld(db_session_factory, await db_session_factory())
    try:
        yield created
    finally:
        await created.cleanup()


def _nvd_status(entries: Sequence[cve_service.CVESourceStatusEntry]) -> Any:
    [entry] = [entry for entry in entries if entry.source == "nvd"]
    return entry.status


@pytest.mark.integration
@pytest.mark.usefixtures("isolated_fetcher_registries")
class TestOverlayAgreement:
    @pytest.mark.parametrize("ending", ["task-release", "owner-release", "ttl-expiry"])
    async def test_written_marker_reports_pending_until_cleanup_or_expiry(
        self,
        world: CommittedWorld,
        redis_client: redis_asyncio.Redis,
        real_session_factory: async_sessionmaker[AsyncSession],
        published: Publications,
        monkeypatch: pytest.MonkeyPatch,
        ending: str,
    ) -> None:
        cve = await world.cve()
        probe: CVEProbe = define_cve_fetcher(source=CVESourceType.NVD)
        await seed_fetcher_config(real_session_factory, probe.name, enabled=True)
        monkeypatch.setattr(
            base_cve_fetcher, "async_session_factory", real_session_factory
        )

        async def status() -> CVESourceDerivedStatus:
            result = await get_cve_source_status(
                cve.cve_id, ANONYMOUS_CALLER, session_factory=real_session_factory
            )
            return cast(CVESourceDerivedStatus, _nvd_status(result.entries))

        async def unchanged(cve_id: str, session: AsyncSession) -> CVEFetchResult:
            return CVEFetchResult(action=UpsertAction.UNCHANGED, post_ingest=None)

        try:
            assert await status() == CVESourceDerivedStatus.NOT_ATTEMPTED
            result = await trigger_on_demand_fetch(
                cve.cve_id, [(probe.name, "nvd", None)]
            )
            assert result.sources_enqueued == ["nvd"]
            [kwargs] = _publication_kwargs(published)
            assert await status() == CVESourceDerivedStatus.PENDING

            key = pending_key(cve.cve_id, "nvd")
            if ending == "task-release":
                probe.step = unchanged
                await cve_service.run_fetch_single_cve(
                    **kwargs, attempt=0, session_factory=real_session_factory
                )
                assert probe.fetched == [cve.cve_id]
            elif ending == "owner-release":
                marker = _PendingMarker(cve.cve_id, "nvd", kwargs["token"])
                await marker.release()
                await marker.aclose()
            else:
                await redis_client.pexpire(key, 1)
                await wait_until_expired(redis_client, key)

            assert await redis_client.exists(key) == 0
            assert await status() == CVESourceDerivedStatus.NOT_ATTEMPTED
        finally:
            await delete_fetcher_rows(real_session_factory, [probe.name])
