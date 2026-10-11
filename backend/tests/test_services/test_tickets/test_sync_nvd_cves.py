"""Tests for the `SyncNvdCves` class attributes and custom settings, the
per-request API key, and `SyncNvdCves.fetch_single()`
(backend/app/services/tickets/sync_nvd_cves.py).

Owning specifications:

- docs/features/tickets/cve-sync-nvd.md (Fetcher Definition, Class Structure,
  HTTP Client Configuration, Custom Settings; NVD Source API Caching and NVD
  Source API Failure Handling; `fetch_single(cve_id)`; Field Mapping,
  including the candidate skip event, CPE configurations, and External
  String Admissibility; Error Handling, the `fetch_single()` table and the
  partial extraction model).
- docs/features/platform/cve-fetcher-infrastructure.md (`CVEFetchResult`;
  `fetch_single` Signaling Convention; Retry Policy for `fetch_single`;
  Error Categorization, with the NVD HTTP 404 deviation; Candidate Skip
  Event).
- docs/features/platform/fetcher-infrastructure.md (Custom Settings Schema;
  BaseFetcher HTTP Client Integration, HTTP Client Ownership Rule) and
  docs/features/platform/networking.md (Redirect Policy; Celery Retry
  Classification); docs/features/platform/logging.md (Secrets and PII
  Discipline).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure,
  Typed result; External String Admissibility; NVD CPE Applicability
  Selection, the outcome, logging, and handoff obligations of
  `fetch_single()`).

HTTP is the in-process `NvdServer` of `tests/support/nvd.py`, injected as
the fetcher's HTTP client, serving the sanitized live fixtures (retargeted
to the processed CVE-ID) or minimal fictional records, and the trimmed live
Source API body. `NVD_API_KEY` is set explicitly on `app.config.settings` by
every test to a fictional value or to empty. Outcome tests that end before
any database work use a session that fails on any use, and spies on
`cve_service.upsert_cve()` and `reference_service.upsert_references()` prove
no mutation was attempted; they are unit tests. Ingestion tests run the real
`upsert_cve()` and `upsert_references()` on `db_session`, rolled back at
teardown. The periodic `execute()` is tested in
`test_sync_nvd_cves_execute.py`. All identifiers and texts are fictional,
except the public data of the live fixtures and NVD's institutional source
identifier `nvd@nist.gov`.
"""

from __future__ import annotations

import asyncio
import copy
import uuid
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Final, cast

import httpx
import pytest
from celery.exceptions import SoftTimeLimitExceeded
from pydantic import BaseModel, SecretStr, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs

import app.services.fetcher_discovery  # noqa: F401
from app.config import Settings
from app.config import settings as app_settings
from app.core.enums import (
    CVESourceFetchStatus,
    CVESourceType,
    CveState,
    ReferenceType,
    TicketStatus,
)
from app.models.cve import CVE
from app.models.cve_cvss_assessment import CVECVSSAssessment
from app.models.cve_cwe import CVECWE
from app.models.cve_source import CVESource
from app.models.system_setting import SystemSetting
from app.models.ticket import Ticket
from app.models.ticket_reference import TicketReference
from app.services import cve_service, fetcher_execution, reference_service
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
    BaseCVEFetcher,
    CVEFetchResult,
    CVENotInSource,
)
from app.services.base_fetcher import FETCHER_REGISTRY, FetcherError
from app.services.cve_ingest import CVEIngestPayload, PostIngestTasks, UpsertAction
from app.services.http_client import is_infrastructure_failure, is_retryable_condition
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import sync_nvd_cves as sync_module
from app.services.tickets.nvd_cve_record import (
    NvdPageError,
    NvdRecordStructureError,
)
from app.services.tickets.sync_nvd_cves import (
    API_KEY_INVALID,
    NVD_SOURCE_API_UNAVAILABLE_EVENT,
    NVD_SOURCE_CACHE_INCOMPLETE_EVENT,
    NVD_SOURCE_ENTRIES_SKIPPED_EVENT,
    NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
    NvdResponseError,
    SyncNvdCves,
)
from tests.support.cve_ingest import SKIP_EVENT
from tests.support.fetch_single_cve import fictional_cve_id
from tests.support.nvd import (
    API_KEY_HEADER,
    CVE_API_URL,
    PAGE_EMPTY,
    PAGE_REJECTED,
    SINGLE_LOG4SHELL,
    SOURCE_API_URL,
    SOURCE_PAGE,
    NvdServer,
    Responder,
    load_json_fixture,
    load_raw_fixture,
    load_record,
    page_body,
    raising,
    status,
)
from tests.support.nvd import body as json_body
from tests.support.ticket_mutations import EventRow, ticket_events

NAME: Final = "sync_nvd_cves"
API_KEY: Final = "fictional-nvd-api-key-0001"
"""A fictional `NVD_API_KEY`; never a real key shape."""
OTHER_KEY: Final = "fictional-nvd-api-key-0002"
NVD: Final = "nvd@nist.gov"
CNA_SOURCE: Final = "hackerone-1@example.com"
"""A fictional CNA identifier of the trimmed live Source API body."""
CNA_NAME: Final = "HackerOne"
UNKNOWN_SOURCE: Final = "unknown-cna-1@example.com"
PUBLISHED: Final = "2026-01-01T00:00:00.000"
LAST_MODIFIED: Final = "2026-01-02T03:04:05.678"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_CNA: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CPE_A: Final = "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"
CPE_O: Final = "cpe:2.3:o:example:system:2.0:*:*:*:*:*:*:*"
CPE_H: Final = "cpe:2.3:h:example:board:-:*:*:*:*:*:*:*"
CPE_PLATFORM: Final = "cpe:2.3:o:example:platform:-:*:*:*:*:*:*:*"
CPE_NEGATED: Final = "cpe:2.3:a:example:negated:-:*:*:*:*:*:*:*"
MATCH_ID: Final = "0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
SECRET: Final = "Example-Secret-Upstream-Value"
"""An upstream value that must never reach a log record or an error."""
INGESTION_COMMENT: Final = "CVE ingested from NVD"


class _Absent:
    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent()
"""Marks a member removed from a record."""


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class _NoSession:
    """A session that fails the test on any use."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used before the final write")


NO_SESSION: Final = cast(AsyncSession, _NoSession())


@dataclass
class Ingestion:
    """Spies on the two ingestion delegates; both call through."""

    upserts: list[tuple[str, CVESourceType, CVEIngestPayload]] = field(
        default_factory=list
    )
    references: list[dict[str, Any]] = field(default_factory=list)

    @property
    def calls(self) -> int:
        return len(self.upserts) + len(self.references)


@pytest.fixture
def ingestion(monkeypatch: pytest.MonkeyPatch) -> Ingestion:
    spy = Ingestion()
    real_upsert = cve_service.upsert_cve
    real_references = reference_service.upsert_references

    async def upsert_cve(
        db: AsyncSession, cve_id: str, source: CVESourceType, payload: CVEIngestPayload
    ) -> Any:
        spy.upserts.append((cve_id, source, payload))
        return await real_upsert(db, cve_id, source, payload)

    async def upsert_references(
        session: AsyncSession,
        ticket_id: Any,
        cve_id: str,
        source: str,
        source_reference: AutomaticReferenceInput | None,
        upstream_references: Iterable[AutomaticReferenceInput],
    ) -> None:
        upstream = list(upstream_references)
        spy.references.append(
            {
                "ticket_id": ticket_id,
                "cve_id": cve_id,
                "source": source,
                "source_reference": source_reference,
                "upstream": upstream,
            }
        )
        await real_references(
            session, ticket_id, cve_id, source, source_reference, upstream
        )

    monkeypatch.setattr(cve_service, "upsert_cve", upsert_cve)
    monkeypatch.setattr(reference_service, "upsert_references", upsert_references)
    return spy


@pytest.fixture(autouse=True)
def nvd_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test sets the key itself, never relying on the environment."""
    monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(API_KEY))


@pytest.fixture
def server() -> NvdServer:
    return NvdServer()


@pytest.fixture(autouse=True)
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Every throttle sleep of the module, recorded instead of slept."""
    recorded: list[float] = []

    async def sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(sync_module, "asyncio", SimpleNamespace(sleep=sleep))
    return recorded


@pytest.fixture
async def fetcher(server: NvdServer) -> AsyncIterator[SyncNvdCves]:
    instance = SyncNvdCves()
    instance._http_client = server.client()
    try:
        yield instance
    finally:
        await instance._teardown_http_client()


@dataclass
class Target:
    cve: CVE
    ticket: Ticket

    @property
    def cve_id(self) -> str:
        return self.cve.cve_id


async def _target(db: AsyncSession, ticket_status: TicketStatus) -> Target:
    if await db.get(SystemSetting, "default_cvss_version") is None:
        db.add(SystemSetting(key="default_cvss_version", value="3.1"))
    cve = CVE(cve_id=fictional_cve_id())
    db.add(cve)
    await db.flush()
    ticket = Ticket(status=ticket_status.value, cve_id=cve.id)
    db.add(ticket)
    await db.flush()
    return Target(cve, ticket)


@pytest.fixture
async def target(db_session: AsyncSession) -> Target:
    """A CVE with its `Analysis` Ticket and the default CVSS version the
    trusted-external batch reads."""
    return await _target(db_session, TicketStatus.ANALYSIS)


# ---------------------------------------------------------------------------
# Record builders and persisted-state readers
# ---------------------------------------------------------------------------


def _record(cve_id: object, **members: Any) -> dict[str, Any]:
    """A minimal fictional `vulnerabilities[]` element; `ABSENT` removes a
    `cve` member."""
    cve: dict[str, Any] = {
        "id": cve_id,
        "published": PUBLISHED,
        "lastModified": LAST_MODIFIED,
        "vulnStatus": "Analyzed",
    }
    cve.update(members)
    return {"cve": {k: v for k, v in cve.items() if v is not ABSENT}}


def _retargeted(name: str, cve_id: str) -> dict[str, Any]:
    """A live record fixture whose `.id` names `cve_id` instead."""
    element = copy.deepcopy(load_record(name))
    element["cve"]["id"] = cve_id
    return element


def _metric(source: object, vector: str) -> dict[str, Any]:
    return {
        "source": source,
        "type": "Primary",
        "cvssData": {"version": "3.1", "vectorString": vector},
    }


def _weakness(source: object, value: str) -> dict[str, Any]:
    return {
        "source": source,
        "type": "Primary",
        "description": [{"lang": "en", "value": value}],
    }


def _sourced(cve_id: str) -> dict[str, Any]:
    """NVD's own and a CNA's CVSS vector and CWE."""
    return _record(
        cve_id,
        metrics={"cvssMetricV31": [_metric(NVD, V31), _metric(CNA_SOURCE, V31_CNA)]},
        weaknesses=[_weakness(NVD, "CWE-79"), _weakness(CNA_SOURCE, "CWE-352")],
    )


def _configuration(*entries: Any, negate: object = ABSENT) -> dict[str, Any]:
    configuration: dict[str, Any] = {
        "operator": "OR",
        "nodes": [{"operator": "OR", "negate": False, "cpeMatch": list(entries)}],
    }
    if negate is not ABSENT:
        configuration["negate"] = negate
    return configuration


def _match(criteria: object, *, vulnerable: object = True, **members: Any) -> Any:
    return {"vulnerable": vulnerable, "criteria": criteria, **members}


CPE_CONFIGURATIONS: Final = [
    {
        "operator": "AND",
        "nodes": [
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [
                    _match(CPE_A, matchCriteriaId=MATCH_ID),
                    _match(CPE_O),
                    _match(f"{CPE_A}\x00"),
                    _match(f"cpe:2.3:a:{SECRET}:x:-:*:*:*:*:*:*:*", vulnerable="yes"),
                ],
            },
            {
                "operator": "OR",
                "negate": False,
                "cpeMatch": [_match(CPE_PLATFORM, vulnerable=False)],
            },
        ],
    },
    _configuration(_match(CPE_NEGATED), negate=True),
    {"operator": "OR", "nodes": SECRET},
    _configuration(_match(CPE_H, matchCriteriaId=f"{SECRET}-not-a-uuid")),
]
"""Two selected entries (an application with a match criteria ID and an
operating system), an excluded platform and negated configuration, two
invalid entries, an invalid configuration, and an entry with an invalid
match criteria ID."""

SELECTED_CPES: Final = [
    {
        "criteria": CPE_A,
        "vulnerable": True,
        "match_criteria_id": str(uuid.UUID(MATCH_ID)),
    },
    {"criteria": CPE_O, "vulnerable": True, "match_criteria_id": None},
]


async def _assessments(db: AsyncSession, cve: CVE) -> set[tuple[str, str, str]]:
    rows = await db.execute(
        select(
            CVECVSSAssessment.provider_name,
            CVECVSSAssessment.cvss_version,
            CVECVSSAssessment.vector_string,
        ).where(CVECVSSAssessment.cve_id == cve.id)
    )
    return {(provider, version, vector) for provider, version, vector in rows}


async def _cwes(db: AsyncSession, cve: CVE) -> set[tuple[str, str]]:
    rows = await db.execute(
        select(CVECWE.cwe_id, CVECWE.source).where(CVECWE.cve_id == cve.id)
    )
    return {(cwe_id, source) for cwe_id, source in rows}


async def _references(
    db: AsyncSession, ticket: Ticket
) -> list[tuple[str, str | None, str | None, str]]:
    """Every reference of the Ticket as (url, title, type, source)."""
    rows = await db.execute(
        select(
            TicketReference.url,
            TicketReference.title,
            TicketReference.type,
            TicketReference.source,
        ).where(TicketReference.ticket_id == ticket.id)
    )
    return sorted((url, title, kind, source) for url, title, kind, source in rows)


async def _source_status(db: AsyncSession, cve: CVE) -> str | None:
    value: str | None = await db.scalar(
        select(CVESource.status).where(
            CVESource.cve_id == cve.id, CVESource.source == "nvd"
        )
    )
    return value


async def _row_count(db: AsyncSession, model: Any, cve: CVE) -> int:
    count = await db.scalar(
        select(func.count()).select_from(model).where(model.cve_id == cve.id)
    )
    return int(count or 0)


def _events(logs: Iterable[Mapping[str, Any]], name: str) -> list[Mapping[str, Any]]:
    return [entry for entry in logs if entry["event"] == name]


def _skip(cve_id: str, reason: str) -> dict[str, Any]:
    """The exact candidate skip event of this fetcher."""
    return {
        "event": CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
        "log_level": "warning",
        "cve_id": cve_id,
        "fetcher_name": NAME,
        "reason": reason,
    }


UNAVAILABLE: Final = {
    "event": NVD_SOURCE_API_UNAVAILABLE_EVENT,
    "log_level": "warning",
    "fetcher_name": NAME,
}


def _assert_private(logs: Iterable[Mapping[str, Any]], *values: str) -> None:
    for entry in logs:
        rendered = repr(dict(entry))
        assert "\\x00" not in rendered, entry
        for value in (API_KEY, OTHER_KEY, API_KEY_HEADER, SECRET, "cpe:2.3", *values):
            assert value not in rendered, entry


def _serve(server: NvdServer, cve_id: str, *elements: Any) -> None:
    server.singles[cve_id] = list(elements)


# ---------------------------------------------------------------------------
# Class attributes, custom settings, and registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestClassAttributes:
    def test_properties_match_the_specification(self) -> None:
        assert SyncNvdCves.name == NAME
        assert SyncNvdCves.cve_source_type is CVESourceType.NVD
        assert SyncNvdCves.cve_source_type.value == "nvd"
        assert SyncNvdCves.description == "Sync CVEs from NVD REST API v2"
        assert SyncNvdCves.default_schedule == "0 */6 * * *"
        assert SyncNvdCves.default_request_delay == 6.0
        assert SyncNvdCves.source_reference_url_pattern == (
            "https://nvd.nist.gov/vuln/detail/{cve_id}"
        )
        assert SyncNvdCves.queue is None
        assert SyncNvdCves.http_client_options == {}

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncNvdCves.supports_fetch_single is True
        assert SyncNvdCves.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncNvdCves.__dict__
        assert SyncNvdCves.catch_up is BaseCVEFetcher.catch_up

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncNvdCves
        assert _CVE_SOURCE_TYPE_MAP[CVESourceType.NVD] is SyncNvdCves

    def test_urls_and_messages_match_the_specification(self) -> None:
        assert (
            sync_module.NVD_CVE_API_URL
            == CVE_API_URL
            == ("https://services.nvd.nist.gov/rest/json/cves/2.0")
        )
        assert (
            sync_module.NVD_SOURCE_API_URL
            == SOURCE_API_URL
            == ("https://services.nvd.nist.gov/rest/json/source/2.0")
        )
        assert sync_module.API_KEY_HEADER == API_KEY_HEADER == "apiKey"
        assert sync_module.CONNECTION_FAILED == "Failed to connect to NVD API"
        assert sync_module.TIMED_OUT == "NVD API request timed out"
        assert sync_module.RATE_LIMIT_EXHAUSTED == (
            "NVD API rate limit exceeded — retries exhausted"
        )
        assert sync_module.UNPARSEABLE_RESPONSE == (
            "NVD API returned unparseable response"
        )
        assert sync_module.RATE_LIMIT_RETRY_DELAY == 30.0


@pytest.mark.unit
class TestCustomSettings:
    def test_schema_declares_results_per_page(self) -> None:
        settings_cls = SyncNvdCves.Settings
        assert settings_cls is not None
        assert issubclass(settings_cls, BaseModel)
        assert settings_cls.model_config.get("extra") == "ignore"
        assert settings_cls.model_config.get("validate_default") is True
        assert set(settings_cls.model_fields) == {"results_per_page"}
        field_info = settings_cls.model_fields["results_per_page"]
        assert field_info.annotation is int
        assert field_info.default == 2000
        assert field_info.description == "Number of CVE records per API page."

    @pytest.mark.parametrize("value", [100, 101, 1999, 2000])
    def test_values_within_100_to_2000_are_accepted(self, value: int) -> None:
        settings_cls = SyncNvdCves.Settings
        assert settings_cls is not None

        model = settings_cls.model_validate({"results_per_page": value})

        assert getattr(model, "results_per_page") == value  # noqa: B009

    @pytest.mark.parametrize(
        "value", [99, 2001, 0, -1, "many", 150.5, None], ids=lambda v: repr(v)
    )
    def test_values_outside_the_bounds_are_rejected(self, value: object) -> None:
        settings_cls = SyncNvdCves.Settings
        assert settings_cls is not None

        with pytest.raises(ValidationError):
            settings_cls.model_validate({"results_per_page": value})

    def test_unknown_keys_are_ignored_and_the_default_applies(self) -> None:
        instance = SyncNvdCves()

        assert instance.get_setting("results_per_page") == 2000
        stored = instance._build_settings_instance({"retired_setting": 1})
        assert stored is not None
        assert getattr(stored, "results_per_page") == 2000  # noqa: B009

    def test_a_stored_value_overrides_the_default(self) -> None:
        instance = SyncNvdCves()
        instance._settings_instance = instance._build_settings_instance(
            {"results_per_page": 100}
        )

        assert instance.get_setting("results_per_page") == 100


# ---------------------------------------------------------------------------
# API key (HTTP Client Configuration)
# ---------------------------------------------------------------------------

_UNSET_KEY: Final = cast(SecretStr, Settings.model_fields["nvd_api_key"].default)
"""The configuration default when `NVD_API_KEY` is unset."""


class _RollbackOnly:
    """A session that accepts only the cursor read's `rollback()`."""

    def __init__(self) -> None:
        self.rollbacks = 0

    async def rollback(self) -> None:
        self.rollbacks += 1

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used")


def _assert_key_only_in_headers(server: NvdServer, expected: str | None) -> None:
    """Every request carries `expected` as the exact `apiKey` header (none
    when `None`), and the key never appears in a URL or query parameter."""
    assert server.requests
    for request in server.requests:
        raw = [
            (name, value)
            for name, value in request.headers.raw
            if name.lower() == API_KEY_HEADER.lower().encode()
        ]
        if expected is None:
            assert raw == []
        else:
            assert raw == [(API_KEY_HEADER.encode(), expected.encode())]
        assert API_KEY_HEADER not in request.url.params
        assert API_KEY not in str(request.url)
        assert OTHER_KEY not in str(request.url)


@pytest.mark.unit
class TestApiKey:
    def test_unset_key_is_the_empty_default(self) -> None:
        assert _UNSET_KEY.get_secret_value() == ""
        # The fetcher reads the process configuration these tests patch.
        assert vars(sync_module)["settings"] is app_settings

    async def test_fetch_single_sends_the_key_on_the_cve_and_source_requests(
        self, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        cve_id = fictional_cve_id()
        # A non-processable record fails after the Source API request and
        # before any database work.
        _serve(server, cve_id, _record(cve_id, published=SECRET))

        with pytest.raises(NvdRecordStructureError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single", "source"]
        _assert_key_only_in_headers(server, API_KEY)

    @pytest.mark.parametrize("key", [SecretStr(""), _UNSET_KEY], ids=["empty", "unset"])
    async def test_fetch_single_without_a_key_sends_no_header(
        self,
        key: SecretStr,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(app_settings, "nvd_api_key", key)
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _record(cve_id, published=SECRET))

        with pytest.raises(NvdRecordStructureError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single", "source"]
        _assert_key_only_in_headers(server, None)

    @pytest.mark.parametrize(
        ("key", "expected"),
        [(SecretStr(API_KEY), API_KEY), (SecretStr(""), None), (_UNSET_KEY, None)],
        ids=["key", "empty", "unset"],
    )
    async def test_execute_sends_the_key_on_the_source_and_page_requests(
        self,
        key: SecretStr,
        expected: str | None,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(app_settings, "nvd_api_key", key)
        server.pages = [[], [], []]
        server.totals[0] = 4001

        async def derived_cursor(session: AsyncSession, name: str) -> datetime:
            return datetime.now(UTC) - timedelta(hours=1)

        monkeypatch.setattr(fetcher_execution, "get_derived_cursor", derived_cursor)
        session = _RollbackOnly()

        await fetcher.execute(cast(AsyncSession, session))

        assert session.rollbacks == 1
        assert server.kinds == ["source", "page", "page", "page"]
        _assert_key_only_in_headers(server, expected)

    async def test_key_is_read_at_call_time_for_every_request(
        self,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        cve_id = fictional_cve_id()
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)
        monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(OTHER_KEY))
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)
        monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(""))

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.api_key_headers == [API_KEY, OTHER_KEY, None]

    async def test_production_client_carries_no_key_and_follows_no_redirect(
        self,
    ) -> None:
        instance = SyncNvdCves()
        try:
            client = instance.http_client
            assert client.follow_redirects is False
            assert API_KEY_HEADER.lower() not in {
                name.lower() for name in client.headers
            }
            assert API_KEY not in repr(dict(client.headers))
            assert API_KEY not in repr(vars(instance))
        finally:
            await instance._teardown_http_client()

    async def test_a_rejected_request_never_renders_the_key(
        self, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        """NVD answers an invalid key with HTTP 404 and an empty body."""
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = status(
            404, headers={"message": "Invalid apiKey."}
        )

        with capture_logs() as logs, pytest.raises(httpx.HTTPStatusError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert API_KEY not in str(raised.value)
        assert API_KEY not in repr(raised.value)
        assert server.source_requests == []
        assert logs == []

    @pytest.mark.parametrize(
        "key",
        [
            f"{API_KEY}\n",
            f" {API_KEY}",
            f"{API_KEY} ",
            "fictional nvd-api-key",
            "fictional-nvd-api-k\u00e9y",
            f"{API_KEY}\x00",
            "\t",
        ],
        ids=[
            "trailing_newline",
            "leading_space",
            "trailing_space",
            "inner_space",
            "non_ascii",
            "nul",
            "whitespace_only",
        ],
    )
    async def test_invalid_header_value_fails_fetch_single_before_any_request(
        self,
        key: str,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The HTTP library would render the key in its protocol error."""
        monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(key))
        cve_id = fictional_cve_id()

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert str(raised.value) == API_KEY_INVALID
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert not is_retryable_condition(raised.value)
        assert server.requests == []
        assert logs == []

    async def test_invalid_header_value_fails_execute_before_any_request(
        self,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(app_settings, "nvd_api_key", SecretStr(f"{API_KEY}\n"))

        async def derived_cursor(session: AsyncSession, name: str) -> datetime:
            return datetime.now(UTC) - timedelta(hours=1)

        monkeypatch.setattr(fetcher_execution, "get_derived_cursor", derived_cursor)

        with capture_logs() as logs, pytest.raises(FetcherError) as raised:
            await fetcher.execute(cast(AsyncSession, _RollbackOnly()))

        # The Source API failure path is not degraded mode: the run fails.
        assert str(raised.value) == API_KEY_INVALID
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert server.requests == []
        assert logs == []


# ---------------------------------------------------------------------------
# Request shape and client ownership
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequest:
    async def test_one_get_with_the_documented_query(
        self, fetcher: SyncNvdCves, server: NvdServer, sleeps: list[float]
    ) -> None:
        cve_id = fictional_cve_id()

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        [request] = server.requests
        assert request.method == "GET"
        assert (request.url.scheme, request.url.host, request.url.port) == (
            "https",
            "services.nvd.nist.gov",
            None,
        )
        assert str(request.url.copy_with(query=None)) == CVE_API_URL
        assert list(request.url.params.multi_items()) == [("cveId", cve_id)]
        # One request, no Source API request for a missing CVE, no throttle.
        assert server.single_requests == [request]
        assert sleeps == []

    async def test_found_cve_adds_one_source_request_without_throttle(
        self, fetcher: SyncNvdCves, server: NvdServer, sleeps: list[float]
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _record(cve_id, lastModified=SECRET))

        with pytest.raises(NvdRecordStructureError):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single", "source"]
        [source] = server.source_requests
        assert source.method == "GET"
        assert str(source.url) == SOURCE_API_URL
        assert sleeps == []

    async def test_fetch_single_never_closes_the_client(
        self, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        client = fetcher._http_client
        assert client is not None

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(fictional_cve_id(), NO_SESSION)

        assert fetcher._http_client is client
        assert not client.is_closed


# ---------------------------------------------------------------------------
# CVENotInSource before any mutation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMissingBeforeMutation:
    @pytest.mark.parametrize(
        "cve_id",
        [
            "CVE-2099-1",
            "cve-2099-0001",
            "CVE-2099-0001 ",
            "",
            "CVE-2099-" + "1" * 12,
            "CVE-2099-0001\x00",
        ],
        ids=["short", "lowercase", "trailing_space", "empty", "over_long", "nul"],
    )
    async def test_malformed_requested_cve_id_is_missing_without_http(
        self,
        cve_id: str,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.requests == []
        assert ingestion.calls == 0

    async def test_live_zero_results_page_is_missing_without_source_request(
        self,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = status(200, load_raw_fixture(PAGE_EMPTY))

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single"]
        assert ingestion.calls == 0
        assert logs == []

    async def test_zero_total_is_missing_whatever_the_elements(
        self, fetcher: SyncNvdCves, server: NvdServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        server.single_responses[cve_id] = json_body(
            page_body([_record(cve_id)], total_results=0)
        )

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single"]
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "record_id",
        [
            "other",
            "CVE-24-1",
            "cve-2099-0001",
            "",
            f"CVE-2099-0001 {SECRET}",
            "requested+nul",
        ],
        ids=["other_valid", "short_year", "lowercase", "empty", "free_text", "nul"],
    )
    async def test_single_element_naming_another_cve_is_missing(
        self,
        record_id: str,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        value = {"other": fictional_cve_id(), "requested+nul": f"{cve_id}\x00"}.get(
            record_id, record_id
        )
        _serve(
            server,
            cve_id,
            _record(value, descriptions=[{"lang": "en", "value": SECRET}]),
        )

        with capture_logs() as logs, pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        # Absence is decided before the Source API request and any write.
        assert server.kinds == ["single"]
        assert ingestion.calls == 0
        assert logs == []


# ---------------------------------------------------------------------------
# Error propagation and classification (`fetch_single()` error table)
# ---------------------------------------------------------------------------


async def _raised(
    fetcher: SyncNvdCves, server: NvdServer, responder: Responder
) -> BaseException:
    """The exception of one `fetch_single()` whose CVE request `responder`
    answers; no Source API request is spent."""
    cve_id = fictional_cve_id()
    server.single_responses[cve_id] = responder
    with pytest.raises(
        (httpx.HTTPError, ValueError, NvdResponseError, CVENotInSource)
    ) as raised:
        await fetcher.fetch_single(cve_id, NO_SESSION)
    assert [request.url.params.get("cveId") for request in server.requests] == [cve_id]
    assert server.source_requests == []
    return raised.value


@pytest.mark.unit
class TestErrorPropagation:
    async def test_404_is_a_non_retryable_status_error_never_missing(
        self, fetcher: SyncNvdCves, server: NvdServer, ingestion: Ingestion
    ) -> None:
        """NVD answers a rejected request (invalid key or `cveId`) with an
        empty HTTP 404; a missing CVE is `totalResults == 0`."""
        error = await _raised(
            fetcher, server, status(404, headers={"message": "Invalid apiKey."})
        )

        assert type(error) is httpx.HTTPStatusError
        assert not isinstance(error, CVENotInSource)
        assert error.response.status_code == 404
        assert not is_retryable_condition(error)
        assert not is_infrastructure_failure(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [400, 401, 403, 405, 410, 422])
    async def test_other_4xx_is_the_unwrapped_non_retryable_status_error(
        self,
        code: int,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(code, SECRET.encode()))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)
        assert SECRET not in str(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    async def test_429_and_5xx_are_unwrapped_and_retryable(
        self, code: int, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        error = await _raised(fetcher, server, status(code))

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert is_retryable_condition(error)

    @pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
    async def test_redirect_is_not_followed_and_is_non_retryable(
        self, code: int, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            status(code, headers={"Location": f"{CVE_API_URL}?cveId=CVE-2099-1"}),
        )

        assert type(error) is httpx.HTTPStatusError
        assert error.response.status_code == code
        assert not is_retryable_condition(error)

    @pytest.mark.parametrize(
        "error",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("timed out"),
            httpx.ReadTimeout("timed out"),
            httpx.RemoteProtocolError("closed"),
        ],
        ids=lambda error: type(error).__name__,
    )
    async def test_transport_error_propagates_unwrapped_and_retryable(
        self, error: Exception, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        raised = await _raised(fetcher, server, raising(error))

        assert raised is error
        assert is_retryable_condition(raised)

    @pytest.mark.parametrize("code", [201, 202, 203, 204, 206])
    async def test_other_2xx_is_a_fixed_error_that_never_reads_the_body(
        self,
        code: int,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        error = await _raised(
            fetcher,
            server,
            json_body(page_body([_record(cve_id, descriptions=SECRET)], 1), code=code),
        )

        assert type(error) is NvdResponseError
        assert str(error) == "NVD API returned an unexpected response"
        assert error.__cause__ is None
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"{",
            f"<html>{SECRET}</html>".encode(),
            b"\xff\xfe\xfd",
            b"[]",
            b"null",
            b'{"vulnerabilities": []}',
            b'{"totalResults": 1}',
            b'{"totalResults": -1, "vulnerabilities": []}',
            b'{"totalResults": "1", "vulnerabilities": []}',
            b'{"totalResults": 1.0, "vulnerabilities": []}',
            b'{"totalResults": 1, "vulnerabilities": {}}',
        ],
        ids=[
            "empty",
            "truncated",
            "html",
            "invalid_utf8",
            "array_root",
            "null_root",
            "total_absent",
            "vulnerabilities_absent",
            "total_negative",
            "total_string",
            "total_float",
            "vulnerabilities_object",
        ],
    )
    async def test_unparseable_body_is_the_fixed_non_retryable_page_error(
        self,
        content: bytes,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        error = await _raised(fetcher, server, status(200, content))

        assert type(error) is NvdPageError
        assert str(error) == "NVD response is not a CVE API page"
        assert error.__cause__ is None
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    async def test_undecodable_body_is_non_retryable(
        self, fetcher: SyncNvdCves, server: NvdServer, ingestion: Ingestion
    ) -> None:
        error = await _raised(
            fetcher,
            server,
            status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
        )

        assert isinstance(error, httpx.DecodingError)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize("count", [0, 2, 3], ids=["empty", "two", "three"])
    async def test_anomalous_element_count_is_a_fixed_non_retryable_error(
        self,
        count: int,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        elements = [_record(cve_id, descriptions=SECRET) for _ in range(count)]

        error = await _raised(
            fetcher, server, json_body(page_body(elements, max(count, 1)))
        )

        # Absence is not established: never CVENotInSource.
        assert type(error) is NvdResponseError
        assert SECRET not in str(error)
        assert not is_retryable_condition(error)
        assert ingestion.calls == 0

    @pytest.mark.parametrize(
        "element",
        [
            "record:published_text",
            "record:last_modified_absent",
            "record:vuln_status_null",
            "CVE-2099-0001",
            None,
            {"cve": None},
            {"cve": ["CVE-2099-0001"]},
            {"cve": {"id": None}},
            {"cve": {"id": 20990001}},
        ],
        ids=[
            "published_text",
            "last_modified_absent",
            "vuln_status_null",
            "string_element",
            "null_element",
            "null_cve",
            "list_cve",
            "null_id",
            "integer_id",
        ],
    )
    async def test_structurally_non_processable_record_is_non_retryable(
        self,
        element: Any,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        if element == "record:published_text":
            element = _record(cve_id, published=SECRET)
        elif element == "record:last_modified_absent":
            element = _record(cve_id, lastModified=ABSENT)
        elif element == "record:vuln_status_null":
            element = _record(cve_id, vulnStatus=None)
        _serve(server, cve_id, element)

        with capture_logs() as logs, pytest.raises(NvdRecordStructureError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert str(raised.value) == "NVD record is structurally non-processable"
        assert raised.value.__cause__ is None
        assert not is_retryable_condition(raised.value)
        assert ingestion.calls == 0
        assert logs == []
        # The Source API is requested only for an element that is the
        # requested CVE: a broken skeleton spends no request.
        cve = element.get("cve") if isinstance(element, dict) else None
        has_string_id = isinstance(cve, dict) and isinstance(cve.get("id"), str)
        assert len(server.source_requests) == (1 if has_string_id else 0)

    @pytest.mark.parametrize(
        "signal",
        [asyncio.CancelledError(), SoftTimeLimitExceeded(), MemoryError()],
        ids=lambda signal: type(signal).__name__,
    )
    @pytest.mark.parametrize("request_kind", ["single", "source"])
    async def test_whole_run_signal_propagates_unchanged(
        self,
        request_kind: str,
        signal: BaseException,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        if request_kind == "single":
            server.single_responses[cve_id] = raising(signal)
        else:
            _serve(server, cve_id, _record(cve_id))
            server.source_response = raising(signal)

        with pytest.raises(type(signal)) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert raised.value is signal
        assert ingestion.calls == 0


# ---------------------------------------------------------------------------
# Source API cache (NVD Source API Caching; Failure Handling)
# ---------------------------------------------------------------------------


def _source_page_with(*entries: Any, **envelope: Any) -> dict[str, Any]:
    page: dict[str, Any] = copy.deepcopy(load_json_fixture(SOURCE_PAGE))
    page["sources"].extend(entries)
    page.update(envelope)
    return page


SOURCE_FAILURES: Final[list[Responder]] = [
    status(500, SECRET.encode()),
    status(503),
    status(429),
    status(403),
    status(404, headers={"message": "Invalid apiKey."}),
    status(400),
    status(302, headers={"Location": "https://nvd.example.invalid/source"}),
    status(204),
    json_body(load_json_fixture(SOURCE_PAGE), code=203),
    raising(httpx.ConnectError("[Errno 111] Connection refused")),
    raising(httpx.ConnectTimeout("timed out")),
    raising(httpx.ReadTimeout("timed out")),
    raising(httpx.RemoteProtocolError("peer closed connection")),
    status(200, b"not gzip", headers={"Content-Encoding": "gzip"}),
    status(200, b"{"),
    status(200, b""),
    status(200, b"\xff\xfe"),
    json_body([]),
    json_body({"sources": []}),
    json_body({"totalResults": 1, "resultsPerPage": 1, "sources": {}}),
    json_body({"totalResults": "1", "resultsPerPage": 1, "sources": []}),
]
SOURCE_FAILURE_IDS: Final = [
    "http_500",
    "http_503",
    "http_429",
    "http_403",
    "http_404",
    "http_400",
    "http_302",
    "http_204",
    "http_203",
    "connection_refused",
    "connect_timeout",
    "read_timeout",
    "protocol_error",
    "undecodable",
    "truncated_json",
    "empty_body",
    "invalid_utf8",
    "array_root",
    "counts_absent",
    "sources_object",
    "total_string",
]


@pytest.mark.integration
class TestSourceApi:
    async def test_resolved_cna_entries_are_ingested_under_their_display_name(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(server, target.cve_id, _sourced(target.cve_id))

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert await _assessments(db_session, target.cve) == {
            ("NVD", "3.1", V31),
            (CNA_NAME, "3.1", V31_CNA),
        }
        assert await _cwes(db_session, target.cve) == {
            ("CWE-79", "NVD"),
            ("CWE-352", CNA_NAME),
        }
        assert logs == []
        assert len(server.source_requests) == 1

    @pytest.mark.parametrize("responder", SOURCE_FAILURES, ids=SOURCE_FAILURE_IDS)
    async def test_failure_is_degraded_mode_with_nvd_data_only(
        self,
        responder: Responder,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(server, target.cve_id, _sourced(target.cve_id))
        server.source_response = responder

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        # One attempt, no retry; NVD's own entries are mapped without the
        # cache, the CNA's are skipped as unresolved.
        assert server.kinds == ["single", "source"]
        assert await _assessments(db_session, target.cve) == {("NVD", "3.1", V31)}
        assert await _cwes(db_session, target.cve) == {("CWE-79", "NVD")}
        assert logs == [UNAVAILABLE, _skip(target.cve_id, "unresolved_source")]
        _assert_private(logs, CNA_SOURCE, CNA_NAME)
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )

    async def test_malformed_entries_are_counted_and_skipped(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        server.sources = _source_page_with(
            {"name": " ", "sourceIdentifiers": [UNKNOWN_SOURCE]},
            {"name": SECRET, "sourceIdentifiers": [UNKNOWN_SOURCE, 7]},
            SECRET,
        )
        record = _sourced(target.cve_id)
        record["cve"]["metrics"]["cvssMetricV31"].append(
            _metric(UNKNOWN_SOURCE, V31_CNA)
        )
        _serve(server, target.cve_id, record)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert logs == [
            {
                "event": NVD_SOURCE_ENTRIES_SKIPPED_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
                "count": 3,
            },
            _skip(target.cve_id, "unresolved_source"),
        ]
        _assert_private(logs, UNKNOWN_SOURCE)
        assert await _assessments(db_session, target.cve) == {
            ("NVD", "3.1", V31),
            (CNA_NAME, "3.1", V31_CNA),
        }

    async def test_incomplete_cache_is_used_with_one_warning(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        server.sources = _source_page_with(totalResults=515, resultsPerPage=514)
        _serve(server, target.cve_id, _sourced(target.cve_id))

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert logs == [
            {
                "event": NVD_SOURCE_CACHE_INCOMPLETE_EVENT,
                "log_level": "warning",
                "fetcher_name": NAME,
            }
        ]
        assert (CNA_NAME, "3.1", V31_CNA) in await _assessments(db_session, target.cve)


# ---------------------------------------------------------------------------
# Ingestion with the real upsert_cve() and upsert_references()
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestIngestion:
    async def test_live_record_is_ingested_completely(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        record = _retargeted("record_analyzed_full", target.cve_id)
        _serve(server, target.cve_id, record)

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        # The firmware entry is selected; its hardware platform is not.
        assert result == CVEFetchResult(
            UpsertAction.UPDATED,
            PostIngestTasks(
                ticket_id=str(target.ticket.id),
                cpe_matches=[
                    {
                        "criteria": (
                            "cpe:2.3:o:tenda:ac6_firmware:15.03.05.16_multi"
                            ":*:*:*:*:*:*:*"
                        ),
                        "vulnerable": True,
                        "match_criteria_id": "d0e5bb82-f2e3-4bb9-ae3c-267d3462ca96",
                    }
                ],
                affected_cpes=[],
                vendor_products=[],
                resolved_packages=[],
            ),
        )
        [(cve_id, source, payload)] = ingestion.upserts
        assert (cve_id, source) == (target.cve_id, CVESourceType.NVD)
        assert payload.cve_state is CveState.PUBLISHED
        assert await _assessments(db_session, target.cve) == {
            ("NVD", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            ("CISA-ADP", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
        }
        assert await _cwes(db_session, target.cve) == {
            ("CWE-787", "NVD"),
            ("CWE-120", "CISA-ADP"),
        }
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )
        assert logs == []

    async def test_source_reference_first_then_the_tagged_references(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _record(
                target.cve_id,
                references=[
                    {"url": URL_1, "source": SECRET, "tags": ["Patch", 7]},
                    {"url": URL_2, "source": SECRET},
                ],
            ),
        )

        await fetcher.fetch_single(target.cve_id, db_session)

        [call] = ingestion.references
        assert call["ticket_id"] == target.ticket.id
        assert call["cve_id"] == target.cve_id
        assert call["source"] == NAME
        source_url = f"https://nvd.nist.gov/vuln/detail/{target.cve_id}"
        assert call["source_reference"] == AutomaticReferenceInput(
            url=source_url, title="NVD", explicit_type=ReferenceType.ADVISORY
        )
        assert [(entry.url, entry.upstream_tags) for entry in call["upstream"]] == [
            (URL_1, ("Patch",)),
            (URL_2, None),
        ]
        assert await _references(db_session, target.ticket) == sorted(
            [
                (source_url, "NVD", "advisory", NAME),
                (URL_1, None, "patch", NAME),
                (URL_2, None, None, NAME),
            ]
        )

    @pytest.mark.parametrize("handoff", [False, True], ids=["no_handoff", "handoff"])
    async def test_new_cve_is_created_with_a_new_ticket(
        self,
        handoff: bool,
        db_session: AsyncSession,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        if await db_session.get(SystemSetting, "default_cvss_version") is None:
            db_session.add(SystemSetting(key="default_cvss_version", value="3.1"))
        cve_id = fictional_cve_id()
        members: dict[str, Any] = {
            "descriptions": [{"lang": "en", "value": "Fictional description"}]
        }
        if handoff:
            members["configurations"] = [_configuration(_match(CPE_A))]
        _serve(server, cve_id, _record(cve_id, **members))

        result = await fetcher.fetch_single(cve_id, db_session)

        cve = await db_session.scalar(select(CVE).where(CVE.cve_id == cve_id))
        assert cve is not None
        assert cve.description == "Fictional description"
        [ticket] = (
            await db_session.scalars(select(Ticket).where(Ticket.cve_id == cve.id))
        ).all()
        assert result == CVEFetchResult(
            UpsertAction.CREATED,
            PostIngestTasks(
                ticket_id=str(ticket.id),
                cpe_matches=[
                    {"criteria": CPE_A, "vulnerable": True, "match_criteria_id": None}
                ],
                affected_cpes=[],
                vendor_products=[],
                resolved_packages=[],
            )
            if handoff
            else None,
        )
        assert ticket.status == "New"
        assert await ticket_events(db_session, ticket) == [
            EventRow("ticket_created", None, None, None, INGESTION_COMMENT, None),
            EventRow("cve_associated", None, None, cve_id, None, None),
        ]
        assert [row[0] for row in await _references(db_session, ticket)] == [
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        ]

    async def test_updated_without_handoff_then_unchanged(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        """An empty `configurations` array transports no candidate."""
        _serve(server, target.cve_id, _record(target.cve_id, configurations=[]))

        first = await fetcher.fetch_single(target.cve_id, db_session)
        second = await fetcher.fetch_single(target.cve_id, db_session)

        assert first == CVEFetchResult(UpsertAction.UPDATED, None)
        assert second == CVEFetchResult(UpsertAction.UNCHANGED, None)

    async def test_unchanged_with_handoff_is_idempotent(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _record(
                target.cve_id,
                configurations=[_configuration(_match(CPE_A), _match(CPE_A))],
                references=[{"url": URL_1}],
            ),
        )
        await fetcher.fetch_single(target.cve_id, db_session)
        references = await _references(db_session, target.ticket)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UNCHANGED
        assert result.post_ingest is not None
        # The repeated occurrence is exact-deduplicated by the handoff.
        assert result.post_ingest.cpe_matches == [
            {"criteria": CPE_A, "vulnerable": True, "match_criteria_id": None}
        ]
        assert await _references(db_session, target.ticket) == references

    async def test_rejected_record_moves_a_new_ticket_to_ignored(
        self, db_session: AsyncSession, fetcher: SyncNvdCves, server: NvdServer
    ) -> None:
        target = await _target(db_session, TicketStatus.NEW)
        element = copy.deepcopy(load_json_fixture(PAGE_REJECTED)["vulnerabilities"][0])
        element["cve"]["id"] = target.cve_id
        _serve(server, target.cve_id, element)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        await db_session.refresh(target.cve)
        await db_session.refresh(target.ticket)
        assert target.cve.cve_state == CveState.REJECTED.value
        assert target.ticket.status == "Ignored"
        assert EventRow(
            "status_change", None, "New", "Ignored", "CVE rejected", None
        ) in await ticket_events(db_session, target.ticket)

    async def test_non_base_v40_vector_is_persisted_as_its_base_vector(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        record = _retargeted("record_awaiting_v40_non_base", target.cve_id)
        received = record["cve"]["metrics"]["cvssMetricV40"][0]["cvssData"][
            "vectorString"
        ]
        _serve(server, target.cve_id, record)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        base = "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert received != base
        assert await _assessments(db_session, target.cve) == {(CNA_NAME, "4.0", base)}
        assert logs == []

    async def test_live_single_response_is_ingested(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        """The live `cveId` body, served as captured with its `.id`
        retargeted."""
        document = copy.deepcopy(load_json_fixture(SINGLE_LOG4SHELL))
        document["vulnerabilities"][0]["cve"]["id"] = target.cve_id
        server.single_responses[target.cve_id] = json_body(document)

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert result.post_ingest is not None
        assert result.post_ingest.cpe_matches
        assert await _assessments(db_session, target.cve) == {
            ("NVD", "2.0", "AV:N/AC:M/Au:N/C:C/I:C/A:C"),
            ("NVD", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            ("CISA-ADP", "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        }
        assert await _cwes(db_session, target.cve) == {
            ("CWE-20", "Apache Software Foundation"),
            ("CWE-400", "Apache Software Foundation"),
            ("CWE-502", "Apache Software Foundation"),
            ("CWE-917", "NVD"),
        }

    async def test_unknown_vuln_status_is_published_with_one_bounded_warning(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(server, target.cve_id, _record(target.cve_id, vulnStatus=SECRET))

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert logs == [
            {
                "event": NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
                "log_level": "warning",
                "cve_id": target.cve_id,
                "fetcher_name": NAME,
            }
        ]
        await db_session.refresh(target.cve)
        assert target.cve.cve_state == CveState.PUBLISHED.value

    async def test_fetch_single_never_commits_and_records_no_metric(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        commits: list[None] = []

        async def commit() -> None:
            commits.append(None)

        monkeypatch.setattr(db_session, "commit", commit)
        _serve(
            server, target.cve_id, _retargeted("record_analyzed_full", target.cve_id)
        )

        result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert commits == []
        assert (
            fetcher._succeeded,
            fetcher._created,
            fetcher._updated,
            fetcher._failed,
        ) == (0, 0, 0, 0)
        assert not result._consumed
        assert fetcher._http_client is not None
        assert not fetcher._http_client.is_closed


# ---------------------------------------------------------------------------
# CPE applicability outcomes (NVD CPE Applicability Selection)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCpeOutcomes:
    async def test_skipped_units_return_normally_with_one_event_per_reason(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _record(target.cve_id, configurations=CPE_CONFIGURATIONS),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert result.post_ingest is not None
        # Selected entries only: no platform, negated, or skipped entry.
        assert result.post_ingest.cpe_matches == SELECTED_CPES
        assert logs == [
            _skip(target.cve_id, "invalid_cpe_configuration"),
            _skip(target.cve_id, "invalid_cpe_match"),
        ]
        _assert_private(logs, MATCH_ID, MATCH_ID.lower(), "example")
        assert await _source_status(db_session, target.cve) == (
            CVESourceFetchStatus.SUCCESS
        )

    async def test_excluded_entries_alone_log_nothing_and_hand_off_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _record(
                target.cve_id,
                configurations=[
                    _configuration(_match(CPE_PLATFORM, vulnerable=False)),
                    _configuration(_match(CPE_NEGATED), negate=True),
                ],
            ),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result == CVEFetchResult(UpsertAction.UPDATED, None)
        assert logs == []


# ---------------------------------------------------------------------------
# External String Admissibility (on-demand outcomes)
# ---------------------------------------------------------------------------

NUL: Final = f"{SECRET}\x00"


@pytest.mark.unit
class TestExternalStringAdmissibility:
    async def test_nul_in_the_english_description_fails_before_any_write(
        self, fetcher: SyncNvdCves, server: NvdServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(
            server,
            cve_id,
            _record(cve_id, descriptions=[{"lang": "en", "value": NUL}]),
        )

        with capture_logs() as logs, pytest.raises(ValidationError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert ingestion.calls == 0
        assert SECRET not in str(raised.value)
        assert not is_retryable_condition(raised.value)
        assert logs == []

    @pytest.mark.parametrize("member", ["published", "lastModified"])
    async def test_nul_in_a_timestamp_is_a_non_processable_record(
        self,
        member: str,
        fetcher: SyncNvdCves,
        server: NvdServer,
        ingestion: Ingestion,
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _record(cve_id, **{member: f"{PUBLISHED}\x00"}))

        with pytest.raises(NvdRecordStructureError) as raised:
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert not is_retryable_condition(raised.value)
        assert ingestion.calls == 0

    async def test_nul_in_the_record_id_is_missing_before_any_write(
        self, fetcher: SyncNvdCves, server: NvdServer, ingestion: Ingestion
    ) -> None:
        cve_id = fictional_cve_id()
        _serve(server, cve_id, _record(f"{cve_id}\x00"))

        with pytest.raises(CVENotInSource):
            await fetcher.fetch_single(cve_id, NO_SESSION)

        assert server.kinds == ["single"]
        assert ingestion.calls == 0


@pytest.mark.integration
class TestAdmissibilityOutcomes:
    async def test_nul_failure_writes_nothing(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        record = _sourced(target.cve_id)
        record["cve"]["descriptions"] = [{"lang": "en", "value": NUL}]
        record["cve"]["references"] = [{"url": URL_1}]
        _serve(server, target.cve_id, record)

        with pytest.raises(ValidationError):
            await fetcher.fetch_single(target.cve_id, db_session)

        for model in (CVECVSSAssessment, CVECWE, CVESource):
            assert await _row_count(db_session, model, target.cve) == 0
        assert await _references(db_session, target.ticket) == []

    async def test_nul_in_a_candidate_skips_only_that_candidate(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        _serve(
            server,
            target.cve_id,
            _record(
                target.cve_id,
                metrics={
                    "cvssMetricV30": [_metric(CNA_SOURCE, f"{V31}\x00")],
                    "cvssMetricV31": [_metric(NVD, V31)],
                },
                weaknesses=[
                    _weakness(NVD, "CWE-79\x00"),
                    _weakness(NVD, "CWE-352"),
                ],
                references=[{"url": f"{URL_1}?{NUL}"}, {"url": URL_2}],
                configurations=[
                    _configuration(
                        _match(f"{CPE_A}\x00"),
                        _match(CPE_O, matchCriteriaId=f"{MATCH_ID}\x00"),
                        _match(CPE_H),
                    )
                ],
            ),
        )

        with capture_logs() as logs:
            result = await fetcher.fetch_single(target.cve_id, db_session)

        assert result.action is UpsertAction.UPDATED
        assert result.post_ingest is not None
        assert result.post_ingest.cpe_matches == [
            {"criteria": CPE_H, "vulnerable": True, "match_criteria_id": None}
        ]
        assert await _assessments(db_session, target.cve) == {("NVD", "3.1", V31)}
        assert await _cwes(db_session, target.cve) == {("CWE-352", "NVD")}
        assert [row[0] for row in await _references(db_session, target.ticket)] == [
            URL_2,
            f"https://nvd.nist.gov/vuln/detail/{target.cve_id}",
        ]
        assert [(entry["event"], entry.get("reason")) for entry in logs] == [
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_cpe_match"),
            (CVE_FETCH_CANDIDATE_SKIPPED_EVENT, "invalid_vector"),
            ("automatic_reference_rejected", "control_character"),
        ]
        _assert_private(logs, V31, URL_1)


# ---------------------------------------------------------------------------
# Log privacy
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestLogPrivacy:
    async def test_a_full_fetch_logs_no_upstream_text_identifier_or_key(
        self,
        db_session: AsyncSession,
        target: Target,
        fetcher: SyncNvdCves,
        server: NvdServer,
    ) -> None:
        record = _retargeted("record_analyzed_full", target.cve_id)
        cve = record["cve"]
        cve["descriptions"] = [{"lang": "en", "value": SECRET}]
        cve["vulnStatus"] = f"Unlisted {SECRET}"
        cve["metrics"]["cvssMetricV31"].extend(
            [
                _metric(UNKNOWN_SOURCE, V31_CNA),
                _metric("suse-1@example.com", V31_CNA),
                _metric(NVD, f"CVSS:3.1/AV:N/{SECRET}"),
                _metric("", V31),
            ]
        )
        cve["weaknesses"].append(_weakness(CNA_SOURCE, f"CWE-1 {SECRET}"))
        cve["weaknesses"].append({"source": [SECRET]})
        cve["configurations"].append(
            _configuration(_match(f"cpe:2.3:a:{SECRET}:x:-:*:*:*:*:*:*:*" * 60))
        )
        cve["descriptions"].append({"lang": SECRET})
        _serve(server, target.cve_id, record)

        with capture_logs() as logs:
            await fetcher.fetch_single(target.cve_id, db_session)

        assert {entry["event"] for entry in logs} == {
            CVE_FETCH_CANDIDATE_SKIPPED_EVENT,
            NVD_VULN_STATUS_UNRECOGNIZED_EVENT,
        }
        assert sorted(entry["reason"] for entry in logs if "reason" in entry) == [
            "invalid_cpe_match",
            "invalid_cwe",
            "invalid_description",
            "invalid_vector",
            "missing_source",
            "reserved_provider",
            "unresolved_source",
        ]
        _assert_private(
            logs,
            UNKNOWN_SOURCE,
            "suse-1@example.com",
            "134c704f-9b21-4f2e-91b3-4a467353bcc0",
            CNA_NAME,
            "CISA-ADP",
            "SUSE",
            V31,
            V31_CNA,
            "Unlisted",
            "tenda",
        )
        for entry in logs:
            assert set(entry) <= {
                "event",
                "log_level",
                "cve_id",
                "fetcher_name",
                "reason",
            }
        assert SKIP_EVENT not in {entry["event"] for entry in logs}
