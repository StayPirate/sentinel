"""Unit tests for the MITRE CVE Program fetcher class
(backend/app/services/tickets/sync_mitre_cves.py): its delta hook, its
candidate path, the caller WARNINGs of `process_item()`, registration,
concrete compliance, and structural absences.

Owning specifications:

- docs/features/tickets/cve-sync-mitre.md (Fetcher Definition; Algorithm
  steps 1 and 2; Caller WARNING fields; `fetch_single()` Behavior step 1;
  Work unit and metric mapping, pre-scope exclusions).
- docs/features/platform/git-fetcher-infrastructure.md (Class Attributes;
  Template Method: `execute()`; Hook Methods; `filter_delta_files`;
  `deduplicate_items`; `_construct_candidate_paths`, the `ValueError`
  contract; Worker Affinity).
- docs/features/platform/cve-fetcher-infrastructure.md (Class Attributes;
  `CVEFetchResult`; CVE Source Type Identity, both registry accessors).
- docs/features/platform/logging.md (Secrets and PII Discipline: no raw
  upstream value in a WARNING).
- docs/features/platform/testing-strategy.md (CVE Fetcher Infrastructure:
  Typed result, Git boundaries, and Concrete compliance, "MITRE and Kernel
  return it from `process_item`").

`process_item()` runs here with `cve_service.upsert_cve()` and
`reference_service.upsert_references()` replaced by recording fakes; its
ingestion, the periodic run, and the per-item failure boundary are tested
against the real database in `test_sync_mitre_cves_execute.py`. The record
mapping itself is tested in `test_mitre_cve_record.py`. The repository
layout sample and the records are `tests/support/mitre.py`; every other path,
CVE-ID, and organisation identifier is fictional. No database, Redis, Git,
or network is used.
"""

from __future__ import annotations

import ast
import enum
import inspect
import json
import textwrap
import uuid
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Final, cast

import pytest
from celery.app.task import Task
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase
from structlog.testing import capture_logs

import app.services.fetcher_discovery as fetcher_discovery
from app.core.enums import CVESourceType, ReferenceType
from app.core.errors import ErrorCode
from app.models.cve import CVE
from app.models.ticket import Ticket
from app.services import cve_service, reference_service
from app.services.base_cve_fetcher import (
    _CVE_SOURCE_TYPE_MAP,
    BaseCVEFetcher,
    CVEFetchResult,
    get_all_cve_source_types,
    get_fetch_single_fetchers,
)
from app.services.base_fetcher import (
    FETCHER_REGISTRY,
    BaseFetcher,
    get_catch_up_fetchers,
)
from app.services.base_git_fetcher import BaseGitFetcher
from app.services.cve_ingest import CVEIngestPayload, UpsertAction, UpsertResult
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets import mitre_cve_record
from app.services.tickets import sync_mitre_cves as sync_module
from app.services.tickets.sync_mitre_cves import SyncMitreCves
from tests.support.mitre import (
    ALL_RECORDS,
    CISA_ADP_ORG_ID,
    load_record,
    record_path,
    repository_paths,
)

pytestmark = pytest.mark.unit

NAME: Final = "sync_mitre_cves"
MITRE: Final = CVESourceType.MITRE
CVE_ID: Final = "CVE-2099-0001"
RECORD: Final = f"cves/2099/0xxx/{CVE_ID}.json"
OTHER_RECORD: Final = "cves/2099/12xxx/CVE-2099-12345.json"
THIRD_RECORD: Final = "cves/2098/100xxx/CVE-2098-100000.json"

SAMPLED_RECORDS: Final = frozenset(
    {
        "cves/1999/0xxx/CVE-1999-0001.json",
        "cves/2000/0xxx/CVE-2000-0001.json",
        "cves/2001/0xxx/CVE-2001-0001.json",
        "cves/2002/0xxx/CVE-2002-0001.json",
        "cves/2002/20xxx/CVE-2002-20001.json",
        "cves/2003/0xxx/CVE-2003-0001.json",
        "cves/2004/0xxx/CVE-2004-0001.json",
        "cves/2005/0xxx/CVE-2005-0001.json",
        "cves/2006/0xxx/CVE-2006-0001.json",
        "cves/2007/0xxx/CVE-2007-0001.json",
        "cves/2008/0xxx/CVE-2008-0001.json",
        "cves/2009/0xxx/CVE-2009-0001.json",
        "cves/2010/0xxx/CVE-2010-0001.json",
        "cves/2011/0xxx/CVE-2011-0001.json",
        "cves/2012/0xxx/CVE-2012-0001.json",
        "cves/2013/0xxx/CVE-2013-0001.json",
        "cves/2014/0xxx/CVE-2014-0001.json",
        "cves/2014/1000xxx/CVE-2014-1000000.json",
        "cves/2014/100xxx/CVE-2014-100000.json",
        "cves/2015/0xxx/CVE-2015-0001.json",
        "cves/2016/0xxx/CVE-2016-0001.json",
        "cves/2017/0xxx/CVE-2017-0001.json",
        "cves/2018/0xxx/CVE-2018-0001.json",
        "cves/2019/0xxx/CVE-2019-0001.json",
        "cves/2020/0xxx/CVE-2020-0001.json",
        "cves/2021/0xxx/CVE-2021-0001.json",
        "cves/2022/0xxx/CVE-2022-0001.json",
        "cves/2023/0xxx/CVE-2023-0001.json",
        "cves/2024/0xxx/CVE-2024-0001.json",
        "cves/2025/0xxx/CVE-2025-0001.json",
        "cves/2026/0xxx/CVE-2026-0001.json",
    }
)
"""The record paths of `repository_paths.txt`, spelled literally."""

EXCLUDED_PATHS: Final = [
    # The automation metadata files beside the record tree.
    "cves/delta.json",
    "cves/deltaLog.json",
    # Repository files outside `cves/`.
    "README.md",
    ".gitattributes",
    ".github/workflows/baseline.yml",
    "cve/published/2099/CVE-2099-0001.json",
    # A record-shaped path whose layout or CVE-ID is not canonical.
    "cves/2099/0xxx/CVE-2099-0001",
    "cves/2099/0xxx/CVE-2099-0001.JSON",
    "cves/2099/0xxx/CVE-2099-0001.json.orig",
    "cves/2099/0xxx/cve-2099-0001.json",
    "cves/2099/0XXX/CVE-2099-0001.json",
    "cves/2099/CVE-2099-0001.json",
    "cves/2099/xxx/CVE-2099-0001.json",
    "cves/2099/0xxx/sub/CVE-2099-0001.json",
    "cves/99/0xxx/CVE-99-0001.json",
    "cves/2099/0xxx/CVE-2099-001.json",
    "cves/2099/123456789xxx/CVE-2099-123456789012.json",
    "cves/Cves/0xxx/CVE-2099-0001.json",
    f"{RECORD}/",
    # Non-ASCII digits.
    "cves/2099/0xxx/CVE-2099-\u0661\u0662\u0663\u0664.json",
    "cves/2099/\u0661xxx/CVE-2099-1234.json",
    "cves/\uff12\uff10\uff19\uff19/0xxx/CVE-\uff12\uff10\uff19\uff19-0001.json",
    # Path syntax variants of a valid record path.
    f"./{RECORD}",
    f"/{RECORD}",
    f"{RECORD}\n",
    f" {RECORD}",
    f"cvelistV5/{RECORD}",
    "",
]

ADP_ORG_ID: Final = "66666666-7777-4888-9999-aaaaaaaaaaaa"
NON_UUID_ORG_ID: Final = "Example-Org-Secret-Value"
"""A fictional `orgId` that is not UUID-shaped: never logged."""
RAW_SHORT_NAME: Final = "Example-Raw-Short-Name\x00"
"""A fictional malformed ADP `shortName`: never logged."""
TICKET_ID: Final = uuid.UUID("00000000-0000-4000-8000-0000000000aa")
SKIP_EVENTS: Final = (
    "mitre_adp_entry_skipped",
    "mitre_cna_provider_skipped",
    "mitre_ssvc_assessment_skipped",
)


def _fetcher() -> SyncMitreCves:
    return SyncMitreCves()


def _class_body_assignments(cls: type) -> set[str]:
    """The names assigned in `cls`'s own class body (static, from source)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    [class_def] = tree.body
    assert isinstance(class_def, ast.ClassDef)
    names: set[str] = set()
    for node in class_def.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
    return names


def _method_names(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if inspect.isfunction(value) or inspect.iscoroutinefunction(value)
    }


def _referenced_names(source: str) -> set[str]:
    """Every identifier and attribute name the source references."""
    tree = ast.parse(textwrap.dedent(source))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name)
    return names


def _imported_modules(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


# ---------------------------------------------------------------------------
# filter_delta_files (Algorithm step 1)
# ---------------------------------------------------------------------------


class TestFilterDeltaFiles:
    def test_sampled_repository_layout_keeps_exactly_the_record_paths(self) -> None:
        sample = repository_paths()

        kept = _fetcher().filter_delta_files(sample)

        assert set(kept) == SAMPLED_RECORDS
        assert kept == [path for path in sample if path in SAMPLED_RECORDS]

    @pytest.mark.parametrize("path", sorted(set(repository_paths()) - SAMPLED_RECORDS))
    def test_sampled_non_record_path_is_dropped(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == []

    def test_every_captured_record_path_is_kept(self) -> None:
        paths = [record_path(name) for name in ALL_RECORDS]

        assert _fetcher().filter_delta_files(paths) == paths

    @pytest.mark.parametrize(
        "path",
        [
            "cves/2099/1xxx/CVE-2099-1234.json",
            "cves/2099/12xxx/CVE-2099-12345.json",
            "cves/2099/100xxx/CVE-2099-100000.json",
            "cves/2099/1999xxx/CVE-2099-1999047.json",
            RECORD,
        ],
        ids=["4-digit", "5-digit", "6-digit", "7-digit", "leading-zero"],
    )
    def test_record_path_of_every_sequence_length_is_kept(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == [path]

    @pytest.mark.parametrize(
        "path",
        [
            "cves/2099/5xxx/CVE-2099-0001.json",
            "cves/2099/0xxx/CVE-2098-0001.json",
            "cves/2099/5xxx/CVE-2098-0001.json",
        ],
        ids=["bucket", "year", "bucket-and-year"],
    )
    def test_bucket_or_year_mismatch_is_kept(self, path: str) -> None:
        """The filter is structural only: it does not cross-check the
        `NNNxxx` bucket or the directory year against the CVE-ID."""
        assert _fetcher().filter_delta_files([path]) == [path]

    def test_twenty_character_cve_id_is_the_longest_kept(self) -> None:
        longest = "cves/2099/12345678xxx/CVE-2099-12345678901.json"
        too_long = "cves/2099/123456789xxx/CVE-2099-123456789012.json"

        assert _fetcher().filter_delta_files([longest, too_long]) == [longest]

    @pytest.mark.parametrize("path", EXCLUDED_PATHS)
    def test_excluded_path_is_dropped(self, path: str) -> None:
        assert _fetcher().filter_delta_files([path]) == []

    def test_kept_paths_preserve_the_input_order(self) -> None:
        delta = [
            OTHER_RECORD,
            "cves/delta.json",
            THIRD_RECORD,
            "cves/deltaLog.json",
            RECORD,
            "README.md",
        ]

        assert _fetcher().filter_delta_files(delta) == [
            OTHER_RECORD,
            THIRD_RECORD,
            RECORD,
        ]

    def test_empty_delta_stays_empty_and_input_is_not_mutated(self) -> None:
        delta = [RECORD, "cves/delta.json"]

        assert _fetcher().filter_delta_files([]) == []
        assert _fetcher().filter_delta_files(delta) == [RECORD]
        assert delta == [RECORD, "cves/delta.json"]


# ---------------------------------------------------------------------------
# deduplicate_items (Algorithm step 1: one CVE has one path)
# ---------------------------------------------------------------------------


class TestDeduplicateItems:
    def test_default_is_inherited(self) -> None:
        assert "deduplicate_items" not in SyncMitreCves.__dict__
        assert SyncMitreCves.deduplicate_items is BaseGitFetcher.deduplicate_items

    def test_selected_paths_pass_unchanged(self) -> None:
        fetcher = _fetcher()
        delta = [OTHER_RECORD, "cves/delta.json", THIRD_RECORD, RECORD]

        selected = fetcher.deduplicate_items(fetcher.filter_delta_files(delta))

        assert selected == [OTHER_RECORD, THIRD_RECORD, RECORD]


# ---------------------------------------------------------------------------
# _construct_candidate_paths (fetch_single() step 1)
# ---------------------------------------------------------------------------


class TestConstructCandidatePaths:
    @pytest.mark.parametrize(
        ("cve_id", "path"),
        [
            ("CVE-2099-0001", "cves/2099/0xxx/CVE-2099-0001.json"),
            ("CVE-2099-0999", "cves/2099/0xxx/CVE-2099-0999.json"),
            ("CVE-2099-1234", "cves/2099/1xxx/CVE-2099-1234.json"),
            ("CVE-2099-12345", "cves/2099/12xxx/CVE-2099-12345.json"),
            ("CVE-2099-100000", "cves/2099/100xxx/CVE-2099-100000.json"),
            ("CVE-2099-1999047", "cves/2099/1999xxx/CVE-2099-1999047.json"),
            (
                "CVE-2099-12345678901",
                "cves/2099/12345678xxx/CVE-2099-12345678901.json",
            ),
        ],
        ids=["4-digit", "below-1000", "4-digit-1xxx", "5", "6", "7", "11"],
    )
    def test_single_path_for_a_canonical_id(self, cve_id: str, path: str) -> None:
        assert _fetcher()._construct_candidate_paths(cve_id) == [path]

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_captured_record_is_found_at_its_candidate_path(self, name: str) -> None:
        cve_id = load_record(name)["cveMetadata"]["cveId"]

        assert _fetcher()._construct_candidate_paths(cve_id) == [record_path(name)]

    @pytest.mark.parametrize("cve_id", ["CVE-2099-0001", "CVE-2099-1999047"])
    def test_candidates_are_selected_record_paths(self, cve_id: str) -> None:
        fetcher = _fetcher()
        candidates = fetcher._construct_candidate_paths(cve_id)

        for path in candidates:
            match = mitre_cve_record.RECORD_PATH_PATTERN.fullmatch(path)
            assert match is not None
            assert match["cve_id"] == cve_id
        assert fetcher.filter_delta_files(candidates) == candidates
        assert fetcher.deduplicate_items(candidates) == candidates

    @pytest.mark.parametrize(
        "item_id",
        [
            "",
            "cve-2099-0001",
            "CVE-24-1",
            "CVE-2099-001",
            "CVE-2099-123456789012",
            "CVE-2099-0001/../CVE-2099-0002",
            "../CVE-2099-0001",
            "CVE-2099-0001/",
            "cves/2099/0xxx/CVE-2099-0001.json",
            "CVE-2099-0001\n",
            " CVE-2099-0001",
            "CVE-2099-\u0661\u0662\u0663\u0664",
            "CVE-\uff12\uff10\uff19\uff19-0001",
            "None",
            "null",
            "CVE",
            "CVE-2099",
            "CVE-2099-0001-0002",
            "GHSA-xxxx-xxxx-xxxx",
        ],
    )
    def test_malformed_value_raises_value_error(self, item_id: str) -> None:
        with pytest.raises(ValueError, match="canonical CVE-ID") as raised:
            _fetcher()._construct_candidate_paths(item_id)

        assert type(raised.value) is ValueError
        # A fixed message: the value is never rendered.
        assert str(raised.value) == "item_id is not a canonical CVE-ID"


# ---------------------------------------------------------------------------
# Caller WARNINGs of process_item() (Caller WARNING fields)
# ---------------------------------------------------------------------------


@dataclass
class FakeIngest:
    """Recording substitutes of `cve_service.upsert_cve()` and
    `reference_service.upsert_references()`. `logs` is the active
    `capture_logs()` list; each upsert records the events logged before
    it. `error`, when set, is raised by `upsert_cve()`."""

    logs: list[Any] = field(default_factory=list)
    error: BaseException | None = None
    upserts: list[tuple[str, CVESourceType, CVEIngestPayload]] = field(
        default_factory=list
    )
    events_at_upsert: list[list[str]] = field(default_factory=list)
    reference_calls: list[tuple[Any, ...]] = field(default_factory=list)

    async def upsert_cve(
        self,
        session: AsyncSession,
        cve_id: str,
        source_type: CVESourceType,
        payload: CVEIngestPayload,
    ) -> UpsertResult:
        self.upserts.append((cve_id, source_type, payload))
        self.events_at_upsert.append([entry["event"] for entry in self.logs])
        if self.error is not None:
            raise self.error
        return UpsertResult(
            cve=CVE(cve_id=cve_id),
            ticket=Ticket(id=TICKET_ID),
            action=UpsertAction.CREATED,
        )

    async def upsert_references(self, *args: Any) -> None:
        self.reference_calls.append(args)


@pytest.fixture
def ingest(monkeypatch: pytest.MonkeyPatch) -> FakeIngest:
    fake = FakeIngest()
    monkeypatch.setattr(cve_service, "upsert_cve", fake.upsert_cve)
    monkeypatch.setattr(reference_service, "upsert_references", fake.upsert_references)
    return fake


def _session() -> AsyncSession:
    """A placeholder the fakes never use."""
    return cast(AsyncSession, object())


def _content(fixture: str, edit: Any = None) -> bytes:
    """The fixture re-keyed to `CVE_ID`, with `edit` applied."""
    record = load_record(fixture)
    record["cveMetadata"]["cveId"] = CVE_ID
    if edit is not None:
        edit(record)
    return json.dumps(record).encode()


async def _process(ingest: FakeIngest, content: bytes) -> tuple[Any, list[Any]]:
    """Run `process_item()` under log capture: (its result, the logs)."""
    with capture_logs() as logs:
        ingest.logs = logs
        result = await _fetcher().process_item(RECORD, content, _session())
    return result, logs


def _skip_events(logs: list[Any]) -> list[dict[str, Any]]:
    return [dict(entry) for entry in logs if entry["event"] in SKIP_EVENTS]


def _cisa(record: dict[str, Any]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = record["containers"]["adp"]
    [cisa] = [
        adp
        for adp in entries
        if adp["providerMetadata"].get("orgId") == CISA_ADP_ORG_ID
    ]
    return cisa


def _ssvc_content(record: dict[str, Any]) -> dict[str, Any]:
    [content] = [
        metric["other"]["content"]
        for metric in _cisa(record)["metrics"]
        if metric.get("other", {}).get("type") == "ssvc"
    ]
    return cast(dict[str, Any], content)


def _malformed_adps(record: dict[str, Any]) -> None:
    """Append three ADP entries the ADP defensive guard skips: a UUID-shaped
    `orgId` without `shortName`, a non-UUID `orgId` with an empty
    `shortName`, and a malformed `shortName` without `orgId`."""
    record["containers"]["adp"].extend(
        [
            {"providerMetadata": {"orgId": ADP_ORG_ID}, "affected": []},
            {"providerMetadata": {"orgId": NON_UUID_ORG_ID, "shortName": " "}},
            {"providerMetadata": {"shortName": RAW_SHORT_NAME}},
        ]
    )


def _incomplete_ssvc(record: dict[str, Any]) -> None:
    content = _ssvc_content(record)
    content["options"] = [o for o in content["options"] if "Automatable" not in o]
    del content["version"]


def _invalid_ssvc(record: dict[str, Any]) -> None:
    _ssvc_content(record)["options"][0]["Exploitation"] = "Example-Raw-Value"


def _non_uuid_cna_org_id(record: dict[str, Any]) -> None:
    record["containers"]["cna"]["providerMetadata"]["orgId"] = NON_UUID_ORG_ID


class TestCallerWarnings:
    async def test_one_event_per_skipped_adp_with_org_id_only_when_uuid_shaped(
        self, ingest: FakeIngest
    ) -> None:
        _, logs = await _process(ingest, _content("cisa_kev_cwe_tags", _malformed_adps))

        assert _skip_events(logs) == [
            {
                "event": "mitre_adp_entry_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
                "org_id": ADP_ORG_ID,
            },
            {
                "event": "mitre_adp_entry_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
            },
            {
                "event": "mitre_adp_entry_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
            },
        ]
        # The valid CISA-ADP and CVE Program containers still contribute.
        [(_, _, payload)] = ingest.upserts
        assert payload.ssvc_assessment is not None
        assert payload.kev_data is not None

    async def test_cna_guard_is_one_event_with_the_uuid_org_id(
        self, ingest: FakeIngest
    ) -> None:
        name = "cna_short_name_missing"
        org_id = load_record(name)["containers"]["cna"]["providerMetadata"]["orgId"]

        _, logs = await _process(ingest, _content(name))

        assert _skip_events(logs) == [
            {
                "event": "mitre_cna_provider_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
                "reason": "cna_short_name_missing",
                "org_id": org_id,
            }
        ]

    async def test_cna_guard_omits_a_non_uuid_org_id(self, ingest: FakeIngest) -> None:
        _, logs = await _process(
            ingest, _content("cna_short_name_missing", _non_uuid_cna_org_id)
        )

        assert _skip_events(logs) == [
            {
                "event": "mitre_cna_provider_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
                "reason": "cna_short_name_missing",
            }
        ]

    @pytest.mark.parametrize(
        ("edit", "reason", "missing_fields"),
        [
            (_incomplete_ssvc, "incomplete", ["Automatable", "version"]),
            (_invalid_ssvc, "invalid_value", []),
        ],
        ids=["incomplete", "invalid-value"],
    )
    async def test_ssvc_skip_is_one_event_with_reason_and_missing_fields(
        self, ingest: FakeIngest, edit: Any, reason: str, missing_fields: list[str]
    ) -> None:
        _, logs = await _process(ingest, _content("cisa_kev_cwe_tags", edit))

        assert _skip_events(logs) == [
            {
                "event": "mitre_ssvc_assessment_skipped",
                "log_level": "warning",
                "cve_id": CVE_ID,
                "fetcher_name": NAME,
                "reason": reason,
                "missing_fields": missing_fields,
            }
        ]
        # The rest of the record is ingested; only the SSVC is omitted.
        [(_, _, payload)] = ingest.upserts
        assert payload.ssvc_assessment is None
        assert payload.kev_data is not None

    async def test_missing_fields_follow_the_reporting_order(
        self, ingest: FakeIngest
    ) -> None:
        def reversed_options(record: dict[str, Any]) -> None:
            content = _ssvc_content(record)
            content["options"] = []
            content["version"] = ""

        _, logs = await _process(
            ingest, _content("cisa_kev_cwe_tags", reversed_options)
        )

        [event] = _skip_events(logs)
        assert event["missing_fields"] == [
            "Exploitation",
            "Automatable",
            "Technical Impact",
            "version",
        ]
        assert event["missing_fields"] == list(mitre_cve_record.SSVC_FIELDS)

    async def test_one_ssvc_event_per_cisa_container(self, ingest: FakeIngest) -> None:
        def doubled_cisa(record: dict[str, Any]) -> None:
            _incomplete_ssvc(record)
            record["containers"]["adp"].append(json.loads(json.dumps(_cisa(record))))

        _, logs = await _process(ingest, _content("cisa_kev_cwe_tags", doubled_cisa))

        assert [event["event"] for event in _skip_events(logs)] == [
            "mitre_ssvc_assessment_skipped",
            "mitre_ssvc_assessment_skipped",
        ]

    async def test_every_kind_in_one_record_precedes_the_upsert(
        self, ingest: FakeIngest
    ) -> None:
        def everything(record: dict[str, Any]) -> None:
            _malformed_adps(record)
            _incomplete_ssvc(record)

        _, logs = await _process(ingest, _content("cna_short_name_missing", everything))

        expected = [
            "mitre_adp_entry_skipped",
            "mitre_adp_entry_skipped",
            "mitre_adp_entry_skipped",
            "mitre_cna_provider_skipped",
            "mitre_ssvc_assessment_skipped",
        ]
        assert [event["event"] for event in _skip_events(logs)] == expected
        assert ingest.events_at_upsert == [expected]

    @pytest.mark.parametrize(
        "name", [name for name in ALL_RECORDS if name != "cna_short_name_missing"]
    )
    async def test_clean_record_emits_no_event(
        self, ingest: FakeIngest, name: str
    ) -> None:
        _, logs = await _process(ingest, _content(name))

        assert _skip_events(logs) == []
        assert logs == []

    async def test_events_are_emitted_even_when_the_upsert_fails(
        self, ingest: FakeIngest
    ) -> None:
        def everything(record: dict[str, Any]) -> None:
            _malformed_adps(record)
            _incomplete_ssvc(record)

        ingest.error = RuntimeError("example: fictional write failure")

        with capture_logs() as logs:
            ingest.logs = logs
            with pytest.raises(RuntimeError, match="fictional write failure"):
                await _fetcher().process_item(
                    RECORD, _content("cna_short_name_missing", everything), _session()
                )

        assert len(_skip_events(logs)) == 5
        assert len(ingest.upserts) == 1
        assert ingest.reference_calls == []

    async def test_no_raw_upstream_value_reaches_an_event(
        self, ingest: FakeIngest
    ) -> None:
        def everything(record: dict[str, Any]) -> None:
            _malformed_adps(record)
            _invalid_ssvc(record)
            _non_uuid_cna_org_id(record)

        content = _content("cna_short_name_missing", everything)
        record = json.loads(content)
        cna = record["containers"]["cna"]

        _, logs = await _process(ingest, content)

        assert len(_skip_events(logs)) == 5
        rendered = repr([dict(entry) for entry in logs])
        for raw in (
            NON_UUID_ORG_ID,
            RAW_SHORT_NAME,
            "Example-Raw-Short-Name",
            "Example-Raw-Value",
            cna["title"],
            cna["descriptions"][0]["value"],
            cna["references"][0]["url"],
            "CISA-ADP",
            "://",
        ):
            assert raw not in rendered, raw


# ---------------------------------------------------------------------------
# process_item() delegation and typed result
# ---------------------------------------------------------------------------


class TestProcessItem:
    async def test_maps_ingests_and_returns_the_typed_token(
        self, ingest: FakeIngest
    ) -> None:
        name = "cisa_kev_cwe_tags"
        fixture = load_record(name)

        result, _ = await _process(ingest, _content(name))

        [(cve_id, source_type, payload)] = ingest.upserts
        assert (cve_id, source_type) == (CVE_ID, MITRE)
        assert payload.title is None
        assert (
            payload.description == "example: fictional description of CVE-2024-21182."
        )
        [(_, ticket_id, ref_cve_id, source, first, upstream)] = ingest.reference_calls
        assert (ticket_id, ref_cve_id, source) == (TICKET_ID, CVE_ID, NAME)
        assert first == AutomaticReferenceInput(
            url=f"https://cve.org/CVERecord?id={CVE_ID}",
            title="MITRE",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert [candidate.url for candidate in upstream] == [
            reference["url"] for reference in fixture["containers"]["cna"]["references"]
        ]
        assert type(result) is CVEFetchResult
        assert result.action is UpsertAction.CREATED
        assert result.post_ingest is not None
        assert result.post_ingest.ticket_id == str(TICKET_ID)
        assert result.post_ingest.vendor_products == [
            ["Oracle Corporation", "WebLogic Server"]
        ]

    async def test_mapping_failure_precedes_every_write(
        self, ingest: FakeIngest
    ) -> None:
        with (
            capture_logs() as logs,
            pytest.raises(mitre_cve_record.MitreRecordDecodeError),
        ):
            await _fetcher().process_item(RECORD, b"[]", _session())

        assert ingest.upserts == []
        assert ingest.reference_calls == []
        assert logs == []


# ---------------------------------------------------------------------------
# Discovery, registration, and capability
# ---------------------------------------------------------------------------


class TestRegistrationAndCapability:
    def test_discovery_imports_the_module(self) -> None:
        assert sync_module.__name__ in _imported_modules(fetcher_discovery)
        assert SyncMitreCves.__module__ == "app.services.tickets.sync_mitre_cves"

    def test_properties_match_the_specification(self) -> None:
        assert SyncMitreCves.name == NAME
        assert SyncMitreCves.cve_source_type is MITRE
        assert SyncMitreCves.cve_source_type.value == "mitre"
        assert SyncMitreCves.description == (
            "Sync CVE data from the MITRE cvelistV5 repository"
        )
        assert SyncMitreCves.default_schedule == "0 */6 * * *"
        assert SyncMitreCves.default_request_delay == 0
        assert SyncMitreCves.source_reference_url_pattern == (
            "https://cve.org/CVERecord?id={cve_id}"
        )
        assert (
            SyncMitreCves.source_reference_url_pattern
            is mitre_cve_record.SOURCE_REFERENCE_URL_PATTERN
        )

    def test_git_attributes_match_the_specification(self) -> None:
        assert SyncMitreCves.repo_url == "https://github.com/CVEProject/cvelistV5.git"
        assert SyncMitreCves.clone_dir_name == "cvelistV5"
        assert SyncMitreCves.delta_path_prefix == "cves/"
        assert SyncMitreCves.recovery_path_prefix == "cves/"
        assert SyncMitreCves.clone_filter is None
        assert SyncMitreCves.clone_single_branch is True

    def test_class_body_declares_exactly_the_fetcher_definition(self) -> None:
        """No `queue`, `abstract`, `Settings`, `clone_filter`,
        `clone_single_branch`, or capability flag in the class body
        (cve-sync-mitre.md, Fetcher Definition; Custom settings: No)."""
        assert _class_body_assignments(SyncMitreCves) == {
            "name",
            "cve_source_type",
            "description",
            "default_schedule",
            "default_request_delay",
            "source_reference_url_pattern",
            "repo_url",
            "clone_dir_name",
            "delta_path_prefix",
            "recovery_path_prefix",
        }

    def test_queue_and_clone_options_are_inherited(self) -> None:
        assert SyncMitreCves.queue == "git"
        for inherited in (
            "queue",
            "clone_filter",
            "clone_single_branch",
            "Settings",
            "http_client_options",
        ):
            assert inherited not in SyncMitreCves.__dict__, inherited
        assert SyncMitreCves.Settings is None

    def test_capability_flags_are_inherited_and_derived(self) -> None:
        assert SyncMitreCves.supports_fetch_single is True
        assert SyncMitreCves.participates_in_catch_up is True
        assert "supports_fetch_single" not in SyncMitreCves.__dict__
        assert "abstract" not in SyncMitreCves.__dict__

    def test_class_name_is_derived_from_the_fetcher_name(self) -> None:
        derived = "".join(part.capitalize() for part in NAME.split("_"))

        assert derived == SyncMitreCves.__name__ == "SyncMitreCves"

    def test_registered_in_both_registries(self) -> None:
        assert FETCHER_REGISTRY[NAME] is SyncMitreCves
        assert _CVE_SOURCE_TYPE_MAP[MITRE] is SyncMitreCves
        assert get_all_cve_source_types()["mitre"] is SyncMitreCves

    def test_member_of_both_rosters(self) -> None:
        assert get_fetch_single_fetchers()["mitre"] is SyncMitreCves
        assert get_catch_up_fetchers()[NAME] is SyncMitreCves


# ---------------------------------------------------------------------------
# Concrete compliance (testing-strategy.md, CVE Fetcher Infrastructure)
# ---------------------------------------------------------------------------


class TestConcreteCompliance:
    def test_only_the_three_hooks_are_implemented(self) -> None:
        assert _method_names(SyncMitreCves) == {
            "filter_delta_files",
            "_construct_candidate_paths",
            "process_item",
        }

    def test_template_and_finalization_are_inherited(self) -> None:
        assert SyncMitreCves.execute is BaseGitFetcher.execute
        assert SyncMitreCves.fetch_single is BaseGitFetcher.fetch_single
        assert SyncMitreCves.catch_up is BaseCVEFetcher.catch_up
        assert SyncMitreCves.commit_and_dispatch is BaseCVEFetcher.commit_and_dispatch
        assert (
            SyncMitreCves._isolated_status_commit
            is BaseCVEFetcher._isolated_status_commit
        )
        assert SyncMitreCves.run is BaseFetcher.run
        for inherited in (
            "execute",
            "fetch_single",
            "catch_up",
            "commit_and_dispatch",
            "_isolated_status_commit",
            "run",
            "deduplicate_items",
        ):
            assert inherited not in SyncMitreCves.__dict__, inherited

    def test_process_item_is_async_and_returns_the_typed_token(self) -> None:
        assert inspect.iscoroutinefunction(SyncMitreCves.process_item)
        annotations = inspect.get_annotations(SyncMitreCves.process_item, eval_str=True)

        assert annotations["return"] is CVEFetchResult

    def test_process_item_returns_the_token_without_finalizing(self) -> None:
        """`process_item()` builds `CVEFetchResult`, never commits, finalizes,
        or records a metric, and never delegates to `fetch_single()`."""
        names = _referenced_names(inspect.getsource(SyncMitreCves.process_item))

        assert {
            "CVEFetchResult",
            "map_record",
            "upsert_cve",
            "upsert_references",
            "build_post_ingest_tasks",
        } <= names
        assert (
            not {
                "commit",
                "rollback",
                "flush",
                "commit_and_dispatch",
                "fetch_single",
                "record_succeeded",
                "record_failed",
                "record_created",
                "record_updated",
                "_isolated_status_commit",
            }
            & names
        )

    def test_hooks_are_synchronous_and_pure(self) -> None:
        for hook in (
            SyncMitreCves.filter_delta_files,
            SyncMitreCves._construct_candidate_paths,
        ):
            assert not inspect.iscoroutinefunction(hook), hook.__name__

    def test_no_base_class_member_is_added(self) -> None:
        for name in (
            "_is_record_path",
            "_log_skipped_data",
            "_org_id_field",
            "ADP_ENTRY_SKIPPED_EVENT",
            "CNA_PROVIDER_SKIPPED_EVENT",
            "SSVC_ASSESSMENT_SKIPPED_EVENT",
        ):
            assert not hasattr(BaseGitFetcher, name), name
            assert not hasattr(BaseCVEFetcher, name), name


# ---------------------------------------------------------------------------
# Structural absences
# ---------------------------------------------------------------------------


class TestStructuralAbsences:
    def test_defines_no_task_model_or_enum(self) -> None:
        own = [
            value
            for value in vars(sync_module).values()
            if getattr(value, "__module__", None) == sync_module.__name__
        ]

        assert not [
            value for value in vars(sync_module).values() if isinstance(value, Task)
        ]
        assert not [
            value
            for value in own
            if isinstance(value, type)
            and issubclass(value, (DeclarativeBase, enum.Enum))
        ]
        assert [value for value in own if isinstance(value, type)] == [SyncMitreCves]

    def test_touches_no_redis_task_or_api_layer(self) -> None:
        imported = _imported_modules(sync_module)

        forbidden = {
            name
            for name in imported
            if name == "app.celery_app"
            or name.split(".")[0] in ("redis", "httpx", "celery", "subprocess")
            or name.startswith(("app.tasks", "app.api", "app.schemas"))
        }
        assert forbidden == set()

    def test_raises_no_api_facing_error(self) -> None:
        names = _referenced_names(inspect.getsource(sync_module))

        assert not {"ErrorCode", "ServiceError", "HTTPException"} & names
        assert not [name for name in names if name.endswith("ServiceError")]

    def test_no_route_task_or_error_code_names_the_source(self) -> None:
        from app.celery_app import celery_app
        from app.main import app as api

        paths = [getattr(route, "path", "") for route in api.routes]
        assert paths
        assert not [
            path
            for path in paths
            if "mitre" in path.lower() or "cvelist" in path.lower()
        ]
        assert not [
            name
            for name in celery_app.tasks
            if "mitre" in name.lower() or "cvelist" in name.lower()
        ]
        assert not [
            member
            for member in ErrorCode
            if "MITRE" in member.name or "CVELIST" in member.name
        ]
