"""Unit tests for the MITRE `cvelistV5` record mapping
(backend/app/services/tickets/mitre_cve_record.py).

Contract under test: docs/features/tickets/cve-sync-mitre.md (Algorithm
step 1 path pattern and step 2 mapping; CVE JSON 5.x Field Path Mapping:
global fields and presence rules including the `PUBLISHED` + `dateRejected`
rejection, CNA fields and the CNA defensive guard, CVSS extraction and the
reserved provider, ADP fields and the ADP defensive guard, CISA-ADP SSVC,
KEV, and CWE, the SSVC skip classification, scoped operation construction
and duplicate scopes, CVE-ID cross-validation, additive child retention,
caller WARNING fields, External String Admissibility), the parser
delegation of docs/features/platform/cve-record-parser.md (Caller Pattern;
What Remains Source-Specific), and the candidate order of
docs/features/platform/cve-fetcher-infrastructure.md (Automatic Reference
Caller Contract). `SyncMitreCves` owns the delta, the ingestion, the
per-item failure outcome, and the WARNING events; those parts are tested
with the fetcher.

Records are the sanitized live fixtures of `tests/support/mitre.py` or
minimal fictional objects. No database, Git, or log is involved.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, date, datetime
from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.core.enums import (
    CveState,
    ReferenceType,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.services import cve_record_parser
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
)
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets.mitre_cve_record import (
    CISA_ADP_CWE_SOURCE,
    CISA_ADP_ORG_ID,
    RECORD_PATH_PATTERN,
    SOURCE_REFERENCE_TITLE,
    SOURCE_REFERENCE_URL_PATTERN,
    SSVC_FIELDS,
    CnaGuard,
    MitreRecord,
    MitreRecordConflictError,
    MitreRecordDecodeError,
    MitreRecordError,
    MitreRecordPathError,
    MitreRecordRejectionDateError,
    MitreRecordStateError,
    SkippedAdp,
    SsvcField,
    SsvcSkip,
    map_record,
)
from tests.support import mitre as mitre_support
from tests.support.mitre import (
    ALL_RECORDS,
    load_raw_record,
    load_record,
    record_path,
    repository_paths,
)
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules

pytestmark = pytest.mark.unit

CVE_ID: Final = "CVE-2026-0001"
PATH: Final = f"cves/2026/0xxx/{CVE_ID}.json"
CNA_ORG_ID: Final = "11111111-2222-4333-8444-555555555555"
ADP_ORG_ID: Final = "66666666-7777-4888-9999-aaaaaaaaaaaa"
CNA_NAME: Final = "ExampleCNA"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_NON_BASE: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C"
V31_NON_BASE_REDUCED: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
V31_OTHER: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
NUL: Final = "\x00"
SECRET: Final = "Example-Secret-Input-Value"
TIMESTAMP: Final = "2026-01-02T03:04:05.000006Z"


# ---------------------------------------------------------------------------
# Fictional record builders
# ---------------------------------------------------------------------------


def _affected(product: str = "Example Product", **overrides: Any) -> dict[str, Any]:
    element: dict[str, Any] = {
        "vendor": "Example Vendor",
        "product": product,
        "defaultStatus": "unaffected",
        "versions": [
            {
                "version": "1.0",
                "lessThan": "1.4",
                "status": "affected",
                "versionType": "semver",
            }
        ],
    }
    element.update(overrides)
    return element


def _ssvc(
    exploitation: Any = "active",
    automatable: Any = "yes",
    technical_impact: Any = "total",
    **content: Any,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "timestamp": TIMESTAMP,
        "id": CVE_ID,
        "options": [
            {"Exploitation": exploitation},
            {"Automatable": automatable},
            {"Technical Impact": technical_impact},
        ],
        "role": "CISA Coordinator",
        "version": "2.0.3",
    }
    body.update(content)
    return {"other": {"type": "ssvc", "content": body}}


def _kev(date_added: Any = "2026-01-05", reference: Any = URL_2) -> dict[str, Any]:
    return {
        "other": {
            "type": "kev",
            "content": {"dateAdded": date_added, "reference": reference},
        }
    }


def _problem_types(*cwe_ids: str) -> list[dict[str, Any]]:
    return [
        {
            "descriptions": [
                {"type": "CWE", "cweId": c, "lang": "en", "description": c}
                for c in cwe_ids
            ]
        }
    ]


def _cisa(**overrides: Any) -> dict[str, Any]:
    adp: dict[str, Any] = {
        "providerMetadata": {"orgId": CISA_ADP_ORG_ID, "shortName": "CISA-ADP"},
        "title": "CISA ADP Vulnrichment",
        "metrics": [_ssvc(), _kev()],
        "problemTypes": _problem_types("CWE-79"),
    }
    adp.update(overrides)
    return adp


def _adp(short_name: Any = "Example-ADP", **overrides: Any) -> dict[str, Any]:
    adp: dict[str, Any] = {
        "providerMetadata": {"orgId": ADP_ORG_ID, "shortName": short_name},
        "affected": [_affected("ADP Product")],
        "metrics": [{"cvssV3_1": {"vectorString": V31_OTHER}}],
    }
    adp.update(overrides)
    return adp


def _adp_identity(provider_metadata: Any = ...) -> dict[str, Any]:
    """An ADP entry whose `providerMetadata` is `provider_metadata`, or
    absent for the default `...`."""
    adp = _adp()
    del adp["providerMetadata"]
    if provider_metadata is not ...:
        adp["providerMetadata"] = provider_metadata
    return adp


def _record(
    *,
    adp: Any = None,
    state: str = "PUBLISHED",
    metadata: dict[str, Any] | None = None,
    **cna: Any,
) -> dict[str, Any]:
    """A minimal fictional 5.2 record; `cna` replaces CNA members, `adp`
    sets `containers.adp` when not `None`."""
    container: dict[str, Any] = {
        "providerMetadata": {"orgId": CNA_ORG_ID, "shortName": CNA_NAME},
        "title": "example: fictional title",
        "descriptions": [{"lang": "en", "value": "Fictional description."}],
        "affected": [_affected()],
        "metrics": [{"cvssV3_1": {"vectorString": V31}}],
        "problemTypes": _problem_types("CWE-787"),
        "references": [{"url": URL_1, "tags": ["patch"]}],
    }
    container.update(cna)
    cve_metadata: dict[str, Any] = {
        "cveId": CVE_ID,
        "assignerOrgId": CNA_ORG_ID,
        "state": state,
        "datePublished": "2026-01-01T00:00:00.000Z",
        "dateUpdated": "2026-01-03T00:00:00.000Z",
    }
    cve_metadata.update(metadata or {})
    containers: dict[str, Any] = {"cna": container}
    if adp is not None:
        containers["adp"] = adp
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": cve_metadata,
        "containers": containers,
    }


def _map(record: object, path: str = PATH) -> MitreRecord:
    return map_record(path, json.dumps(record).encode())


def _payload(record: object, path: str = PATH) -> CVEIngestPayload:
    return _map(record, path).payload


def _operations(payload: CVEIngestPayload) -> dict[str, AffectedVersionScopeOperation]:
    operations = payload.affected_version_operations or []
    by_scope = {o.source_container: o for o in operations}
    assert len(by_scope) == len(operations)
    assert all(o.operation is AffectedVersionOperation.REPLACE for o in operations)
    return by_scope


def _entries(payload: CVEIngestPayload, scope: str) -> list[AffectedVersionEntry]:
    return list(_operations(payload)[scope].entries or [])


def _cvss(payload: CVEIngestPayload) -> set[tuple[object, object]]:
    return {(c.provider_name, c.vector_string) for c in payload.cvss_assessments or []}


def _cwe(payload: CVEIngestPayload) -> set[tuple[str, str]]:
    return {(c.cwe_id, c.source) for c in payload.cwe_classifications or []}


# ---------------------------------------------------------------------------
# Path
# ---------------------------------------------------------------------------


class TestPath:
    @pytest.mark.parametrize(
        "path",
        [
            "cves/2026/0xxx/CVE-2026-0001.json",
            "cves/2024/12xxx/CVE-2024-12345.json",
            "cves/2014/100xxx/CVE-2014-100000.json",
            "cves/2018/1999xxx/CVE-2018-1999047.json",
        ],
    )
    def test_record_path_is_accepted(self, path: str) -> None:
        cve_id = path.rsplit("/", 1)[1].removesuffix(".json")
        record = _record(metadata={"cveId": cve_id})

        result = _map(record, path)

        assert result.cve_id == cve_id
        assert result.source_reference.url == f"https://cve.org/CVERecord?id={cve_id}"

    @pytest.mark.parametrize(
        "path",
        [
            "cves/2026/9xxx/CVE-2026-0001.json",
            "cves/2025/0xxx/CVE-2026-0001.json",
        ],
    )
    def test_pattern_is_structural_only(self, path: str) -> None:
        """Bucket and directory year are not cross-checked (Algorithm step 1)."""
        assert _map(_record(), path).cve_id == CVE_ID

    @pytest.mark.parametrize(
        "path",
        [
            "cves/delta.json",
            "cves/deltaLog.json",
            "README.md",
            ".github/workflows/baseline.yml",
            "cves/2026/0xxx/CVE-2026-0001",
            "cves/2026/0xxx/CVE-2026-0001.JSON",
            "cves/2026/0xxx/CVE-2026-0001.json.orig",
            "cves/2026/0XXX/CVE-2026-0001.json",
            "cves/2026/CVE-2026-0001.json",
            "cves/2026/0xxx/x/CVE-2026-0001.json",
            "cves/2026/0xxx/CVE-2026-001.json",
            "cves/2026/0xxx/cve-2026-0001.json",
            "cves/26/0xxx/CVE-2026-0001.json",
            "cves/2026/xxx/CVE-2026-0001.json",
            "cves/2026/0xxx/CVE-2026-0000000000001.json",
            "cves/\uff12\uff10\uff12\uff16/0xxx/CVE-\uff12\uff10\uff12\uff16-0001.json",
            "cves/2026/0xxx/CVE-2026-0001.json\n",
            "/cves/2026/0xxx/CVE-2026-0001.json",
            "./cves/2026/0xxx/CVE-2026-0001.json",
            "cve/published/2026/CVE-2026-0001.json",
            "cves/2026/0xxx/CVE-2026-\udcff.json",
            "",
        ],
    )
    def test_path_outside_the_record_pattern_fails(self, path: str) -> None:
        with pytest.raises(MitreRecordPathError):
            _map(_record(), path)

    def test_path_is_checked_before_the_content(self) -> None:
        with pytest.raises(MitreRecordPathError):
            map_record("cves/delta.json", b"\xff")

    def test_pattern_selects_exactly_the_sampled_record_paths(self) -> None:
        paths = repository_paths()

        rejected = [p for p in paths if not RECORD_PATH_PATTERN.fullmatch(p)]

        assert {p for p in rejected if p.startswith("cves/")} == {
            "cves/delta.json",
            "cves/deltaLog.json",
        }
        assert all(RECORD_PATH_PATTERN.fullmatch(record_path(n)) for n in ALL_RECORDS)


# ---------------------------------------------------------------------------
# Decoding and errors
# ---------------------------------------------------------------------------


class TestDecode:
    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"\xff\xfe{}",
            b'{"title": "\xe9"}',
            b"\xef\xbb\xbf{}",
            "{}".encode("utf-16"),
            b"{",
            b"[]",
            b'"CVE-2026-0001"',
            b"null",
            b"[" * 100_000 + b"]" * 100_000,
            b'{"n": ' + b"9" * 5000 + b"}",
        ],
        ids=[
            "empty",
            "non-utf-8",
            "latin-1-byte",
            "utf-8-bom",
            "utf-16",
            "truncated",
            "array-root",
            "string-root",
            "null-root",
            "deep-nesting",
            "oversized-integer",
        ],
    )
    def test_undecodable_content_fails(self, content: bytes) -> None:
        with pytest.raises(MitreRecordDecodeError):
            map_record(PATH, content)

    def test_error_message_and_cause_carry_no_content(self) -> None:
        with pytest.raises(MitreRecordDecodeError) as caught:
            map_record(PATH, f'{{"title": "{SECRET}"'.encode())

        assert SECRET not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__

    def test_errors_are_value_errors_with_fixed_messages(self) -> None:
        errors = [
            MitreRecordPathError(),
            MitreRecordDecodeError(),
            MitreRecordStateError(),
            MitreRecordRejectionDateError(),
            MitreRecordConflictError(),
        ]

        assert all(isinstance(e, MitreRecordError) for e in errors)
        assert all(isinstance(e, ValueError) for e in errors)
        assert len({str(e) for e in errors}) == len(errors)


# ---------------------------------------------------------------------------
# Global fields
# ---------------------------------------------------------------------------


class TestState:
    @pytest.mark.parametrize("state", [CveState.PUBLISHED, CveState.REJECTED])
    def test_json_state_is_mapped(self, state: CveState) -> None:
        assert _payload(_record(state=state.value)).cve_state is state

    @pytest.mark.parametrize(
        "state", ["RESERVED", "published", "", " PUBLISHED", None, 1, ["PUBLISHED"]]
    )
    def test_unrecognized_state_fails(self, state: Any) -> None:
        record = _record()
        record["cveMetadata"]["state"] = state

        with pytest.raises(MitreRecordStateError):
            _map(record)

    def test_absent_state_fails(self) -> None:
        record = _record()
        del record["cveMetadata"]["state"]

        with pytest.raises(MitreRecordStateError):
            _map(record)

    @pytest.mark.parametrize("metadata", [None, [], "PUBLISHED"])
    def test_unusable_metadata_fails(self, metadata: Any) -> None:
        record = _record()
        record["cveMetadata"] = metadata

        with pytest.raises(MitreRecordStateError):
            _map(record)

    def test_absent_metadata_fails(self) -> None:
        record = _record()
        del record["cveMetadata"]

        with pytest.raises(MitreRecordStateError):
            _map(record)


class TestCveId:
    @pytest.mark.parametrize(
        "cve_id", ["CVE-2026-9999", "cve-2026-0001", None, 7, f"{CVE_ID}{NUL}"]
    )
    def test_file_name_id_is_authoritative(self, cve_id: Any) -> None:
        record = _record(metadata={"cveId": cve_id})

        assert _map(record).cve_id == CVE_ID

    def test_absent_json_id_is_the_file_name_id(self) -> None:
        record = _record()
        del record["cveMetadata"]["cveId"]

        assert _map(record).cve_id == CVE_ID


class TestDates:
    @pytest.mark.parametrize(
        ("field", "key"),
        [("published_date", "datePublished"), ("modified_date", "dateUpdated")],
    )
    def test_date_presence_rules(self, field: str, key: str) -> None:
        absent = _record()
        del absent["cveMetadata"][key]

        assert field not in _payload(absent).model_fields_set
        null = _payload(_record(metadata={key: None}))
        assert field in null.model_fields_set
        assert getattr(null, field) is None
        value = _payload(_record(metadata={key: "2026-02-03T04:05:06.000Z"}))
        assert getattr(value, field) == datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
        for malformed in ("2026-02-03", "not a date", 20260203, ["2026"]):
            payload = _payload(_record(metadata={key: malformed}))
            assert field not in payload.model_fields_set

    def test_rejected_date_presence_rules(self) -> None:
        def payload(**metadata: Any) -> CVEIngestPayload:
            return _payload(_record(state="REJECTED", metadata=metadata))

        assert "date_rejected" not in payload().model_fields_set
        assert payload(dateRejected=None).model_fields_set >= {"date_rejected"}
        assert payload(dateRejected=None).date_rejected is None
        assert payload(dateRejected="2026-04-05T00:00:00.000Z").date_rejected == (
            datetime(2026, 4, 5, tzinfo=UTC)
        )
        assert "date_rejected" not in payload(dateRejected="x").model_fields_set

    @pytest.mark.parametrize(
        "value", ["2026-04-05T00:00:00.000Z", "not a date", 0, False, {}, []]
    )
    def test_published_with_any_non_null_rejection_date_fails(self, value: Any) -> None:
        with pytest.raises(MitreRecordRejectionDateError):
            _map(_record(metadata={"dateRejected": value}))

    def test_published_with_null_rejection_date_omits_it(self) -> None:
        payload = _payload(_record(metadata={"dateRejected": None}))

        assert payload.cve_state is CveState.PUBLISHED
        assert "date_rejected" not in payload.model_fields_set

    def test_published_record_never_sets_a_rejection_date(self) -> None:
        assert "date_rejected" not in _payload(_record()).model_fields_set


class TestGlobalFields:
    def test_title_and_description_are_mapped(self) -> None:
        payload = _payload(_record())

        assert payload.title == "example: fictional title"
        assert payload.description == "Fictional description."

    def test_title_is_truncated_to_256_characters(self) -> None:
        assert _payload(_record(title="t" * 300)).title == "t" * 256

    def test_absent_title_and_descriptions_are_omitted(self) -> None:
        record = _record()
        del record["containers"]["cna"]["title"]
        del record["containers"]["cna"]["descriptions"]

        assert not {"title", "description"} & _payload(record).model_fields_set

    def test_null_title_and_descriptions_are_explicit_clears(self) -> None:
        payload = _payload(_record(title=None, descriptions=None))

        assert {"title", "description"} <= payload.model_fields_set
        assert payload.title is None
        assert payload.description is None

    @pytest.mark.parametrize("title", [1, ["t"], {"t": 1}, True])
    def test_non_string_title_is_omitted(self, title: Any) -> None:
        assert "title" not in _payload(_record(title=title)).model_fields_set

    @pytest.mark.parametrize(
        "descriptions", [[], "text", [{"lang": "en"}], [{"lang": "en", "value": 1}]]
    )
    def test_descriptions_without_a_string_value_are_omitted(
        self, descriptions: Any
    ) -> None:
        payload = _payload(_record(descriptions=descriptions))

        assert "description" not in payload.model_fields_set

    def test_english_description_is_selected(self) -> None:
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": "en-US", "value": "Fictional description."},
        ]

        assert _payload(_record(descriptions=descriptions)).description == (
            "Fictional description."
        )

    @pytest.mark.parametrize("cna", [None, [], "cna"])
    def test_unusable_cna_is_an_empty_container(self, cna: Any) -> None:
        record = _record()
        record["containers"]["cna"] = cna

        result = _map(record)

        assert result.payload.model_fields_set == {
            "cve_state",
            "published_date",
            "modified_date",
        }
        assert result.cna_guard == CnaGuard(org_id=None)
        assert result.upstream_references == ()

    @pytest.mark.parametrize("containers", [None, [], "containers"])
    def test_unusable_containers_is_an_empty_cna(self, containers: Any) -> None:
        record = _record(adp=[_cisa()])
        record["containers"] = containers

        result = _map(record)

        assert result.payload.model_fields_set == {
            "cve_state",
            "published_date",
            "modified_date",
        }
        assert result.skipped_adps == ()
        assert result.ssvc_skips == ()
        assert result.cna_guard == CnaGuard(org_id=None)

    def test_resolved_packages_is_never_set(self) -> None:
        affected = [_affected(packageName="example-package")]
        payload = _payload(_record(affected=affected, adp=[_adp(), _cisa()]))

        assert "resolved_packages" not in payload.model_fields_set
        assert "cpe_matches" not in payload.model_fields_set


# ---------------------------------------------------------------------------
# CNA container
# ---------------------------------------------------------------------------


class TestCna:
    def test_cvss_uses_the_cna_short_name_and_is_reduced_to_base(self) -> None:
        metrics = [
            {"cvssV3_1": {"vectorString": V31_NON_BASE}},
            {"cvssV4_0": {"vectorString": V40}},
        ]

        payload = _payload(_record(metrics=metrics))

        assert _cvss(payload) == {(CNA_NAME, V31_NON_BASE_REDUCED), (CNA_NAME, V40)}

    def test_mapping_delegates_cvss_and_cwe_to_the_parser(self) -> None:
        cna = _record()["containers"]["cna"]

        payload = _payload(_record())

        assert payload.cvss_assessments == cve_record_parser.parse_cvss_assessments(
            cna["metrics"], CNA_NAME
        )
        assert payload.cwe_classifications == (
            cve_record_parser.parse_cwe_classifications(
                cna["problemTypes"], f"cna:{CNA_NAME}"
            )
        )

    def test_short_name_is_trimmed_for_provider_and_cwe_source(self) -> None:
        provider = {"orgId": CNA_ORG_ID, "shortName": f"  {CNA_NAME}\t"}

        payload = _payload(_record(providerMetadata=provider))

        assert _cvss(payload) == {(CNA_NAME, V31)}
        assert _cwe(payload) == {("CWE-787", f"cna:{CNA_NAME}")}

    @pytest.mark.parametrize("short_name", ["SUSE", "suse", " Suse "])
    def test_reserved_suse_provider_skips_only_the_cna_cvss(
        self, short_name: str
    ) -> None:
        provider = {"orgId": CNA_ORG_ID, "shortName": short_name}

        result = _map(_record(providerMetadata=provider))

        assert "cvss_assessments" not in result.payload.model_fields_set
        assert _cwe(result.payload) == {("CWE-787", f"cna:{short_name.strip()}")}
        assert result.cna_guard is None

    def test_affected_array_replaces_the_cna_scope(self) -> None:
        entries = _entries(_payload(_record()), "cna")

        assert entries == cve_record_parser.parse_affected_versions([_affected()])

    def test_empty_affected_replaces_the_cna_scope_with_nothing(self) -> None:
        assert _entries(_payload(_record(affected=[])), "cna") == []

    @pytest.mark.parametrize("affected", [None, {}, "affected"])
    def test_null_or_non_array_affected_emits_no_operation(self, affected: Any) -> None:
        payload = _payload(_record(affected=affected))

        assert "affected_version_operations" not in payload.model_fields_set

    def test_absent_affected_emits_no_operation(self) -> None:
        record = _record()
        del record["containers"]["cna"]["affected"]

        assert "affected_version_operations" not in _payload(record).model_fields_set

    def test_cna_ssvc_and_kev_are_not_consumed(self) -> None:
        metrics = [{"cvssV3_1": {"vectorString": V31}}, _ssvc(), _kev()]

        payload = _payload(_record(metrics=metrics))

        assert payload.ssvc_assessment is None
        assert payload.kev_data is None


class TestCnaGuard:
    @pytest.mark.parametrize(
        "provider",
        [
            {"orgId": CNA_ORG_ID},
            {"orgId": CNA_ORG_ID, "shortName": None},
            {"orgId": CNA_ORG_ID, "shortName": ""},
            {"orgId": CNA_ORG_ID, "shortName": " \t\n"},
            {"orgId": CNA_ORG_ID, "shortName": 7},
            {"orgId": CNA_ORG_ID, "shortName": ["ExampleCNA"]},
        ],
        ids=["absent", "null", "empty", "whitespace", "number", "list"],
    )
    def test_unusable_short_name_skips_only_cna_cvss_and_cwe(
        self, provider: dict[str, Any]
    ) -> None:
        guarded = _map(_record(providerMetadata=provider, adp=[_adp(), _cisa()]))
        unguarded = _map(_record(adp=[_adp(), _cisa()]))

        assert guarded.cna_guard == CnaGuard(org_id=CNA_ORG_ID)
        assert guarded.cna_guard is not None
        assert guarded.cna_guard.reason == "cna_short_name_missing"
        assert unguarded.cna_guard is None
        assert _cvss(guarded.payload) == {("adp:Example-ADP", V31_OTHER)}
        assert _cwe(guarded.payload) == {("CWE-79", CISA_ADP_CWE_SOURCE)}
        unaffected = (
            "title",
            "description",
            "affected_version_operations",
            "ssvc_assessment",
            "kev_data",
            "cve_state",
        )
        for field in unaffected:
            assert getattr(guarded.payload, field) == getattr(unguarded.payload, field)
        assert guarded.upstream_references == unguarded.upstream_references
        assert guarded.source_reference == unguarded.source_reference

    @pytest.mark.parametrize("provider", [None, "ExampleCNA", ["ExampleCNA"]])
    def test_unusable_provider_metadata_is_guarded_without_org_id(
        self, provider: Any
    ) -> None:
        result = _map(_record(providerMetadata=provider))

        assert result.cna_guard == CnaGuard(org_id=None)
        assert not {"cvss_assessments", "cwe_classifications"} & (
            result.payload.model_fields_set
        )

    def test_absent_provider_metadata_is_guarded(self) -> None:
        record = _record()
        del record["containers"]["cna"]["providerMetadata"]

        assert _map(record).cna_guard == CnaGuard(org_id=None)

    @pytest.mark.parametrize(
        ("org_id", "expected"),
        [
            (CNA_ORG_ID, CNA_ORG_ID),
            (CNA_ORG_ID.upper(), CNA_ORG_ID.upper()),
            (SECRET, None),
            (f"{CNA_ORG_ID}x", None),
            (CNA_ORG_ID.replace("-", ""), None),
            (f"{CNA_ORG_ID}\n", None),
            (f"{CNA_ORG_ID}{NUL}", None),
            (42, None),
            (None, None),
        ],
    )
    def test_guard_org_id_is_kept_only_when_uuid_shaped(
        self, org_id: Any, expected: str | None
    ) -> None:
        result = _map(_record(providerMetadata={"orgId": org_id}))

        assert result.cna_guard == CnaGuard(org_id=expected)

    def test_live_record_without_short_name_is_guarded(self) -> None:
        name = "cna_short_name_missing"
        cna = load_record(name)["containers"]["cna"]

        result = map_record(record_path(name), load_raw_record(name))

        assert result.cna_guard == CnaGuard(org_id=cna["providerMetadata"]["orgId"])
        # Its ADP containers carry no vector and no CWE.
        assert not {"cvss_assessments", "cwe_classifications"} & (
            result.payload.model_fields_set
        )
        assert result.payload.title == cna["title"]
        assert _entries(result.payload, "cna") == (
            cve_record_parser.parse_affected_versions(cna["affected"])
        )


# ---------------------------------------------------------------------------
# ADP containers
# ---------------------------------------------------------------------------


class TestAdp:
    def test_every_valid_adp_is_its_own_scope_and_provider(self) -> None:
        adps = [
            _adp("Example-ADP"),
            _adp("Second-ADP", metrics=[{"cvssV4_0": {"vectorString": V40}}]),
        ]

        payload = _payload(_record(adp=adps))

        assert set(_operations(payload)) == {"cna", "adp:Example-ADP", "adp:Second-ADP"}
        assert _cvss(payload) == {
            (CNA_NAME, V31),
            ("adp:Example-ADP", V31_OTHER),
            ("adp:Second-ADP", V40),
        }
        assert _entries(payload, "adp:Second-ADP") == (
            cve_record_parser.parse_affected_versions([_affected("ADP Product")])
        )

    def test_short_name_is_trimmed(self) -> None:
        payload = _payload(_record(adp=[_adp("  Example-ADP \t")]))

        assert "adp:Example-ADP" in _operations(payload)
        assert ("adp:Example-ADP", V31_OTHER) in _cvss(payload)

    def test_adp_suse_is_not_the_reserved_provider(self) -> None:
        payload = _payload(_record(adp=[_adp("SUSE")]))

        assert ("adp:SUSE", V31_OTHER) in _cvss(payload)

    @pytest.mark.parametrize(
        ("affected", "expected"),
        [([], []), (None, None), ("x", None)],
        ids=["empty", "null", "non-array"],
    )
    def test_adp_affected_presence(self, affected: Any, expected: Any) -> None:
        payload = _payload(_record(adp=[_adp(affected=affected)]))

        if expected is None:
            assert "adp:Example-ADP" not in _operations(payload)
        else:
            assert _entries(payload, "adp:Example-ADP") == expected

    def test_adp_without_affected_leaves_its_scope_unobserved(self) -> None:
        adp = _adp()
        del adp["affected"]

        payload = _payload(_record(adp=[adp]))

        assert set(_operations(payload)) == {"cna"}
        assert ("adp:Example-ADP", V31_OTHER) in _cvss(payload)

    @pytest.mark.parametrize("adps", [None, {}, "adp", []])
    def test_null_empty_or_non_array_adp_observes_no_adp_scope(self, adps: Any) -> None:
        record = _record()
        record["containers"]["adp"] = adps

        result = _map(record)

        assert set(_operations(result.payload)) == {"cna"}
        assert result.skipped_adps == ()

    def test_non_cisa_adp_contributes_no_ssvc_kev_or_cwe(self) -> None:
        adp = _adp(
            metrics=[_ssvc(), _kev(), {"cvssV3_1": {"vectorString": V31_OTHER}}],
            problemTypes=_problem_types("CWE-20"),
        )

        payload = _payload(_record(adp=[adp]))

        assert payload.ssvc_assessment is None
        assert payload.kev_data is None
        assert _cwe(payload) == {("CWE-787", f"cna:{CNA_NAME}")}

    def test_cisa_short_name_with_another_org_id_is_not_cisa(self) -> None:
        impostor = _cisa(
            providerMetadata={"orgId": ADP_ORG_ID, "shortName": "CISA-ADP"}
        )

        payload = _payload(_record(adp=[impostor]))

        assert payload.ssvc_assessment is None
        assert payload.kev_data is None
        assert ("CWE-79", CISA_ADP_CWE_SOURCE) not in _cwe(payload)


class TestAdpGuard:
    @pytest.mark.parametrize(
        ("adp", "org_id"),
        [
            (_adp_identity(), None),
            (_adp_identity(None), None),
            (_adp_identity("CISA-ADP"), None),
            (_adp_identity({"orgId": ADP_ORG_ID}), ADP_ORG_ID),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": None}), ADP_ORG_ID),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": ""}), ADP_ORG_ID),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": "  "}), ADP_ORG_ID),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": 3}), ADP_ORG_ID),
            (_adp_identity({"orgId": SECRET, "shortName": ""}), None),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": f"A{NUL}"}), ADP_ORG_ID),
            (_adp_identity({"orgId": ADP_ORG_ID, "shortName": "a" * 97}), ADP_ORG_ID),
            (None, None),
            ("adp", None),
            (["adp"], None),
        ],
        ids=[
            "no-provider-metadata",
            "null-provider-metadata",
            "string-provider-metadata",
            "no-short-name",
            "null-short-name",
            "empty-short-name",
            "whitespace-short-name",
            "number-short-name",
            "non-uuid-org-id",
            "nul-short-name",
            "over-bound-short-name",
            "null-element",
            "string-element",
            "list-element",
        ],
    )
    def test_malformed_identity_skips_the_entry_and_reports_it(
        self, adp: Any, org_id: str | None
    ) -> None:
        result = _map(_record(adp=[adp, _cisa()]))

        assert result.skipped_adps == (SkippedAdp(org_id=org_id),)
        assert set(_operations(result.payload)) == {"cna"}
        assert _cvss(result.payload) == {(CNA_NAME, V31)}
        assert result.payload.ssvc_assessment is not None

    @pytest.mark.parametrize("short_name", [None, "", " "])
    def test_cisa_entry_without_short_name_contributes_nothing(
        self, short_name: Any
    ) -> None:
        """CISA-ADP is recognized by `orgId`, but the guard skips the entire
        entry first: no SSVC, KEV, CWE, or SSVC skip."""
        cisa = _cisa(
            providerMetadata={"orgId": CISA_ADP_ORG_ID, "shortName": short_name},
            metrics=[_ssvc(exploitation=None), _kev()],
            affected=[_affected("CISA Product")],
        )

        result = _map(_record(adp=[cisa]))

        assert result.skipped_adps == (SkippedAdp(CISA_ADP_ORG_ID),)
        assert result.ssvc_skips == ()
        assert not {"ssvc_assessment", "kev_data"} & result.payload.model_fields_set
        assert ("CWE-79", CISA_ADP_CWE_SOURCE) not in _cwe(result.payload)
        assert set(_operations(result.payload)) == {"cna"}

    def test_short_name_at_the_scope_bound_is_kept(self) -> None:
        name = "a" * 96

        result = _map(_record(adp=[_adp(name)]))

        assert result.skipped_adps == ()
        assert f"adp:{name}" in _operations(result.payload)

    def test_scope_bound_is_the_payload_bound(self) -> None:
        field = AffectedVersionScopeOperation.model_fields["source_container"]

        assert any(getattr(m, "max_length", None) == 100 for m in field.metadata)

    def test_one_fact_per_skipped_entry(self) -> None:
        adps = [_adp_identity(), _adp(), _adp_identity({"orgId": ADP_ORG_ID})]

        result = _map(_record(adp=adps))

        assert result.skipped_adps == (SkippedAdp(None), SkippedAdp(ADP_ORG_ID))
        assert "adp:Example-ADP" in _operations(result.payload)


class TestDuplicateScopes:
    def test_identical_duplicate_adps_collapse(self) -> None:
        single = _payload(_record(adp=[_adp()]))

        doubled = _payload(_record(adp=[_adp(), copy.deepcopy(_adp())]))

        assert doubled == single

    def test_duplicates_differing_only_in_unconsumed_fields_collapse(self) -> None:
        other = _adp(title="Another title", references=[{"url": URL_2}])
        other["providerMetadata"]["dateUpdated"] = "2026-01-09T00:00:00.000Z"

        assert _payload(_record(adp=[_adp(), other])) == _payload(_record(adp=[_adp()]))

    def test_duplicates_with_equivalent_short_names_collapse(self) -> None:
        payload = _payload(_record(adp=[_adp("Example-ADP"), _adp(" Example-ADP ")]))

        assert payload == _payload(_record(adp=[_adp()]))

    @pytest.mark.parametrize(
        "difference",
        [
            {"affected": [_affected("Other Product")]},
            {"affected": []},
            {"metrics": [{"cvssV3_1": {"vectorString": V31}}]},
            {"metrics": []},
        ],
        ids=["affected", "empty-affected", "cvss", "no-cvss"],
    )
    def test_differing_duplicate_adps_fail(self, difference: dict[str, Any]) -> None:
        with pytest.raises(MitreRecordConflictError):
            _map(_record(adp=[_adp(), _adp(**difference)]))

    def test_duplicate_without_affected_differs_from_one_with_it(self) -> None:
        unobserved = _adp()
        del unobserved["affected"]

        with pytest.raises(MitreRecordConflictError):
            _map(_record(adp=[_adp(), unobserved]))

    @pytest.mark.parametrize(
        "difference",
        [
            {"metrics": [_ssvc(exploitation="none"), _kev()]},
            {"metrics": [_ssvc(), _kev(date_added="2026-02-01")]},
            {"problemTypes": _problem_types("CWE-80")},
        ],
        ids=["ssvc", "kev", "cwe"],
    )
    def test_differing_duplicate_cisa_adps_fail(
        self, difference: dict[str, Any]
    ) -> None:
        with pytest.raises(MitreRecordConflictError):
            _map(_record(adp=[_cisa(), _cisa(**difference)]))

    def test_two_cisa_containers_with_identical_ssvc_and_kev_collapse(self) -> None:
        renamed = _cisa(
            providerMetadata={"orgId": CISA_ADP_ORG_ID, "shortName": "CISA-ADP-2"}
        )

        payload = _payload(_record(adp=[_cisa(), renamed]))

        assert payload.ssvc_assessment is not None
        assert payload.kev_data is not None
        assert _cwe(payload) == {
            ("CWE-787", f"cna:{CNA_NAME}"),
            ("CWE-79", CISA_ADP_CWE_SOURCE),
        }
        assert len(payload.cwe_classifications or []) == 2

    @pytest.mark.parametrize(
        "metrics",
        [
            [_ssvc(exploitation="none"), _kev()],
            [_ssvc(), _kev(date_added="2026-02-01")],
        ],
        ids=["ssvc", "kev"],
    )
    def test_two_cisa_containers_with_differing_values_fail(
        self, metrics: list[dict[str, Any]]
    ) -> None:
        renamed = _cisa(
            providerMetadata={"orgId": CISA_ADP_ORG_ID, "shortName": "CISA-ADP-2"},
            metrics=metrics,
        )

        with pytest.raises(MitreRecordConflictError):
            _map(_record(adp=[_cisa(), renamed]))

    def test_one_usable_and_one_skipped_cisa_ssvc_keep_the_usable_one(self) -> None:
        renamed = _cisa(
            providerMetadata={"orgId": CISA_ADP_ORG_ID, "shortName": "CISA-ADP-2"},
            metrics=[_ssvc(automatable=None), _kev()],
        )

        result = _map(_record(adp=[_cisa(), renamed]))

        assert result.payload.ssvc_assessment is not None
        assert result.ssvc_skips == (SsvcSkip("incomplete", ("Automatable",)),)


# ---------------------------------------------------------------------------
# CISA-ADP
# ---------------------------------------------------------------------------


class TestCisaAdp:
    def test_complete_ssvc_kev_and_cwe_are_set(self) -> None:
        payload = _payload(_record(adp=[_cisa()]))

        assert payload.ssvc_assessment == SSVCEntry(
            exploitation=SSVCExploitation.ACTIVE,
            automatable=SSVCAutomatable.YES,
            technical_impact=SSVCTechnicalImpact.TOTAL,
            version="2.0.3",
            assessed_at=datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC),
        )
        assert payload.kev_data == KEVEntry(
            date_added=date(2026, 1, 5), reference_url=URL_2
        )
        assert CWEEntry(cwe_id="CWE-79", source="adp:CISA-ADP") in (
            payload.cwe_classifications or []
        )

    def test_cisa_scope_and_provider_follow_the_common_adp_rule(self) -> None:
        cisa = _cisa(
            affected=[_affected("CISA Product")],
            metrics=[{"cvssV4_0": {"vectorString": V40}}, _ssvc()],
        )

        payload = _payload(_record(adp=[cisa]))

        assert "adp:CISA-ADP" in _operations(payload)
        assert ("adp:CISA-ADP", V40) in _cvss(payload)

    def test_cisa_is_identified_by_org_id(self) -> None:
        renamed = _cisa(providerMetadata={"orgId": CISA_ADP_ORG_ID, "shortName": "X"})

        payload = _payload(_record(adp=[renamed]))

        assert payload.ssvc_assessment is not None
        assert ("CWE-79", CISA_ADP_CWE_SOURCE) in _cwe(payload)

    def test_last_ssvc_and_kev_entries_win(self) -> None:
        metrics = [
            _ssvc(exploitation="none"),
            _kev(date_added="2026-01-01"),
            _ssvc(exploitation="poc"),
            _kev(date_added="2026-03-01"),
        ]

        payload = _payload(_record(adp=[_cisa(metrics=metrics)]))

        assert payload.ssvc_assessment is not None
        assert payload.ssvc_assessment.exploitation is SSVCExploitation.POC
        assert payload.kev_data is not None
        assert payload.kev_data.date_added.isoformat() == "2026-03-01"

    def test_mapping_delegates_ssvc_and_kev_to_the_parser(self) -> None:
        metrics = _cisa()["metrics"]

        payload = _payload(_record(adp=[_cisa()]))

        assert payload.ssvc_assessment == cve_record_parser.parse_ssvc_assessment(
            metrics
        )
        assert payload.kev_data == cve_record_parser.parse_kev_data(metrics)

    def test_kev_without_ssvc_is_set(self) -> None:
        result = _map(_record(adp=[_cisa(metrics=[_kev()])]))

        assert result.payload.kev_data is not None
        assert result.payload.ssvc_assessment is None
        assert result.ssvc_skips == ()


class TestSsvcSkip:
    @pytest.mark.parametrize(
        ("ssvc", "missing"),
        [
            (_ssvc(exploitation=None), ("Exploitation",)),
            (_ssvc(automatable=""), ("Automatable",)),
            (
                _ssvc(technical_impact=None, version=None),
                ("Technical Impact", "version"),
            ),
            (_ssvc(version=""), ("version",)),
            (
                {"other": {"type": "ssvc", "content": {"version": "2.0.3"}}},
                ("Exploitation", "Automatable", "Technical Impact"),
            ),
            (
                {"other": {"type": "ssvc", "content": {"options": "x"}}},
                SSVC_FIELDS,
            ),
            ({"other": {"type": "ssvc"}}, SSVC_FIELDS),
            ({"other": {"type": "ssvc", "content": []}}, SSVC_FIELDS),
        ],
        ids=[
            "null-exploitation",
            "empty-automatable",
            "two-missing",
            "empty-version",
            "no-options",
            "non-array-options",
            "no-content",
            "non-object-content",
        ],
    )
    def test_incomplete_assessment_is_omitted_and_reported(
        self, ssvc: dict[str, Any], missing: tuple[SsvcField, ...]
    ) -> None:
        result = _map(_record(adp=[_cisa(metrics=[ssvc, _kev()])]))

        assert "ssvc_assessment" not in result.payload.model_fields_set
        assert result.ssvc_skips == (SsvcSkip("incomplete", missing),)
        assert result.payload.kev_data is not None

    def test_missing_option_object_is_incomplete(self) -> None:
        ssvc = _ssvc()
        ssvc["other"]["content"]["options"] = [{"Exploitation": "active"}]

        result = _map(_record(adp=[_cisa(metrics=[ssvc])]))

        assert result.ssvc_skips == (
            SsvcSkip("incomplete", ("Automatable", "Technical Impact")),
        )

    def test_option_lookup_uses_the_first_object_carrying_a_key(self) -> None:
        ssvc = _ssvc()
        ssvc["other"]["content"]["options"].insert(0, {"Exploitation": None})

        result = _map(_record(adp=[_cisa(metrics=[ssvc])]))

        assert result.ssvc_skips == (SsvcSkip("incomplete", ("Exploitation",)),)

    @pytest.mark.parametrize(
        "ssvc",
        [
            _ssvc(exploitation="unknown"),
            _ssvc(automatable="Yes"),
            _ssvc(technical_impact=1),
            _ssvc(exploitation=["active"]),
            _ssvc(version="2.0.3.0.0.0.1"),
            _ssvc(version=203),
            _ssvc(timestamp="yesterday"),
            _ssvc(timestamp=20260102),
        ],
        ids=[
            "exploitation-enum",
            "automatable-case",
            "impact-type",
            "exploitation-list",
            "version-bound",
            "version-type",
            "timestamp-form",
            "timestamp-type",
        ],
    )
    def test_invalid_value_is_omitted_and_reported(self, ssvc: dict[str, Any]) -> None:
        result = _map(_record(adp=[_cisa(metrics=[ssvc])]))

        assert "ssvc_assessment" not in result.payload.model_fields_set
        assert result.ssvc_skips == (SsvcSkip("invalid_value", ()),)

    def test_last_entry_decides_the_skip(self) -> None:
        metrics = [_ssvc(), _ssvc(exploitation=None)]

        result = _map(_record(adp=[_cisa(metrics=metrics)]))

        assert result.payload.ssvc_assessment is None
        assert result.ssvc_skips == (SsvcSkip("incomplete", ("Exploitation",)),)

    def test_container_without_ssvc_entry_reports_nothing(self) -> None:
        cisa = _cisa(metrics=[{"cvssV3_1": {"vectorString": V31_OTHER}}])

        assert _map(_record(adp=[cisa])).ssvc_skips == ()

    @pytest.mark.parametrize(
        "metrics", [None, "ssvc", [None, "x", {"other": None}, {"other": {}}]]
    )
    def test_unusable_metrics_report_nothing(self, metrics: Any) -> None:
        assert _map(_record(adp=[_cisa(metrics=metrics)])).ssvc_skips == ()

    def test_usable_assessment_reports_nothing(self) -> None:
        assert _map(_record(adp=[_cisa()])).ssvc_skips == ()

    def test_non_cisa_ssvc_reports_nothing(self) -> None:
        adp = _adp(metrics=[_ssvc(exploitation=None)])

        assert _map(_record(adp=[adp])).ssvc_skips == ()

    def test_skip_fields_are_bounded(self) -> None:
        ssvc = _ssvc(exploitation=SECRET, automatable=None)

        (skip,) = _map(_record(adp=[_cisa(metrics=[ssvc])])).ssvc_skips

        # A missing field takes precedence over an invalid value.
        assert skip == SsvcSkip("incomplete", ("Automatable",))
        assert SECRET not in repr(skip)


# ---------------------------------------------------------------------------
# Additive retention
# ---------------------------------------------------------------------------


class TestAdditiveRetention:
    @pytest.mark.parametrize(
        "mutate",
        [
            lambda r: r["containers"]["cna"].update(metrics=[], problemTypes=[]),
            lambda r: r["containers"]["cna"].update(metrics=None, problemTypes=None),
            lambda r: r["containers"]["cna"].update(
                metrics=[{"cvssV3_1": {"vectorString": "invalid"}}],
                problemTypes=_problem_types("CWE-0"),
            ),
            lambda r: r["containers"]["cna"]["providerMetadata"].pop("shortName"),
            lambda r: r["containers"]["cna"]["providerMetadata"].update(
                shortName="SUSE"
            ),
        ],
        ids=["empty", "null", "rejected", "guarded", "reserved"],
    )
    def test_no_cvss_or_cwe_form_requests_deletion(self, mutate: Any) -> None:
        record = _record(problemTypes=[])
        mutate(record)

        payload = _payload(record)

        assert "cvss_assessments" not in payload.model_fields_set
        assert "cwe_classifications" not in payload.model_fields_set

    @pytest.mark.parametrize(
        "metrics",
        [[], None, [_ssvc(exploitation=None), _kev(date_added=None)]],
        ids=["empty", "null", "rejected"],
    )
    def test_no_ssvc_or_kev_form_requests_deletion(self, metrics: Any) -> None:
        payload = _payload(_record(adp=[_cisa(metrics=metrics, problemTypes=[])]))

        assert not {"ssvc_assessment", "kev_data"} & payload.model_fields_set
        assert ("CWE-79", CISA_ADP_CWE_SOURCE) not in _cwe(payload)

    def test_payload_without_child_data_sets_only_globals(self) -> None:
        record = _record(metrics=[], problemTypes=[], affected=None)

        assert _payload(record).model_fields_set == {
            "cve_state",
            "title",
            "description",
            "published_date",
            "modified_date",
        }


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


class TestReferences:
    def test_source_candidate_is_the_cve_org_advisory(self) -> None:
        result = _map(_record())

        assert result.source_reference == AutomaticReferenceInput(
            url=f"https://cve.org/CVERecord?id={CVE_ID}",
            title="MITRE",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert SOURCE_REFERENCE_TITLE == "MITRE"
        assert SOURCE_REFERENCE_URL_PATTERN.format(cve_id=CVE_ID) == (
            result.source_reference.url
        )

    def test_upstream_candidates_keep_url_and_tags_in_array_order(self) -> None:
        references = [
            {
                "url": URL_2,
                "name": "Fictional name",
                "tags": ["vendor-advisory", "x_a"],
            },
            {"url": URL_1},
            {"url": URL_2, "tags": []},
        ]

        upstream = _map(_record(references=references)).upstream_references

        assert upstream == (
            AutomaticReferenceInput(
                url=URL_2, upstream_tags=("vendor-advisory", "x_a")
            ),
            AutomaticReferenceInput(url=URL_1),
            AutomaticReferenceInput(url=URL_2, upstream_tags=()),
        )

    def test_non_string_tags_are_dropped_and_non_array_tags_ignored(self) -> None:
        references = [
            {"url": URL_1, "tags": ["patch", 1, None, ["x"]]},
            {"url": URL_2, "tags": "patch"},
        ]

        upstream = _map(_record(references=references)).upstream_references

        assert [r.upstream_tags for r in upstream] == [("patch",), None]

    @pytest.mark.parametrize("element", [None, "https://x.example.invalid", 1, []])
    def test_non_object_element_is_a_candidate_without_url(self, element: Any) -> None:
        upstream = _map(_record(references=[element])).upstream_references

        assert upstream == (AutomaticReferenceInput(url=None),)

    @pytest.mark.parametrize("url", [None, 7, {"u": URL_1}])
    def test_url_is_passed_unvalidated_to_the_service(self, url: Any) -> None:
        upstream = _map(_record(references=[{"url": url}])).upstream_references

        assert upstream == (AutomaticReferenceInput(url=url),)

    @pytest.mark.parametrize("references", [None, [], {}, "x"])
    def test_null_non_array_or_empty_references_yield_none(
        self, references: Any
    ) -> None:
        assert _map(_record(references=references)).upstream_references == ()

    def test_adp_references_are_not_candidates(self) -> None:
        adp = _adp(references=[{"url": URL_2, "tags": ["x_transferred"]}])

        upstream = _map(_record(adp=[adp])).upstream_references

        assert [r.url for r in upstream] == [URL_1]

    def test_live_references_keep_their_order_and_tags(self) -> None:
        name = "references_x_tags"
        references = load_record(name)["containers"]["cna"]["references"]

        upstream = map_record(
            record_path(name), load_raw_record(name)
        ).upstream_references

        assert [(r.url, r.upstream_tags) for r in upstream] == [
            (r["url"], tuple(r["tags"])) for r in references
        ]


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        "cna",
        [
            {"title": f"{SECRET}{NUL}"},
            {"title": SECRET * 20 + NUL},
            {"descriptions": [{"lang": "en", "value": f"{SECRET}{NUL}"}]},
        ],
        ids=["title", "title-after-bound", "description"],
    )
    def test_global_string_fails_payload_construction(
        self, cna: dict[str, Any]
    ) -> None:
        with pytest.raises(ValidationError) as caught:
            _map(_record(**cna))

        assert SECRET not in str(caught.value)

    def test_unselected_description_is_not_consumed(self) -> None:
        descriptions = [
            {"lang": "en", "value": "Fictional description."},
            {"lang": "de", "value": f"Fiktiv{NUL}"},
        ]

        assert _payload(_record(descriptions=descriptions)).description == (
            "Fictional description."
        )

    def test_state_is_unrecognized(self) -> None:
        with pytest.raises(MitreRecordStateError):
            _map(_record(state=f"PUBLISHED{NUL}"))

    @pytest.mark.parametrize(
        ("field", "key"),
        [("published_date", "datePublished"), ("modified_date", "dateUpdated")],
    )
    def test_date_is_omitted(self, field: str, key: str) -> None:
        payload = _payload(_record(metadata={key: f"2026-01-01T00:00:00Z{NUL}"}))

        assert field not in payload.model_fields_set

    def test_rejected_date_is_omitted(self) -> None:
        record = _record(state="REJECTED", metadata={"dateRejected": f"2026{NUL}"})

        assert "date_rejected" not in _payload(record).model_fields_set

    @pytest.mark.parametrize("scope", ["cna", "adp"])
    @pytest.mark.parametrize("field", ["programFiles", "version", "product"])
    def test_affected_value_skips_its_entry_and_keeps_siblings(
        self, scope: str, field: str
    ) -> None:
        """One element-level list, one version-level, and one element-level
        string; the parser tests own the per-field matrix."""
        poisoned = _affected("Poisoned Product")
        if field == "programFiles":
            poisoned["programFiles"] = ["src/example.c", f"src/{NUL}.c"]
        elif field == "version":
            poisoned["versions"][0]["version"] = f"1{NUL}"
        else:
            poisoned["product"] = f"Poisoned{NUL}"
        affected = [_affected("Kept Product"), poisoned]
        if scope == "cna":
            record = _record(affected=affected)
        else:
            record = _record(adp=[_adp(affected=affected)])

        payload = _payload(record)
        entries = _entries(payload, "cna" if scope == "cna" else "adp:Example-ADP")

        assert [e.product for e in entries] == ["Kept Product"]

    def test_vector_skips_its_candidate(self) -> None:
        metrics = [
            {"cvssV4_0": {"vectorString": V40 + NUL}},
            {"cvssV3_1": {"vectorString": V31}},
        ]

        cvss = _payload(_record(metrics=metrics)).cvss_assessments

        assert cvss == [CVSSAssessmentEntry(provider_name=CNA_NAME, vector_string=V31)]

    @pytest.mark.parametrize("container", ["cna", "cisa"])
    def test_cwe_id_skips_its_classification(self, container: str) -> None:
        poisoned = _problem_types("CWE-20")
        poisoned[0]["descriptions"].append({"type": "CWE", "cweId": f"CWE-1{NUL}"})
        if container == "cna":
            record = _record(problemTypes=poisoned)
        else:
            record = _record(problemTypes=[], adp=[_cisa(problemTypes=poisoned)])

        cwe = _cwe(_payload(record))

        assert {c[0] for c in cwe} == {"CWE-20"}

    @pytest.mark.parametrize(
        "ssvc",
        [
            _ssvc(exploitation=f"active{NUL}"),
            _ssvc(version=f"2.0{NUL}"),
            _ssvc(timestamp=f"{TIMESTAMP}{NUL}"),
        ],
        ids=["option", "version", "timestamp"],
    )
    def test_ssvc_value_skips_the_assessment_as_invalid(
        self, ssvc: dict[str, Any]
    ) -> None:
        result = _map(_record(adp=[_cisa(metrics=[ssvc, _kev()])]))

        assert result.payload.ssvc_assessment is None
        assert result.ssvc_skips == (SsvcSkip("invalid_value", ()),)
        assert result.payload.kev_data is not None

    @pytest.mark.parametrize(
        "kev",
        [_kev(date_added=f"2026-01-05{NUL}"), _kev(reference=f"{URL_2}{NUL}")],
        ids=["date-added", "reference"],
    )
    def test_kev_value_skips_the_entry(self, kev: dict[str, Any]) -> None:
        payload = _payload(_record(adp=[_cisa(metrics=[_ssvc(), kev])]))

        assert "kev_data" not in payload.model_fields_set
        assert payload.ssvc_assessment is not None

    def test_cna_short_name_leaves_cvss_to_upsert_and_skips_cwe(self) -> None:
        provider = {"orgId": CNA_ORG_ID, "shortName": f"Example{NUL}"}

        result = _map(_record(providerMetadata=provider))

        assert _cvss(result.payload) == {(f"Example{NUL}", V31)}
        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.cna_guard is None

    def test_adp_short_name_skips_the_entry(self) -> None:
        result = _map(_record(adp=[_adp(f"Example{NUL}")]))

        assert result.skipped_adps == (SkippedAdp(ADP_ORG_ID),)

    def test_reference_url_is_left_to_the_reference_service(self) -> None:
        url = f"{URL_1}{NUL}"

        upstream = _map(_record(references=[{"url": url}])).upstream_references

        assert upstream == (AutomaticReferenceInput(url=url),)

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda r: r["cveMetadata"].update(cveId=f"{CVE_ID}{NUL}"),
            lambda r: r["cveMetadata"].update(assignerOrgId=NUL),
            lambda r: r["cveMetadata"].update(dateReserved=NUL),
            lambda r: r["containers"]["cna"].update(x_generator={"engine": NUL}),
            lambda r: r["containers"]["cna"]["providerMetadata"].update(orgId=NUL),
            lambda r: r["containers"]["cna"]["references"][0].update(name=NUL),
            lambda r: r["containers"]["cna"]["references"][0].update(
                tags=["patch", f"x_{NUL}"]
            ),
            lambda r: r["containers"]["cna"]["descriptions"][0].update(
                supportingMedia=[{"value": NUL}]
            ),
        ],
        ids=[
            "cve-id",
            "assigner-org-id",
            "date-reserved",
            "x-generator",
            "provider-org-id",
            "reference-name",
            "reference-tag",
            "supporting-media",
        ],
    )
    def test_unconsumed_or_compared_only_value_has_no_effect(self, mutate: Any) -> None:
        record = _record()
        mutate(record)

        assert _map(record).payload == _payload(_record())


# ---------------------------------------------------------------------------
# Live records, purity, and module boundary
# ---------------------------------------------------------------------------


class TestLiveRecords:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_live_record_maps_without_failure_or_fact(self, name: str) -> None:
        record = load_record(name)

        result = map_record(record_path(name), load_raw_record(name))

        assert result.cve_id == record["cveMetadata"]["cveId"]
        assert result.payload.cve_state == CveState(record["cveMetadata"]["state"])
        assert result.skipped_adps == ()
        assert result.ssvc_skips == ()
        assert (result.cna_guard is None) == (name != "cna_short_name_missing")

    def test_suse_cna_vector_is_not_ingested(self) -> None:
        name = "cna_suse_reserved_provider"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert not [
            c for c in payload.cvss_assessments or [] if c.provider_name == "suse"
        ]
        assert ("CWE-276", "cna:suse") in _cwe(payload)

    def test_cisa_record_maps_ssvc_kev_and_scopes(self) -> None:
        name = "cisa_kev_cwe_tags"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert payload.ssvc_assessment is not None
        assert payload.kev_data is not None
        assert payload.kev_data.reference_url
        assert set(_operations(payload)) == {"cna"}
        assert {c.provider_name for c in payload.cvss_assessments or []} == {"oracle"}
        # The CISA `CWE-noinfo` description has no `cweId`; the CNA problem
        # type is free text.
        assert "cwe_classifications" not in payload.model_fields_set

    @pytest.mark.parametrize(
        ("name", "scopes"),
        [
            ("siemens_sadp", {"cna", "adp:siemens-SADP"}),
            ("cisa_adp_affected", {"cna", "adp:CISA-ADP"}),
            ("cvelistv5_program_files_adp_affected", {"cna", "adp:redhat-SADP"}),
        ],
    )
    def test_adp_affected_scopes_are_mapped(self, name: str, scopes: set[str]) -> None:
        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert set(_operations(payload)) == scopes

    def test_cna_ssvc_record_has_no_ssvc(self) -> None:
        name = "cna_ssvc_not_consumed"

        payload = map_record(record_path(name), load_raw_record(name)).payload

        assert payload.ssvc_assessment is None
        assert len(payload.cvss_assessments or []) == 2

    def test_rejected_records_map_their_rejection_dates(self) -> None:
        dated = "cvelistv5_5_2_rejected"
        undated = "cvelistv5_5_1_rejected_without_date_rejected"

        dated_payload = map_record(record_path(dated), load_raw_record(dated)).payload
        undated_payload = map_record(
            record_path(undated), load_raw_record(undated)
        ).payload

        assert dated_payload.cve_state is CveState.REJECTED
        assert dated_payload.date_rejected is not None
        assert "date_rejected" not in undated_payload.model_fields_set

    def test_fixture_cisa_org_id_is_the_mapping_constant(self) -> None:
        assert mitre_support.CISA_ADP_ORG_ID == CISA_ADP_ORG_ID


class TestPurity:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_repeated_calls_yield_equal_results(self, name: str) -> None:
        path, content = record_path(name), load_raw_record(name)

        first = map_record(path, content)
        _map(_record(adp=[_adp(), _cisa()]))

        assert map_record(path, content) == first

    def test_result_is_immutable(self) -> None:
        result = _map(_record(adp=[{"metrics": []}]))

        with pytest.raises(AttributeError):
            result.cve_id = "CVE-2026-9999"  # type: ignore[misc]
        assert isinstance(result.upstream_references, tuple)
        assert isinstance(result.skipped_adps, tuple)
        assert isinstance(result.ssvc_skips, tuple)

    def test_input_record_is_not_mutated(self) -> None:
        record = _record(adp=[_adp(), _cisa()])
        before = copy.deepcopy(record)

        _map(record)

        assert record == before


_MODULE: Final = APP_ROOT / "services" / "tickets" / "mitre_cve_record.py"


class TestModuleBoundary:
    def test_imports_include_no_logging_database_settings_or_io(self) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert forbidden_imports(modules) == set()
        assert not {
            m
            for m in modules
            if m.split(".")[0] in {"structlog", "subprocess", "sys", "io", "asyncio"}
            or m in {"app.core.logging", "app.services.git_operations"}
        }

    def test_application_imports_are_core_parser_payload_and_reference_input(
        self,
    ) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.core.external_strings",
            "app.core.identifiers",
            "app.services.cve_record_parser",
            "app.services.cve_ingest",
            "app.services.reference_service",
        }

    def test_module_defines_no_coroutine(self) -> None:
        source = _MODULE.read_text(encoding="utf-8")

        assert "async def" not in source
        assert "await " not in source
