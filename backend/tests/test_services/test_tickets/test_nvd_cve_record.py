"""Unit tests of the NVD CVE record mapping
(backend/app/services/tickets/nvd_cve_record.py).

Contract under test: docs/features/tickets/cve-sync-nvd.md (Algorithm step
4.c page envelope; Field Mapping: Global CVE fields with the Required fields
rule, the `vulnStatus` mapping and Unknown `vulnStatus` handling, Optional
member validation, Candidate skip event, Source identity, CVSS metrics,
CWE / weaknesses, CPE configurations, References, Explicitly ignored fields,
CVSS deduplication rules, External String Admissibility; NVD Source API
Caching; NVD Source API Failure Handling; Error Handling, Partial extraction
model), the selection, negation, shapes, and invalid-data obligations of
docs/features/platform/testing-strategy.md (NVD CPE Applicability
Selection; External String Admissibility), the External Base Reduction and
the reserved provider of docs/features/tickets/cvss-scoring.md, and the
payload rules of docs/features/tickets/cve-service.md (CVEIngestPayload
Schema). `SyncNvdCves` owns the requests, the emission of the events built
from the reported facts, the per-item outcome, the metrics, and the
package-candidate handoff; those parts are tested with the fetcher.

Records are the sanitized live fixtures of `tests/support/nvd.py` or minimal
fictional objects. No database, HTTP, or log is involved.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final, get_args

import pytest
from pydantic import ValidationError

from app.core.enums import CveState, ReferenceType
from app.services.cve_ingest import CVEIngestPayload
from app.services.cvss import validate_external_cvss_vector
from app.services.reference_service import AutomaticReferenceInput
from app.services.tickets.nvd_cve_record import (
    CPE_CRITERIA_MAX_LENGTH,
    CVSS_METRIC_ARRAYS,
    INVALID_CPE_CONFIGURATION,
    INVALID_CPE_MATCH,
    INVALID_CVSS_METRIC,
    INVALID_CWE,
    INVALID_DESCRIPTION,
    INVALID_REFERENCE,
    INVALID_VECTOR,
    MISSING_SOURCE,
    NVD_PROVIDER_NAME,
    NVD_SOURCE_IDENTIFIER,
    RESERVED_PROVIDER,
    SOURCE_REFERENCE_TITLE,
    SOURCE_REFERENCE_URL_PATTERN,
    UNRESOLVED_SOURCE,
    CpeSelection,
    NvdCvePage,
    NvdCveRecord,
    NvdPageError,
    NvdRecordError,
    NvdRecordIdError,
    NvdRecordStructureError,
    NvdSourceCache,
    SkipReason,
    build_source_cache,
    element_cve_id,
    map_vulnerability,
    parse_page,
    select_cpe_matches,
)
from tests.support import nvd as nvd_support
from tests.support.module_imports import APP_ROOT, forbidden_imports, imported_modules
from tests.support.nvd import (
    CISA_ADP_SOURCE_IDENTIFIER,
    PAGE_EMPTY,
    PAGE_REJECTED,
    RECORD_CVE_IDS,
    SINGLE_LOG4SHELL,
    SINGLE_PLATFORM_ALSO_VULNERABLE,
    SOURCE_PAGE,
    all_records,
    load_json_fixture,
    load_raw_fixture,
    load_record,
)

pytestmark = pytest.mark.unit

CVE_ID: Final = "CVE-2026-0001"
PUBLISHED: Final = "2026-01-01T00:00:00.000"
LAST_MODIFIED: Final = "2026-01-02T03:04:05.678"
CNA_SOURCE: Final = "cna-alpha@example.com"
CNA_NAME: Final = "Example CNA"
CNA_BETA_SOURCE: Final = "cna-beta@example.com"
ADP_SOURCE: Final = "00000000-0000-0000-0000-000000000001"
ADP_NAME: Final = "Example ADP"
UNKNOWN_SOURCE: Final = "cna-unknown@example.com"
NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {CNA_SOURCE: CNA_NAME, ADP_SOURCE: ADP_NAME}
)
"""A fictional Source API cache."""

V2: Final = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
V2_NON_BASE: Final = "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C"
V30: Final = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_OTHER: Final = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
V31_NON_BASE: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N/E:U/RL:O/RC:C"
V31_NON_BASE_REDUCED: Final = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V40_NON_BASE: Final = f"{V40}/E:A/CR:H/MAV:L/S:N/AU:Y/U:Red"

CPE_A: Final = "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"
CPE_O: Final = "cpe:2.3:o:example:system:2.0:*:*:*:*:*:*:*"
CPE_H: Final = "cpe:2.3:h:example:board:-:*:*:*:*:*:*:*"
CPE_WILDCARD: Final = "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*"
CPE_NA: Final = "cpe:2.3:a:example:service:-:*:*:*:*:*:*:*"
CPE_LINUX: Final = "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"
MATCH_ID: Final = "0A1B2C3D-4E5F-4A6B-8C7D-0E1F2A3B4C5D"
MATCH_ID_LOWER: Final = MATCH_ID.lower()

URL_1: Final = "https://advisory.example.invalid/upstream/1"
URL_2: Final = "https://advisory.example.invalid/upstream/2"
NUL: Final = "\x00"
SURROGATE: Final[str] = chr(0xD800)
"""An unpaired surrogate, built at runtime: mypy cannot cache it as a literal."""
SECRET: Final = "Example-Secret-Input-Value"

STRUCTURE_MESSAGE: Final = "NVD record is structurally non-processable"
ID_MESSAGE: Final = "NVD record id is not a valid CVE-ID"
PAGE_MESSAGE: Final = "NVD response is not a CVE API page"

VULN_STATUSES: Final = {
    "Received": CveState.PUBLISHED,
    "Awaiting Analysis": CveState.PUBLISHED,
    "Undergoing Analysis": CveState.PUBLISHED,
    "Analyzed": CveState.PUBLISHED,
    "Modified": CveState.PUBLISHED,
    "Deferred": CveState.PUBLISHED,
    "Rejected": CveState.REJECTED,
}
"""The `vulnStatus` → `CVEState` table of Global CVE fields."""

ALL_REASONS: Final[frozenset[str]] = frozenset(get_args(SkipReason.__value__))


class _Absent:
    """Marks a member the builders leave out."""

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT: Final = _Absent()


# ---------------------------------------------------------------------------
# Fictional record builders
# ---------------------------------------------------------------------------


def _present(members: Mapping[str, object]) -> dict[str, Any]:
    return {k: v for k, v in members.items() if v is not ABSENT}


def _record(**members: object) -> dict[str, Any]:
    """A minimal fictional `vulnerabilities[]` element; `members` replace or,
    with `ABSENT`, remove `cve` members."""
    cve: dict[str, object] = {
        "id": CVE_ID,
        "published": PUBLISHED,
        "lastModified": LAST_MODIFIED,
        "vulnStatus": "Analyzed",
    }
    cve.update(members)
    return {"cve": _present(cve)}


def _metric(
    source: object = CNA_SOURCE, vector: object = V31, **members: object
) -> dict[str, Any]:
    entry: dict[str, object] = {
        "source": source,
        "type": "Secondary",
        "cvssData": _present({"version": "3.1", "vectorString": vector}),
    }
    entry.update(members)
    return _present(entry)


def _weakness(
    *values: str, source: object = CNA_SOURCE, lang: str = "en", **members: object
) -> dict[str, Any]:
    entry: dict[str, object] = {
        "source": source,
        "type": "Primary",
        "description": [{"lang": lang, "value": value} for value in values],
    }
    entry.update(members)
    return _present(entry)


def _match(
    criteria: object = CPE_A,
    *,
    vulnerable: object = True,
    match_criteria_id: object = MATCH_ID,
    **members: object,
) -> dict[str, Any]:
    entry: dict[str, object] = {
        "vulnerable": vulnerable,
        "criteria": criteria,
        "matchCriteriaId": match_criteria_id,
    }
    entry.update(members)
    return _present(entry)


def _platform(criteria: object = CPE_LINUX, **members: object) -> dict[str, Any]:
    return _match(criteria, vulnerable=False, **members)


def _node(
    *entries: object, negate: object = False, operator: object = "OR"
) -> dict[str, Any]:
    return _present({"operator": operator, "negate": negate, "cpeMatch": list(entries)})


def _configuration(
    *nodes: object, negate: object = ABSENT, operator: object = ABSENT
) -> dict[str, Any]:
    return _present({"operator": operator, "negate": negate, "nodes": list(nodes)})


def _map(element: object, names: Mapping[str, str] | None = NAMES) -> NvdCveRecord:
    return map_vulnerability(element, names)


def _payload(
    element: object, names: Mapping[str, str] | None = NAMES
) -> CVEIngestPayload:
    return _map(element, names).payload


def _cvss(payload: CVEIngestPayload) -> list[tuple[object, object]]:
    return [(c.provider_name, c.vector_string) for c in payload.cvss_assessments or []]


def _cwe(payload: CVEIngestPayload) -> list[tuple[str, str]]:
    return [(c.cwe_id, c.source) for c in payload.cwe_classifications or []]


def _criteria(selection: CpeSelection) -> list[str]:
    assert selection.matches is not None
    assert all(m.vulnerable is True for m in selection.matches)
    return [m.criteria for m in selection.matches]


def _payload_criteria(payload: CVEIngestPayload) -> list[str]:
    assert payload.cpe_matches is not None
    assert all(m.vulnerable is True for m in payload.cpe_matches)
    return [m.criteria for m in payload.cpe_matches]


def _page(**members: object) -> bytes:
    envelope: dict[str, object] = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-10T00:00:00.000",
        "vulnerabilities": [_record()],
    }
    envelope.update(members)
    return json.dumps(_present(envelope)).encode()


def _source(name: object = CNA_NAME, *identifiers: object) -> dict[str, Any]:
    return {
        "name": name,
        "contactEmail": "contact-example@example.com",
        "sourceIdentifiers": list(identifiers or (CNA_SOURCE,)),
    }


def _source_page(*sources: object, **members: object) -> bytes:
    envelope: dict[str, object] = {
        "resultsPerPage": len(sources),
        "startIndex": 0,
        "totalResults": len(sources),
        "format": "NVD_SOURCE",
        "version": "2.0",
        "timestamp": "2026-10-10T00:00:00.000",
        "sources": list(sources),
    }
    envelope.update(members)
    return json.dumps(_present(envelope)).encode()


def _live_names() -> Mapping[str, str]:
    names = build_source_cache(load_raw_fixture(SOURCE_PAGE)).names
    assert names is not None
    return names


# ---------------------------------------------------------------------------
# Page envelope (Algorithm step 4.c)
# ---------------------------------------------------------------------------


class TestParsePage:
    def test_valid_envelope_keeps_total_and_raw_elements(self) -> None:
        elements: list[object] = [_record(), 5, "not a record", None, {"cve": []}]

        page = parse_page(_page(totalResults=7, vulnerabilities=elements))

        assert page == NvdCvePage(total_results=7, vulnerabilities=tuple(elements))
        assert isinstance(page.vulnerabilities, tuple)

    def test_unconsumed_envelope_members_are_ignored(self) -> None:
        content = _page(
            resultsPerPage="many",
            startIndex=None,
            format=1,
            version=[],
            timestamp={},
            extra="member",
        )

        assert parse_page(content).total_results == 1

    def test_empty_vulnerabilities_with_zero_total_parses(self) -> None:
        page = parse_page(_page(totalResults=0, vulnerabilities=[]))

        assert page == NvdCvePage(total_results=0, vulnerabilities=())

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(b"\xff\xfe{}", id="non-utf-8"),
            pytest.param("{}".encode("utf-16"), id="utf-16"),
            pytest.param(b"\xef\xbb\xbf" + _page(), id="utf-8-bom"),
            pytest.param(b"", id="empty"),
            pytest.param(b"{", id="invalid-json"),
            pytest.param(b"[]", id="array-root"),
            pytest.param(b'"page"', id="string-root"),
            pytest.param(b"null", id="null-root"),
            pytest.param(b"[" * 100_000 + b"]" * 100_000, id="deep-nesting"),
            pytest.param(
                b'{"totalResults": ' + b"9" * 5000 + b', "vulnerabilities": []}',
                id="oversized-integer",
            ),
            pytest.param(_page(totalResults=ABSENT), id="total-absent"),
            pytest.param(_page(totalResults=None), id="total-null"),
            pytest.param(_page(totalResults=-1), id="total-negative"),
            pytest.param(_page(totalResults=True), id="total-bool"),
            pytest.param(_page(totalResults=1.0), id="total-float"),
            pytest.param(_page(totalResults="1"), id="total-string"),
            pytest.param(_page(vulnerabilities=ABSENT), id="vulnerabilities-absent"),
            pytest.param(_page(vulnerabilities=None), id="vulnerabilities-null"),
            pytest.param(_page(vulnerabilities={}), id="vulnerabilities-object"),
            pytest.param(_page(vulnerabilities="x"), id="vulnerabilities-string"),
        ],
    )
    def test_body_that_is_not_a_page_fails(self, content: bytes) -> None:
        with pytest.raises(NvdPageError) as caught:
            parse_page(content)

        assert str(caught.value) == PAGE_MESSAGE

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(f'{{"totalResults": "{SECRET}"'.encode(), id="invalid-json"),
            pytest.param(_page(totalResults=SECRET), id="invalid-total"),
            pytest.param(_page(vulnerabilities={SECRET: SECRET}), id="invalid-array"),
        ],
    )
    def test_error_never_renders_the_input(self, content: bytes) -> None:
        with pytest.raises(NvdPageError) as caught:
            parse_page(content)

        assert SECRET not in str(caught.value)
        assert SECRET not in repr(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__

    def test_unpaired_surrogate_escape_inside_an_element_is_kept(self) -> None:
        content = (
            b'{"totalResults": 1, "vulnerabilities": '
            b'[{"cve": {"id": "CVE-2026-0001", "note": "\\ud800"}}]}'
        )

        page = parse_page(content)

        assert page.vulnerabilities == ({"cve": {"id": CVE_ID, "note": SURROGATE}},)

    @pytest.mark.parametrize(
        ("name", "total"),
        [
            (SINGLE_LOG4SHELL, 1),
            (SINGLE_PLATFORM_ALSO_VULNERABLE, 1),
            (PAGE_REJECTED, 12),
            (PAGE_EMPTY, 0),
        ],
    )
    def test_live_pages_parse_with_their_totals(self, name: str, total: int) -> None:
        page = parse_page(load_raw_fixture(name))

        assert page.total_results == total
        assert page.vulnerabilities == tuple(load_json_fixture(name)["vulnerabilities"])


# ---------------------------------------------------------------------------
# NVD Source API Caching and Failure Handling
# ---------------------------------------------------------------------------


class TestSourceCache:
    def test_live_source_page_builds_the_cache(self) -> None:
        data = load_json_fixture(SOURCE_PAGE)

        cache = build_source_cache(load_raw_fixture(SOURCE_PAGE))

        assert cache.names == {
            identifier: source["name"].strip()
            for source in data["sources"]
            for identifier in source["sourceIdentifiers"]
        }
        assert cache.names[NVD_SOURCE_IDENTIFIER] == "NIST"
        assert cache.names[CISA_ADP_SOURCE_IDENTIFIER] == "CISA-ADP"
        assert cache.names["mitre-1@example.com"] == "MITRE"
        assert cache.names["8254265b-2729-46b6-b9e3-3dfca2d5bfca"] == "MITRE"
        assert {cache.names[f"suse-{n}@example.com"] for n in (1, 2, 3)} == {"SUSE"}
        assert cache.malformed_entries == 0
        assert cache.incomplete is False

    def test_several_identifiers_of_one_source_map_to_its_name(self) -> None:
        content = _source_page(
            _source(CNA_NAME, CNA_SOURCE, CNA_BETA_SOURCE, ADP_SOURCE)
        )

        assert build_source_cache(content).names == {
            CNA_SOURCE: CNA_NAME,
            CNA_BETA_SOURCE: CNA_NAME,
            ADP_SOURCE: CNA_NAME,
        }

    def test_later_entry_wins_for_a_repeated_identifier(self) -> None:
        content = _source_page(
            _source("Earlier Name", CNA_SOURCE, ADP_SOURCE),
            _source("Later Name", CNA_SOURCE),
        )

        assert build_source_cache(content).names == {
            CNA_SOURCE: "Later Name",
            ADP_SOURCE: "Earlier Name",
        }

    def test_name_is_stored_trimmed(self) -> None:
        content = _source_page(_source(" \t Example CNA \n", CNA_SOURCE))

        assert build_source_cache(content).names == {CNA_SOURCE: CNA_NAME}

    def test_unconsumed_entry_and_envelope_members_are_ignored(self) -> None:
        entry = _source(CNA_NAME, CNA_SOURCE) | {
            "contactEmail": 1,
            "lastModified": None,
            "created": [],
            "v3AcceptanceLevel": {"description": 1},
            "cweAcceptanceLevel": "x",
        }
        content = _source_page(entry, startIndex="x", format=None, timestamp=1)

        cache = build_source_cache(content)

        assert cache == NvdSourceCache(
            names={CNA_SOURCE: CNA_NAME}, malformed_entries=0, incomplete=False
        )

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(1, id="int"),
            pytest.param("Example CNA", id="string"),
            pytest.param(None, id="null"),
            pytest.param([CNA_NAME, ADP_SOURCE], id="array"),
            pytest.param({"sourceIdentifiers": [ADP_SOURCE]}, id="name-absent"),
            pytest.param(_source(None, ADP_SOURCE), id="name-null"),
            pytest.param(_source(1, ADP_SOURCE), id="name-int"),
            pytest.param(_source([ADP_NAME], ADP_SOURCE), id="name-array"),
            pytest.param(_source("", ADP_SOURCE), id="name-empty"),
            pytest.param(_source(" \t\n", ADP_SOURCE), id="name-blank"),
            pytest.param({"name": ADP_NAME}, id="identifiers-absent"),
            pytest.param({"name": ADP_NAME, "sourceIdentifiers": None}, id="ids-null"),
            pytest.param(
                {"name": ADP_NAME, "sourceIdentifiers": ADP_SOURCE}, id="ids-string"
            ),
            pytest.param(
                {"name": ADP_NAME, "sourceIdentifiers": {ADP_SOURCE: 1}},
                id="ids-object",
            ),
            pytest.param(_source(ADP_NAME, ADP_SOURCE, 1), id="ids-with-int"),
            pytest.param(_source(ADP_NAME, ADP_SOURCE, None), id="ids-with-null"),
        ],
    )
    def test_malformed_entry_is_counted_and_skipped(self, entry: object) -> None:
        content = _source_page(
            _source(CNA_NAME, CNA_SOURCE), entry, _source("Other CNA", CNA_BETA_SOURCE)
        )

        cache = build_source_cache(content)

        assert cache.names == {CNA_SOURCE: CNA_NAME, CNA_BETA_SOURCE: "Other CNA"}
        assert cache.malformed_entries == 1
        assert cache.incomplete is False

    def test_every_malformed_entry_is_counted(self) -> None:
        content = _source_page(None, _source("", ADP_SOURCE), 1, _source(CNA_NAME))

        cache = build_source_cache(content)

        assert cache.names == {CNA_SOURCE: CNA_NAME}
        assert cache.malformed_entries == 3

    def test_empty_identifier_list_is_valid_and_contributes_nothing(self) -> None:
        content = _source_page(
            {"name": ADP_NAME, "sourceIdentifiers": []}, _source(CNA_NAME)
        )

        cache = build_source_cache(content)

        assert cache.names == {CNA_SOURCE: CNA_NAME}
        assert cache.malformed_entries == 0

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param(b"\xff\xfe{}", id="non-utf-8"),
            pytest.param(b"{", id="invalid-json"),
            pytest.param(b"", id="empty"),
            pytest.param(b"[]", id="array-root"),
            pytest.param(b"null", id="null-root"),
            pytest.param(b"[" * 100_000 + b"]" * 100_000, id="deep-nesting"),
            pytest.param(
                _source_page(_source(), totalResults=ABSENT), id="total-absent"
            ),
            pytest.param(_source_page(_source(), totalResults="1"), id="total-string"),
            pytest.param(_source_page(_source(), totalResults=True), id="total-bool"),
            pytest.param(_source_page(_source(), totalResults=1.0), id="total-float"),
            pytest.param(_source_page(_source(), totalResults=None), id="total-null"),
            pytest.param(
                _source_page(_source(), resultsPerPage=ABSENT), id="per-page-absent"
            ),
            pytest.param(
                _source_page(_source(), resultsPerPage="1"), id="per-page-string"
            ),
            pytest.param(
                _source_page(_source(), resultsPerPage=False), id="per-page-bool"
            ),
            pytest.param(
                _source_page(_source(), resultsPerPage=1.5), id="per-page-float"
            ),
            pytest.param(_source_page(_source(), sources=ABSENT), id="sources-absent"),
            pytest.param(_source_page(_source(), sources=None), id="sources-null"),
            pytest.param(_source_page(_source(), sources={}), id="sources-object"),
            pytest.param(_source_page(_source(), sources="x"), id="sources-string"),
        ],
    )
    def test_unparseable_body_enters_degraded_mode(self, content: bytes) -> None:
        assert build_source_cache(content) == NvdSourceCache(
            names=None, malformed_entries=0, incomplete=False
        )

    @pytest.mark.parametrize(
        ("total", "per_page", "incomplete"),
        [(3, 2, True), (2, 2, False), (1, 2, False), (0, 0, False)],
    )
    def test_pagination_guard_reports_an_incomplete_cache(
        self, total: int, per_page: int, incomplete: bool
    ) -> None:
        content = _source_page(
            _source(CNA_NAME), totalResults=total, resultsPerPage=per_page
        )

        cache = build_source_cache(content)

        assert cache.incomplete is incomplete
        assert cache.names == {CNA_SOURCE: CNA_NAME}

    def test_names_mapping_is_read_only(self) -> None:
        names = build_source_cache(_source_page(_source())).names
        assert names is not None

        with pytest.raises(TypeError):
            names[ADP_SOURCE] = ADP_NAME  # type: ignore[index]


# ---------------------------------------------------------------------------
# Global CVE fields: Required fields and identity
# ---------------------------------------------------------------------------

_TIMESTAMP_FIELDS: Final = ("published", "lastModified")


class TestRequiredFields:
    def test_minimal_record_maps_the_required_globals_only(self) -> None:
        result = _map(_record())

        assert result.cve_id == CVE_ID
        assert result.payload.model_fields_set == {
            "published_date",
            "modified_date",
            "cve_state",
        }
        assert result.payload.published_date == datetime(2026, 1, 1, tzinfo=UTC)
        assert result.payload.modified_date == datetime(
            2026, 1, 2, 3, 4, 5, 678000, tzinfo=UTC
        )
        assert result.skip_reasons == frozenset()
        assert result.upstream_references == ()

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="null"),
            pytest.param([], id="array"),
            pytest.param("CVE-2026-0001", id="string"),
            pytest.param(1, id="int"),
            pytest.param({}, id="cve-absent"),
            pytest.param({"cve": None}, id="cve-null"),
            pytest.param({"cve": [_record()["cve"]]}, id="cve-array"),
            pytest.param({"cve": CVE_ID}, id="cve-string"),
        ],
    )
    def test_element_or_cve_that_is_not_an_object_is_structural(
        self, element: object
    ) -> None:
        with pytest.raises(NvdRecordStructureError):
            _map(element)

    @pytest.mark.parametrize(
        "value",
        [ABSENT, None, 1, 2026.0001, True, [CVE_ID], {"id": CVE_ID}],
        ids=repr,
    )
    def test_id_that_is_not_a_string_is_structural(self, value: object) -> None:
        with pytest.raises(NvdRecordStructureError):
            _map(_record(id=value))

    @pytest.mark.parametrize(
        "value",
        [
            "cve-2026-0001",
            "Cve-2026-0001",
            "CVE-2026-001",
            "CVE-26-0001",
            "CVE-2026-",
            "CVE_2026_0001",
            " CVE-2026-0001",
            "CVE-2026-0001 ",
            "CVE-2026-0001\n",
            "",
            f"CVE-2026-0001{NUL}",
            f"CVE-2026-{NUL}0001",
            "CVE-\uff12\uff10\uff12\uff16-0001",
        ],
        ids=repr,
    )
    def test_id_string_that_is_not_a_cve_id_takes_the_id_path(self, value: str) -> None:
        with pytest.raises(NvdRecordIdError):
            _map(_record(id=value))

    @pytest.mark.parametrize("field", _TIMESTAMP_FIELDS)
    @pytest.mark.parametrize(
        "value",
        [
            ABSENT,
            None,
            1,
            1.5,
            True,
            ["2026-10-01T00:00:00.000"],
            {"value": "2026-10-01T00:00:00.000"},
            "2026-10-01",
            "2026-10-01 00:00:00.000",
            "20261001T000000",
            "2026-10-01T12",
            "2026-10-01T1234",
            "2026-10-01T12:34:56.789+0200",
            "2026-10-01T12:34:56.789+02",
            "2026-10-01T12:34:56.",
            "2026-10-01T12:34:56,789",
            "not a date",
            "",
            "2026-10-01T",
            "2026-10-01Tgarbage",
            "2026-13-01T00:00:00.000",
            "2026-02-30T00:00:00.000",
            "2026-10-01T25:00:00.000",
            f"2026-10-01T00:00:00.000{NUL}",
            f"{NUL}2026-10-01T00:00:00.000",
            f"2026-10-01T00:{NUL}00:00.000",
        ],
        ids=repr,
    )
    def test_timestamp_that_is_not_a_date_time_is_structural(
        self, field: str, value: object
    ) -> None:
        with pytest.raises(NvdRecordStructureError):
            _map(_record(**{field: value}))

    @pytest.mark.parametrize("field", _TIMESTAMP_FIELDS)
    @pytest.mark.parametrize(
        "value", ["0001-01-01T00:00:00.000+01:00", "9999-12-31T23:59:59.999-01:00"]
    )
    def test_offset_timestamp_outside_the_utc_range_is_structural(
        self, field: str, value: str
    ) -> None:
        """A valid ISO 8601 date-time whose UTC conversion is out of range
        cannot be mapped to an aware UTC instant (Required fields)."""
        with pytest.raises(NvdRecordStructureError):
            _map(_record(**{field: value}))

    @pytest.mark.parametrize(
        "value", [ABSENT, None, 1, True, ["Analyzed"], {"Analyzed": 1}], ids=repr
    )
    def test_vuln_status_that_is_not_a_string_is_structural(
        self, value: object
    ) -> None:
        with pytest.raises(NvdRecordStructureError):
            _map(_record(vulnStatus=value))

    @pytest.mark.parametrize(
        ("element", "error", "message"),
        [
            pytest.param({"cve": SECRET}, NvdRecordStructureError, STRUCTURE_MESSAGE),
            pytest.param(
                _record(id=[SECRET]), NvdRecordStructureError, STRUCTURE_MESSAGE
            ),
            pytest.param(_record(id=SECRET), NvdRecordIdError, ID_MESSAGE),
            pytest.param(
                _record(published=f"2026-10-01T{SECRET}"),
                NvdRecordStructureError,
                STRUCTURE_MESSAGE,
            ),
            pytest.param(
                _record(lastModified=SECRET), NvdRecordStructureError, STRUCTURE_MESSAGE
            ),
            pytest.param(
                _record(vulnStatus=[SECRET]), NvdRecordStructureError, STRUCTURE_MESSAGE
            ),
        ],
    )
    def test_error_message_is_fixed_and_never_renders_the_input(
        self, element: object, error: type[NvdRecordError], message: str
    ) -> None:
        with pytest.raises(error) as caught:
            _map(element)

        assert str(caught.value) == message
        assert SECRET not in repr(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None or caught.value.__suppress_context__

    def test_record_errors_are_value_errors(self) -> None:
        assert issubclass(NvdRecordError, ValueError)
        assert issubclass(NvdRecordStructureError, NvdRecordError)
        assert issubclass(NvdRecordIdError, NvdRecordError)
        assert issubclass(NvdPageError, ValueError)
        assert not issubclass(NvdPageError, NvdRecordError)

    def test_id_is_checked_before_the_other_required_fields(self) -> None:
        with pytest.raises(NvdRecordIdError):
            _map(_record(id="cve-2026-0001", published=None, vulnStatus=None))

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param(
                "2026-10-01T12:34:56.789",
                datetime(2026, 10, 1, 12, 34, 56, 789000, tzinfo=UTC),
                id="offset-less",
            ),
            pytest.param(
                "2026-10-01T12:34:56.789+02:00",
                datetime(2026, 10, 1, 10, 34, 56, 789000, tzinfo=UTC),
                id="positive-offset",
            ),
            pytest.param(
                "2026-10-01T00:30:00.000-05:30",
                datetime(2026, 10, 1, 6, 0, tzinfo=UTC),
                id="negative-offset",
            ),
            pytest.param(
                "2026-10-01T23:59:59.001Z",
                datetime(2026, 10, 1, 23, 59, 59, 1000, tzinfo=UTC),
                id="zulu",
            ),
            pytest.param(
                "2026-10-01T12:34:56",
                datetime(2026, 10, 1, 12, 34, 56, tzinfo=UTC),
                id="seconds",
            ),
            pytest.param(
                "2026-10-01T12:34",
                datetime(2026, 10, 1, 12, 34, tzinfo=UTC),
                id="minutes",
            ),
            pytest.param(
                "2026-10-01T12:34+01:00",
                datetime(2026, 10, 1, 11, 34, tzinfo=UTC),
                id="minutes-offset",
            ),
            pytest.param(
                "2026-10-01T12:34:56.7",
                datetime(2026, 10, 1, 12, 34, 56, 700000, tzinfo=UTC),
                id="one-digit-fraction",
            ),
        ],
    )
    @pytest.mark.parametrize(
        ("field", "attribute"),
        [("published", "published_date"), ("lastModified", "modified_date")],
    )
    def test_timestamp_maps_to_aware_utc(
        self, value: str, expected: datetime, field: str, attribute: str
    ) -> None:
        mapped = getattr(_payload(_record(**{field: value})), attribute)

        assert mapped == expected
        assert mapped.tzinfo is UTC
        assert mapped.microsecond == expected.microsecond

    def test_element_cve_id_returns_a_valid_id(self) -> None:
        assert element_cve_id(_record()) == CVE_ID

    def test_element_cve_id_ignores_the_other_required_fields(self) -> None:
        assert element_cve_id(_record(published=None, vulnStatus=1)) == CVE_ID

    @pytest.mark.parametrize(
        "element",
        [
            pytest.param(None, id="null"),
            pytest.param([_record()], id="array"),
            pytest.param({}, id="cve-absent"),
            pytest.param({"cve": [CVE_ID]}, id="cve-array"),
            pytest.param(_record(id=ABSENT), id="id-absent"),
            pytest.param(_record(id=None), id="id-null"),
            pytest.param(_record(id=1), id="id-int"),
            pytest.param(_record(id="cve-2026-0001"), id="id-lowercase"),
            pytest.param(_record(id="CVE-2026-1"), id="id-malformed"),
            pytest.param(_record(id=f"{CVE_ID}{NUL}"), id="id-nul"),
        ],
    )
    def test_element_cve_id_is_none_without_a_valid_id(self, element: object) -> None:
        assert element_cve_id(element) is None


# ---------------------------------------------------------------------------
# `vulnStatus` mapping
# ---------------------------------------------------------------------------


class TestVulnStatus:
    @pytest.mark.parametrize(("status", "state"), list(VULN_STATUSES.items()))
    def test_listed_status_maps_per_the_table(
        self, status: str, state: CveState
    ) -> None:
        result = _map(_record(vulnStatus=status))

        assert result.payload.cve_state is state
        assert result.unrecognized_vuln_status is False

    @pytest.mark.parametrize(
        "status",
        [
            "AwaitingAnalysis",
            "UndergoingAnalysis",
            "Future State",
            "rejected",
            "REJECTED",
            "Rejected ",
            "",
            f"Rejected{NUL}",
        ],
        ids=repr,
    )
    def test_unlisted_status_maps_to_published_and_is_reported(
        self, status: str
    ) -> None:
        result = _map(_record(vulnStatus=status))

        assert result.payload.cve_state is CveState.PUBLISHED
        assert "cve_state" in result.payload.model_fields_set
        assert result.unrecognized_vuln_status is True
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("status", [*VULN_STATUSES, "Future State"])
    def test_date_rejected_and_title_are_never_supplied(self, status: str) -> None:
        payload = _payload(
            _record(vulnStatus=status, descriptions=[{"lang": "en", "value": "Text."}])
        )

        assert "date_rejected" not in payload.model_fields_set
        assert "title" not in payload.model_fields_set
        assert payload.date_rejected is None


# ---------------------------------------------------------------------------
# Description
# ---------------------------------------------------------------------------


def _description(lang: object, value: object) -> dict[str, object]:
    return {"lang": lang, "value": value}


class TestDescription:
    def test_first_english_entry_is_selected_after_another_language(self) -> None:
        payload = _payload(
            _record(
                descriptions=[
                    _description("es", "Descripción ficticia."),
                    _description("en", "Fictional description."),
                ]
            )
        )

        assert payload.description == "Fictional description."

    def test_first_of_several_english_entries_is_selected(self) -> None:
        payload = _payload(
            _record(
                descriptions=[
                    _description("en", "First description."),
                    _description("en", "Second description."),
                ]
            )
        )

        assert payload.description == "First description."

    @pytest.mark.parametrize(
        "descriptions",
        [
            pytest.param(ABSENT, id="absent"),
            pytest.param(None, id="null"),
            pytest.param([], id="empty"),
            pytest.param([_description("es", "Descripción.")], id="spanish-only"),
            pytest.param(
                [_description("EN", "Upper."), _description("en-US", "Region.")],
                id="lang-compared-exactly",
            ),
        ],
    )
    def test_no_english_entry_omits_the_description(self, descriptions: object) -> None:
        result = _map(_record(descriptions=descriptions))

        assert "description" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("descriptions", [{}, "Fictional.", 1, True], ids=repr)
    def test_descriptions_that_is_not_an_array_is_skipped(
        self, descriptions: object
    ) -> None:
        result = _map(_record(descriptions=descriptions))

        assert "description" not in result.payload.model_fields_set
        assert result.skip_reasons == {INVALID_DESCRIPTION}

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(1, id="int"),
            pytest.param(None, id="null"),
            pytest.param("Fictional.", id="string"),
            pytest.param([_description("en", "Wrong.")], id="array"),
            pytest.param({"value": "Wrong."}, id="lang-absent"),
            pytest.param(_description(None, "Wrong."), id="lang-null"),
            pytest.param(_description(1, "Wrong."), id="lang-int"),
            pytest.param({"lang": "en"}, id="value-absent"),
            pytest.param(_description("en", None), id="value-null"),
            pytest.param(_description("en", ["Wrong."]), id="value-array"),
        ],
    )
    def test_invalid_entry_is_skipped_and_a_later_english_entry_selected(
        self, entry: object
    ) -> None:
        result = _map(_record(descriptions=[entry, _description("en", "Fictional.")]))

        assert result.payload.description == "Fictional."
        assert result.skip_reasons == {INVALID_DESCRIPTION}

    def test_invalid_entry_after_the_selected_one_is_reported(self) -> None:
        result = _map(_record(descriptions=[_description("en", "Fictional."), 1]))

        assert result.payload.description == "Fictional."
        assert result.skip_reasons == {INVALID_DESCRIPTION}

    def test_nul_in_the_selected_english_value_fails_the_item(self) -> None:
        element = _record(descriptions=[_description("en", f"{SECRET}{NUL}text")])

        with pytest.raises(ValidationError) as caught:
            _map(element)

        assert SECRET not in str(caught.value)
        assert SECRET not in repr(caught.value)

    @pytest.mark.parametrize(
        "descriptions",
        [
            pytest.param(
                [_description("es", f"No{NUL}"), _description("en", "Fictional.")],
                id="other-language",
            ),
            pytest.param(
                [_description("en", "Fictional."), _description("en", f"No{NUL}")],
                id="later-english",
            ),
        ],
    )
    def test_nul_in_an_unselected_value_is_not_consumed(
        self, descriptions: object
    ) -> None:
        assert _payload(_record(descriptions=descriptions)).description == "Fictional."


# ---------------------------------------------------------------------------
# Source identity
# ---------------------------------------------------------------------------


def _cvss_record(*entries: object, array: str = "cvssMetricV31") -> dict[str, Any]:
    return _record(metrics={array: list(entries)})


def _cwe_record(*weaknesses: object) -> dict[str, Any]:
    return _record(weaknesses=list(weaknesses))


class TestSourceIdentity:
    @pytest.mark.parametrize(
        "entry_type", ["Primary", "Secondary", ABSENT, None, "Garbage", 1], ids=repr
    )
    def test_nvd_identifier_is_nvd_whatever_the_type(self, entry_type: object) -> None:
        names = {NVD_SOURCE_IDENTIFIER: "NIST", **NAMES}
        element = _record(
            metrics={
                "cvssMetricV31": [_metric(NVD_SOURCE_IDENTIFIER, type=entry_type)]
            },
            weaknesses=[
                _weakness("CWE-79", source=NVD_SOURCE_IDENTIFIER, type=entry_type)
            ],
        )

        payload = _payload(element, names)

        assert _cvss(payload) == [(NVD_PROVIDER_NAME, V31)]
        assert _cwe(payload) == [("CWE-79", NVD_PROVIDER_NAME)]

    @pytest.mark.parametrize(
        "entry_type", ["Primary", "Secondary", ABSENT, "Garbage"], ids=repr
    )
    def test_other_identifier_is_its_display_name_whatever_the_type(
        self, entry_type: object
    ) -> None:
        element = _record(
            metrics={"cvssMetricV31": [_metric(CNA_SOURCE, type=entry_type)]},
            weaknesses=[_weakness("CWE-79", source=ADP_SOURCE, type=entry_type)],
        )

        payload = _payload(element)

        assert _cvss(payload) == [(CNA_NAME, V31)]
        assert _cwe(payload) == [("CWE-79", ADP_NAME)]

    def test_display_name_is_trimmed(self) -> None:
        names = {CNA_SOURCE: f"  {CNA_NAME}\t\n"}
        element = _record(
            metrics={"cvssMetricV31": [_metric(CNA_SOURCE)]},
            weaknesses=[_weakness("CWE-79", source=CNA_SOURCE)],
        )

        payload = _payload(element, names)

        assert _cvss(payload) == [(CNA_NAME, V31)]
        assert _cwe(payload) == [("CWE-79", CNA_NAME)]

    @pytest.mark.parametrize(
        "names", [None, {}, MappingProxyType({NVD_SOURCE_IDENTIFIER: "NIST"})], ids=repr
    )
    def test_nvd_needs_no_cache_entry(self, names: Mapping[str, str] | None) -> None:
        element = _record(
            metrics={"cvssMetricV31": [_metric(NVD_SOURCE_IDENTIFIER)]},
            weaknesses=[_weakness("CWE-79", source=NVD_SOURCE_IDENTIFIER)],
        )

        result = _map(element, names)

        assert _cvss(result.payload) == [(NVD_PROVIDER_NAME, V31)]
        assert _cwe(result.payload) == [("CWE-79", NVD_PROVIDER_NAME)]
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("source", [ABSENT, None, ""], ids=repr)
    def test_missing_source_is_skipped(self, source: object) -> None:
        element = _record(
            metrics={"cvssMetricV31": [_metric(source), _metric(ADP_SOURCE)]},
            weaknesses=[_weakness("CWE-79", source=source), _weakness("CWE-20")],
        )

        result = _map(element)

        assert _cvss(result.payload) == [(ADP_NAME, V31)]
        assert _cwe(result.payload) == [("CWE-20", CNA_NAME)]
        assert result.skip_reasons == {MISSING_SOURCE}

    @pytest.mark.parametrize(
        "source",
        [UNKNOWN_SOURCE, CNA_SOURCE.upper(), f" {CNA_SOURCE}", " ", "NVD", "NIST"],
        ids=repr,
    )
    def test_unknown_identifier_is_unresolved(self, source: str) -> None:
        element = _record(
            metrics={"cvssMetricV31": [_metric(source), _metric(ADP_SOURCE)]},
            weaknesses=[_weakness("CWE-79", source=source), _weakness("CWE-20")],
        )

        result = _map(element)

        assert _cvss(result.payload) == [(ADP_NAME, V31)]
        assert _cwe(result.payload) == [("CWE-20", CNA_NAME)]
        assert result.skip_reasons == {UNRESOLVED_SOURCE}

    def test_degraded_mode_keeps_only_nvd_entries(self) -> None:
        element = _record(
            metrics={
                "cvssMetricV31": [
                    _metric(CNA_SOURCE),
                    _metric(NVD_SOURCE_IDENTIFIER, V31_OTHER),
                    _metric(ADP_SOURCE),
                ]
            },
            weaknesses=[
                _weakness("CWE-79", source=CNA_SOURCE),
                _weakness("CWE-20", source=NVD_SOURCE_IDENTIFIER),
            ],
        )

        result = _map(element, None)

        assert _cvss(result.payload) == [(NVD_PROVIDER_NAME, V31_OTHER)]
        assert _cwe(result.payload) == [("CWE-20", NVD_PROVIDER_NAME)]
        assert result.skip_reasons == {UNRESOLVED_SOURCE}


# ---------------------------------------------------------------------------
# CVSS metrics
# ---------------------------------------------------------------------------


class TestCvssMetrics:
    def test_arrays_are_iterated_in_version_order(self) -> None:
        metrics = {
            "cvssMetricV40": [_metric(vector=V40)],
            "cvssMetricV31": [_metric(vector=V31)],
            "cvssMetricV30": [_metric(vector=V30)],
            "cvssMetricV2": [_metric(vector=V2)],
        }

        payload = _payload(_record(metrics=metrics))

        assert CVSS_METRIC_ARRAYS == (
            "cvssMetricV2",
            "cvssMetricV30",
            "cvssMetricV31",
            "cvssMetricV40",
        )
        assert _cvss(payload) == [
            (CNA_NAME, V2),
            (CNA_NAME, V30),
            (CNA_NAME, V31),
            (CNA_NAME, V40),
        ]

    @pytest.mark.parametrize(
        ("array", "vector"),
        [
            ("cvssMetricV2", V2),
            ("cvssMetricV30", V30),
            ("cvssMetricV31", V31),
            ("cvssMetricV40", V40),
        ],
    )
    def test_each_array_yields_its_base_vector(self, array: str, vector: str) -> None:
        result = _map(_cvss_record(_metric(vector=vector), array=array))

        assert _cvss(result.payload) == [(CNA_NAME, vector)]
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        ("array", "vector"),
        [
            ("cvssMetricV2", V2_NON_BASE),
            ("cvssMetricV31", V31_NON_BASE),
            ("cvssMetricV40", V40_NON_BASE),
        ],
    )
    def test_non_base_vector_is_reduced_to_its_canonical_base(
        self, array: str, vector: str
    ) -> None:
        canonical = validate_external_cvss_vector(vector).canonical_vector

        payload = _payload(_cvss_record(_metric(vector=vector), array=array))

        assert _cvss(payload) == [(CNA_NAME, canonical)]
        assert canonical != vector

    def test_v31_reduction_keeps_the_base_metrics(self) -> None:
        payload = _payload(_cvss_record(_metric(vector=V31_NON_BASE)))

        assert _cvss(payload) == [(CNA_NAME, V31_NON_BASE_REDUCED)]

    def test_v40_reduction_keeps_the_base_metrics(self) -> None:
        payload = _payload(
            _cvss_record(_metric(vector=V40_NON_BASE), array="cvssMetricV40")
        )

        assert _cvss(payload) == [(CNA_NAME, V40)]

    @pytest.mark.parametrize(
        "metrics",
        [
            pytest.param(ABSENT, id="absent"),
            pytest.param(None, id="null"),
            pytest.param({}, id="empty"),
            pytest.param({"cvssMetricV31": None}, id="array-null"),
            pytest.param({"cvssMetricV31": []}, id="array-empty"),
        ],
    )
    def test_no_entry_omits_the_cvss_candidates(self, metrics: object) -> None:
        result = _map(_record(metrics=metrics))

        assert "cvss_assessments" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        "provider",
        ["SUSE", " suse ", "Suse", "sUsE", "\tSUSE\n", "\u017fuse"],
        ids=repr,
    )
    def test_reserved_provider_is_skipped(self, provider: str) -> None:
        names = {CNA_SOURCE: provider, ADP_SOURCE: ADP_NAME}

        result = _map(_cvss_record(_metric(CNA_SOURCE), _metric(ADP_SOURCE)), names)

        assert _cvss(result.payload) == [(ADP_NAME, V31)]
        assert result.skip_reasons == {RESERVED_PROVIDER}

    @pytest.mark.parametrize("provider", ["SUSE Linux", "SUSE-ADP", "S USE"], ids=repr)
    def test_similar_provider_is_not_reserved(self, provider: str) -> None:
        payload = _payload(_cvss_record(_metric(CNA_SOURCE)), {CNA_SOURCE: provider})

        assert _cvss(payload) == [(provider, V31)]

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(_metric(vector=ABSENT), id="vector-absent"),
            pytest.param(_metric(vector=None), id="vector-null"),
            pytest.param(_metric(vector=""), id="vector-empty"),
            pytest.param(_metric(vector=1), id="vector-int"),
            pytest.param(_metric(vector=[V31]), id="vector-array"),
            pytest.param(_metric(vector={"v": V31}), id="vector-object"),
            pytest.param(_metric(cvssData=ABSENT), id="cvss-data-absent"),
            pytest.param(_metric(cvssData=None), id="cvss-data-null"),
            pytest.param(_metric(cvssData={}), id="cvss-data-empty"),
            pytest.param(_metric(vector="garbage"), id="garbage"),
            pytest.param(_metric(vector="   "), id="blank"),
            pytest.param(_metric(vector="CVSS:3.1/AV:N"), id="incomplete"),
            pytest.param(_metric(vector="CVSS:9.9/AV:N/AC:L"), id="unknown-version"),
            pytest.param(_metric(vector=f"{V31}/E:Z"), id="invalid-non-base"),
            pytest.param(_metric(vector=f"{V31}/E:U/E:U"), id="duplicate-non-base"),
            pytest.param(_metric(vector=V31.lower()), id="lowercase"),
            pytest.param(_metric(vector=f"{V31}{NUL}"), id="nul"),
            pytest.param(_metric(vector=f"{V31}{SURROGATE}"), id="surrogate"),
            pytest.param(_metric(vector=V31 + "/E:U" * 60), id="over-200"),
        ],
    )
    def test_invalid_vector_is_skipped(self, entry: dict[str, Any]) -> None:
        result = _map(_cvss_record(entry, _metric(ADP_SOURCE)))

        assert _cvss(result.payload) == [(ADP_NAME, V31)]
        assert result.skip_reasons == {INVALID_VECTOR}

    @pytest.mark.parametrize("metrics", [[], "metrics", 1, True], ids=repr)
    def test_metrics_that_is_not_an_object_is_skipped(self, metrics: object) -> None:
        result = _map(_record(metrics=metrics))

        assert "cvss_assessments" not in result.payload.model_fields_set
        assert result.skip_reasons == {INVALID_CVSS_METRIC}

    @pytest.mark.parametrize("array", CVSS_METRIC_ARRAYS)
    @pytest.mark.parametrize("value", [{}, "x", 1, True], ids=repr)
    def test_array_that_is_not_a_list_is_skipped_alone(
        self, array: str, value: object
    ) -> None:
        sibling = next(a for a in CVSS_METRIC_ARRAYS if a != array)
        vector = V2 if sibling == "cvssMetricV2" else V31
        if sibling == "cvssMetricV30":
            vector = V30
        metrics = {array: value, sibling: [_metric(vector=vector)]}

        result = _map(_record(metrics=metrics))

        assert _cvss(result.payload) == [(CNA_NAME, vector)]
        assert result.skip_reasons == {INVALID_CVSS_METRIC}

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(1, id="int"),
            pytest.param(None, id="null"),
            pytest.param(V31, id="string"),
            pytest.param([_metric()], id="array"),
            pytest.param(_metric(1), id="source-int"),
            pytest.param(_metric(True), id="source-bool"),
            pytest.param(_metric([CNA_SOURCE]), id="source-array"),
            pytest.param(_metric({CNA_SOURCE: 1}), id="source-object"),
            pytest.param(_metric(cvssData=V31), id="cvss-data-string"),
            pytest.param(_metric(cvssData=[V31]), id="cvss-data-array"),
            pytest.param(_metric(cvssData=1), id="cvss-data-int"),
        ],
    )
    def test_entry_with_an_invalid_shape_is_skipped(self, entry: object) -> None:
        result = _map(_cvss_record(entry, _metric(ADP_SOURCE)))

        assert _cvss(result.payload) == [(ADP_NAME, V31)]
        assert result.skip_reasons == {INVALID_CVSS_METRIC}

    def test_shape_is_checked_before_the_source(self) -> None:
        result = _map(_cvss_record(_metric(None, cvssData="x")))

        assert result.skip_reasons == {INVALID_CVSS_METRIC}

    @pytest.mark.parametrize("source", [ABSENT, None, ""], ids=repr)
    def test_missing_source_precedes_an_invalid_vector(self, source: object) -> None:
        result = _map(_cvss_record(_metric(source, "garbage")))

        assert result.skip_reasons == {MISSING_SOURCE}

    def test_unresolved_source_precedes_an_invalid_vector(self) -> None:
        result = _map(_cvss_record(_metric(UNKNOWN_SOURCE, cvssData=None)))

        assert result.skip_reasons == {UNRESOLVED_SOURCE}

    def test_reserved_provider_precedes_an_invalid_vector(self) -> None:
        result = _map(
            _cvss_record(_metric(CNA_SOURCE, "garbage")), {CNA_SOURCE: "SUSE"}
        )

        assert result.skip_reasons == {RESERVED_PROVIDER}

    def test_last_accepted_entry_of_one_source_wins_within_an_array(self) -> None:
        result = _map(
            _cvss_record(
                _metric(CNA_SOURCE, V31),
                _metric(ADP_SOURCE, V31),
                _metric(CNA_SOURCE, V31_OTHER),
            )
        )

        assert sorted(map(str, _cvss(result.payload))) == sorted(
            map(str, [(ADP_NAME, V31), (CNA_NAME, V31_OTHER)])
        )
        assert result.skip_reasons == frozenset()

    def test_last_nvd_entry_wins_within_an_array(self) -> None:
        payload = _payload(
            _cvss_record(
                _metric(NVD_SOURCE_IDENTIFIER, V31, type="Primary"),
                _metric(NVD_SOURCE_IDENTIFIER, V31_OTHER, type="Secondary"),
            )
        )

        assert _cvss(payload) == [(NVD_PROVIDER_NAME, V31_OTHER)]

    @pytest.mark.parametrize(
        "rejected",
        [
            pytest.param(_metric(CNA_SOURCE, "garbage"), id="invalid-vector"),
            pytest.param(_metric(CNA_SOURCE, cvssData=None), id="no-cvss-data"),
            pytest.param(_metric(CNA_SOURCE, cvssData="x"), id="invalid-shape"),
        ],
    )
    def test_later_rejected_entry_does_not_displace_an_accepted_one(
        self, rejected: dict[str, Any]
    ) -> None:
        payload = _payload(_cvss_record(_metric(CNA_SOURCE, V31), rejected))

        assert _cvss(payload) == [(CNA_NAME, V31)]

    def test_same_source_in_two_arrays_yields_one_entry_per_array(self) -> None:
        metrics = {
            "cvssMetricV31": [_metric(CNA_SOURCE, V31)],
            "cvssMetricV40": [_metric(CNA_SOURCE, V40)],
        }

        payload = _payload(_record(metrics=metrics))

        assert _cvss(payload) == [(CNA_NAME, V31), (CNA_NAME, V40)]

    def test_two_identifiers_of_one_name_are_separate_sources(self) -> None:
        names = {CNA_SOURCE: CNA_NAME, CNA_BETA_SOURCE: CNA_NAME}

        payload = _payload(
            _cvss_record(_metric(CNA_SOURCE, V31), _metric(CNA_BETA_SOURCE, V31_OTHER)),
            names,
        )

        assert _cvss(payload) == [(CNA_NAME, V31), (CNA_NAME, V31_OTHER)]

    def test_unconsumed_metric_members_never_influence_the_payload(self) -> None:
        plain = _record(
            metrics={
                "cvssMetricV2": [_metric(NVD_SOURCE_IDENTIFIER, V2)],
                "cvssMetricV40": [_metric(CNA_SOURCE, V40)],
            }
        )
        rich = _record(
            metrics={
                "cvssMetricV2": [
                    _metric(
                        NVD_SOURCE_IDENTIFIER,
                        cvssData={
                            "version": "3.1",
                            "vectorString": V2,
                            "baseScore": "high",
                            "baseSeverity": 1,
                        },
                        type=[],
                        exploitabilityScore="x",
                        impactScore=None,
                        acInsufInfo="x",
                        obtainAllPrivilege=1,
                        obtainUserPrivilege=[],
                        obtainOtherPrivilege={},
                        userInteractionRequired="x",
                        baseSeverity=3,
                    )
                ],
                "cvssMetricV40": [
                    _metric(
                        CNA_SOURCE,
                        cvssData={
                            "version": "2.0",
                            "vectorString": V40,
                            "baseScore": 0.0,
                            "attackVector": "PHYSICAL",
                            "Safety": "x",
                            "Automatable": [],
                        },
                        type=None,
                    )
                ],
                "ssvcV203": "not an array",
                "cvssMetricV50": [1],
                "otherMember": {"cvssData": None},
            }
        )

        plain_result, rich_result = _map(plain), _map(rich)

        assert rich_result.payload == plain_result.payload
        assert rich_result.skip_reasons == plain_result.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        "provider",
        [f"Example{NUL}CNA", "P" * 101, "P" * 200],
        ids=["nul", "over-100", "over-200"],
    )
    def test_inadmissible_provider_is_passed_to_upsert_cve(self, provider: str) -> None:
        result = _map(_cvss_record(_metric(CNA_SOURCE)), {CNA_SOURCE: provider})

        assert _cvss(result.payload) == [(provider, V31)]
        assert result.skip_reasons == frozenset()


# ---------------------------------------------------------------------------
# CWE / weaknesses
# ---------------------------------------------------------------------------


class TestCweWeaknesses:
    def test_english_cwe_values_of_nvd_and_a_cna_are_mapped(self) -> None:
        payload = _payload(
            _cwe_record(
                _weakness("CWE-79", "CWE-20", source=CNA_SOURCE),
                _weakness("CWE-787", source=NVD_SOURCE_IDENTIFIER, type="Secondary"),
            )
        )

        assert _cwe(payload) == [
            ("CWE-79", CNA_NAME),
            ("CWE-20", CNA_NAME),
            ("CWE-787", NVD_PROVIDER_NAME),
        ]

    @pytest.mark.parametrize(
        "value",
        [
            "NVD-CWE-Other",
            "NVD-CWE-noinfo",
            "CWE-0",
            "CWE-079",
            "cwe-79",
            "CWE-79 ",
            " CWE-79",
            "CWE-79\n",
            "CWE-",
            "CWE-7a",
            "CWE 79",
            "79",
            "",
            f"CWE-79{NUL}",
        ],
        ids=repr,
    )
    def test_non_matching_value_is_skipped_silently(self, value: str) -> None:
        result = _map(_cwe_record(_weakness(value, "CWE-20")))

        assert _cwe(result.payload) == [("CWE-20", CNA_NAME)]
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("lang", ["es", "EN", "en-US", ""], ids=repr)
    def test_non_english_entry_is_ignored(self, lang: str) -> None:
        result = _map(_cwe_record(_weakness("CWE-79", lang=lang)))

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        ("source", "names"),
        [
            pytest.param(ABSENT, NAMES, id="source-absent"),
            pytest.param(None, NAMES, id="source-null"),
            pytest.param("", NAMES, id="source-empty"),
            pytest.param(UNKNOWN_SOURCE, NAMES, id="unresolved"),
            pytest.param(CNA_SOURCE, None, id="degraded"),
        ],
    )
    def test_source_is_resolved_only_for_a_matching_value(
        self, source: object, names: Mapping[str, str] | None
    ) -> None:
        element = _cwe_record(
            _weakness("NVD-CWE-noinfo", "NVD-CWE-Other", source=source),
            _weakness("CWE-79", source=source, lang="es"),
            _weakness(source=source),
        )

        result = _map(element, names)

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        ("source", "names", "reason"),
        [
            pytest.param(ABSENT, NAMES, MISSING_SOURCE, id="source-absent"),
            pytest.param(None, NAMES, MISSING_SOURCE, id="source-null"),
            pytest.param("", NAMES, MISSING_SOURCE, id="source-empty"),
            pytest.param(UNKNOWN_SOURCE, NAMES, UNRESOLVED_SOURCE, id="unresolved"),
            pytest.param(CNA_SOURCE, None, UNRESOLVED_SOURCE, id="degraded"),
        ],
    )
    def test_unusable_source_skips_the_weakness(
        self, source: object, names: Mapping[str, str] | None, reason: str
    ) -> None:
        element = _cwe_record(
            _weakness("CWE-79", "CWE-20", source=source),
            _weakness("CWE-787", source=NVD_SOURCE_IDENTIFIER),
        )

        result = _map(element, names)

        assert _cwe(result.payload) == [("CWE-787", NVD_PROVIDER_NAME)]
        assert result.skip_reasons == {reason}

    def test_overlong_value_is_skipped_and_siblings_kept(self) -> None:
        overlong = "CWE-" + "1" * 17
        longest = "CWE-" + "1" * 16

        result = _map(_cwe_record(_weakness(overlong, "CWE-79", longest)))

        assert len(overlong) == 21
        assert _cwe(result.payload) == [("CWE-79", CNA_NAME), (longest, CNA_NAME)]
        assert result.skip_reasons == {INVALID_CWE}

    @pytest.mark.parametrize(
        "name", ["S" * 101, f"Example{NUL}CNA"], ids=["over-100", "nul"]
    )
    def test_inadmissible_source_is_skipped_and_the_cve_mapped(self, name: str) -> None:
        element = _record(
            descriptions=[_description("en", "Fictional.")],
            metrics={"cvssMetricV31": [_metric(NVD_SOURCE_IDENTIFIER)]},
            weaknesses=[
                _weakness("CWE-79", "CWE-20", source=CNA_SOURCE),
                _weakness("CWE-787", source=ADP_SOURCE),
            ],
        )

        result = _map(element, {CNA_SOURCE: name, ADP_SOURCE: ADP_NAME})

        assert _cwe(result.payload) == [("CWE-787", ADP_NAME)]
        assert _cvss(result.payload) == [(NVD_PROVIDER_NAME, V31)]
        assert result.payload.description == "Fictional."
        assert result.skip_reasons == {INVALID_CWE}

    def test_source_of_exactly_100_characters_is_accepted(self) -> None:
        name = "S" * 100

        result = _map(_cwe_record(_weakness("CWE-79")), {CNA_SOURCE: name})

        assert _cwe(result.payload) == [("CWE-79", name)]
        assert result.skip_reasons == frozenset()

    def test_source_is_trimmed_before_the_length_bound(self) -> None:
        name = "S" * 100

        result = _map(_cwe_record(_weakness("CWE-79")), {CNA_SOURCE: f"  {name}  "})

        assert _cwe(result.payload) == [("CWE-79", name)]

    @pytest.mark.parametrize("weaknesses", [{}, "CWE-79", 1, True], ids=repr)
    def test_weaknesses_that_is_not_an_array_is_skipped(
        self, weaknesses: object
    ) -> None:
        result = _map(_record(weaknesses=weaknesses))

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == {INVALID_CWE}

    @pytest.mark.parametrize(
        "weakness",
        [
            pytest.param(1, id="int"),
            pytest.param(None, id="null"),
            pytest.param("CWE-787", id="string"),
            pytest.param([_weakness("CWE-787")], id="array"),
            pytest.param(_weakness("CWE-787", source=1), id="source-int"),
            pytest.param(_weakness("CWE-787", source=[CNA_SOURCE]), id="source-array"),
            pytest.param(_weakness(description="CWE-787"), id="description-string"),
            pytest.param(
                _weakness(description={"lang": "en", "value": "CWE-787"}),
                id="description-object",
            ),
        ],
    )
    def test_invalid_weakness_is_skipped_and_siblings_kept(
        self, weakness: object
    ) -> None:
        result = _map(_cwe_record(weakness, _weakness("CWE-79")))

        assert _cwe(result.payload) == [("CWE-79", CNA_NAME)]
        assert result.skip_reasons == {INVALID_CWE}

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(1, id="int"),
            pytest.param(None, id="null"),
            pytest.param("CWE-787", id="string"),
            pytest.param({"value": "CWE-787"}, id="lang-absent"),
            pytest.param({"lang": 1, "value": "CWE-787"}, id="lang-int"),
            pytest.param({"lang": "en"}, id="value-absent"),
            pytest.param({"lang": "en", "value": 787}, id="value-int"),
        ],
    )
    def test_invalid_description_entry_skips_only_that_entry(
        self, entry: object
    ) -> None:
        weakness = _weakness(description=[entry, {"lang": "en", "value": "CWE-79"}])

        result = _map(_cwe_record(weakness))

        assert _cwe(result.payload) == [("CWE-79", CNA_NAME)]
        assert result.skip_reasons == {INVALID_CWE}

    @pytest.mark.parametrize("description", [ABSENT, None, []], ids=repr)
    def test_weakness_without_description_yields_nothing(
        self, description: object
    ) -> None:
        result = _map(_cwe_record(_weakness(description=description)))

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("weaknesses", [ABSENT, None, []], ids=repr)
    def test_no_weakness_omits_the_cwe_candidates(self, weaknesses: object) -> None:
        result = _map(_record(weaknesses=weaknesses))

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    def test_identical_candidates_collapse_in_first_occurrence_order(self) -> None:
        names = {CNA_SOURCE: CNA_NAME, CNA_BETA_SOURCE: f" {CNA_NAME} "}

        payload = _payload(
            _cwe_record(
                _weakness("CWE-79", "CWE-20", "CWE-79"),
                _weakness("CWE-787", "CWE-20", source=CNA_BETA_SOURCE),
            ),
            names,
        )

        assert _cwe(payload) == [
            ("CWE-79", CNA_NAME),
            ("CWE-20", CNA_NAME),
            ("CWE-787", CNA_NAME),
        ]

    def test_same_cwe_from_two_sources_yields_two_entries(self) -> None:
        payload = _payload(
            _cwe_record(
                _weakness("CWE-79", source=CNA_SOURCE),
                _weakness("CWE-79", source=NVD_SOURCE_IDENTIFIER),
            )
        )

        assert _cwe(payload) == [("CWE-79", CNA_NAME), ("CWE-79", NVD_PROVIDER_NAME)]

    def test_reserved_name_is_a_valid_cwe_source(self) -> None:
        result = _map(_cwe_record(_weakness("CWE-79")), {CNA_SOURCE: "SUSE"})

        assert _cwe(result.payload) == [("CWE-79", "SUSE")]
        assert result.skip_reasons == frozenset()


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


class TestReferences:
    def test_source_reference_is_the_nvd_detail_page(self) -> None:
        result = _map(_record())

        assert result.source_reference == AutomaticReferenceInput(
            url=f"https://nvd.nist.gov/vuln/detail/{CVE_ID}",
            title="NVD",
            explicit_type=ReferenceType.ADVISORY,
        )
        assert result.source_reference.upstream_tags is None
        assert (
            SOURCE_REFERENCE_URL_PATTERN == "https://nvd.nist.gov/vuln/detail/{cve_id}"
        )
        assert SOURCE_REFERENCE_TITLE == "NVD"

    def test_upstream_candidates_keep_array_order_url_and_tags(self) -> None:
        references = [
            {"url": URL_2, "source": CNA_SOURCE, "tags": ["Patch", "Vendor Advisory"]},
            {"url": URL_1, "source": ADP_SOURCE},
        ]

        result = _map(_record(references=references))

        assert result.upstream_references == (
            AutomaticReferenceInput(
                url=URL_2, upstream_tags=("Patch", "Vendor Advisory")
            ),
            AutomaticReferenceInput(url=URL_1),
        )
        assert all(r.title is None for r in result.upstream_references)
        assert all(r.explicit_type is None for r in result.upstream_references)
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("url", [1, None, [URL_1], {"href": URL_1}, ""], ids=repr)
    def test_url_of_another_type_is_passed_unchanged(self, url: object) -> None:
        (candidate,) = _map(_record(references=[{"url": url}])).upstream_references

        assert candidate.url == url

    def test_absent_url_yields_a_candidate_without_url(self) -> None:
        (candidate,) = _map(
            _record(references=[{"tags": ["Patch"]}])
        ).upstream_references

        assert candidate == AutomaticReferenceInput(url=None, upstream_tags=("Patch",))

    def test_only_string_tags_are_passed(self) -> None:
        references = [
            {"url": URL_1, "tags": ["Patch", 1, None, ["Exploit"], "Exploit"]}
        ]

        (candidate,) = _map(_record(references=references)).upstream_references

        assert candidate.upstream_tags == ("Patch", "Exploit")
        assert isinstance(candidate.upstream_tags, tuple)

    @pytest.mark.parametrize("tags", [ABSENT, None, "Patch", {"Patch": 1}, 1], ids=repr)
    def test_tags_that_is_not_an_array_passes_no_tags(self, tags: object) -> None:
        references = [_present({"url": URL_1, "tags": tags})]

        (candidate,) = _map(_record(references=references)).upstream_references

        assert candidate.upstream_tags is None

    def test_empty_tags_pass_no_tag(self) -> None:
        (candidate,) = _map(
            _record(references=[{"url": URL_1, "tags": []}])
        ).upstream_references

        assert candidate.upstream_tags == ()

    @pytest.mark.parametrize("element", [URL_1, 1, None, [URL_1]], ids=repr)
    def test_element_that_is_not_an_object_yields_a_candidate_without_url(
        self, element: object
    ) -> None:
        result = _map(_record(references=[element, {"url": URL_1}]))

        assert result.upstream_references == (
            AutomaticReferenceInput(url=None),
            AutomaticReferenceInput(url=URL_1),
        )
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("references", [ABSENT, None, []], ids=repr)
    def test_no_reference_yields_the_source_candidate_only(
        self, references: object
    ) -> None:
        result = _map(_record(references=references))

        assert result.upstream_references == ()
        assert result.source_reference.url == SOURCE_REFERENCE_URL_PATTERN.format(
            cve_id=CVE_ID
        )
        assert result.skip_reasons == frozenset()

    @pytest.mark.parametrize("references", [{}, URL_1, 1], ids=repr)
    def test_references_that_is_not_an_array_is_skipped(
        self, references: object
    ) -> None:
        result = _map(_record(references=references))

        assert result.upstream_references == ()
        assert result.skip_reasons == {INVALID_REFERENCE}

    def test_reference_source_is_not_read(self) -> None:
        with_source = _map(_record(references=[{"url": URL_1, "source": [1]}]))
        without_source = _map(_record(references=[{"url": URL_1}]))

        assert with_source.upstream_references == without_source.upstream_references


# ---------------------------------------------------------------------------
# CPE configurations: traversal, selection rule, and result
# ---------------------------------------------------------------------------


class TestCpeSelection:
    def test_vulnerable_entries_of_a_single_node_are_selected(self) -> None:
        configurations = [_configuration(_node(_match(CPE_A), _match(CPE_O)))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A, CPE_O]
        assert selection.skip_reasons == frozenset()

    def test_selected_entry_carries_criteria_and_match_criteria_id(self) -> None:
        selection = select_cpe_matches([_configuration(_node(_match(CPE_A)))])

        assert selection.matches is not None
        (match,) = selection.matches
        assert match.criteria == CPE_A
        assert match.vulnerable is True
        assert match.match_criteria_id == uuid.UUID(MATCH_ID)

    def test_vulnerable_node_of_an_and_configuration_is_selected(self) -> None:
        configurations = [
            _configuration(
                _node(_match(CPE_A)),
                _node(_platform(CPE_LINUX), _platform(CPE_H)),
                operator="AND",
            )
        ]

        assert _criteria(select_cpe_matches(configurations)) == [CPE_A]

    def test_platform_with_a_mapped_vendor_and_product_is_excluded(self) -> None:
        configurations = [
            _configuration(
                _node(_match(CPE_A)), _node(_platform(CPE_LINUX)), operator="AND"
            )
        ]

        payload = _payload(_record(configurations=configurations))

        assert _payload_criteria(payload) == [CPE_A]

    def test_platform_in_one_configuration_and_selected_in_another(self) -> None:
        configurations = [
            _configuration(_node(_match(CPE_O))),
            _configuration(
                _node(_match(CPE_A)), _node(_platform(CPE_O)), operator="AND"
            ),
        ]

        assert _criteria(select_cpe_matches(configurations)) == [CPE_O, CPE_A]

    def test_live_platform_also_vulnerable_is_selected_once(self) -> None:
        windows = "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*"
        configurations = load_record(SINGLE_PLATFORM_ALSO_VULNERABLE)["cve"][
            "configurations"
        ]

        criteria = _criteria(select_cpe_matches(configurations))

        assert criteria.count(windows) == 1
        assert criteria == [
            windows,
            "cpe:2.3:a:microsoft:.net_framework:4.8:*:*:*:*:*:*:*",
        ]

    @pytest.mark.parametrize(
        "criteria",
        [
            pytest.param(CPE_A, id="application-versioned"),
            pytest.param(CPE_O, id="operating-system"),
            pytest.param(CPE_H, id="hardware"),
            pytest.param(CPE_WILDCARD, id="wildcard"),
            pytest.param(CPE_NA, id="not-applicable"),
            pytest.param(CPE_LINUX, id="linux-kernel"),
        ],
    )
    def test_entries_are_selected_alike(self, criteria: str) -> None:
        configurations = [_configuration(_node(_match(criteria)))]

        assert _criteria(select_cpe_matches(configurations)) == [criteria]

    @pytest.mark.parametrize(
        "criteria", [CPE_A, CPE_O, CPE_H, CPE_WILDCARD, CPE_NA], ids=repr
    )
    def test_platform_entries_are_excluded_alike(self, criteria: str) -> None:
        selection = select_cpe_matches([_configuration(_node(_platform(criteria)))])

        assert _criteria(selection) == []
        assert selection.skip_reasons == frozenset()

    def test_range_qualified_entry_is_selected(self) -> None:
        entry = _match(
            CPE_WILDCARD,
            versionStartIncluding="1.0",
            versionEndExcluding="2.0",
        )

        assert _criteria(select_cpe_matches([_configuration(_node(entry))])) == [
            CPE_WILDCARD
        ]

    @pytest.mark.parametrize(
        ("configuration_operator", "node_operator"),
        [
            ("AND", "OR"),
            ("OR", "AND"),
            (ABSENT, ABSENT),
            (None, None),
            ("NOT", "XOR"),
            (1, ["AND"]),
        ],
        ids=repr,
    )
    def test_operators_and_ranges_never_change_the_result(
        self, configuration_operator: object, node_operator: object
    ) -> None:
        ranges = {
            "versionStartIncluding": [],
            "versionStartExcluding": 1,
            "versionEndIncluding": None,
            "versionEndExcluding": {"x": NUL},
        }
        reference = [
            _configuration(
                _node(_match(CPE_A), _match(CPE_WILDCARD)), _node(_platform(CPE_O))
            )
        ]
        mutated = [
            _configuration(
                _node(
                    _match(CPE_A, **ranges),
                    _match(CPE_WILDCARD, **ranges),
                    operator=node_operator,
                ),
                _node(_platform(CPE_O, **ranges), operator=node_operator),
                operator=configuration_operator,
            )
        ]

        assert select_cpe_matches(mutated) == select_cpe_matches(reference)

    def test_nested_and_unknown_members_are_not_traversed(self) -> None:
        node = _node(_match(CPE_A)) | {
            "nodes": [_node(_match(CPE_O))],
            "children": [_match(CPE_H)],
        }
        configuration = _configuration(node) | {"cpeMatch": [_match(CPE_H)]}

        assert _criteria(select_cpe_matches([configuration])) == [CPE_A]

    @pytest.mark.parametrize(
        "garbage",
        [
            pytest.param("not an array", id="cpe-match-string"),
            pytest.param(None, id="cpe-match-null"),
            pytest.param([1, None, "x"], id="non-object-entries"),
            pytest.param([_match(vulnerable="yes")], id="vulnerable-string"),
            pytest.param([_match(f"cpe{NUL}")], id="criteria-nul"),
            pytest.param([_match(match_criteria_id="{bad}")], id="match-id-invalid"),
        ],
    )
    def test_negated_node_is_excluded_without_validation(self, garbage: object) -> None:
        negated: dict[str, Any] = {"negate": True, "cpeMatch": garbage, "operator": 1}
        configurations = [_configuration(negated, _node(_match(CPE_A)))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == frozenset()

    def test_negated_node_excludes_valid_vulnerable_entries(self) -> None:
        configurations = [
            _configuration(_node(_match(CPE_O), negate=True), _node(_match(CPE_A)))
        ]

        assert _criteria(select_cpe_matches(configurations)) == [CPE_A]

    @pytest.mark.parametrize(
        "garbage",
        [
            pytest.param("not an array", id="nodes-string"),
            pytest.param(None, id="nodes-null"),
            pytest.param([1, {"negate": "x"}], id="invalid-nodes"),
            pytest.param([_node(_match(vulnerable=None))], id="invalid-entry"),
            pytest.param([_node(_match(CPE_O))], id="valid-entry"),
        ],
    )
    def test_negated_configuration_is_excluded_without_validation(
        self, garbage: object
    ) -> None:
        negated: dict[str, Any] = {"negate": True, "nodes": garbage}
        configurations = [negated, _configuration(_node(_match(CPE_A)))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == frozenset()

    @pytest.mark.parametrize("negate", [ABSENT, None, False], ids=repr)
    def test_absent_null_or_false_negate_does_not_exclude(self, negate: object) -> None:
        configurations = [
            _configuration(_node(_match(CPE_A), negate=negate), negate=negate)
        ]

        assert _criteria(select_cpe_matches(configurations)) == [CPE_A]

    @pytest.mark.parametrize("configurations", [ABSENT, None], ids=repr)
    def test_absent_or_null_configurations_leave_cpe_matches_unset(
        self, configurations: object
    ) -> None:
        result = _map(_record(configurations=configurations))

        assert "cpe_matches" not in result.payload.model_fields_set
        assert result.payload.cpe_matches is None
        assert result.skip_reasons == frozenset()

    def test_null_configurations_select_nothing(self) -> None:
        assert select_cpe_matches(None) == CpeSelection(
            matches=None, skip_reasons=frozenset()
        )

    @pytest.mark.parametrize(
        "configurations",
        [
            pytest.param([], id="configurations-empty"),
            pytest.param([_configuration()], id="nodes-empty"),
            pytest.param([_configuration(_node())], id="cpe-match-empty"),
            pytest.param(
                [
                    _configuration(
                        _node(_platform(CPE_O)), _node(_match(CPE_A), negate=True)
                    ),
                    _configuration(_node(_match(CPE_H)), negate=True),
                ],
                id="all-excluded",
            ),
        ],
    )
    def test_nothing_selected_yields_an_empty_list(
        self, configurations: object
    ) -> None:
        selection = select_cpe_matches(configurations)
        payload = _payload(_record(configurations=configurations))

        assert selection == CpeSelection(matches=(), skip_reasons=frozenset())
        assert "cpe_matches" in payload.model_fields_set
        assert payload.cpe_matches == []

    def test_entry_appears_once_per_occurrence(self) -> None:
        other_id = "0a1b2c3d-0000-4000-8000-000000000002"
        configurations = [
            _configuration(_node(_match(CPE_A)), _node(_match(CPE_A))),
            _configuration(_node(_match(CPE_A, match_criteria_id=other_id))),
        ]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A, CPE_A, CPE_A]
        assert selection.matches is not None
        assert [m.match_criteria_id for m in selection.matches] == [
            uuid.UUID(MATCH_ID),
            uuid.UUID(MATCH_ID),
            uuid.UUID(other_id),
        ]

    def test_live_repeated_criteria_appears_once_per_occurrence(self) -> None:
        log4j = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"

        payload = _payload(load_record(SINGLE_LOG4SHELL), _live_names())

        criteria = _payload_criteria(payload)
        assert criteria.count(log4j) == 3
        assert "cpe:2.3:h:siemens:6bk1602-0aa12-0tp0:-:*:*:*:*:*:*:*" not in criteria
        assert payload.cpe_matches is not None
        assert len({m.match_criteria_id for m in payload.cpe_matches}) == len(criteria)

    def test_rejected_record_follows_the_same_rule(self) -> None:
        configurations = [
            _configuration(
                _node(_match(CPE_A)), _node(_platform(CPE_O)), operator="AND"
            )
        ]

        payload = _payload(
            _record(vulnStatus="Rejected", configurations=configurations)
        )

        assert payload.cve_state is CveState.REJECTED
        assert _payload_criteria(payload) == [CPE_A]

    def test_mapping_joins_the_selection(self) -> None:
        configurations = [
            _configuration(_node(_match(CPE_A), _platform(CPE_O), 1)),
            "invalid configuration",
        ]

        result = _map(_record(configurations=configurations))

        assert result.payload.cpe_matches == list(
            select_cpe_matches(configurations).matches or ()
        )
        assert result.skip_reasons == {INVALID_CPE_MATCH, INVALID_CPE_CONFIGURATION}


# ---------------------------------------------------------------------------
# CPE configurations: validation
# ---------------------------------------------------------------------------

_SIBLING: Final = _match(CPE_A)


class TestCpeValidation:
    @pytest.mark.parametrize("configurations", [{}, "x", 1, True], ids=repr)
    def test_configurations_that_is_not_an_array_is_skipped(
        self, configurations: object
    ) -> None:
        selection = select_cpe_matches(configurations)
        result = _map(_record(configurations=configurations))

        assert selection == CpeSelection(
            matches=None, skip_reasons=frozenset({INVALID_CPE_CONFIGURATION})
        )
        assert result.payload.cpe_matches is None
        assert "cpe_matches" not in result.payload.model_fields_set
        assert result.skip_reasons == {INVALID_CPE_CONFIGURATION}

    @pytest.mark.parametrize(
        "configuration",
        [
            pytest.param(1, id="int"),
            pytest.param("x", id="string"),
            pytest.param(None, id="null"),
            pytest.param([_node(_match(CPE_O))], id="array"),
            pytest.param(
                _configuration(_node(_match(CPE_O)), negate="true"), id="negate-string"
            ),
            pytest.param(
                _configuration(_node(_match(CPE_O)), negate=1), id="negate-one"
            ),
            pytest.param(
                _configuration(_node(_match(CPE_O)), negate=0), id="negate-zero"
            ),
            pytest.param(
                _configuration(_node(_match(CPE_O)), negate=[]), id="negate-array"
            ),
            pytest.param({"negate": False}, id="nodes-absent"),
            pytest.param({"nodes": None}, id="nodes-null"),
            pytest.param({"nodes": _node(_match(CPE_O))}, id="nodes-object"),
            pytest.param({"nodes": "x"}, id="nodes-string"),
        ],
    )
    def test_invalid_configuration_is_skipped_with_everything_beneath(
        self, configuration: object
    ) -> None:
        configurations = [configuration, _configuration(_node(_SIBLING))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == {INVALID_CPE_CONFIGURATION}

    @pytest.mark.parametrize(
        "node",
        [
            pytest.param(1, id="int"),
            pytest.param("x", id="string"),
            pytest.param(None, id="null"),
            pytest.param([_match(CPE_O)], id="array"),
            pytest.param(_node(_match(CPE_O), negate="false"), id="negate-string"),
            pytest.param(_node(_match(CPE_O), negate=1), id="negate-one"),
            pytest.param(_node(_match(CPE_O), negate={}), id="negate-object"),
            pytest.param({"negate": False}, id="cpe-match-absent"),
            pytest.param({"cpeMatch": None}, id="cpe-match-null"),
            pytest.param({"cpeMatch": _match(CPE_O)}, id="cpe-match-object"),
            pytest.param({"cpeMatch": CPE_O}, id="cpe-match-string"),
        ],
    )
    def test_invalid_node_is_skipped_with_everything_beneath(
        self, node: object
    ) -> None:
        configurations = [_configuration(node, _node(_SIBLING))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == {INVALID_CPE_CONFIGURATION}

    @pytest.mark.parametrize(
        "entry",
        [
            pytest.param(1, id="int"),
            pytest.param(CPE_O, id="string"),
            pytest.param(None, id="null"),
            pytest.param([_match(CPE_O)], id="array"),
            pytest.param(_match(CPE_O, vulnerable=ABSENT), id="vulnerable-absent"),
            pytest.param(_match(CPE_O, vulnerable=None), id="vulnerable-null"),
            pytest.param(_match(CPE_O, vulnerable="true"), id="vulnerable-string"),
            pytest.param(_match(CPE_O, vulnerable=1), id="vulnerable-one"),
            pytest.param(_match(CPE_O, vulnerable=0), id="vulnerable-zero"),
            pytest.param(_match(criteria=ABSENT), id="criteria-absent"),
            pytest.param(_match(criteria=None), id="criteria-null"),
            pytest.param(_match(criteria=1), id="criteria-int"),
            pytest.param(_match(criteria=[CPE_O]), id="criteria-array"),
            pytest.param(_match("c" * 2049), id="criteria-2049"),
            pytest.param(_match(f"{CPE_O}{NUL}"), id="criteria-nul"),
            pytest.param(
                _match(f"cpe:2.3:a:example:{SURROGATE}:1.0:*:*:*:*:*:*:*"),
                id="criteria-surrogate",
            ),
            pytest.param(_match(CPE_O, match_criteria_id=1), id="id-int"),
            pytest.param(_match(CPE_O, match_criteria_id=[MATCH_ID]), id="id-array"),
            pytest.param(_match(CPE_O, match_criteria_id=""), id="id-empty"),
            pytest.param(
                _match(CPE_O, match_criteria_id=MATCH_ID.replace("-", "")),
                id="id-non-hyphenated",
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{{{MATCH_ID}}}"), id="id-braced"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"urn:uuid:{MATCH_ID}"), id="id-urn"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=MATCH_ID[:-1]), id="id-too-short"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{MATCH_ID}0"), id="id-too-long"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{MATCH_ID[:8]}{MATCH_ID[9:13]}-0-0"),
                id="id-wrong-groups",
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"G{MATCH_ID[1:]}"), id="id-non-hex"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f" {MATCH_ID}"), id="id-leading-space"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{MATCH_ID}\n"), id="id-newline"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{MATCH_ID[:-1]}{NUL}"), id="id-nul"
            ),
            pytest.param(
                _match(CPE_O, match_criteria_id=f"{MATCH_ID[:-1]}{SURROGATE}"),
                id="id-surrogate",
            ),
        ],
    )
    def test_invalid_entry_is_skipped_and_siblings_selected(
        self, entry: object
    ) -> None:
        configurations = [_configuration(_node(entry, _SIBLING))]

        selection = select_cpe_matches(configurations)

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == {INVALID_CPE_MATCH}

    def test_criteria_bound_is_the_documented_constant(self) -> None:
        assert CPE_CRITERIA_MAX_LENGTH == 2048

    @pytest.mark.parametrize(
        "criteria",
        ["c" * 2048, "\U0001f600" * 2048, "\u00e9" * 2048],
        ids=["ascii", "astral", "two-byte"],
    )
    def test_criteria_of_2048_code_points_is_accepted(self, criteria: str) -> None:
        configurations = [_configuration(_node(_match(criteria)))]

        payload = _payload(_record(configurations=configurations))

        assert _payload_criteria(payload) == [criteria]

    @pytest.mark.parametrize(
        "criteria", ["c" * 2049, "\U0001f600" * 2049], ids=["ascii", "astral"]
    )
    def test_criteria_of_2049_code_points_is_rejected(self, criteria: str) -> None:
        selection = select_cpe_matches([_configuration(_node(_match(criteria)))])

        assert _criteria(selection) == []
        assert selection.skip_reasons == {INVALID_CPE_MATCH}

    @pytest.mark.parametrize("match_criteria_id", [ABSENT, None], ids=repr)
    def test_absent_or_null_match_criteria_id_is_none(
        self, match_criteria_id: object
    ) -> None:
        entry = _match(CPE_A, match_criteria_id=match_criteria_id)

        selection = select_cpe_matches([_configuration(_node(entry))])

        assert selection.matches is not None
        (match,) = selection.matches
        assert match.match_criteria_id is None
        assert selection.skip_reasons == frozenset()

    @pytest.mark.parametrize(
        "value",
        [MATCH_ID, MATCH_ID_LOWER, "0a1B2c3D-4e5F-4a6B-8c7D-0e1F2a3B4c5D"],
        ids=["uppercase", "lowercase", "mixed-case"],
    )
    def test_uuid_is_compared_case_insensitively(self, value: str) -> None:
        entry = _match(CPE_A, match_criteria_id=value)

        selection = select_cpe_matches([_configuration(_node(entry))])

        assert selection.matches is not None
        (match,) = selection.matches
        assert match.match_criteria_id == uuid.UUID(value) == uuid.UUID(MATCH_ID)

    @pytest.mark.parametrize(
        "criteria",
        [
            "not-a-cpe",
            "",
            "cpe:/a:example:product:1.0",
            "cpe:2.3:a:dolibarr:dolibarr_erp\\/crm:21.0.1:*:*:*:*:*:*:*",
            "  cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*  ",
        ],
        ids=repr,
    )
    def test_criteria_within_the_bounds_is_transported_unchanged(
        self, criteria: str
    ) -> None:
        payload = _payload(
            _record(configurations=[_configuration(_node(_match(criteria)))])
        )

        assert _payload_criteria(payload) == [criteria]

    @pytest.mark.parametrize(
        ("criteria", "match_criteria_id"),
        [
            (ABSENT, ABSENT),
            (None, None),
            (1, 1),
            ("c" * 5000, "not-a-uuid"),
            (f"cpe{NUL}", f"id{NUL}"),
            (SURROGATE, SURROGATE),
        ],
        ids=repr,
    )
    def test_platform_criteria_and_id_are_not_validated(
        self, criteria: object, match_criteria_id: object
    ) -> None:
        entry = _platform(criteria, match_criteria_id=match_criteria_id)

        selection = select_cpe_matches([_configuration(_node(entry, _SIBLING))])

        assert _criteria(selection) == [CPE_A]
        assert selection.skip_reasons == frozenset()

    def test_cpe_data_never_fails_payload_construction(self) -> None:
        invalid_entries: list[object] = [
            1,
            None,
            _match(vulnerable=None),
            _match(criteria=None),
            _match("c" * 2049),
            _match(f"cpe{NUL}"),
            _match(SURROGATE),
            _match(match_criteria_id="not-a-uuid"),
            _match(match_criteria_id=f"{MATCH_ID[:-1]}{NUL}"),
            _platform(f"cpe{NUL}", match_criteria_id=SURROGATE),
        ]
        configurations: list[object] = [
            1,
            None,
            {"negate": "x", "nodes": []},
            {"nodes": None},
            _configuration(
                1,
                {"negate": 1},
                {"cpeMatch": "x"},
                _node(*invalid_entries, _SIBLING, _match("c" * 2048)),
                _node(*invalid_entries, negate=True),
            ),
            {"negate": True, "nodes": SURROGATE},
        ]

        result = _map(_record(configurations=configurations))

        assert _payload_criteria(result.payload) == [CPE_A, "c" * 2048]
        assert result.skip_reasons == {INVALID_CPE_CONFIGURATION, INVALID_CPE_MATCH}


# ---------------------------------------------------------------------------
# External String Admissibility
# ---------------------------------------------------------------------------


class TestExternalStringAdmissibility:
    @pytest.mark.parametrize(
        ("element", "error"),
        [
            pytest.param(_record(id=f"CVE-2026-0{NUL}001"), NvdRecordIdError, id="id"),
            pytest.param(
                _record(published=f"2026-10-01T00:00{NUL}:00.000"),
                NvdRecordStructureError,
                id="published",
            ),
            pytest.param(
                _record(lastModified=f"2026-10-01T00:00:00.000{NUL}"),
                NvdRecordStructureError,
                id="last-modified",
            ),
            pytest.param(
                _record(descriptions=[_description("en", f"Fictional{NUL}.")]),
                ValidationError,
                id="selected-description",
            ),
        ],
    )
    def test_nul_fails_the_cve_item(
        self, element: dict[str, Any], error: type[Exception]
    ) -> None:
        with pytest.raises(error):
            _map(element)

    @pytest.mark.parametrize(
        ("element", "names", "reason"),
        [
            pytest.param(
                _cvss_record(_metric(vector=f"CVSS:3.1/AV:N{NUL}/AC:L")),
                NAMES,
                INVALID_VECTOR,
                id="vector-string",
            ),
            pytest.param(
                _cwe_record(_weakness("CWE-79")),
                {CNA_SOURCE: f"Example{NUL}CNA"},
                INVALID_CWE,
                id="resolved-cwe-source",
            ),
            pytest.param(
                _record(
                    configurations=[_configuration(_node(_match(f"{CPE_A}{NUL}")))]
                ),
                NAMES,
                INVALID_CPE_MATCH,
                id="criteria",
            ),
            pytest.param(
                _record(
                    configurations=[
                        _configuration(
                            _node(_match(match_criteria_id=f"{NUL}{MATCH_ID[1:]}"))
                        )
                    ]
                ),
                NAMES,
                INVALID_CPE_MATCH,
                id="match-criteria-id",
            ),
        ],
    )
    def test_nul_skips_the_unit_with_its_reason(
        self, element: dict[str, Any], names: Mapping[str, str], reason: str
    ) -> None:
        result = _map(element, names)

        assert result.skip_reasons == {reason}
        assert "\\u0000" not in result.payload.model_dump_json()

    def test_nul_in_a_resolved_cvss_provider_is_passed_to_upsert_cve(self) -> None:
        provider = f"Example{NUL}CNA"

        result = _map(_cvss_record(_metric()), {CNA_SOURCE: provider})

        assert _cvss(result.payload) == [(provider, V31)]
        assert result.skip_reasons == frozenset()

    def test_nul_in_a_reference_url_and_tag_is_passed_to_reference_service(
        self,
    ) -> None:
        url, tag = f"{URL_1}{NUL}", f"Patch{NUL}"

        result = _map(_record(references=[{"url": url, "tags": [tag]}]))

        assert result.upstream_references == (
            AutomaticReferenceInput(url=url, upstream_tags=(tag,)),
        )
        assert result.skip_reasons == frozenset()

    def test_nul_in_a_weakness_value_is_skipped_silently(self) -> None:
        result = _map(_cwe_record(_weakness(f"CWE-79{NUL}", f"{NUL}CWE-20")))

        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    def test_nul_in_vuln_status_is_only_compared(self) -> None:
        result = _map(_record(vulnStatus=f"Analyzed{NUL}"))

        assert result.payload.cve_state is CveState.PUBLISHED
        assert result.unrecognized_vuln_status is True

    def test_nul_in_lang_is_only_compared(self) -> None:
        result = _map(
            _record(
                descriptions=[_description(f"en{NUL}", "Fictional.")],
                weaknesses=[_weakness("CWE-79", lang=f"en{NUL}")],
            )
        )

        assert "description" not in result.payload.model_fields_set
        assert "cwe_classifications" not in result.payload.model_fields_set
        assert result.skip_reasons == frozenset()

    def test_nul_in_a_source_identifier_is_only_a_cache_key(self) -> None:
        source = f"cna{NUL}@example.com"
        element = _record(
            metrics={"cvssMetricV31": [_metric(source)]},
            weaknesses=[_weakness("CWE-79", source=source)],
        )

        unresolved = _map(element)
        resolved = _map(element, {source: CNA_NAME})

        assert unresolved.skip_reasons == {UNRESOLVED_SOURCE}
        assert _cvss(resolved.payload) == [(CNA_NAME, V31)]
        assert _cwe(resolved.payload) == [("CWE-79", CNA_NAME)]
        assert resolved.skip_reasons == frozenset()

    def test_nul_in_excluded_or_negated_cpe_data_is_not_checked(self) -> None:
        configurations = [
            _configuration(
                _node(_platform(f"{CPE_O}{NUL}"), _SIBLING, operator=NUL),
                _node(_match(f"{CPE_H}{NUL}"), negate=True),
            ),
            {"negate": True, "nodes": [_node(_match(NUL, match_criteria_id=NUL))]},
        ]

        result = _map(_record(configurations=configurations))

        assert _payload_criteria(result.payload) == [CPE_A]
        assert result.skip_reasons == frozenset()

    def test_nul_in_a_source_api_name_is_kept_until_resolved(self) -> None:
        content = _source_page(_source(f"Example{NUL}CNA", CNA_SOURCE))

        cache = build_source_cache(content)

        assert cache.names == {CNA_SOURCE: f"Example{NUL}CNA"}
        assert cache.malformed_entries == 0


# ---------------------------------------------------------------------------
# Explicitly ignored fields
# ---------------------------------------------------------------------------


class TestIgnoredFields:
    def test_unconsumed_record_members_are_not_read_or_validated(self) -> None:
        plain = _record(
            descriptions=[_description("en", "Fictional.")],
            metrics={"cvssMetricV31": [_metric()]},
            weaknesses=[_weakness("CWE-79")],
            references=[{"url": URL_1}],
        )
        rich = copy.deepcopy(plain)
        rich["cve"].update(
            {
                "sourceIdentifier": [SECRET],
                "cveTags": "not an array",
                "evaluatorComment": 1,
                "evaluatorImpact": None,
                "evaluatorSolution": {},
                "vendorComments": "x",
                "cisaExploitAdd": [],
                "cisaActionDue": 1,
                "cisaRequiredAction": None,
                "cisaVulnerabilityName": {},
                "affected": "not an array",
                "title": "Ignored title",
                "dateRejected": "2026-10-01T00:00:00.000",
                "unknownMember": {"nested": NUL},
            }
        )
        rich["unknownElementMember"] = 1

        plain_result, rich_result = _map(plain), _map(rich)

        assert rich_result.payload == plain_result.payload
        assert (
            rich_result.payload.model_fields_set
            == plain_result.payload.model_fields_set
        )
        assert rich_result.skip_reasons == frozenset()
        assert "title" not in rich_result.payload.model_fields_set
        assert "date_rejected" not in rich_result.payload.model_fields_set


# ---------------------------------------------------------------------------
# Candidate skip event facts
# ---------------------------------------------------------------------------


class TestSkipReasons:
    def test_reason_constants_are_the_closed_vocabulary(self) -> None:
        constants = {
            INVALID_DESCRIPTION,
            INVALID_CVSS_METRIC,
            INVALID_VECTOR,
            MISSING_SOURCE,
            UNRESOLVED_SOURCE,
            RESERVED_PROVIDER,
            INVALID_CWE,
            INVALID_REFERENCE,
            INVALID_CPE_CONFIGURATION,
            INVALID_CPE_MATCH,
        }

        assert (
            constants
            == ALL_REASONS
            == {
                "invalid_description",
                "invalid_cvss_metric",
                "invalid_vector",
                "missing_source",
                "unresolved_source",
                "reserved_provider",
                "invalid_cwe",
                "invalid_reference",
                "invalid_cpe_configuration",
                "invalid_cpe_match",
            }
        )

    def test_many_skipped_units_of_one_reason_yield_it_once(self) -> None:
        element = _cvss_record(
            *(_metric(f"cna-{n}@example.com", "garbage") for n in range(5)),
            _metric(CNA_SOURCE, "garbage"),
            _metric(ADP_SOURCE, ""),
        )

        result = _map(element, None)

        assert result.skip_reasons == {UNRESOLVED_SOURCE}
        assert isinstance(result.skip_reasons, frozenset)

    def test_record_without_skipped_unit_has_no_reason(self) -> None:
        result = _map(load_record("record_analyzed_full"), _live_names())

        assert result.skip_reasons == frozenset()

    def test_reasons_of_every_unit_aggregate(self) -> None:
        names = {CNA_SOURCE: CNA_NAME, ADP_SOURCE: "SUSE"}
        element = _record(
            descriptions=[1, _description("en", "Fictional.")],
            metrics={
                "cvssMetricV2": "not an array",
                "cvssMetricV31": [
                    _metric(CNA_SOURCE, "garbage"),
                    _metric(None),
                    _metric(UNKNOWN_SOURCE),
                    _metric(ADP_SOURCE),
                    _metric(NVD_SOURCE_IDENTIFIER),
                ],
            },
            weaknesses=[1, _weakness("CWE-79")],
            references="not an array",
            configurations=[1, _configuration(_node(1, _SIBLING))],
        )

        result = _map(element, names)

        assert result.skip_reasons == ALL_REASONS
        assert result.skip_reasons <= ALL_REASONS
        assert _cvss(result.payload) == [(NVD_PROVIDER_NAME, V31)]
        assert _cwe(result.payload) == [("CWE-79", CNA_NAME)]
        assert _payload_criteria(result.payload) == [CPE_A]
        assert result.payload.description == "Fictional."

    def test_selection_reasons_are_within_the_vocabulary(self) -> None:
        selection = select_cpe_matches([1, _configuration(_node(1))])

        assert selection.skip_reasons <= ALL_REASONS
        assert isinstance(selection.skip_reasons, frozenset)


# ---------------------------------------------------------------------------
# Live records
# ---------------------------------------------------------------------------


class TestLiveRecords:
    @pytest.mark.parametrize(
        ("name", "element"), all_records(), ids=[n for n, _ in all_records()]
    )
    def test_every_live_record_maps(self, name: str, element: dict[str, Any]) -> None:
        result = _map(element, _live_names())

        assert result.cve_id == element["cve"]["id"] == element_cve_id(element)
        assert result.skip_reasons <= ALL_REASONS
        assert result.unrecognized_vuln_status is False
        assert result.payload.published_date == datetime.fromisoformat(
            element["cve"]["published"]
        ).replace(tzinfo=UTC)
        if name in RECORD_CVE_IDS:
            assert result.cve_id == RECORD_CVE_IDS[name]

    @pytest.mark.parametrize(
        ("name", "element"), all_records(), ids=[n for n, _ in all_records()]
    )
    def test_every_live_record_maps_in_degraded_mode(
        self, name: str, element: dict[str, Any]
    ) -> None:
        degraded = _map(element, None).payload
        resolved = _map(element, _live_names()).payload

        assert _cvss(degraded) == [
            entry for entry in _cvss(resolved) if entry[0] == NVD_PROVIDER_NAME
        ]
        assert _cwe(degraded) == [
            entry for entry in _cwe(resolved) if entry[1] == NVD_PROVIDER_NAME
        ]

    def test_cna_primary_cvss_keeps_both_providers(self) -> None:
        payload = _payload(load_record("record_cna_primary_cvss"), _live_names())

        assert _cvss(payload) == [
            ("Microsoft Corporation", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"),
            (NVD_PROVIDER_NAME, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
        ]

    def test_cna_primary_cwe_keeps_every_source(self) -> None:
        payload = _payload(load_record("record_cna_primary_cwe"), _live_names())

        assert _cwe(payload) == [
            ("CWE-749", "Microsoft Corporation"),
            ("CWE-290", NVD_PROVIDER_NAME),
            ("CWE-290", "CISA-ADP"),
        ]

    def test_log4shell_maps_nvd_v2_and_v31_and_cisa_adp(self) -> None:
        v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

        payload = _payload(load_record(SINGLE_LOG4SHELL), _live_names())

        assert _cvss(payload) == [
            (NVD_PROVIDER_NAME, "AV:N/AC:M/Au:N/C:C/I:C/A:C"),
            (NVD_PROVIDER_NAME, v31),
            ("CISA-ADP", v31),
        ]
        assert ("CWE-917", NVD_PROVIDER_NAME) in _cwe(payload)
        assert {s for _, s in _cwe(payload)} == {
            NVD_PROVIDER_NAME,
            "Apache Software Foundation",
        }

    def test_reserved_suse_record_skips_its_cvss_and_keeps_its_cwe(self) -> None:
        result = _map(load_record("record_reserved_suse"), _live_names())

        assert "cvss_assessments" not in result.payload.model_fields_set
        assert result.skip_reasons == {RESERVED_PROVIDER}
        assert _cwe(result.payload) == [("CWE-532", "SUSE")]

    def test_v40_non_base_vector_is_reduced(self) -> None:
        element = load_record("record_awaiting_v40_non_base")
        (entry,) = element["cve"]["metrics"]["cvssMetricV40"]
        received = entry["cvssData"]["vectorString"]

        payload = _payload(element, _live_names())

        assert _cvss(payload) == [
            ("HackerOne", validate_external_cvss_vector(received).canonical_vector)
        ]
        assert _cvss(payload)[0][1] == (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        )

    def test_rejected_records_carry_no_child_data(self) -> None:
        elements = load_json_fixture(PAGE_REJECTED)["vulnerabilities"]

        results = [_map(element, _live_names()) for element in elements]

        assert len(results) == 12
        for result in results:
            assert result.payload.cve_state is CveState.REJECTED
            assert result.payload.model_fields_set == {
                "published_date",
                "modified_date",
                "cve_state",
                "description",
            }
            assert result.upstream_references == ()
            assert result.skip_reasons == frozenset()

    def test_analyzed_full_selects_the_english_description(self) -> None:
        payload = _payload(load_record("record_analyzed_full"), _live_names())

        assert payload.description == "Fictional description of CVE-2025-52221."

    def test_live_mapping_is_deterministic(self) -> None:
        names = _live_names()
        first = [_map(element, names) for _, element in all_records()]

        assert [_map(element, names) for _, element in all_records()] == first

    def test_support_constants_match_the_mapping(self) -> None:
        assert nvd_support.NVD_SOURCE_IDENTIFIER == NVD_SOURCE_IDENTIFIER


# ---------------------------------------------------------------------------
# Purity and module boundary
# ---------------------------------------------------------------------------


class TestPurity:
    @pytest.mark.parametrize(
        ("name", "element"), all_records(), ids=[n for n, _ in all_records()]
    )
    def test_repeated_calls_yield_equal_results(
        self, name: str, element: dict[str, Any]
    ) -> None:
        names = _live_names()

        first = map_vulnerability(element, names)
        _map(_record(metrics={"cvssMetricV31": [_metric()]}))

        assert map_vulnerability(element, names) == first

    def test_results_are_immutable(self) -> None:
        record = _map(
            _record(
                references=[{"url": URL_1, "tags": ["Patch"]}],
                configurations=[_configuration(_node(_SIBLING))],
            )
        )
        page = parse_page(_page())
        cache = build_source_cache(_source_page(_source()))
        selection = select_cpe_matches([_configuration(_node(_SIBLING))])

        with pytest.raises(dataclasses.FrozenInstanceError):
            record.cve_id = "CVE-2026-9999"  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            page.total_results = 2  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            cache.names = {}  # type: ignore[misc]
        with pytest.raises(dataclasses.FrozenInstanceError):
            selection.matches = None  # type: ignore[misc]
        with pytest.raises(ValidationError):
            record.payload.description = "Changed."
        assert isinstance(record.upstream_references, tuple)
        assert isinstance(record.upstream_references[0].upstream_tags, tuple)
        assert isinstance(record.skip_reasons, frozenset)
        assert isinstance(page.vulnerabilities, tuple)
        assert isinstance(selection.matches, tuple)
        assert isinstance(selection.skip_reasons, frozenset)
        assert isinstance(cache.names, MappingProxyType)

    def test_input_element_is_not_mutated(self) -> None:
        element = _record(
            descriptions=[1, _description("en", "Fictional.")],
            metrics={"cvssMetricV31": [_metric(), _metric(CNA_SOURCE, V31_OTHER)]},
            weaknesses=[_weakness("CWE-79", "CWE-79")],
            references=[{"url": URL_1, "tags": ["Patch", 1]}],
            configurations=[_configuration(_node(_SIBLING, 1), negate=None)],
        )
        before = copy.deepcopy(element)

        _map(element)
        select_cpe_matches(element["cve"]["configurations"])

        assert element == before

    def test_live_elements_are_not_mutated(self) -> None:
        names = _live_names()
        for _, element in all_records():
            before = copy.deepcopy(element)

            _map(element, names)

            assert element == before


_MODULE: Final = APP_ROOT / "services" / "tickets" / "nvd_cve_record.py"


class TestModuleBoundary:
    def test_imports_include_no_logging_database_settings_or_io(self) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert forbidden_imports(modules) == set()
        assert not {
            m
            for m in modules
            if m.split(".")[0] in {"structlog", "subprocess", "sys", "io", "asyncio"}
            or m == "app.core.logging"
        }

    def test_application_imports_are_core_payload_cvss_and_reference_input(
        self,
    ) -> None:
        modules = imported_modules(_MODULE, "app.services.tickets")

        assert {m for m in modules if m.startswith("app.")} == {
            "app.core.enums",
            "app.core.external_strings",
            "app.core.identifiers",
            "app.services.cve_ingest",
            "app.services.cvss",
            "app.services.reference_service",
            "app.services.ticket_mutations_errors",
        }

    def test_module_defines_no_coroutine(self) -> None:
        source = _MODULE.read_text(encoding="utf-8")

        assert "async def" not in source
        assert "await " not in source
