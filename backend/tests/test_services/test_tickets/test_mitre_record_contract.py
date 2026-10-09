"""Contract tests for the MITRE `cvelistV5` source facts.

Contract under test: docs/features/tickets/cve-sync-mitre.md (Algorithm
step 1 file filtering, Global CVE fields, CNA container fields and the CNA
defensive guard, ADP container fields and the ADP defensive guard,
CISA-ADP specific fields, SSVC and KEV extraction, `fetch_single()`
Behavior: single candidate) and docs/features/tickets/cve-service.md
(RESERVED CVEs), verified against the sanitized live capture documented in
`tests/support/mitre.py`.

Only source-specific facts are asserted here. The CVE Record 5.x field
shapes (types, nullability, bounds, U+0000) are owned by
`tests/test_services/test_cve_record_contract.py`; its strict typed model and
consumed-string inventory are applied to the records added here, and its own
assertions already cover the parser's `cvelistv5_*` fixtures.

Facts recorded in `tests/support/mitre.py` rather than asserted from a
fixture: the default branch (`main`), the byte identity of the release
asset with the tagged tree, the record counts and frequencies of the full
scan (no RESERVED record, no `PUBLISHED` record with `dateRejected`, 12
records without a CNA `shortName`, no duplicate ADP scope, no second
CISA-ADP container, no second SSVC or KEV entry, every non-`x_` tag mapped),
and the source reference URL form. Not observable live, and therefore
covered by the mapping unit tests only: a RESERVED or unrecognized state, a
`PUBLISHED` record with `dateRejected`, a `null` or mistyped global, an ADP
without `providerMetadata` or `shortName`, two ADPs resolving to one scope,
two CISA-ADP containers, an incomplete or invalid SSVC, a non-object
reference element, U+0000 in any string, and undecodable content.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import pytest

import tests.test_services.test_cve_record_contract as record_contract
from app.services.cvss import is_reserved_provider_name
from tests.support.mitre import (
    ADP_IDENTITIES,
    ALL_RECORDS,
    CISA_ADP_ORG_ID,
    RECORD_SOURCES,
    load_raw_record,
    load_record,
    record_path,
    repository_paths,
)

pytestmark = pytest.mark.unit

_RECORD_PATH = re.compile(
    r"cves/(?P<year>[0-9]{4})/(?P<bucket>[0-9]+)xxx/"
    r"CVE-(?P<cve_year>[0-9]{4})-(?P<seq>[0-9]{4,})\.json"
)
"""cve-sync-mitre.md Algorithm step 1 (test-local; independent of the
production pattern)."""

_METADATA_FILES = frozenset({"cves/delta.json", "cves/deltaLog.json"})
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_MITRE_TAGS = frozenset(
    {
        "patch",
        "vendor-advisory",
        "third-party-advisory",
        "government-resource",
        "vdb-entry",
        "issue-tracking",
        "exploit",
        "mailing-list",
        "release-notes",
        "technical-description",
        "mitigation",
        "media-coverage",
        "signature",
        "broken-link",
        "not-applicable",
        "permissions-required",
        "product",
        "customer-entitlement",
        "related",
    }
)
"""The MITRE column of ticket-references.md § CVE Source Tag Mapping."""

_WITHOUT_SHORT_NAME = "cna_short_name_missing"
_SUSE_CNA = "cna_suse_reserved_provider"
_CNA_SSVC = "cna_ssvc_not_consumed"
_SSVC_POINTS = frozenset({"Exploitation", "Automatable", "Technical Impact"})
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_REMOVED_MEMBERS = frozenset(
    {"credits", "datePublic", "impacts", "source", "timeline", "x_generator"}
)
_KEPT_ADP_TITLES = frozenset({"CISA ADP Vulnrichment", "CVE Program Container"})
_FICTIONAL_UPSTREAM = re.compile(r"https://advisory\.example\.invalid/upstream/[0-9]+")
_KEPT_HOSTS = frozenset(
    {
        "bugzilla.suse.com",
        "cert-portal.siemens.com",
        "npmjs.com",
        "security.gentoo.org",
        "www.cisa.gov",
        "www.cve.org",
        "www.oracle.com",
        "www.veeam.com",
    }
)
"""Organisation, vendor, project, and advisory-database hosts whose URLs are
retained."""
_KEPT_PATH_OWNERS = {
    "gitee.com": "openharmony",
    "github.com": "browserify",
    "raw.githubusercontent.com": "cisagov",
}
"""Code-hosting hosts → the project organisation whose URLs are retained."""
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _cna(name: str) -> dict[str, Any]:
    cna: dict[str, Any] = load_record(name)["containers"]["cna"]
    return cna


def _adps(name: str) -> list[dict[str, Any]]:
    adps: list[dict[str, Any]] = load_record(name)["containers"].get("adp", [])
    return adps


def _cisa_adps(name: str) -> list[dict[str, Any]]:
    return [a for a in _adps(name) if a["providerMetadata"]["orgId"] == CISA_ADP_ORG_ID]


def _other(container: dict[str, Any], type_: str) -> list[dict[str, Any]]:
    return [
        m["other"]
        for m in container.get("metrics", [])
        if "other" in m and m["other"]["type"] == type_
    ]


def _cna_tags(name: str) -> list[str]:
    return [t for r in _cna(name).get("references", []) for t in r.get("tags", [])]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for key, item in value.items() for s in (key, *_strings(item))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRepositoryLayout:
    def test_only_the_two_metadata_files_under_cves_fail_the_pattern(self) -> None:
        under_cves = [p for p in repository_paths() if p.startswith("cves/")]

        assert {p for p in under_cves if not _RECORD_PATH.fullmatch(p)} == (
            _METADATA_FILES
        )

    def test_repository_files_outside_cves_exist(self) -> None:
        outside = [p for p in repository_paths() if not p.startswith("cves/")]

        assert {"README.md", ".github/workflows/baseline.yml"} <= set(outside)
        assert not [p for p in outside if _RECORD_PATH.fullmatch(p)]

    @pytest.mark.parametrize(
        "path",
        [
            *(p for p in repository_paths() if _RECORD_PATH.fullmatch(p)),
            *(record_path(n) for n in ALL_RECORDS),
        ],
    )
    def test_bucket_is_seq_div_1000_and_year_is_the_cve_id_year(
        self, path: str
    ) -> None:
        match = _RECORD_PATH.fullmatch(path)

        assert match is not None
        assert int(match["bucket"]) == int(match["seq"]) // 1000
        assert match["year"] == match["cve_year"]

    def test_four_to_seven_digit_sequences_are_sampled(self) -> None:
        lengths = {
            len(m["seq"])
            for p in repository_paths()
            if (m := _RECORD_PATH.fullmatch(p)) is not None
        }

        assert lengths == {4, 5, 6, 7}


class TestTypedRecord:
    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_consumed_fields_validate_strictly_without_coercion(
        self, name: str
    ) -> None:
        raw = load_record(name)

        dumped = record_contract._Record.model_validate(raw).model_dump(
            by_alias=True, exclude_unset=True
        )

        assert dumped == record_contract._project(raw, dumped)

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_every_consumed_string_is_nul_free_and_within_its_bound(
        self, name: str
    ) -> None:
        record = record_contract._Record.model_validate(load_record(name))

        for label, value, bound in record_contract._consumed_strings(record):
            assert "\x00" not in value, label
            assert bound is None or len(value) <= bound, label


class TestMetadata:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_json_cve_id_matches_the_file_name(self, name: str) -> None:
        cve_id = load_record(name)["cveMetadata"]["cveId"]

        assert cve_id == PurePosixPath(record_path(name)).stem

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_state_is_published_or_rejected(self, name: str) -> None:
        assert load_record(name)["cveMetadata"]["state"] in {"PUBLISHED", "REJECTED"}

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_published_record_has_no_date_rejected(self, name: str) -> None:
        metadata = load_record(name)["cveMetadata"]

        if metadata["state"] == "PUBLISHED":
            assert "dateRejected" not in metadata


class TestCnaProvider:
    def test_cna_without_short_name_has_a_uuid_org_id_and_guarded_data(
        self,
    ) -> None:
        cna = _cna(_WITHOUT_SHORT_NAME)

        assert "shortName" not in cna["providerMetadata"]
        assert _UUID.fullmatch(cna["providerMetadata"]["orgId"])
        # The data the guard skips is present: a vector and a CWE.
        assert cna["metrics"][0]["cvssV3_1"]["vectorString"]
        assert cna["problemTypes"][0]["descriptions"][0]["cweId"] == "CWE-120"

    def test_suse_cna_short_name_is_the_reserved_provider(self) -> None:
        cna = _cna(_SUSE_CNA)

        assert cna["providerMetadata"]["shortName"] == "suse"
        assert is_reserved_provider_name(cna["providerMetadata"]["shortName"])
        assert cna["metrics"][0]["cvssV3_1"]["vectorString"]
        assert cna["problemTypes"][0]["descriptions"][0]["cweId"]

    @pytest.mark.parametrize(
        "name", [n for n in ALL_RECORDS if n != _WITHOUT_SHORT_NAME]
    )
    def test_cna_short_name_is_a_trimmed_non_empty_string(self, name: str) -> None:
        short_name = _cna(name)["providerMetadata"]["shortName"]

        assert isinstance(short_name, str)
        assert short_name
        assert short_name == short_name.strip()
        assert not short_name.startswith("adp:")


class TestAdp:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_adp_identity_is_one_of_the_observed_pairs(self, name: str) -> None:
        for adp in _adps(name):
            metadata = adp["providerMetadata"]

            assert ADP_IDENTITIES[metadata["shortName"]] == metadata["orgId"]

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_no_two_adps_resolve_to_one_scope(self, name: str) -> None:
        names = Counter(a["providerMetadata"]["shortName"] for a in _adps(name))

        assert all(count == 1 for count in names.values())
        assert len(_cisa_adps(name)) <= 1

    def test_cisa_org_id_carries_the_cisa_adp_short_name(self) -> None:
        cisa = [a for n in ALL_RECORDS for a in _cisa_adps(n)]

        assert cisa
        assert {a["providerMetadata"]["shortName"] for a in cisa} == {"CISA-ADP"}

    def test_adp_affected_arrays_are_captured(self) -> None:
        with_affected = {
            a["providerMetadata"]["shortName"]
            for n in ALL_RECORDS
            for a in _adps(n)
            if isinstance(a.get("affected"), list)
        }

        assert {"CISA-ADP", "siemens-SADP", "redhat-SADP"} <= with_affected


class TestCisaAdp:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_ssvc_and_kev_occur_only_in_cisa_adp_among_adps(self, name: str) -> None:
        for adp in _adps(name):
            if adp["providerMetadata"]["orgId"] != CISA_ADP_ORG_ID:
                assert not _other(adp, "ssvc")
                assert not _other(adp, "kev")

    def test_cna_ssvc_entry_without_cisa_adp_is_captured(self) -> None:
        assert _other(_cna(_CNA_SSVC), "ssvc")
        assert _adps(_CNA_SSVC) == []

    @pytest.mark.parametrize("name", [n for n in RECORD_SOURCES if _cisa_adps(n)])
    def test_cisa_ssvc_is_one_entry_of_three_single_key_options(
        self, name: str
    ) -> None:
        (cisa,) = _cisa_adps(name)
        (ssvc,) = _other(cisa, "ssvc")
        options = ssvc["content"]["options"]

        assert all(isinstance(o, dict) and len(o) == 1 for o in options)
        assert {k for o in options for k in o} == _SSVC_POINTS
        assert ssvc["content"]["version"] == "2.0.3"
        assert len(_other(cisa, "kev")) <= 1

    def test_kev_is_a_date_and_a_reference_string(self) -> None:
        (cisa,) = _cisa_adps("cisa_kev_cwe_tags")
        (kev,) = _other(cisa, "kev")

        assert _DATE.fullmatch(kev["content"]["dateAdded"])
        assert isinstance(kev["content"]["reference"], str)

    def test_cisa_adp_cwe_is_captured(self) -> None:
        (cisa,) = _cisa_adps("cisa_adp_affected")

        assert cisa["problemTypes"][0]["descriptions"][0]["cweId"] == "CWE-284"

    def test_cisa_adp_cwe_type_without_cwe_id_is_captured(self) -> None:
        (cisa,) = _cisa_adps("cisa_kev_cwe_tags")
        (description,) = cisa["problemTypes"][0]["descriptions"]

        assert description["type"] == "CWE"
        assert "cweId" not in description
        assert description["description"].startswith("CWE-noinfo")


class TestReferences:
    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_cna_reference_is_an_object_with_a_url_and_string_tags(
        self, name: str
    ) -> None:
        for reference in _cna(name).get("references", []):
            assert isinstance(reference, dict)
            assert isinstance(reference["url"], str)
            tags = reference.get("tags", [])
            assert isinstance(tags, list)
            assert all(isinstance(t, str) for t in tags)

    @pytest.mark.parametrize("name", ALL_RECORDS)
    def test_every_non_x_tag_is_in_the_source_tag_mapping(self, name: str) -> None:
        for tag in _cna_tags(name):
            assert tag.startswith("x_") or tag in _MITRE_TAGS, tag

    def test_mapped_and_unknown_tags_are_captured(self) -> None:
        tags = set(_cna_tags("references_x_tags"))

        assert {"patch", "third-party-advisory"} <= tags
        assert any(t.startswith("x_") for t in tags)


class TestSanitization:
    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_fixture_retains_no_email(self, name: str) -> None:
        assert _EMAIL.search(load_raw_record(name)) is None

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_free_text_is_fictional(self, name: str) -> None:
        record = load_record(name)
        cve_id = record["cveMetadata"]["cveId"]
        containers = [record["containers"]["cna"], *_adps(name)]

        for container in containers:
            assert not _REMOVED_MEMBERS & container.keys()
            title = container.get("title")
            assert title in (None, f"example: fictional title of {cve_id}") or (
                title in _KEPT_ADP_TITLES
            )
            for description in container.get("descriptions", []):
                assert description["value"] == (
                    f"example: fictional description of {cve_id}."
                )
            for metric in container.get("metrics", []):
                for scenario in metric.get("scenarios", []):
                    assert scenario["value"] in {"GENERAL", "Fictional scenario."}

    @pytest.mark.parametrize("name", list(RECORD_SOURCES))
    def test_urls_are_kept_organisation_locations_or_fictional(self, name: str) -> None:
        urls = [
            s
            for s in _strings(load_record(name))
            if s.startswith(("http://", "https://"))
        ]

        for url in urls:
            parts = urlsplit(url)
            host = parts.hostname or ""
            if host == "advisory.example.invalid":
                assert _FICTIONAL_UPSTREAM.fullmatch(url), url
            elif host in _KEPT_PATH_OWNERS:
                owner = parts.path.split("/")[1]
                assert owner == _KEPT_PATH_OWNERS[host], url
            else:
                assert host in _KEPT_HOSTS, url
