"""Contract tests for the anonymous IBS Product repository data.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Download Origin and Repository Paths, HTTP and Redirect Contract, Repomd
Contract, Resource and XML Safety, Updateinfo and Advisory Validation,
Exact Source-Package Match, External Contract Verification Status),
verified against the sanitized live captures described in
`tests/support/ibs_download.py` (docs/conventions.md, External Integration
Contract Verification). Every consumed field is asserted for name,
nesting, cardinality, and format; the documents are read with the
standard-library tree parser because the fixtures are trusted.

Not observable live, and therefore covered by synthetic fixtures in the
boundary tests only: an anonymous HTTP 403, hostile or malformed
documents, every resource ceiling, and duplicate or conflicting advisory
IDs (the specification permits this).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any, Final
from urllib.parse import urlsplit

import pytest

from tests.support.ibs_download import (
    REPOMD_FIXTURES,
    REPOMD_NAMESPACE,
    REPOMD_WITH_UPDATEINFO,
    UPDATEINFO_FIXTURES,
    load_repomd_fixture,
    load_responses,
    load_updateinfo_fixture,
)

pytestmark = pytest.mark.unit

_NS: Final = f"{{{REPOMD_NAMESPACE}}}"
_CONSUMED: Final = (
    "location",
    "checksum",
    "open-checksum",
    "size",
    "open-size",
    "timestamp",
)
_CANONICAL: Final = re.compile(r"0|[1-9][0-9]*")
_SEGMENT: Final = re.compile(r"[A-Za-z0-9._+-]+")
_ADVISORY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,254}")
_SOURCE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}")
_HEX_LENGTH: Final = {"sha256": 64, "sha": 40}
_MEDIA_TYPE: Final = re.compile(r"([^/;\s]+/[^/;\s]+)(;.*)?")


def _base_media_type(value: str) -> str:
    match = _MEDIA_TYPE.fullmatch(value)
    assert match is not None, value
    return match[1].lower()


def _updateinfo_entries(name: str) -> list[ET.Element]:
    root = ET.fromstring(load_repomd_fixture(name))
    return [d for d in root.findall(f"{_NS}data") if d.get("type") == "updateinfo"]


def _entry(name: str) -> ET.Element:
    (entry,) = _updateinfo_entries(name)
    return entry


def _updates(name: str) -> list[ET.Element]:
    return list(ET.fromstring(load_updateinfo_fixture(name)))


def _all_updates() -> list[ET.Element]:
    return [update for name in UPDATEINFO_FIXTURES for update in _updates(name)]


# --- Repomd --------------------------------------------------------------


@pytest.mark.parametrize("name", REPOMD_FIXTURES)
def test_repomd_root_is_repomd_in_exact_namespace(name: str) -> None:
    root = ET.fromstring(load_repomd_fixture(name))
    assert root.tag == f"{_NS}repomd"


@pytest.mark.parametrize("name", REPOMD_WITH_UPDATEINFO)
def test_repomd_updateinfo_entry_has_each_consumed_child_once(name: str) -> None:
    assert len(_updateinfo_entries(name)) == 1
    children = Counter(child.tag for child in _entry(name))
    for field in _CONSUMED:
        assert children[f"{_NS}{field}"] == 1, field


@pytest.mark.parametrize("name", ["espos_no_updateinfo", "source_no_updateinfo"])
def test_repomd_without_updateinfo_entry(name: str) -> None:
    assert _updateinfo_entries(name) == []


@pytest.mark.parametrize("name", REPOMD_WITH_UPDATEINFO)
def test_repomd_checksums_have_supported_algorithm_and_exact_length(name: str) -> None:
    entry = _entry(name)
    for field in ("checksum", "open-checksum"):
        element = entry.find(f"{_NS}{field}")
        assert element is not None
        algorithm = element.get("type")
        assert algorithm in _HEX_LENGTH
        assert element.text is not None
        assert re.fullmatch(rf"[0-9a-fA-F]{{{_HEX_LENGTH[algorithm]}}}", element.text)


def test_repomd_checksum_algorithms_cover_sha256_and_legacy_sha1() -> None:
    algorithms = {
        name: _entry(name).find(f"{_NS}checksum").get("type")  # type: ignore[union-attr]
        for name in REPOMD_WITH_UPDATEINFO
    }
    assert algorithms["legacy_sha1"] == "sha"
    assert algorithms["current"] == "sha256"


@pytest.mark.parametrize("name", REPOMD_WITH_UPDATEINFO)
def test_repomd_sizes_and_timestamp_are_canonical_and_within_limits(name: str) -> None:
    entry = _entry(name)
    values = {}
    for field in ("size", "open-size", "timestamp"):
        text = entry.findtext(f"{_NS}{field}")
        assert text is not None
        assert _CANONICAL.fullmatch(text), field
        values[field] = int(text)
    assert 0 < values["size"] <= 32 * 1024 * 1024
    assert values["open-size"] <= 256 * 1024 * 1024
    assert values["open-size"] <= values["size"] * 100


@pytest.mark.parametrize("name", REPOMD_WITH_UPDATEINFO)
def test_repomd_location_is_a_safe_relative_repodata_path(name: str) -> None:
    location = _entry(name).find(f"{_NS}location")
    assert location is not None
    href = location.get("href")
    assert href is not None
    segments = href.split("/")
    assert segments[0] == "repodata"
    assert len(segments) >= 2
    assert all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments)


@pytest.mark.parametrize("name", REPOMD_FIXTURES)
def test_repomd_fits_the_transfer_and_xml_limits(name: str) -> None:
    content = load_repomd_fixture(name)
    root = ET.fromstring(content)

    def depth(element: ET.Element) -> int:
        return 1 + max((depth(child) for child in element), default=0)

    assert len(content) <= 64 * 1024
    assert depth(root) <= 16
    assert sum(1 for _ in root.iter()) <= 10_000
    assert b"<!DOCTYPE" not in content


# --- HTTP responses ------------------------------------------------------


def _responses() -> dict[str, Any]:
    return load_responses()


@pytest.mark.parametrize("name", REPOMD_FIXTURES)
def test_repomd_response_is_200_with_accepted_media_type(name: str) -> None:
    response = _responses()["repomd"][name]
    assert response["status"] == 200
    assert _base_media_type(response["content_type"]) in {"application/xml", "text/xml"}
    assert "content_encoding" not in response
    (length,) = response["content_length"]
    assert length.isdigit()
    assert int(length) == len(load_repomd_fixture(name))


def test_repomd_media_type_parameter_is_observed() -> None:
    assert _responses()["repomd"]["current"]["content_type"] == (
        'application/xml;name="repomd.xml"'
    )
    assert _responses()["repomd"]["espos_no_updateinfo"]["content_type"] == "text/xml"


@pytest.mark.parametrize("name", ["absent", "non_rpm_ubuntu", "non_rpm_debian"])
def test_absent_and_non_rpm_repositories_return_404(name: str) -> None:
    assert _responses()["repomd"][name]["status"] == 404


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_updateinfo_artifact_is_one_same_path_302_to_dist(name: str) -> None:
    redirect, final = _responses()["artifacts"][f"updateinfo_{name}"]["responses"]
    assert redirect["status"] == 302
    location = urlsplit(redirect["location"])
    assert location.scheme == "https"
    assert location.netloc == "dist.suse.de"
    assert location.path == redirect["url_path"]
    assert not location.query
    assert not location.fragment
    assert final["status"] == 200
    assert final["url_path"] == redirect["url_path"]
    assert _base_media_type(final["content_type"]) == "application/x-gzip"
    assert "content_encoding" not in final


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_downloaded_artifact_matched_repomd_sizes_and_checksums(name: str) -> None:
    artifact = _responses()["artifacts"][f"updateinfo_{name}"]
    verification = artifact["verification"]
    assert verification == {
        **verification,
        "size_matches": True,
        "open_size_matches": True,
        "checksum_matches": True,
        "open_checksum_matches": True,
        "gzip_magic": "1f8b",
    }
    (length,) = artifact["responses"][-1]["content_length"]
    assert int(length) == verification["compressed_bytes"]


def test_small_artifact_is_served_directly_with_media_type_parameter() -> None:
    (response,) = _responses()["artifacts"]["direct_artifact"]["responses"]
    assert response["status"] == 200
    assert _base_media_type(response["content_type"]) == "application/x-gzip"
    assert ";name=" in response["content_type"]


def test_path_changing_redirect_is_recorded() -> None:
    (response,) = _responses()["artifacts"]["path_changing_redirect"]["responses"]
    assert response["status"] == 302
    location = urlsplit(response["location"])
    assert location.netloc == "dist.suse.de"
    assert location.path != response["url_path"]


# --- Updateinfo ----------------------------------------------------------


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_updateinfo_root_is_no_namespace_updates(name: str) -> None:
    root = ET.fromstring(load_updateinfo_fixture(name))
    assert root.tag == "updates"
    assert all(child.tag == "update" for child in root)


def test_every_advisory_has_the_consumed_fields() -> None:
    for update in _all_updates():
        assert update.get("status")
        assert update.get("type")
        ids = update.findall("id")
        assert len(ids) == 1
        assert ids[0].text is not None
        assert _ADVISORY_ID.fullmatch(ids[0].text)
        (issued,) = update.findall("issued")
        assert _CANONICAL.fullmatch(issued.get("date", ""))
        assert len(update.findall("references")) == 1
        (pkglist,) = update.findall("pkglist")
        collections = pkglist.findall("collection")
        assert collections
        assert sum(len(c.findall("package")) for c in collections) >= 1
        for reference in update.iter("reference"):
            assert reference.get("type")
            assert reference.get("id")


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_issued_times_are_not_after_the_metadata_timestamp(name: str) -> None:
    timestamp = int(_entry(name).findtext(f"{_NS}timestamp") or "")
    for update in _updates(name):
        assert int(update.find("issued").get("date")) <= timestamp  # type: ignore[union-attr, arg-type]


def test_source_entries_follow_the_exact_path_contract() -> None:
    sources = [
        package
        for update in _all_updates()
        for package in update.iter("package")
        if package.get("arch") in ("src", "nosrc")
    ]
    assert {package.get("arch") for package in sources} == {"src", "nosrc"}
    for package in sources:
        name, epoch, version, release, arch, src = (
            package.get(key)
            for key in ("name", "epoch", "version", "release", "arch", "src")
        )
        assert all((name, epoch, version, release, arch, src))
        assert name is not None
        assert epoch is not None
        assert _SOURCE_NAME.fullmatch(name)
        assert _CANONICAL.fullmatch(epoch)
        assert src == f"{arch}/{name}-{version}-{release}.{arch}.rpm"


def test_binary_entries_carry_a_binary_architecture() -> None:
    binaries = [
        package
        for update in _all_updates()
        for package in update.iter("package")
        if package.get("arch") not in ("src", "nosrc")
    ]
    assert binaries
    assert {package.get("arch") for package in binaries} <= {
        "x86_64",
        "aarch64",
        "s390x",
        "ppc64le",
        "noarch",
        "i586",
    }


def test_representative_advisory_shapes_are_present() -> None:
    updates = _all_updates()
    kinds = Counter((u.get("type"), u.get("status")) for u in updates)
    assert kinds[("security", "stable")] >= 4
    assert kinds[("security", "retracted")] >= 1

    def cves(update: ET.Element) -> set[str]:
        return {
            r.get("id", "") for r in update.iter("reference") if r.get("type") == "cve"
        }

    def sources(update: ET.Element) -> set[str]:
        return {
            p.get("name", "")
            for p in update.iter("package")
            if p.get("arch") in ("src", "nosrc")
        }

    assert any(u.get("type") != "security" and cves(u) for u in updates)
    assert any(
        u.get("type") != "security" and not list(u.iter("reference")) for u in updates
    )
    assert any(len(sources(u)) > 1 for u in updates)
    security = [u for u in _updates("current") if u.get("type") == "security"]
    shared = Counter(cve for u in security for cve in cves(u))
    assert any(count > 1 for count in shared.values())


def test_issued_dates_are_unix_seconds_without_timezone_text() -> None:
    for update in _all_updates():
        date = update.find("issued").get("date")  # type: ignore[union-attr]
        assert date is not None
        assert date.isascii()
        assert date.isdigit()


# --- Sanitization ---------------------------------------------------------


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_updateinfo_fixtures_carry_only_fictional_free_text(name: str) -> None:
    for update in _updates(name):
        assert update.get("from") == "maintenance@example.invalid"
        assert (update.findtext("title") or "").startswith("Fictional")
        assert update.findtext("description") == "Fictional advisory description."
        for message in update.findall("message"):
            assert (message.text or "").startswith("Fictional")
        for reference in update.iter("reference"):
            assert reference.get("title") == "Fictional reference title"
    assert b"@suse" not in load_updateinfo_fixture(name)
