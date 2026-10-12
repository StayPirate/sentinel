"""Tests for IBS Product repository names, paths, and `repomd.xml`.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Download Origin and Repository Paths > Repository qualification and URL
construction, Artifact location; Repository Traversal ordering within one
tier; Repomd Contract with Checksums; the `repomd.xml` and size rows of
Resource and XML Safety; Snapshot Consistency step 4, the updateinfo
identity tuple) and docs/conventions.md (External String Admissibility:
an inadmissible character in `repomd.xml` is an XML failure of the whole
document).

Every function under test is pure: the live `repomd.xml` captures from
`tests/support/ibs_download.py` and synthetic documents are parsed
in-process, with no network, database, or Redis.
"""

from __future__ import annotations

import dataclasses
import itertools
import xml.etree.ElementTree as ET
from typing import Any, Final

import pytest

from app.services.packages.ibs_repodata import (
    RECOGNIZED_ARCHITECTURES,
    REPOMD_MAX_BYTES,
    REPOMD_MAX_DEPTH,
    REPOMD_MAX_ELEMENTS,
    UPDATEINFO_MAX_COMPRESSED_BYTES,
    UPDATEINFO_MAX_OPEN_BYTES,
    UPDATEINFO_MAX_RATIO,
    RepositoryDataError,
    UpdateinfoIdentity,
    order_tier,
    parse_repomd,
    qualify_repository_name,
    repository_root_url,
    validate_artifact_location,
)
from tests.support.ibs_download import (
    REPOMD_NAMESPACE,
    REPOMD_WITH_UPDATEINFO,
    TEST_BASE_URL,
    Artifact,
    advisory,
    artifact,
    load_repomd_fixture,
    repomd_document,
    updateinfo_data,
    updateinfo_document,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS

pytestmark = pytest.mark.unit

_NS: Final = f"{{{REPOMD_NAMESPACE}}}"
_OTHER_NAMESPACE: Final = "urn:example:other"
_FIELDS: Final = (
    "location",
    "checksum",
    "open-checksum",
    "size",
    "open-size",
    "timestamp",
)
_TEXT_FIELDS: Final = ("checksum", "open-checksum", "size", "open-size", "timestamp")
_NUMERIC_FIELDS: Final = ("size", "open-size", "timestamp")
_HEX64: Final = "0123456789abcdef" * 4
_HEX40: Final = _HEX64[:40]
_INJECT: Final = "QQINJECTQQ"

_ITEM: Final = artifact(
    updateinfo_document(
        advisory("SUSE-EXAMPLE-2024-1", cves=["CVE-2024-0001"], sources=["example"])
    )
)


def _identity(item: Artifact) -> UpdateinfoIdentity:
    return UpdateinfoIdentity(
        location=item.href,
        checksum_type=item.checksum_type,
        checksum=item.checksum,
        open_checksum_type=item.checksum_type,
        open_checksum=item.open_checksum,
        size=len(item.compressed),
        open_size=len(item.open_bytes),
        timestamp=item.timestamp,
    )


def _repomd(
    *,
    overrides: dict[str, str] | None = None,
    omit: tuple[str, ...] = (),
    extra: str = "",
    item: Artifact = _ITEM,
) -> bytes:
    return repomd_document(updateinfo_data(item, overrides=overrides, omit=omit), extra)


def _failure(content: bytes) -> str:
    with pytest.raises(RepositoryDataError) as caught:
        parse_repomd(content)
    return caught.value.category


def _sizes(size: int, open_size: int) -> dict[str, str]:
    return {
        "size": f"<size>{size}</size>",
        "open-size": f"<open-size>{open_size}</open-size>",
    }


# --- Repository qualification -----------------------------------------------


@pytest.mark.parametrize(
    "repo_name",
    [
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64",
        "SUSE:Updates:SLE-Module-Basesystem:15-SP2:x86_64",
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:aarch64",
        "SUSE:Updates:openSUSE-Leap-Micro:5.5",
        "SUSE:Updates:SLE-SERVER:12-SP5-LTSS:x86_64",
        "SUSE:Updates:SLE-Product-HPC:15-SP6-ESPOS:x86_64",
        "SUSE:Updates:MultiLinuxManagerTools:SLE-Micro-5:x86_64",
        "SUSE:Updates:Example+Plus:1.0_beta:s390x",
        "SUSE:Updates:debug:x86_64",
        "SUSE:Updates:src:x86_64",
        "SUSE:Updates:Example:15-SP6:debuginfo",
        "SUSE:Updates:Example:15-SP6:Debug",
        "SUSE:Updates:Debianish:1",
        "SUSE:Updates:xUbuntu:24.04",
        "SUSE:Updates:debian:12",
        "SUSE:Updates:ubuntu-24.04:x86_64",
        "SUSE:Updates:Example-Debian:12",
        "SUSE:Updates:DebianTools:12",
    ],
)
def test_qualify_repository_name_valid_name_returns_segments(repo_name: str) -> None:
    assert qualify_repository_name(repo_name) == tuple(repo_name.split(":"))


@pytest.mark.parametrize(
    "repo_name",
    [
        pytest.param(
            "SUSE:Products:SLE-Module-Basesystem:15-SP6:x86_64", id="products"
        ),
        pytest.param(
            "suse:updates:SLE-Module-Basesystem:15-SP6", id="lowercase-prefix"
        ),
        pytest.param("SUSE:Updates", id="prefix-without-separator"),
        pytest.param("SUSE:Updates:", id="prefix-only"),
        pytest.param("SUSE:UpdatesX:Example:1", id="prefix-extended"),
        pytest.param(":SUSE:Updates:Example:1", id="leading-colon"),
        pytest.param("", id="empty"),
        pytest.param("SUSE:Updates::x86_64", id="empty-segment"),
        pytest.param("SUSE:Updates:Example:15-SP6:", id="trailing-colon"),
        pytest.param("SUSE:Updates:SLE Module:15", id="space"),
        pytest.param("SUSE:Updates:SLE/Module:15", id="slash"),
        pytest.param("SUSE:Updates:SLE%2FModule:15", id="percent"),
        pytest.param("SUSE:Updates:SLE\\Module:15", id="backslash"),
        pytest.param("SUSE:Updates:Example?x:15", id="query"),
        pytest.param("SUSE:Updates:Example#x:15", id="fragment"),
        pytest.param("SUSE:Updates:Exämple:15", id="non-ascii"),
        pytest.param("SUSE:Updates:Example\t:15", id="tab"),
        pytest.param("SUSE:Updates:Example:15\n", id="trailing-newline"),
        pytest.param("SUSE:Updates:Example\x01:15", id="control"),
        pytest.param("SUSE:Updates:Example\x00:15", id="nul"),
        pytest.param(f"SUSE:Updates:Example{chr(0xD800)}:15", id="surrogate"),
        pytest.param("SUSE:Updates:SLE-Module-Basesystem:15-SP6:debug", id="debug"),
        pytest.param("SUSE:Updates:RES:7-LTSS:src", id="src"),
        pytest.param("SUSE:Updates:Debian:12", id="debian"),
        pytest.param("SUSE:Updates:Ubuntu:24.04", id="ubuntu"),
        pytest.param("SUSE:Updates:Debian-12:x86_64", id="debian-prefix"),
        pytest.param("SUSE:Updates:Ubuntu-24.04", id="ubuntu-prefix-terminal"),
        pytest.param(
            "SUSE:Updates:MultiLinuxManagerTools:Debian-12:x86_64", id="mixed-debian"
        ),
        pytest.param(
            "SUSE:Updates:MultiLinuxManagerTools:Ubuntu-24.04:x86_64",
            id="mixed-ubuntu",
        ),
        pytest.param("SUSE:Updates:Example:Debian", id="debian-terminal"),
        pytest.param("SUSE:Updates:Example:Ubuntu:x86_64", id="ubuntu-middle"),
        pytest.param(
            "SUSE:Updates:..:..:SUSE:Products:SLE-Product-SLES:15-SP6:x86_64",
            id="dot-dot-escapes-updates",
        ),
        pytest.param("SUSE:Updates:..:..:..:Example:x86_64", id="dot-dot-escapes-base"),
        pytest.param("SUSE:Updates:Example:..", id="dot-dot-terminal"),
        pytest.param("SUSE:Updates:.:Example:x86_64", id="dot"),
    ],
)
def test_qualify_repository_name_excluded_or_invalid_returns_none(
    repo_name: str,
) -> None:
    assert qualify_repository_name(repo_name) is None


def test_repository_root_url_joins_segments_under_base() -> None:
    segments = qualify_repository_name(
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64"
    )
    assert segments is not None

    assert repository_root_url(TEST_BASE_URL, segments) == (
        "https://download.example.test/ibs/SUSE/Updates/SLE-Module-Basesystem/"
        "15-SP6/x86_64/update"
    )


def test_repository_root_url_suffixless_name() -> None:
    segments = qualify_repository_name("SUSE:Updates:openSUSE-Leap-Micro:5.5")
    assert segments is not None

    assert repository_root_url("https://ibs.example.test:8443/a/b", segments) == (
        "https://ibs.example.test:8443/a/b/SUSE/Updates/openSUSE-Leap-Micro/5.5/update"
    )


# --- Tier ordering ------------------------------------------------------------


def test_recognized_architectures_match_the_specification() -> None:
    assert (
        frozenset(
            {"aarch64", "i586", "i686", "ia64", "ppc64", "ppc64le", "s390x", "x86_64"}
        )
        == RECOGNIZED_ARCHITECTURES
    )


_ORDERED_TIER: Final = [
    # Suffixless or unrecognized terminal segment, lexical.
    "SUSE:Updates:Example:X86_64",
    "SUSE:Updates:Example:armv7l",
    "SUSE:Updates:openSUSE-Leap-Micro:5.5",
    # Terminal x86_64, lexical.
    "SUSE:Updates:Alpha:15-SP6:x86_64",
    "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64",
    # Other architectures, lexical architecture then name.
    "SUSE:Updates:SLE-Module-Basesystem:15-SP6:aarch64",
    "SUSE:Updates:Zeta:15-SP6:aarch64",
    "SUSE:Updates:Zeta:12:i586",
    "SUSE:Updates:Zeta:12:i686",
    "SUSE:Updates:Zeta:11:ia64",
    "SUSE:Updates:SLE-Module-Basesystem:15-SP6:ppc64",
    "SUSE:Updates:SLE-Module-Basesystem:15-SP6:ppc64le",
    "SUSE:Updates:Aaa:1:s390x",
    "SUSE:Updates:SLE-Module-Basesystem:15-SP6:s390x",
]


def test_order_tier_orders_suffixless_then_x86_64_then_other_architectures() -> None:
    assert order_tier(reversed(_ORDERED_TIER)) == _ORDERED_TIER


def test_order_tier_input_order_is_irrelevant() -> None:
    sample = _ORDERED_TIER[1:6]

    for permutation in itertools.permutations(sample):
        assert order_tier(permutation) == sample


def test_order_tier_drops_unqualified_names_and_collapses_duplicates() -> None:
    names = [
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64",
        "SUSE:Products:SLE-Module-Basesystem:15-SP6:x86_64",
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:debug",
        "SUSE:Updates:MultiLinuxManagerTools:Debian-12:x86_64",
        "SUSE:Updates:Bad Name:x86_64",
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64",
        "SUSE:Updates:openSUSE-Leap-Micro:5.5",
        "SUSE:Updates:openSUSE-Leap-Micro:5.5",
    ]

    assert order_tier(names) == [
        "SUSE:Updates:openSUSE-Leap-Micro:5.5",
        "SUSE:Updates:SLE-Module-Basesystem:15-SP6:x86_64",
    ]


def test_order_tier_empty_input_returns_empty_list() -> None:
    assert order_tier([]) == []


# --- Artifact location --------------------------------------------------------


@pytest.mark.parametrize(
    "href",
    [
        "repodata/updateinfo.xml.gz",
        f"repodata/{_HEX64}-updateinfo.xml.gz",
        "repodata/a/b.gz",
        "repodata/x",
        "repodata/a+b_c-d.e",
        "repodata/...",
    ],
)
def test_validate_artifact_location_safe_path_returns_it_unchanged(href: str) -> None:
    assert validate_artifact_location(href) == href


@pytest.mark.parametrize(
    "href",
    [
        pytest.param("https://download.example.test/repodata/x.gz", id="absolute-url"),
        pytest.param("https:repodata/x.gz", id="scheme"),
        pytest.param("//download.example.test/repodata/x.gz", id="authority"),
        pytest.param("/repodata/x.gz", id="leading-slash"),
        pytest.param("repodata", id="no-segment"),
        pytest.param("repodata/", id="empty-segment"),
        pytest.param("repodata//x.gz", id="duplicate-separator"),
        pytest.param("repodata/x.gz/", id="trailing-slash"),
        pytest.param("repodata/./x.gz", id="dot"),
        pytest.param("repodata/../x.gz", id="dot-dot"),
        pytest.param("repodata/a/../../x.gz", id="traversal"),
        pytest.param("repodata/..", id="terminal-dot-dot"),
        pytest.param("repodata/.", id="terminal-dot"),
        pytest.param("./repodata/x.gz", id="leading-dot"),
        pytest.param("repodata\\x.gz", id="backslash-separator"),
        pytest.param("repodata/a\\..\\x.gz", id="backslash"),
        pytest.param("repodata/%2e%2e/x.gz", id="percent-dot"),
        pytest.param("repodata/x%2Egz", id="percent"),
        pytest.param("repodata/x.gz?y=1", id="query"),
        pytest.param("repodata/x.gz#f", id="fragment"),
        pytest.param("repodata/x\x01.gz", id="control"),
        pytest.param("repodata/x.gz\n", id="newline"),
        pytest.param("repodata/x\x00.gz", id="nul"),
        pytest.param(f"repodata/x{chr(0xD800)}.gz", id="surrogate"),
        pytest.param("repodata/x .gz", id="space"),
        pytest.param("repodata/é.gz", id="non-ascii"),
        pytest.param("other/x.gz", id="other-directory"),
        pytest.param("Repodata/x.gz", id="case"),
        pytest.param("repodatax/y.gz", id="prefix-extended"),
        pytest.param("", id="empty"),
    ],
)
def test_validate_artifact_location_unsafe_path_raises_unsafe_path(href: str) -> None:
    with pytest.raises(RepositoryDataError) as caught:
        validate_artifact_location(href)

    assert caught.value.category == "unsafe_path"
    if href:
        assert href not in str(caught.value)


# --- Repomd: live fixtures ----------------------------------------------------


def _fixture_identity(name: str) -> UpdateinfoIdentity:
    root = ET.fromstring(load_repomd_fixture(name))
    (entry,) = [d for d in root.findall(f"{_NS}data") if d.get("type") == "updateinfo"]

    def child(field: str) -> ET.Element:
        element = entry.find(f"{_NS}{field}")
        assert element is not None
        return element

    return UpdateinfoIdentity(
        location=child("location").get("href", ""),
        checksum_type=child("checksum").get("type", ""),
        checksum=(child("checksum").text or "").lower(),
        open_checksum_type=child("open-checksum").get("type", ""),
        open_checksum=(child("open-checksum").text or "").lower(),
        size=int(child("size").text or ""),
        open_size=int(child("open-size").text or ""),
        timestamp=int(child("timestamp").text or ""),
    )


@pytest.mark.parametrize("name", REPOMD_WITH_UPDATEINFO)
def test_parse_repomd_live_fixture_returns_the_declared_identity(name: str) -> None:
    assert parse_repomd(load_repomd_fixture(name)) == _fixture_identity(name)


def test_parse_repomd_current_fixture_returns_exact_values() -> None:
    checksum = "fa618aba4fb91be6c4ba5d732e175f4a89c81af8cd1667e64c167c15540b79c8"

    assert parse_repomd(load_repomd_fixture("current")) == UpdateinfoIdentity(
        location=f"repodata/{checksum}-updateinfo.xml.gz",
        checksum_type="sha256",
        checksum=checksum,
        open_checksum_type="sha256",
        open_checksum="82b369699df98dbd7b10c0bad3502cb299837ba6a39b107df5972ae4882b3bb5",
        size=1130443,
        open_size=6325465,
        timestamp=1782862012,
    )


def test_parse_repomd_legacy_fixture_returns_sha1_identity() -> None:
    identity = parse_repomd(load_repomd_fixture("legacy_sha1"))

    assert identity is not None
    assert identity.location == "repodata/updateinfo.xml.gz"
    assert identity.checksum_type == "sha"
    assert identity.checksum == "0c1480b70894cfdefcbaf26807e3a714494cf75b"
    assert identity.open_checksum_type == "sha"


@pytest.mark.parametrize("name", ["espos_no_updateinfo", "source_no_updateinfo"])
def test_parse_repomd_live_fixture_without_updateinfo_returns_none(name: str) -> None:
    assert parse_repomd(load_repomd_fixture(name)) is None


# --- Repomd: structure and cardinality ---------------------------------------


def test_parse_repomd_valid_entry_returns_identity() -> None:
    assert parse_repomd(_repomd()) == _identity(_ITEM)


def test_parse_repomd_zero_updateinfo_entries_returns_none() -> None:
    assert parse_repomd(repomd_document()) is None


def test_parse_repomd_two_updateinfo_entries_raises_xml_structure() -> None:
    entry = updateinfo_data(_ITEM)
    other = updateinfo_data(artifact(updateinfo_document()))

    assert _failure(repomd_document(entry, entry)) == "xml_structure"
    assert _failure(repomd_document(entry, other)) == "xml_structure"


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(
            repomd_document(updateinfo_data(_ITEM), namespace=_OTHER_NAMESPACE),
            id="other-namespace",
        ),
        pytest.param(
            repomd_document(updateinfo_data(_ITEM), namespace=""), id="no-namespace"
        ),
        pytest.param(
            (
                f'<metadata xmlns="{REPOMD_NAMESPACE}">{updateinfo_data(_ITEM)}'
                "</metadata>"
            ).encode(),
            id="other-local-name",
        ),
        pytest.param(
            (
                f'<Repomd xmlns="{REPOMD_NAMESPACE}">{updateinfo_data(_ITEM)}</Repomd>'
            ).encode(),
            id="local-name-case",
        ),
    ],
)
def test_parse_repomd_wrong_root_raises_xml_structure(content: bytes) -> None:
    assert _failure(content) == "xml_structure"


def test_parse_repomd_prefixed_names_in_exact_namespace_are_accepted() -> None:
    entry = updateinfo_data(_ITEM)
    prefixed = entry.replace("<", "<r:").replace("<r:/", "</r:")
    content = f'<r:repomd xmlns:r="{REPOMD_NAMESPACE}">{prefixed}</r:repomd>'.encode()

    assert parse_repomd(content) == _identity(_ITEM)


def test_parse_repomd_nested_updateinfo_entry_is_ignored() -> None:
    nested = f"<tags>{updateinfo_data(_ITEM)}</tags>"

    assert parse_repomd(repomd_document(nested)) is None


@pytest.mark.parametrize(
    "replacement",
    [
        'type="UpdateInfo"',
        'type="updateinfo "',
        'type="updateinfos"',
        'kind="updateinfo"',
    ],
)
def test_parse_repomd_inexact_updateinfo_type_is_ignored(replacement: str) -> None:
    entry = updateinfo_data(_ITEM).replace('type="updateinfo"', replacement, 1)

    assert parse_repomd(repomd_document(entry)) is None


def test_parse_repomd_data_in_other_namespace_is_ignored() -> None:
    entry = (
        updateinfo_data(_ITEM)
        .replace("<data ", f'<o:data xmlns:o="{_OTHER_NAMESPACE}" ', 1)
        .replace("</data>", "</o:data>")
    )

    assert parse_repomd(repomd_document(entry)) is None


@pytest.mark.parametrize("field", _FIELDS)
def test_parse_repomd_missing_field_raises_xml_structure(field: str) -> None:
    assert _failure(_repomd(omit=(field,))) == "xml_structure"


@pytest.mark.parametrize("field", _FIELDS)
def test_parse_repomd_duplicate_field_raises_xml_structure(field: str) -> None:
    markup = _field_markup(field)

    assert _failure(_repomd(overrides={field: markup * 2})) == "xml_structure"


@pytest.mark.parametrize("field", _FIELDS)
def test_parse_repomd_field_in_other_namespace_counts_as_missing(field: str) -> None:
    markup = _field_markup(field).replace(
        f"<{field}", f'<{field} xmlns="{_OTHER_NAMESPACE}"', 1
    )

    assert _failure(_repomd(overrides={field: markup})) == "xml_structure"


def _field_markup(field: str, item: Artifact = _ITEM) -> str:
    """The markup `updateinfo_data()` renders for `field`."""
    entry = updateinfo_data(item)
    start = entry.index(f"<{field}")
    if field == "location":
        end = entry.index("/>", start) + 2
    else:
        end = entry.index(f"</{field}>", start) + len(f"</{field}>")
    return entry[start:end]


def test_parse_repomd_unknown_elements_and_attributes_are_ignored() -> None:
    overrides = {
        "location": f'<location href="{_ITEM.href}" extra="ignored"/>',
        "size": f'<size unit="bytes">{len(_ITEM.compressed)}</size>',
    }
    extra_children = (
        f'<header-checksum type="sha256">{_HEX64}</header-checksum>'
        "<database_version>10</database_version>"
        f'<o:size xmlns:o="{_OTHER_NAMESPACE}">999</o:size>'
        "<group><size>999</size><timestamp>1</timestamp></group>"
    )
    entry = (
        updateinfo_data(_ITEM, overrides=overrides)
        .replace('<data type="updateinfo">', '<data type="updateinfo" extra="1">', 1)
        .replace("</data>", f"{extra_children}</data>")
    )

    assert parse_repomd(repomd_document(entry, "<unknown><data/></unknown>")) == (
        _identity(_ITEM)
    )


# --- Repomd: checksums --------------------------------------------------------


@pytest.mark.parametrize(
    ("algorithm", "value"),
    [
        ("sha256", _HEX64),
        ("sha256", _HEX64.upper()),
        ("sha256", _HEX64[:32].upper() + _HEX64[32:]),
        ("sha", _HEX40),
        ("sha", _HEX40.upper()),
    ],
)
@pytest.mark.parametrize("field", ["checksum", "open-checksum"])
def test_parse_repomd_supported_checksum_is_accepted_lowercased(
    algorithm: str, value: str, field: str
) -> None:
    markup = f'<{field} type="{algorithm}">{value}</{field}>'

    identity = parse_repomd(_repomd(overrides={field: markup}))

    assert identity is not None
    if field == "checksum":
        assert (identity.checksum_type, identity.checksum) == (algorithm, value.lower())
    else:
        assert (identity.open_checksum_type, identity.open_checksum) == (
            algorithm,
            value.lower(),
        )


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        pytest.param('type="md5"', _HEX64[:32], id="md5"),
        pytest.param('type="sha1"', _HEX40, id="sha1-name"),
        pytest.param('type="SHA256"', _HEX64, id="uppercase-name"),
        pytest.param('type="Sha"', _HEX40, id="mixed-case-sha"),
        pytest.param('type="sha512"', _HEX64 * 2, id="sha512"),
        pytest.param('type=" sha256"', _HEX64, id="padded-name"),
        pytest.param("", _HEX64, id="missing-type"),
        pytest.param('type=""', _HEX64, id="empty-type"),
        pytest.param('type="sha256"', _HEX64[:63], id="short"),
        pytest.param('type="sha256"', _HEX64 + "0", id="long"),
        pytest.param('type="sha256"', _HEX40, id="sha1-length-for-sha256"),
        pytest.param('type="sha"', _HEX64, id="sha256-length-for-sha"),
        pytest.param('type="sha256"', "g" + _HEX64[1:], id="non-hex"),
        pytest.param('type="sha256"', "0x" + _HEX64[2:], id="hex-prefix"),
        pytest.param('type="sha256"', f" {_HEX64}", id="leading-space"),
        pytest.param('type="sha256"', f"{_HEX64}\n", id="trailing-newline"),
        pytest.param('type="sha256"', f" {_HEX64[1:]}", id="space-inside-length"),
        pytest.param('type="sha256"', "", id="empty-value"),
        pytest.param('type="sha256"', "\u0660" * 64, id="non-ascii-digits"),
    ],
)
@pytest.mark.parametrize("field", ["checksum", "open-checksum"])
def test_parse_repomd_invalid_checksum_raises_checksum(
    attribute: str, value: str, field: str
) -> None:
    markup = f"<{field} {attribute}>{value}</{field}>"

    assert _failure(_repomd(overrides={field: markup})) == "checksum"


# --- Repomd: sizes and timestamp ------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("010", id="leading-zero"),
        pytest.param("00", id="double-zero"),
        pytest.param("+10", id="plus"),
        pytest.param("-10", id="minus"),
        pytest.param("1.0", id="fraction"),
        pytest.param("1e3", id="exponent"),
        pytest.param("0x10", id="hexadecimal"),
        pytest.param(" 10", id="leading-space"),
        pytest.param("10 ", id="trailing-space"),
        pytest.param("10\n", id="trailing-newline"),
        pytest.param("1 0", id="inner-space"),
        pytest.param("", id="empty"),
        pytest.param("\u0661\u0660", id="arabic-indic-digits"),
        pytest.param("\uff11\uff10", id="fullwidth-digits"),
    ],
)
@pytest.mark.parametrize("field", _NUMERIC_FIELDS)
def test_parse_repomd_non_canonical_number_raises_xml_structure(
    value: str, field: str
) -> None:
    markup = f"<{field}>{value}</{field}>"

    assert _failure(_repomd(overrides={field: markup})) == "xml_structure"


def test_parse_repomd_zero_timestamp_is_accepted() -> None:
    identity = parse_repomd(
        _repomd(overrides={"timestamp": "<timestamp>0</timestamp>"})
    )

    assert identity is not None
    assert identity.timestamp == 0


def test_parse_repomd_zero_compressed_size_raises_size() -> None:
    assert _failure(_repomd(overrides=_sizes(0, 0))) == "size"


@pytest.mark.parametrize(
    ("size", "open_size"),
    [
        pytest.param(UPDATEINFO_MAX_COMPRESSED_BYTES, 1, id="compressed-at-limit"),
        pytest.param(
            UPDATEINFO_MAX_COMPRESSED_BYTES,
            UPDATEINFO_MAX_OPEN_BYTES,
            id="open-at-limit",
        ),
        pytest.param(1000, 1000 * UPDATEINFO_MAX_RATIO, id="ratio-at-limit"),
    ],
)
def test_parse_repomd_sizes_at_limits_are_accepted(size: int, open_size: int) -> None:
    identity = parse_repomd(_repomd(overrides=_sizes(size, open_size)))

    assert identity is not None
    assert (identity.size, identity.open_size) == (size, open_size)


@pytest.mark.parametrize(
    ("size", "open_size"),
    [
        pytest.param(UPDATEINFO_MAX_COMPRESSED_BYTES + 1, 1, id="compressed-over"),
        pytest.param(
            UPDATEINFO_MAX_COMPRESSED_BYTES,
            UPDATEINFO_MAX_OPEN_BYTES + 1,
            id="open-over",
        ),
        pytest.param(1000, 1000 * UPDATEINFO_MAX_RATIO + 1, id="ratio-over"),
        pytest.param(1, 101, id="ratio-over-small"),
    ],
)
def test_parse_repomd_sizes_over_limits_raise_resource_limit(
    size: int, open_size: int
) -> None:
    assert _failure(_repomd(overrides=_sizes(size, open_size))) == "resource_limit"


def test_resource_limit_constants_match_the_specification() -> None:
    assert UPDATEINFO_MAX_COMPRESSED_BYTES == 32 * 1024 * 1024
    assert UPDATEINFO_MAX_OPEN_BYTES == 256 * 1024 * 1024
    assert UPDATEINFO_MAX_RATIO == 100
    assert REPOMD_MAX_BYTES == 64 * 1024
    assert REPOMD_MAX_DEPTH == 16
    assert REPOMD_MAX_ELEMENTS == 10_000


@pytest.mark.parametrize("field", _TEXT_FIELDS)
def test_parse_repomd_text_field_with_child_element_raises_xml_structure(
    field: str,
) -> None:
    markup = _field_markup(field)
    split = markup.index(">") + 2
    nested = f"{markup[:split]}<x/>{markup[split:]}"

    assert _failure(_repomd(overrides={field: nested})) == "xml_structure"


@pytest.mark.parametrize("field", _TEXT_FIELDS)
def test_parse_repomd_overlong_field_text_raises_xml_structure(field: str) -> None:
    # Consumed text is bounded while parsing (128 characters), far above
    # every valid value: the longest is a 64-digit SHA-256 checksum.
    markup = _field_markup(field)
    start = markup.index(">") + 1
    overlong = f"{markup[:start]}{'0' * 129}{markup[markup.index('</') :]}"

    assert _failure(_repomd(overrides={field: overlong})) == "xml_structure"


@pytest.mark.parametrize(
    "location",
    [
        pytest.param('<location href="https://example.test/repodata/x.gz"/>', id="url"),
        pytest.param('<location href="repodata/../x.gz"/>', id="traversal"),
        pytest.param('<location href="/repodata/x.gz"/>', id="leading-slash"),
        pytest.param('<location href=""/>', id="empty-href"),
        pytest.param("<location/>", id="missing-href"),
        pytest.param(
            f'<location xmlns:o="{_OTHER_NAMESPACE}" o:href="{_ITEM.href}"/>',
            id="namespaced-href",
        ),
    ],
)
def test_parse_repomd_unsafe_location_raises_unsafe_path(location: str) -> None:
    assert _failure(_repomd(overrides={"location": location})) == "unsafe_path"


# --- Repomd: XML safety -----------------------------------------------------


def test_parse_repomd_doctype_raises_xml_structure() -> None:
    content = _repomd().replace(b"<repomd", b"<!DOCTYPE repomd><repomd", 1)

    assert _failure(content) == "xml_structure"


def test_parse_repomd_entity_declaration_raises_xml_structure() -> None:
    content = _repomd().replace(
        b"<repomd", b'<!DOCTYPE repomd [<!ENTITY e "x">]><repomd', 1
    )

    assert _failure(content) == "xml_structure"


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(_repomd()[:-20], id="truncated"),
        pytest.param(_repomd() + b"<repomd/>", id="second-root"),
        pytest.param(_repomd().replace(b"</data>", b"</date>", 1), id="mismatched"),
        pytest.param(b"", id="empty"),
    ],
)
def test_parse_repomd_malformed_document_raises_xml_structure(content: bytes) -> None:
    assert _failure(content) == "xml_structure"


def test_parse_repomd_depth_at_limit_is_accepted() -> None:
    # The root is depth 1; the nested elements are its descendants.
    depth = REPOMD_MAX_DEPTH - 1

    content = _repomd(extra="<x>" * depth + "</x>" * depth)

    assert parse_repomd(content) == _identity(_ITEM)


def test_parse_repomd_depth_over_limit_raises_resource_limit() -> None:
    depth = REPOMD_MAX_DEPTH

    content = _repomd(extra="<x>" * depth + "</x>" * depth)

    assert _failure(content) == "resource_limit"


def test_parse_repomd_element_count_at_limit_is_accepted() -> None:
    base = sum(1 for _ in ET.fromstring(_repomd()).iter())

    content = _repomd(extra="<x/>" * (REPOMD_MAX_ELEMENTS - base))

    assert parse_repomd(content) == _identity(_ITEM)


def test_parse_repomd_element_count_over_limit_raises_resource_limit() -> None:
    base = sum(1 for _ in ET.fromstring(_repomd()).iter())

    content = _repomd(extra="<x/>" * (REPOMD_MAX_ELEMENTS - base + 1))

    assert _failure(content) == "resource_limit"


_INJECTION_SITES: Final[dict[str, tuple[dict[str, str], str]]] = {
    "unknown-text": ({}, f"<note>a{_INJECT}b</note>"),
    "location-href": (
        {"location": f'<location href="repodata/a{_INJECT}b.xml.gz"/>'},
        "",
    ),
    "checksum-text": (
        {
            "checksum": f'<checksum type="sha256">{_HEX64[:32]}{_INJECT}'
            f"{_HEX64[32:]}</checksum>"
        },
        "",
    ),
    "size-text": ({"size": f"<size>1{_INJECT}0</size>"}, ""),
    "timestamp-text": ({"timestamp": f"<timestamp>1{_INJECT}</timestamp>"}, ""),
}


@pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
@pytest.mark.parametrize("encoding", ["raw", "reference"])
@pytest.mark.parametrize("site", sorted(_INJECTION_SITES))
def test_parse_repomd_inadmissible_character_raises_xml_structure(
    character: str, encoding: str, site: str
) -> None:
    overrides, extra = _INJECTION_SITES[site]
    template = _repomd(overrides=overrides, extra=extra)
    injected = (
        character.encode("utf-8", "surrogatepass")
        if encoding == "raw"
        else f"&#x{ord(character):X};".encode()
    )

    content = template.replace(_INJECT.encode(), injected)

    assert _INJECT.encode() not in content
    assert _failure(content) == "xml_structure"


def test_parse_repomd_data_type_with_inadmissible_reference_raises_xml_structure() -> (
    None
):
    content = _repomd().replace(
        b'<data type="updateinfo">', b'<data type="updateinfo&#0;">', 1
    )

    assert _failure(content) == "xml_structure"


# --- Identity equality --------------------------------------------------------


def test_identity_same_document_parsed_twice_is_equal() -> None:
    first = parse_repomd(_repomd())
    second = parse_repomd(_repomd())

    assert first == second
    assert hash(first) == hash(second)


def test_identity_checksum_case_does_not_change_equality() -> None:
    upper = {
        "checksum": f'<checksum type="sha256">{_ITEM.checksum.upper()}</checksum>',
        "open-checksum": (
            f'<open-checksum type="sha256">{_ITEM.open_checksum.upper()}'
            "</open-checksum>"
        ),
    }

    assert parse_repomd(_repomd(overrides=upper)) == parse_repomd(_repomd())


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param(
            {"location": '<location href="repodata/other-updateinfo.xml.gz"/>'},
            id="location",
        ),
        pytest.param(
            {"checksum": f'<checksum type="sha256">{_HEX64}</checksum>'}, id="checksum"
        ),
        pytest.param(
            {"checksum": f'<checksum type="sha">{_HEX40}</checksum>'},
            id="checksum-type",
        ),
        pytest.param(
            {"open-checksum": f'<open-checksum type="sha256">{_HEX64}</open-checksum>'},
            id="open-checksum",
        ),
        pytest.param(
            {"open-checksum": f'<open-checksum type="sha">{_HEX40}</open-checksum>'},
            id="open-checksum-type",
        ),
        pytest.param(
            _sizes(len(_ITEM.compressed) + 1, len(_ITEM.open_bytes)), id="size"
        ),
        pytest.param(
            _sizes(len(_ITEM.compressed), len(_ITEM.open_bytes) + 1), id="open-size"
        ),
        pytest.param(
            {"timestamp": f"<timestamp>{_ITEM.timestamp + 1}</timestamp>"},
            id="timestamp",
        ),
    ],
)
def test_identity_any_differing_field_is_unequal(overrides: dict[str, str]) -> None:
    changed = parse_repomd(_repomd(overrides=overrides))

    assert changed is not None
    assert changed != parse_repomd(_repomd())


@pytest.mark.parametrize(
    "field", [field.name for field in dataclasses.fields(UpdateinfoIdentity)]
)
def test_identity_each_tuple_field_takes_part_in_equality(field: str) -> None:
    identity = _identity(_ITEM)
    values: dict[str, Any] = dataclasses.asdict(identity)
    current = values[field]
    values[field] = current + 1 if isinstance(current, int) else f"{current}x"

    assert UpdateinfoIdentity(**values) != identity
