"""Tests for the incremental `updateinfo.xml` validation and matching.

Contract under test: docs/features/packages/ibs-product-release-detection.md
(Source Authority conditions 2-6; Updateinfo and Advisory Validation with
Issued time; Exact Source-Package Match; the updateinfo rows of Resource
and XML Safety; Testing Requirements for advisory shapes, issued seconds,
source entries, and matching) and docs/conventions.md (External String
Admissibility: an inadmissible character in a consumed updateinfo string
is an XML failure of the whole document, so no advisory is returned).

A document-level failure raises `RepositoryDataError`; a malformed stable
security advisory is ignored as a whole and counted once per distinct ID,
while every other advisory is never authoritative and never counted.

The live updateinfo captures from `tests/support/ibs_download.py` and
synthetic documents are parsed in-process, with no network, database, or
Redis.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from xml.sax.saxutils import quoteattr

import pytest

from app.services.packages.ibs_repodata import RepositoryDataError, parse_repomd
from app.services.packages.ibs_updateinfo import (
    MAX_UTC_SECONDS,
    UPDATEINFO_MAX_DEPTH,
    UPDATEINFO_MAX_ELEMENTS,
    UPDATEINFO_MAX_PACKAGES,
    UPDATEINFO_MAX_UPDATES,
    SecurityAdvisory,
    UpdateinfoParser,
    UpdateinfoSnapshot,
)
from tests.support.ibs_download import (
    UPDATEINFO_FIXTURES,
    advisory,
    binary_package,
    load_repomd_fixture,
    load_updateinfo_fixture,
    source_package,
    updateinfo_document,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS

pytestmark = pytest.mark.unit

_TIMESTAMP = 1_782_862_012
_TARGET_ID = "SUSE-TARGET-2024-1"
_TARGET_CVE = "CVE-2024-0001"
_SIBLING_ID = "SUSE-SIBLING-2024-1"
_SIBLING = advisory(_SIBLING_ID, cves=["CVE-2024-0002"], sources=["sibling"])
_INJECT = "QQINJECTQQ"
_CVE_REFERENCE = (
    f'<reference href="https://cve.example.test/x" id="{_TARGET_CVE}" type="cve"/>'
)


def _parse(
    document: bytes,
    *,
    metadata_timestamp: int = _TIMESTAMP,
    cve_filter: list[str] | None = None,
) -> UpdateinfoSnapshot:
    parser = UpdateinfoParser(
        metadata_timestamp=metadata_timestamp, cve_filter=cve_filter
    )
    parser.feed(document)
    return parser.close()


def _ids(snapshot: UpdateinfoSnapshot) -> set[str]:
    return {item.advisory_id for item in snapshot.advisories}


def _failure(document: bytes) -> str:
    with pytest.raises(RepositoryDataError) as caught:
        _parse(document)
    return caught.value.category


def _target(**kwargs: str) -> str:
    """The target advisory: one CVE, source `example`, binary `example-tools`."""
    return advisory(_TARGET_ID, cves=[_TARGET_CVE], sources=["example"], **kwargs)


def _target_with(
    *, references: list[str] | None = None, packages: list[str] | None = None
) -> str:
    return advisory(
        _TARGET_ID,
        cves=[_TARGET_CVE],
        sources=["example"],
        references=references,
        packages=packages,
    )


def _package(**overrides: str | None) -> str:
    """A `package` element; `None` omits an attribute."""
    attributes: dict[str, str | None] = {
        "name": "example",
        "epoch": "0",
        "version": "1.0",
        "release": "1.1",
        "arch": "src",
        "src": "src/example-1.0-1.1.src.rpm",
    }
    attributes.update(overrides)
    rendered = " ".join(
        f"{key}={quoteattr(value)}"
        for key, value in attributes.items()
        if value is not None
    )
    return f"<package {rendered}/>"


def _with_id(markup: str) -> str:
    return _target().replace(f"<id>{_TARGET_ID}</id>", markup, 1)


def _without(pattern: str) -> str:
    return re.sub(pattern, "", _target(), count=1, flags=re.DOTALL)


def _assert_malformed(update: str) -> None:
    snapshot = _parse(updateinfo_document(update, _SIBLING))

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 1


def _assert_ignored(update: str) -> None:
    snapshot = _parse(updateinfo_document(update, _SIBLING))

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 0


def _assert_valid(update: str) -> UpdateinfoSnapshot:
    snapshot = _parse(updateinfo_document(update, _SIBLING))

    assert _ids(snapshot) == {_TARGET_ID, _SIBLING_ID}
    assert snapshot.malformed_advisory_count == 0
    return snapshot


def _advisory(snapshot: UpdateinfoSnapshot, advisory_id: str) -> SecurityAdvisory:
    (item,) = [a for a in snapshot.advisories if a.advisory_id == advisory_id]
    return item


# --- Live fixtures --------------------------------------------------------


def _fixture_snapshot(name: str) -> UpdateinfoSnapshot:
    identity = parse_repomd(load_repomd_fixture(name))
    assert identity is not None
    return _parse(load_updateinfo_fixture(name), metadata_timestamp=identity.timestamp)


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_parse_live_fixture_retains_exactly_the_stable_security_advisories(
    name: str,
) -> None:
    root = ET.fromstring(load_updateinfo_fixture(name))
    expected = {
        update.findtext("id")
        for update in root
        if update.get("type") == "security"
        and update.get("status") == "stable"
        and list(update.iter("reference"))
    }

    snapshot = _fixture_snapshot(name)

    assert expected
    assert _ids(snapshot) == expected
    assert snapshot.malformed_advisory_count == 0


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_parse_live_fixture_advisory_content_matches_the_document(name: str) -> None:
    snapshot = _fixture_snapshot(name)
    updates = {
        update.findtext("id"): update
        for update in ET.fromstring(load_updateinfo_fixture(name))
    }

    for item in snapshot.advisories:
        update = updates[item.advisory_id]
        issued = update.find("issued")
        assert issued is not None
        assert item.issued == int(issued.get("date", ""))
        assert item.cve_ids == {
            reference.get("id")
            for reference in update.iter("reference")
            if reference.get("type") == "cve"
        }
        assert item.source_names == {
            package.get("name")
            for package in update.iter("package")
            if package.get("arch") in ("src", "nosrc")
        }


def test_parse_current_fixture_excludes_non_authoritative_advisories() -> None:
    retained = _ids(_fixture_snapshot("current"))

    for advisory_id in (
        "SUSE-SLE-Module-Basesystem-15-SP6-2025-118",  # retracted security
        "SUSE-SLE-Module-Basesystem-15-SP6-2024-2684",  # recommended with CVE
        "SUSE-SLE-Module-Basesystem-15-SP6-2024-839",  # feature
        "SUSE-SLE-Module-Basesystem-15-SP6-2024-1501",  # optional
    ):
        assert advisory_id not in retained


def test_match_current_fixture_known_source_package() -> None:
    snapshot = _fixture_snapshot("current")

    match = snapshot.match("CVE-2021-3521", "rpm")

    assert match is not None
    assert match.advisory_id == "SUSE-SLE-Module-Basesystem-15-SP6-2024-1557"
    assert match.issued == 1717068854
    assert match.issued_at == datetime(2024, 5, 30, 11, 34, 14, tzinfo=UTC)
    assert snapshot.match("CVE-2021-3521", "python-rpm") == match


def test_match_current_fixture_binary_package_name_does_not_match() -> None:
    snapshot = _fixture_snapshot("current")

    assert snapshot.match("CVE-2021-3521", "python3-rpm") is None
    assert snapshot.match("CVE-2024-4855", "libwireshark15") is None


@pytest.mark.parametrize(
    "package_name", ["kernel-default", "kernel-default-base", "kernel-source"]
)
def test_match_current_fixture_multi_source_and_nosrc_advisory(
    package_name: str,
) -> None:
    match = _fixture_snapshot("current").match("CVE-2023-0160", package_name)

    assert match is not None
    assert match.advisory_id == "SUSE-SLE-Module-Basesystem-15-SP6-2024-2203"


def test_match_current_fixture_shared_cve_selects_earliest_issued() -> None:
    match = _fixture_snapshot("current").match("CVE-2024-4855", "wireshark")

    assert match is not None
    assert match.advisory_id == "SUSE-SLE-Module-Basesystem-15-SP6-2024-1865"
    assert match.issued == 1717071611


def test_match_legacy_fixture_nosrc_entry() -> None:
    match = _fixture_snapshot("legacy_sha1").match("CVE-2019-7222", "kernel-xen")

    assert match is not None
    assert match.advisory_id == "slessp4-kernel-20190225-13979"


# --- Document-level failures ------------------------------------------------


def test_limit_constants_match_the_specification() -> None:
    assert UPDATEINFO_MAX_DEPTH == 32
    assert UPDATEINFO_MAX_ELEMENTS == 1_000_000
    assert UPDATEINFO_MAX_UPDATES == 50_000
    assert UPDATEINFO_MAX_PACKAGES == 500_000
    latest = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    assert int(latest.timestamp()) == MAX_UTC_SECONDS


def test_parse_empty_updates_returns_empty_snapshot() -> None:
    snapshot = _parse(updateinfo_document())

    assert snapshot.advisories == ()
    assert snapshot.malformed_advisory_count == 0


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(b'<updates xmlns="urn:example:other"/>', id="default-namespace"),
        pytest.param(b'<u:updates xmlns:u="urn:example:other"/>', id="prefixed"),
        pytest.param(b"<other/>", id="other-name"),
        pytest.param(b"<Updates/>", id="case"),
        pytest.param(b"<update/>", id="update-root"),
    ],
)
def test_parse_wrong_root_raises_xml_structure(document: bytes) -> None:
    assert _failure(document) == "xml_structure"


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(updateinfo_document(_target())[:-15], id="truncated"),
        pytest.param(b"", id="empty"),
        pytest.param(b"<updates><update></updates>", id="mismatched"),
        pytest.param(b"<updates/><updates/>", id="two-roots"),
        pytest.param(b"<updates/>junk", id="junk-after-root"),
        pytest.param(b"<!DOCTYPE updates><updates/>", id="doctype"),
        pytest.param(
            b'<!DOCTYPE updates [<!ENTITY e "x">]><updates>&e;</updates>',
            id="entity-declaration",
        ),
        pytest.param(b"<updates>&e;</updates>", id="undefined-entity"),
    ],
)
def test_parse_malformed_document_raises_xml_structure(document: bytes) -> None:
    assert _failure(document) == "xml_structure"


def test_close_truncated_document_raises_on_finalization() -> None:
    document = updateinfo_document(_target())
    parser = UpdateinfoParser(metadata_timestamp=_TIMESTAMP)
    parser.feed(document[: document.index(b"</updates>")])

    with pytest.raises(RepositoryDataError) as caught:
        parser.close()

    assert caught.value.category == "xml_structure"


def test_parse_depth_at_limit_is_accepted() -> None:
    nested = UPDATEINFO_MAX_DEPTH - 1
    document = b"<updates>" + b"<x>" * nested + b"</x>" * nested + b"</updates>"

    assert _parse(document).advisories == ()


def test_parse_depth_over_limit_raises_resource_limit() -> None:
    nested = UPDATEINFO_MAX_DEPTH
    document = b"<updates>" + b"<x>" * nested + b"</x>" * nested + b"</updates>"

    assert _failure(document) == "resource_limit"


def test_parse_depth_over_limit_inside_advisory_raises_resource_limit() -> None:
    # `update` is depth 2, so its descendants reach depth 2 + nested.
    nested = UPDATEINFO_MAX_DEPTH - 1
    deep = "<x>" * nested + "</x>" * nested

    assert _failure(updateinfo_document(_target(extra=deep))) == "resource_limit"


def test_parse_total_elements_over_limit_raises_resource_limit() -> None:
    document = b"<updates>" + b"<x/>" * UPDATEINFO_MAX_ELEMENTS + b"</updates>"

    assert _failure(document) == "resource_limit"


def test_parse_update_count_at_limit_is_accepted() -> None:
    document = b"<updates>" + b"<update/>" * UPDATEINFO_MAX_UPDATES + b"</updates>"

    assert _parse(document).malformed_advisory_count == 0


def test_parse_update_count_over_limit_raises_resource_limit() -> None:
    document = (
        b"<updates>" + b"<update/>" * (UPDATEINFO_MAX_UPDATES + 1) + b"</updates>"
    )

    assert _failure(document) == "resource_limit"


def test_parse_package_count_at_limit_is_accepted() -> None:
    document = b"<updates>" + b"<package/>" * UPDATEINFO_MAX_PACKAGES + b"</updates>"

    assert _parse(document).advisories == ()


def test_parse_package_count_over_limit_raises_resource_limit() -> None:
    document = (
        b"<updates>" + b"<package/>" * (UPDATEINFO_MAX_PACKAGES + 1) + b"</updates>"
    )

    assert _failure(document) == "resource_limit"


# --- Incremental feeding ----------------------------------------------------


def _snapshot_key(
    snapshot: UpdateinfoSnapshot,
) -> tuple[list[SecurityAdvisory], int]:
    advisories = sorted(snapshot.advisories, key=lambda item: item.advisory_id)
    return advisories, snapshot.malformed_advisory_count


def test_feed_byte_by_byte_equals_one_shot() -> None:
    document = updateinfo_document(
        _target(),
        _SIBLING,
        _target(),
        advisory("SUSE-BAD-2024-1", cves=["CVE-2024-0003"], issued="01"),
        advisory("SUSE-RECOMMENDED-2024-1", cves=[_TARGET_CVE], type_="recommended"),
    )
    parser = UpdateinfoParser(metadata_timestamp=_TIMESTAMP)

    for index in range(len(document)):
        parser.feed(document[index : index + 1])
    chunked = parser.close()

    one_shot = _parse(document)
    assert _snapshot_key(chunked) == _snapshot_key(one_shot)
    assert _ids(one_shot) == {_TARGET_ID, _SIBLING_ID}
    assert one_shot.malformed_advisory_count == 1


@pytest.mark.parametrize("name", UPDATEINFO_FIXTURES)
def test_feed_live_fixture_in_small_chunks_equals_one_shot(name: str) -> None:
    identity = parse_repomd(load_repomd_fixture(name))
    assert identity is not None
    document = load_updateinfo_fixture(name)
    parser = UpdateinfoParser(metadata_timestamp=identity.timestamp)

    for index in range(0, len(document), 7):
        parser.feed(document[index : index + 7])

    assert _snapshot_key(parser.close()) == _snapshot_key(_fixture_snapshot(name))


# --- Advisory validation: authoritative selection ---------------------------


def test_parse_valid_target_advisory_is_retained() -> None:
    snapshot = _assert_valid(_target())
    item = _advisory(snapshot, _TARGET_ID)

    assert item.cve_ids == {_TARGET_CVE}
    assert item.source_names == {"example"}
    assert item.issued == 1717068854


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(_target(type_="Security"), id="type-capitalized"),
        pytest.param(_target(type_="SECURITY"), id="type-uppercase"),
        pytest.param(_target(type_="security "), id="type-trailing-space"),
        pytest.param(_target(type_=" security"), id="type-leading-space"),
        pytest.param(_target(type_="recommended"), id="recommended"),
        pytest.param(_target(type_="optional"), id="optional"),
        pytest.param(_target(type_="feature"), id="feature"),
        pytest.param(_target(type_=""), id="type-empty"),
        pytest.param(_target().replace(' type="security"', "", 1), id="type-missing"),
        pytest.param(_target(status="Stable"), id="status-capitalized"),
        pytest.param(_target(status="stable "), id="status-trailing-space"),
        pytest.param(_target(status="retracted"), id="retracted"),
        pytest.param(_target(status="testing"), id="testing"),
        pytest.param(_target(status=""), id="status-empty"),
        pytest.param(_target().replace(' status="stable"', "", 1), id="status-missing"),
        pytest.param(
            advisory(_TARGET_ID, type_="recommended", issued="01"),
            id="malformed-recommended",
        ),
        pytest.param(
            _with_id("<id/>").replace('type="security"', 'type="optional"'),
            id="unidentified-optional",
        ),
    ],
)
def test_parse_non_authoritative_advisory_is_ignored_and_not_counted(
    update: str,
) -> None:
    _assert_ignored(update)


def test_parse_namespaced_update_is_not_an_advisory() -> None:
    namespaced = _target().replace("<update ", '<update xmlns="urn:example:other" ', 1)

    _assert_ignored(namespaced)


def test_parse_nested_update_is_not_an_advisory() -> None:
    _assert_ignored(f"<group>{_target()}</group>")


# --- Advisory validation: id ------------------------------------------------


@pytest.mark.parametrize(
    "markup",
    [
        pytest.param("", id="missing"),
        pytest.param(f"<id>{_TARGET_ID}</id><id>{_TARGET_ID}</id>", id="twice"),
        pytest.param(f"<id>{_TARGET_ID}</id><id>SUSE-OTHER-1</id>", id="two-values"),
        pytest.param("<id></id>", id="empty"),
        pytest.param("<id/>", id="self-closing"),
        pytest.param(f"<id> {_TARGET_ID}</id>", id="leading-space"),
        pytest.param(f"<id>{_TARGET_ID} </id>", id="trailing-space"),
        pytest.param(f"<id>{_TARGET_ID}\n</id>", id="trailing-newline"),
        pytest.param("<id>SUSE TARGET</id>", id="inner-space"),
        pytest.param("<id>SUSE&#9;TARGET</id>", id="tab"),
        pytest.param(f"<id>-{_TARGET_ID}</id>", id="leading-hyphen"),
        pytest.param(f"<id>.{_TARGET_ID}</id>", id="leading-dot"),
        pytest.param(f"<id>:{_TARGET_ID}</id>", id="leading-colon"),
        pytest.param(f"<id>_{_TARGET_ID}</id>", id="leading-underscore"),
        pytest.param(f"<id>+{_TARGET_ID}</id>", id="leading-plus"),
        pytest.param(f"<id>{'A' * 256}</id>", id="256-characters"),
        pytest.param(f"<id>{_TARGET_ID}-é</id>", id="non-ascii"),
        pytest.param("<id>SUSE/TARGET</id>", id="slash"),
        pytest.param("<id>SUSE%41</id>", id="percent"),
        pytest.param("<id>SUSE#1</id>", id="hash"),
        pytest.param("<id>SUSE?1</id>", id="question-mark"),
        pytest.param("<id>SUSE\x7f1</id>", id="delete"),
        pytest.param(f"<id>SUSE-<b/>{_TARGET_ID}</id>", id="child-element"),
        pytest.param("<id>SUSE-<b>TARGET</b>-1</id>", id="child-with-text"),
        pytest.param(
            f'<id xmlns="urn:example:other">{_TARGET_ID}</id>', id="namespaced"
        ),
    ],
)
def test_parse_invalid_id_ignores_advisory_and_counts_it(markup: str) -> None:
    _assert_malformed(_with_id(markup))


def test_parse_id_of_255_characters_is_accepted() -> None:
    advisory_id = "A" + "b.:_+-9" * 36 + "Z" * 2

    assert len(advisory_id) == 255
    update = advisory(advisory_id, cves=[_TARGET_CVE], sources=["example"])

    snapshot = _parse(updateinfo_document(update))

    assert _ids(snapshot) == {advisory_id}
    assert snapshot.malformed_advisory_count == 0


# --- Advisory validation: issued --------------------------------------------


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(_without(r"<issued [^>]*/>"), id="missing"),
        pytest.param(
            _target().replace(
                '<issued date="1717068854"/>',
                '<issued date="1717068854"/><issued date="1717068854"/>',
            ),
            id="twice",
        ),
        pytest.param(
            _target().replace('<issued date="1717068854"/>', "<issued/>"),
            id="missing-date",
        ),
        pytest.param(
            _target().replace(
                '<issued date="1717068854"/>',
                '<issued xmlns:o="urn:example:other" o:date="1717068854"/>',
            ),
            id="namespaced-date",
        ),
    ],
)
def test_parse_invalid_issued_element_ignores_advisory_and_counts_it(
    update: str,
) -> None:
    _assert_malformed(update)


@pytest.mark.parametrize(
    "date",
    [
        pytest.param("", id="empty"),
        pytest.param("+1", id="plus"),
        pytest.param("-1", id="minus"),
        pytest.param("01", id="leading-zero"),
        pytest.param("00", id="double-zero"),
        pytest.param("1.0", id="fraction"),
        pytest.param(" 1", id="leading-space"),
        pytest.param("1 ", id="trailing-space"),
        pytest.param("1Z", id="timezone"),
        pytest.param("1e9", id="exponent"),
        pytest.param("2024-05-30", id="date-text"),
        pytest.param("2024-05-30 11:34:14", id="datetime-text"),
        pytest.param("\u0661\u0662\u0663", id="arabic-indic-digits"),
        pytest.param(str(_TIMESTAMP + 1), id="after-metadata"),
    ],
)
def test_parse_invalid_issued_date_ignores_advisory_and_counts_it(date: str) -> None:
    _assert_malformed(_target(issued=date))


def test_parse_issued_after_max_utc_ignores_advisory_and_counts_it() -> None:
    document = updateinfo_document(_target(issued=str(MAX_UTC_SECONDS + 1)), _SIBLING)

    snapshot = _parse(document, metadata_timestamp=MAX_UTC_SECONDS + 10)

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 1


def test_parse_issued_at_max_utc_is_accepted() -> None:
    document = updateinfo_document(_target(issued=str(MAX_UTC_SECONDS)))

    snapshot = _parse(document, metadata_timestamp=MAX_UTC_SECONDS)

    item = _advisory(snapshot, _TARGET_ID)
    assert item.issued_at == datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)


def test_parse_issued_epoch_boundary_is_accepted_as_utc() -> None:
    snapshot = _assert_valid(_target(issued="0"))

    issued_at = _advisory(snapshot, _TARGET_ID).issued_at
    assert issued_at == datetime(1970, 1, 1, tzinfo=UTC)
    assert issued_at.tzinfo is UTC
    assert issued_at.utcoffset() == timedelta(0)


def test_parse_issued_equal_to_metadata_timestamp_is_accepted() -> None:
    snapshot = _assert_valid(_target(issued=str(_TIMESTAMP)))

    assert _advisory(snapshot, _TARGET_ID).issued == _TIMESTAMP


def test_parse_issued_short_value_is_accepted() -> None:
    # No fixed digit-count assumption: a short value is canonical too.
    snapshot = _assert_valid(_target(issued="7"))

    assert _advisory(snapshot, _TARGET_ID).issued == 7


def test_issued_at_is_timezone_aware_utc() -> None:
    snapshot = _assert_valid(_target())

    issued_at = _advisory(snapshot, _TARGET_ID).issued_at
    assert issued_at.tzinfo is UTC
    assert issued_at == datetime.fromtimestamp(1717068854, UTC)


# --- Advisory validation: references ----------------------------------------


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(_without(r"<references>.*?</references>"), id="missing"),
        pytest.param(
            _target(extra=f"<references>{_CVE_REFERENCE}</references>"), id="twice"
        ),
        pytest.param(_target_with(references=[]), id="empty"),
        pytest.param(
            _target_with(references=[f"<group>{_CVE_REFERENCE}</group>"]),
            id="reference-not-direct-child",
        ),
        pytest.param(
            _target_with(
                references=[_CVE_REFERENCE, f'<reference id="{_TARGET_CVE}"/>']
            ),
            id="reference-missing-type",
        ),
        pytest.param(
            _target_with(references=[_CVE_REFERENCE, '<reference type="cve"/>']),
            id="reference-missing-id",
        ),
        pytest.param(
            _target_with(
                references=[_CVE_REFERENCE, f'<reference id="{_TARGET_CVE}" type=""/>']
            ),
            id="reference-empty-type",
        ),
        pytest.param(
            _target_with(references=[_CVE_REFERENCE, '<reference id="" type="cve"/>']),
            id="reference-empty-id",
        ),
        pytest.param(
            _target_with(references=['<reference id="1191175" type=""/>']),
            id="only-reference-empty-type",
        ),
    ],
)
def test_parse_invalid_references_ignore_advisory_and_count_it(update: str) -> None:
    _assert_malformed(update)


def test_parse_non_cve_references_only_is_valid_without_cves() -> None:
    update = _target_with(references=['<reference id="1191175" type="bugzilla"/>'])

    snapshot = _assert_valid(update)

    assert _advisory(snapshot, _TARGET_ID).cve_ids == frozenset()


@pytest.mark.parametrize(
    "reference",
    [
        pytest.param(
            f'<reference id="{_TARGET_CVE}" type="CVE"/>', id="type-uppercase"
        ),
        pytest.param(f'<reference id="{_TARGET_CVE}" type="Cve"/>', id="type-mixed"),
        pytest.param(f'<reference id="{_TARGET_CVE}" type=" cve"/>', id="type-padded"),
        pytest.param('<reference id="cve-2024-0001" type="cve"/>', id="id-lowercase"),
        pytest.param(f'<reference id=" {_TARGET_CVE}" type="cve"/>', id="id-padded"),
        pytest.param(f'<reference id="{_TARGET_CVE}x" type="cve"/>', id="id-suffix"),
    ],
)
def test_match_inexact_cve_reference_does_not_match(reference: str) -> None:
    snapshot = _assert_valid(_target_with(references=[reference]))

    assert snapshot.match(_TARGET_CVE, "example") is None


# --- Advisory validation: pkglist -------------------------------------------


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(_without(r"<pkglist>.*?</pkglist>"), id="missing"),
        pytest.param(
            _target(
                extra=f"<pkglist><collection>{source_package('example')}</collection>"
                "</pkglist>"
            ),
            id="twice",
        ),
        pytest.param(
            re.sub(
                r"<pkglist>.*?</pkglist>",
                "<pkglist/>",
                _target(),
                flags=re.DOTALL,
            ),
            id="no-collection",
        ),
        pytest.param(
            re.sub(
                r"<pkglist>.*?</pkglist>",
                "<pkglist><collection/><collection></collection></pkglist>",
                _target(),
                flags=re.DOTALL,
            ),
            id="collections-without-package",
        ),
        pytest.param(
            re.sub(
                r"<pkglist>.*?</pkglist>",
                f"<pkglist>{source_package('example')}</pkglist>",
                _target(),
                flags=re.DOTALL,
            ),
            id="package-outside-collection",
        ),
    ],
)
def test_parse_invalid_pkglist_ignores_advisory_and_counts_it(update: str) -> None:
    _assert_malformed(update)


def test_parse_combined_collections_supply_the_packages() -> None:
    pkglist = (
        "<pkglist><collection/>"
        f"<collection>{source_package('alpha')}</collection>"
        f"<collection>{source_package('beta')}</collection></pkglist>"
    )
    update = re.sub(r"<pkglist>.*?</pkglist>", pkglist, _target(), flags=re.DOTALL)

    snapshot = _assert_valid(update)

    assert _advisory(snapshot, _TARGET_ID).source_names == {"alpha", "beta"}


# --- Exact source-package entries -------------------------------------------


@pytest.mark.parametrize(
    "package",
    [
        *(
            pytest.param(_package(**{key: None}), id=f"{key}-missing")
            for key in ("name", "epoch", "version", "release", "src")
        ),
        *(
            pytest.param(_package(**{key: ""}), id=f"{key}-empty")
            for key in ("name", "epoch", "version", "release", "src")
        ),
        pytest.param(_package(epoch="01"), id="epoch-leading-zero"),
        pytest.param(_package(epoch="-1"), id="epoch-negative"),
        pytest.param(_package(epoch="+1"), id="epoch-plus"),
        pytest.param(_package(epoch="a"), id="epoch-letter"),
        pytest.param(_package(epoch=" 0"), id="epoch-space"),
        pytest.param(_package(epoch="1.0"), id="epoch-fraction"),
        *(
            pytest.param(source_package(name), id=f"name-{label}")
            for label, name in (
                ("slash", "ex/ample"),
                ("backslash", "ex\\ample"),
                ("percent", "ex%41mple"),
                ("question-mark", "ex?ample"),
                ("hash", "ex#ample"),
                ("space", "ex ample"),
                ("tab", "ex\tample"),
                ("delete", "ex\x7fample"),
                ("non-ascii", "exämple"),
                ("leading-dot", ".example"),
                ("leading-hyphen", "-example"),
                ("leading-underscore", "_example"),
                ("leading-plus", "+example"),
                ("tilde", "ex~ample"),
                ("256-characters", "a" * 256),
            )
        ),
        *(
            pytest.param(
                source_package("example", **{field: value}),
                id=f"{field}-{label}",
            )
            for field in ("version", "release")
            for label, value in (
                ("slash", "1/0"),
                ("backslash", "1\\0"),
                ("percent", "1%30"),
                ("question-mark", "1?0"),
                ("hash", "1#0"),
                ("space", "1 0"),
                ("tab", "1\t0"),
                ("newline", "1\n0"),
                ("delete", "1\x7f0"),
                ("non-ascii", "1.é"),
            )
        ),
        *(
            pytest.param(_package(src=src), id=f"src-{label}")
            for label, src in (
                ("leading-slash", "/src/example-1.0-1.1.src.rpm"),
                ("extra-segment", "src/extra/example-1.0-1.1.src.rpm"),
                ("no-directory", "example-1.0-1.1.src.rpm"),
                ("wrong-directory", "x86_64/example-1.0-1.1.src.rpm"),
                ("uppercase-directory", "SRC/example-1.0-1.1.src.rpm"),
                ("wrong-suffix", "src/example-1.0-1.1.nosrc.rpm"),
                ("no-arch-suffix", "src/example-1.0-1.1.rpm"),
                ("percent-encoded", "src/example%2D1.0-1.1.src.rpm"),
                ("dot-prefix", "./src/example-1.0-1.1.src.rpm"),
                ("dot-segment", "src/./example-1.0-1.1.src.rpm"),
                ("traversal", "src/../src/example-1.0-1.1.src.rpm"),
                ("backslash", "src\\example-1.0-1.1.src.rpm"),
                ("trailing-space", "src/example-1.0-1.1.src.rpm "),
                ("other-name", "src/other-1.0-1.1.src.rpm"),
                ("other-version", "src/example-2.0-1.1.src.rpm"),
                ("other-release", "src/example-1.0-1.2.src.rpm"),
                ("url", "https://example.test/src/example-1.0-1.1.src.rpm"),
            )
        ),
        pytest.param(
            _package(arch="nosrc", src="src/example-1.0-1.1.nosrc.rpm"),
            id="nosrc-in-src-directory",
        ),
        pytest.param(
            _package(arch="nosrc", src="nosrc/example-1.0-1.1.src.rpm"),
            id="nosrc-with-src-suffix",
        ),
        pytest.param(
            _package(arch="nosrc", src="src/example-1.0-1.1.src.rpm"),
            id="nosrc-with-src-path",
        ),
    ],
)
def test_parse_invalid_source_entry_ignores_advisory_and_counts_it(
    package: str,
) -> None:
    _assert_malformed(_target_with(packages=[source_package("valid"), package]))


@pytest.mark.parametrize(
    ("package", "name"),
    [
        pytest.param(
            source_package(
                "kernel-default-base",
                version="6.4.0",
                release="150600.23.7.3.150600.12.2.7",
            ),
            "kernel-default-base",
            id="hyphenated-name",
        ),
        pytest.param(
            source_package("kernel-xen", arch="nosrc"), "kernel-xen", id="nosrc"
        ),
        pytest.param(source_package("example", epoch="12"), "example", id="epoch"),
        pytest.param(
            source_package("example", version="2.4.58~rc1+git3", release="1.1^x"),
            "example",
            id="version-punctuation",
        ),
        pytest.param(
            source_package("a" + "b" * 254), "a" + "b" * 254, id="255-character-name"
        ),
        pytest.param(
            source_package("Ex_am.p+le-9"), "Ex_am.p+le-9", id="name-punctuation"
        ),
    ],
)
def test_parse_valid_source_entry_establishes_source_name(
    package: str, name: str
) -> None:
    snapshot = _assert_valid(_target_with(packages=[package]))

    match = snapshot.match(_TARGET_CVE, name)
    assert match is not None
    assert match.advisory_id == _TARGET_ID
    assert _advisory(snapshot, _TARGET_ID).source_names == {name}


def test_match_hyphenated_name_does_not_match_its_prefix() -> None:
    package = source_package(
        "kernel-default-base", version="6.4.0", release="150600.23.7.3"
    )

    snapshot = _assert_valid(_target_with(packages=[package]))

    assert snapshot.match(_TARGET_CVE, "kernel-default") is None
    assert snapshot.match(_TARGET_CVE, "kernel") is None


@pytest.mark.parametrize(
    "binary",
    [
        pytest.param(
            _package(name="bad/name", epoch="x", arch="x86_64", src="../../x"),
            id="unsafe-binary",
        ),
        pytest.param("<package/>", id="no-attributes"),
        pytest.param(_package(arch=None), id="arch-missing"),
        pytest.param(_package(arch=""), id="arch-empty"),
        pytest.param(_package(arch="SRC"), id="arch-uppercase"),
        pytest.param(_package(arch="src "), id="arch-padded"),
        pytest.param(_package(arch="noarch", name="", src=""), id="empty-binary"),
    ],
)
def test_parse_binary_entry_never_invalidates_and_never_matches(binary: str) -> None:
    snapshot = _assert_valid(_target_with(packages=[source_package("example"), binary]))

    assert _advisory(snapshot, _TARGET_ID).source_names == {"example"}
    assert snapshot.match(_TARGET_CVE, "bad/name") is None


def test_parse_binary_only_advisory_is_valid_but_never_matches() -> None:
    update = _target_with(packages=[binary_package("example")])

    snapshot = _assert_valid(update)

    assert _advisory(snapshot, _TARGET_ID).source_names == frozenset()
    assert snapshot.match(_TARGET_CVE, "example") is None


# --- Duplicates and conflicts -------------------------------------------------


def test_parse_identical_repeated_advisory_is_retained_once() -> None:
    snapshot = _parse(updateinfo_document(_target(), _SIBLING, _target()))

    assert sorted(item.advisory_id for item in snapshot.advisories) == [
        _SIBLING_ID,
        _TARGET_ID,
    ]
    assert snapshot.malformed_advisory_count == 0


def test_parse_repeat_differing_only_in_non_consumed_content_collapses() -> None:
    variant = _target(extra="<message>Fictional notice.</message>").replace(
        "Fictional title", "Another fictional title"
    )

    snapshot = _parse(updateinfo_document(_target(), variant, _SIBLING))

    assert _ids(snapshot) == {_TARGET_ID, _SIBLING_ID}
    assert snapshot.malformed_advisory_count == 0


_CONFLICTING_VARIANTS = [
    pytest.param(_target(issued="1717068855"), id="issued"),
    pytest.param(_target(status="retracted"), id="status"),
    pytest.param(_target(type_="recommended"), id="type"),
    pytest.param(
        advisory(_TARGET_ID, cves=[_TARGET_CVE, "CVE-2024-0003"], sources=["example"]),
        id="extra-reference",
    ),
    pytest.param(
        advisory(_TARGET_ID, cves=["CVE-2024-0003"], sources=["example"]),
        id="other-reference",
    ),
    pytest.param(
        advisory(_TARGET_ID, cves=[_TARGET_CVE], sources=["example", "other"]),
        id="extra-package",
    ),
    pytest.param(
        _target_with(
            packages=[
                source_package("example", version="2.0"),
                binary_package("example-tools"),
            ]
        ),
        id="package-version",
    ),
    pytest.param(_target(issued="01"), id="malformed-variant"),
]


@pytest.mark.parametrize("variant", _CONFLICTING_VARIANTS)
@pytest.mark.parametrize("variant_first", [False, True])
def test_parse_conflicting_variants_invalidate_every_variant(
    variant: str, variant_first: bool
) -> None:
    updates = [variant, _target()] if variant_first else [_target(), variant]

    snapshot = _parse(updateinfo_document(*updates, _SIBLING))

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 1
    assert snapshot.match(_TARGET_CVE, "example") is None


def test_parse_repeated_conflicting_variants_are_counted_once() -> None:
    variant = _target(issued="1717068855")

    snapshot = _parse(
        updateinfo_document(_target(), variant, _target(), variant, _SIBLING)
    )

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 1


def test_parse_repeated_malformed_advisory_is_counted_once() -> None:
    malformed = _target(issued="01")

    snapshot = _parse(updateinfo_document(malformed, malformed, _SIBLING))

    assert snapshot.malformed_advisory_count == 1


def test_parse_conflicting_non_authoritative_variants_are_not_counted() -> None:
    snapshot = _parse(
        updateinfo_document(
            _target(type_="recommended"), _target(type_="optional"), _SIBLING
        )
    )

    assert _ids(snapshot) == {_SIBLING_ID}
    assert snapshot.malformed_advisory_count == 0


def test_parse_duplicate_references_and_packages_collapse() -> None:
    update = advisory(
        _TARGET_ID,
        references=[_CVE_REFERENCE, _CVE_REFERENCE],
        packages=[
            source_package("example"),
            source_package("example"),
            binary_package("example-tools"),
            binary_package("example-tools"),
        ],
    )

    snapshot = _assert_valid(update)

    item = _advisory(snapshot, _TARGET_ID)
    assert item.cve_ids == {_TARGET_CVE}
    assert item.source_names == {"example"}


def test_parse_two_advisories_sharing_a_cve_are_both_retained() -> None:
    other = advisory(
        "SUSE-OTHER-2024-1", cves=[_TARGET_CVE], sources=["other"], issued="1717068000"
    )

    snapshot = _parse(updateinfo_document(_target(), other))

    assert _ids(snapshot) == {_TARGET_ID, "SUSE-OTHER-2024-1"}
    assert snapshot.malformed_advisory_count == 0


# --- Matching -----------------------------------------------------------------


def test_match_requires_exact_case_sensitive_package_name() -> None:
    snapshot = _assert_valid(_target())

    assert snapshot.match(_TARGET_CVE, "example") is not None
    for name in ("Example", "EXAMPLE", "example ", "exampl", "example-tools"):
        assert snapshot.match(_TARGET_CVE, name) is None


def test_match_requires_exact_cve() -> None:
    snapshot = _assert_valid(_target())

    for cve_id in ("cve-2024-0001", "CVE-2024-00010", "CVE-2024-0002", ""):
        assert snapshot.match(cve_id, "example") is None


def test_match_selects_earliest_issued_advisory() -> None:
    updates = [
        advisory(advisory_id, cves=[_TARGET_CVE], sources=["example"], issued=issued)
        for advisory_id, issued in (
            ("SUSE-A-2024-1", "1700000300"),
            ("SUSE-B-2024-1", "1700000100"),
            ("SUSE-C-2024-1", "1700000200"),
        )
    ]

    match = _parse(updateinfo_document(*updates)).match(_TARGET_CVE, "example")

    assert match is not None
    assert match.advisory_id == "SUSE-B-2024-1"
    assert match.issued == 1700000100


@pytest.mark.parametrize("reverse", [False, True])
def test_match_equal_issued_selects_lexically_smallest_id(reverse: bool) -> None:
    updates = [
        advisory(advisory_id, cves=[_TARGET_CVE], sources=["example"])
        for advisory_id in ("SUSE-2024-9", "SUSE-2024-10", "SUSE-2024-2")
    ]
    if reverse:
        updates.reverse()

    match = _parse(updateinfo_document(*updates)).match(_TARGET_CVE, "example")

    assert match is not None
    assert match.advisory_id == "SUSE-2024-10"


def test_match_several_nvrs_of_one_source_name_collapse() -> None:
    update = _target_with(
        packages=[
            source_package("example", version="1.0"),
            source_package("example", version="2.0"),
            source_package("example", release="2.1"),
            source_package("example", arch="nosrc"),
        ]
    )

    snapshot = _assert_valid(update)

    assert _advisory(snapshot, _TARGET_ID).source_names == {"example"}
    match = snapshot.match(_TARGET_CVE, "example")
    assert match is not None
    assert match.advisory_id == _TARGET_ID


def test_match_one_advisory_matches_several_source_names() -> None:
    update = advisory(_TARGET_ID, cves=[_TARGET_CVE], sources=["alpha", "beta"])

    snapshot = _parse(updateinfo_document(update))

    for name in ("alpha", "beta"):
        match = snapshot.match(_TARGET_CVE, name)
        assert match is not None
        assert match.advisory_id == _TARGET_ID
    assert snapshot.match(_TARGET_CVE, "alpha-tools") is None


def test_match_unknown_cve_or_package_returns_none() -> None:
    snapshot = _assert_valid(_target())

    assert snapshot.match("CVE-2099-0001", "example") is None
    assert snapshot.match(_TARGET_CVE, "unknown") is None
    assert snapshot.match("CVE-2024-0002", "example") is None


# --- CVE filter ---------------------------------------------------------------


def _filter_document() -> bytes:
    return updateinfo_document(
        advisory("SUSE-A-2024-1", cves=[_TARGET_CVE, "CVE-2024-0003"], sources=["a"]),
        advisory("SUSE-B-2024-1", cves=["CVE-2024-0002"], sources=["b"]),
        advisory("SUSE-M-2024-1", cves=[_TARGET_CVE], sources=["m"], issued="01"),
    )


def test_parse_cve_filter_limits_retained_advisories() -> None:
    snapshot = _parse(_filter_document(), cve_filter=[_TARGET_CVE])

    assert _ids(snapshot) == {"SUSE-A-2024-1"}
    assert _advisory(snapshot, "SUSE-A-2024-1").cve_ids == {
        _TARGET_CVE,
        "CVE-2024-0003",
    }
    assert snapshot.malformed_advisory_count == 1


def test_parse_cve_filter_still_counts_malformed_advisories_without_match() -> None:
    snapshot = _parse(_filter_document(), cve_filter=["CVE-2099-0001"])

    assert snapshot.advisories == ()
    assert snapshot.malformed_advisory_count == 1


def test_parse_empty_cve_filter_retains_nothing() -> None:
    snapshot = _parse(_filter_document(), cve_filter=[])

    assert snapshot.advisories == ()
    assert snapshot.malformed_advisory_count == 1


def test_parse_without_cve_filter_retains_every_valid_advisory() -> None:
    snapshot = _parse(_filter_document(), cve_filter=None)

    assert _ids(snapshot) == {"SUSE-A-2024-1", "SUSE-B-2024-1"}
    assert snapshot.malformed_advisory_count == 1


# --- External String Admissibility --------------------------------------------

_INJECTION_SITES = {
    "id-text": advisory(f"SUSE-{_INJECT}-1", cves=[_TARGET_CVE], sources=["example"]),
    "status": _target(status=f"stable{_INJECT}"),
    "type": _target(type_=f"security{_INJECT}"),
    "issued-date": _target(issued=f"1{_INJECT}"),
    "reference-type": _target_with(
        references=[f'<reference id="{_TARGET_CVE}" type="cve{_INJECT}"/>']
    ),
    "reference-id": advisory(
        _TARGET_ID, cves=[f"CVE-2024-{_INJECT}"], sources=["example"]
    ),
    "package-name": _target_with(packages=[source_package(f"ex{_INJECT}ample")]),
    "package-epoch": _target_with(packages=[_package(epoch=f"0{_INJECT}")]),
    "package-version": _target_with(packages=[_package(version=f"1{_INJECT}")]),
    "package-release": _target_with(packages=[_package(release=f"1{_INJECT}")]),
    "package-arch": _target_with(packages=[_package(arch=f"src{_INJECT}")]),
    "package-src": _target_with(packages=[_package(src=f"src/{_INJECT}")]),
}


@pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
@pytest.mark.parametrize("encoding", ["raw", "reference"])
@pytest.mark.parametrize("site", sorted(_INJECTION_SITES))
def test_parse_inadmissible_character_fails_the_whole_document(
    character: str, encoding: str, site: str
) -> None:
    template = updateinfo_document(_SIBLING, _INJECTION_SITES[site], _target())
    assert _INJECT.encode() in template
    injected = (
        character.encode("utf-8", "surrogatepass")
        if encoding == "raw"
        else f"&#{ord(character)};".encode()
    )

    assert _failure(template.replace(_INJECT.encode(), injected)) == "xml_structure"
