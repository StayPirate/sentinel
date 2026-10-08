"""Unit tests for the CVE Record Format 5.x parser
(backend/app/services/cve_record_parser.py).

Contract under test: docs/features/platform/cve-record-parser.md (Design
Principles, Module-Level Defaults including Input Validation, every
Functions subsection, Caller Pattern, Schema Version Handling), the
External Base Reduction and Provider Identity rules of
docs/features/tickets/cvss-scoring.md, and the entry conflict key of
docs/features/tickets/cve-service.md (Canonical Payload Duplicate
Handling; CVEIngestPayload Schema). The decisions recorded on issue #876
(type-strict field access, optional SSVC/KEV fields, the package-coordinate
sentinel refinement, the date-time forms, exact SSVC enums with last-entry
selection, and last-occurrence affected deduplication) are pinned here.

Robustness against mutated input, External String Admissibility, and the
module boundary are covered by `test_cve_record_parser_robustness.py`.

Records are the sanitized live fixtures of `tests/support/cve_record.py` or
minimal fictional objects. No database, network, or log is involved.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from typing import Any, Final

import pytest
from pydantic import ValidationError

from app.core.enums import (
    CveState,
    SSVCAutomatable,
    SSVCExploitation,
    SSVCTechnicalImpact,
)
from app.services.cve_ingest import (
    AffectedVersionEntry,
    AffectedVersionOperation,
    AffectedVersionScopeOperation,
    CVEIngestPayload,
    CVSSAssessmentEntry,
    CWEEntry,
    KEVEntry,
    SSVCEntry,
    affected_version_key,
)
from app.services.cve_record_parser import (
    CVSS_VECTOR_KEYS,
    TITLE_MAX_LENGTH,
    extract_cve_state,
    extract_dates,
    parse_affected_versions,
    parse_cvss_assessments,
    parse_cwe_classifications,
    parse_description,
    parse_kev_data,
    parse_ssvc_assessment,
    parse_title,
    validate_cve_id,
)
from tests.support.cve_record import (
    ALL_FIXTURES,
    VULNS_FIXTURES,
    load_fixture,
    source_cve_id,
)

pytestmark = pytest.mark.unit

V20: Final = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
V30: Final = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V30_ALT: Final = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
V31: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V31_ALT: Final = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
V40: Final = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
PROVIDER: Final = "Example CNA"
SOURCE: Final = "cna:Example CNA"
CVE_ID: Final = "CVE-2026-0001"
SSVC_TIMESTAMP: Final = "2024-04-02T04:00:23.138684Z"
KEV_REFERENCE: Final = "https://kev.example.invalid/catalog?cve=CVE-2026-0001"

VENDOR: Final = "Example Vendor"
PRODUCT: Final = "example-product"
SIBLING: Final[dict[str, Any]] = {
    "vendor": VENDOR,
    "product": "example-sibling",
    "versions": [{"version": "1.0", "status": "affected"}],
}
"""A valid `affected[]` element whose entry must survive any skipped
neighbour."""
SIBLING_ENTRY: Final = AffectedVersionEntry(
    vendor=VENDOR, product="example-sibling", version="1.0", status="affected"
)

_ABSENT: Final = object()
"""Marks a key to omit from a crafted object."""


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _element(**fields: Any) -> dict[str, Any]:
    """An `affected[]` element with the fictional vendor and product unless
    overridden; `_ABSENT` omits a key."""
    element: dict[str, Any] = {"vendor": VENDOR, "product": PRODUCT, **fields}
    return {k: v for k, v in element.items() if v is not _ABSENT}


def _version(**fields: Any) -> dict[str, Any]:
    version: dict[str, Any] = {"version": "1.0", "status": "affected", **fields}
    return {k: v for k, v in version.items() if v is not _ABSENT}


def _entry(**fields: Any) -> AffectedVersionEntry:
    return AffectedVersionEntry(**{"vendor": VENDOR, "product": PRODUCT, **fields})


def _cvss(key: str, vector: Any) -> dict[str, Any]:
    return {key: {"version": "x", "vectorString": vector, "baseScore": 9.8}}


def _vectors(entries: list[CVSSAssessmentEntry]) -> list[Any]:
    return [entry.vector_string for entry in entries]


def _ssvc_content(
    *,
    exploitation: Any = "active",
    automatable: Any = "no",
    technical_impact: Any = "total",
    version: Any = "2.0.3",
    timestamp: Any = SSVC_TIMESTAMP,
) -> dict[str, Any]:
    options = [
        {key: value}
        for key, value in (
            ("Exploitation", exploitation),
            ("Automatable", automatable),
            ("Technical Impact", technical_impact),
        )
        if value is not _ABSENT
    ]
    content: dict[str, Any] = {
        "id": CVE_ID,
        "role": "CISA Coordinator",
        "options": options,
        "version": version,
        "timestamp": timestamp,
    }
    return {k: v for k, v in content.items() if v is not _ABSENT}


def _other(type_: str, content: Any) -> dict[str, Any]:
    return {"other": {"type": type_, "content": content}}


def _kev_content(
    *, date_added: Any = "2024-01-15", reference: Any = KEV_REFERENCE
) -> dict[str, Any]:
    content: dict[str, Any] = {"dateAdded": date_added, "reference": reference}
    return {k: v for k, v in content.items() if v is not _ABSENT}


def _ssvc_entry(**fields: Any) -> SSVCEntry:
    values: dict[str, Any] = {
        "exploitation": SSVCExploitation.ACTIVE,
        "automatable": SSVCAutomatable.NO,
        "technical_impact": SSVCTechnicalImpact.TOTAL,
        "version": "2.0.3",
        "assessed_at": datetime(2024, 4, 2, 4, 0, 23, 138684, tzinfo=UTC),
        **fields,
    }
    return SSVCEntry(**values)


def _replace_operation(
    entries: list[AffectedVersionEntry],
) -> AffectedVersionScopeOperation:
    return AffectedVersionScopeOperation(
        source_container="cna",
        operation=AffectedVersionOperation.REPLACE,
        entries=entries,
    )


def _assert_accepted_as_snapshot(entries: list[AffectedVersionEntry]) -> None:
    """The parser output is a valid `replace` snapshot of one scope and a
    valid payload, with no duplicate-key error."""
    keys = [affected_version_key(entry) for entry in entries]
    assert len(keys) == len(set(keys))
    operation = _replace_operation(entries)
    CVEIngestPayload(affected_version_operations=[operation])


# ---------------------------------------------------------------------------
# Fixture helpers (Caller Pattern)
# ---------------------------------------------------------------------------


def _containers(record: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(scope label, container) of the CNA and every ADP container."""
    containers = record["containers"]
    found = [("cna", containers["cna"])]
    for adp in containers.get("adp", []):
        found.append((f"adp:{adp['providerMetadata']['shortName']}", adp))
    return found


def _container(name: str, label: str) -> dict[str, Any]:
    (container,) = [c for lbl, c in _containers(load_fixture(name)) if lbl == label]
    return container


def _provider(label: str, container: dict[str, Any]) -> str:
    """CNA short name (kernel: hardcoded `Linux`) or the ADP scope label."""
    if label != "cna":
        return label
    short_name: str = container["providerMetadata"].get("shortName", "Linux")
    return short_name


def _add_present_nullable(
    kwargs: dict[str, Any],
    field: str,
    container: dict[str, Any],
    key: str,
    parsed: object,
) -> None:
    """Caller Pattern: absent key → omit; upstream null → None; parsed
    value → value; malformed non-null value → omit."""
    if key not in container:
        return
    if container[key] is None:
        kwargs[field] = None
    elif parsed is not None:
        kwargs[field] = parsed


def _caller_payload(name: str) -> CVEIngestPayload:
    """`CVEIngestPayload` assembled from the parser outputs as in the Caller
    Pattern, with every ADP container's children."""
    record = load_fixture(name)
    metadata = record["cveMetadata"]
    cna = record["containers"]["cna"]
    kwargs: dict[str, Any] = {}
    validate_cve_id(source_cve_id(name), metadata)
    cve_state = extract_cve_state(metadata)
    assert cve_state is not None
    kwargs["cve_state"] = cve_state
    published, modified, rejected = extract_dates(metadata)
    _add_present_nullable(
        kwargs, "published_date", metadata, "datePublished", published
    )
    _add_present_nullable(kwargs, "modified_date", metadata, "dateUpdated", modified)
    _add_present_nullable(kwargs, "date_rejected", metadata, "dateRejected", rejected)
    _add_present_nullable(kwargs, "title", cna, "title", parse_title(cna))
    _add_present_nullable(
        kwargs,
        "description",
        cna,
        "descriptions",
        parse_description(cna.get("descriptions", [])),
    )
    operations: list[AffectedVersionScopeOperation] = []
    cvss: list[CVSSAssessmentEntry] = []
    cwe: list[CWEEntry] = []
    ssvc: SSVCEntry | None = None
    kev: KEVEntry | None = None
    for label, container in _containers(record):
        provider = _provider(label, container)
        if container.get("affected") is not None:
            operations.append(
                AffectedVersionScopeOperation(
                    source_container=label,
                    operation=AffectedVersionOperation.REPLACE,
                    entries=parse_affected_versions(container["affected"]),
                )
            )
        cvss += parse_cvss_assessments(container.get("metrics", []), provider)
        source = f"cna:{provider}" if label == "cna" else label
        cwe += parse_cwe_classifications(container.get("problemTypes", []), source)
        if label == "adp:CISA-ADP":
            ssvc = parse_ssvc_assessment(container.get("metrics", []))
            kev = parse_kev_data(container.get("metrics", []))
    return CVEIngestPayload(
        **kwargs,
        affected_version_operations=operations,
        cvss_assessments=cvss,
        cwe_classifications=cwe,
        ssvc_assessment=ssvc,
        kev_data=kev,
    )


# ---------------------------------------------------------------------------
# parse_affected_versions
# ---------------------------------------------------------------------------


class TestAffectedSentinels:
    @pytest.mark.parametrize("vendor", ["n/a", "", None, _ABSENT])
    @pytest.mark.parametrize("product", ["n/a", "", None, _ABSENT])
    def test_both_sentinels_without_a_coordinate_skip_the_element(
        self, vendor: Any, product: Any
    ) -> None:
        element = _element(vendor=vendor, product=product, versions=[_version()])

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize("sentinel", ["n/a", "", None, _ABSENT])
    def test_sentinel_vendor_alone_is_none(self, sentinel: Any) -> None:
        (entry,) = parse_affected_versions([_element(vendor=sentinel)])

        assert (entry.vendor, entry.product) == (None, PRODUCT)

    @pytest.mark.parametrize("sentinel", ["n/a", "", None, _ABSENT])
    def test_sentinel_product_alone_is_none(self, sentinel: Any) -> None:
        (entry,) = parse_affected_versions([_element(product=sentinel)])

        assert (entry.vendor, entry.product) == (VENDOR, None)

    def test_uppercase_n_a_is_not_a_sentinel(self) -> None:
        element = _element(
            vendor="N/A", product="N/A", versions=[_version(version="N/A")]
        )

        (entry,) = parse_affected_versions([element])

        assert (entry.vendor, entry.product, entry.version) == ("N/A", "N/A", "N/A")

    @pytest.mark.parametrize("sentinel", ["n/a", "", None, _ABSENT])
    def test_sentinel_version_is_none(self, sentinel: Any) -> None:
        element = _element(versions=[_version(version=sentinel)])

        (entry,) = parse_affected_versions([element])

        assert entry.version is None
        assert entry.status == "affected"

    @pytest.mark.parametrize(
        ("key", "value", "field", "expected"),
        [
            ("packageName", "example-package", "package_name", "example-package"),
            (
                "packageURL",
                "pkg:generic/example-package",
                "package_url",
                "pkg:generic/example-package",
            ),
            (
                "collectionURL",
                "https://packages.example.invalid",
                "collection_url",
                "https://packages.example.invalid",
            ),
            (
                "repo",
                "https://git.example.invalid/example/project",
                "repo",
                "https://git.example.invalid/example/project",
            ),
            (
                "cpes",
                ["cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"],
                "cpe",
                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
            ),
        ],
    )
    def test_each_package_coordinate_keeps_a_both_sentinel_element(
        self, key: str, value: Any, field: str, expected: str
    ) -> None:
        element = {"vendor": "n/a", "product": "n/a", key: value}

        (entry,) = parse_affected_versions([element])

        assert (entry.vendor, entry.product) == (None, None)
        assert getattr(entry, field) == expected

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("packageName", ""),
            ("packageURL", ""),
            ("collectionURL", ""),
            ("repo", ""),
            ("cpes", []),
            ("cpes", [""]),
            ("cpes", ["", "cpe:2.3:a:example:second:*:*:*:*:*:*:*:*"]),
            ("packageName", None),
            ("cpes", None),
        ],
    )
    def test_empty_package_coordinate_does_not_keep_the_element(
        self, key: str, value: Any
    ) -> None:
        element = {"vendor": "n/a", "product": "n/a", key: value}

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    def test_unconsumed_identifying_fields_do_not_keep_the_element(self) -> None:
        element = {
            "vendor": "n/a",
            "product": "n/a",
            "modules": ["example-module"],
            "platforms": ["x86_64"],
            "programRoutines": [{"name": "example_routine"}],
            "defaultStatus": "affected",
            "programFiles": ["src/example.c"],
        }

        assert parse_affected_versions([element]) == []

    def test_package_only_element_keeps_its_versions(self) -> None:
        element = {
            "collectionURL": "https://packages.example.invalid",
            "packageName": "example-package",
            "defaultStatus": "unaffected",
            "versions": [_version(version="1.0"), _version(version="1.1")],
        }

        entries = parse_affected_versions([element])

        assert entries == [
            AffectedVersionEntry(
                collection_url="https://packages.example.invalid",
                package_name="example-package",
                default_status="unaffected",
                version=version,
                status="affected",
            )
            for version in ("1.0", "1.1")
        ]


class TestAffectedFields:
    @pytest.mark.parametrize("versions", [_ABSENT, None, []])
    def test_absent_or_empty_versions_yield_one_unversioned_entry(
        self, versions: Any
    ) -> None:
        element = _element(
            versions=versions,
            defaultStatus="affected",
            repo="https://git.example.invalid/example/project",
            cpes=["cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"],
            programFiles=["src/example.c"],
        )

        (entry,) = parse_affected_versions([element])

        assert entry == _entry(
            default_status="affected",
            repo="https://git.example.invalid/example/project",
            cpe="cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
            program_files=["src/example.c"],
        )
        assert entry.version is None
        assert entry.version_type is None
        assert entry.version_end is None
        assert entry.version_end_inclusive is None
        assert entry.status is None

    def test_every_field_is_mapped(self) -> None:
        element = {
            "vendor": VENDOR,
            "product": PRODUCT,
            "repo": "https://git.example.invalid/example/project",
            "packageURL": "pkg:generic/example-package",
            "collectionURL": "https://packages.example.invalid",
            "packageName": "example-package",
            "defaultStatus": "unaffected",
            "cpes": [
                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:example:other:*:*:*:*:*:*:*:*",
            ],
            "programFiles": ["src/example.c", "src/other.c"],
            "modules": ["ignored"],
            "versions": [
                {
                    "version": "1.0",
                    "versionType": "semver",
                    "lessThan": "1.4",
                    "status": "affected",
                    "changes": [{"at": "1.2", "status": "unaffected"}],
                }
            ],
        }

        assert parse_affected_versions([element]) == [
            AffectedVersionEntry(
                vendor=VENDOR,
                product=PRODUCT,
                repo="https://git.example.invalid/example/project",
                package_url="pkg:generic/example-package",
                collection_url="https://packages.example.invalid",
                package_name="example-package",
                default_status="unaffected",
                cpe="cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                program_files=["src/example.c", "src/other.c"],
                version="1.0",
                version_type="semver",
                version_end="1.4",
                version_end_inclusive=False,
                status="affected",
                ecosystem=None,
            )
        ]

    @pytest.mark.parametrize(
        ("bounds", "version_end", "inclusive"),
        [
            ({"lessThan": "2.0"}, "2.0", False),
            ({"lessThanOrEqual": "2.0"}, "2.0", True),
            ({"lessThan": "2.0", "lessThanOrEqual": "3.0"}, "2.0", False),
            ({"lessThan": None, "lessThanOrEqual": "3.0"}, "3.0", True),
            ({"lessThan": "2.0", "lessThanOrEqual": None}, "2.0", False),
            ({}, None, None),
            ({"lessThan": None, "lessThanOrEqual": None}, None, None),
            ({"lessThan": ""}, "", False),
        ],
    )
    def test_version_end_and_inclusivity(
        self, bounds: dict[str, Any], version_end: str | None, inclusive: bool | None
    ) -> None:
        element = _element(versions=[_version(**bounds)])

        (entry,) = parse_affected_versions([element])

        assert entry.version_end == version_end
        assert entry.version_end_inclusive is inclusive

    @pytest.mark.parametrize(
        "version_type", ["semver", "git", "custom", "original_commit_for_fix", "rpm"]
    )
    def test_version_type_is_an_open_set_stored_as_is(self, version_type: str) -> None:
        element = _element(versions=[_version(versionType=version_type)])

        (entry,) = parse_affected_versions([element])

        assert entry.version_type == version_type

    @pytest.mark.parametrize("status", ["affected", "unaffected", "unknown", "Other"])
    def test_status_and_default_status_are_stored_as_is(self, status: str) -> None:
        element = _element(defaultStatus=status, versions=[_version(status=status)])

        (entry,) = parse_affected_versions([element])

        assert (entry.status, entry.default_status) == (status, status)

    def test_first_cpe_is_used(self) -> None:
        element = _element(cpes=["cpe:/a:example:first", "cpe:/a:example:second"])

        (entry,) = parse_affected_versions([element])

        assert entry.cpe == "cpe:/a:example:first"

    def test_only_the_first_cpe_is_consumed(self) -> None:
        element = _element(cpes=["cpe:/a:example:first", 1, None])

        (entry,) = parse_affected_versions([element])

        assert entry.cpe == "cpe:/a:example:first"

    @pytest.mark.parametrize("cpes", [[], None, _ABSENT])
    def test_empty_or_absent_cpes_yield_none(self, cpes: Any) -> None:
        (entry,) = parse_affected_versions([_element(cpes=cpes)])

        assert entry.cpe is None

    @pytest.mark.parametrize(
        ("package_url", "expected"),
        [
            ("pkg:generic/example-package", "pkg:generic/example-package"),
            (_ABSENT, None),
            (None, None),
        ],
    )
    def test_package_url_is_optional(
        self, package_url: Any, expected: str | None
    ) -> None:
        (entry,) = parse_affected_versions([_element(packageURL=package_url)])

        assert entry.package_url == expected

    @pytest.mark.parametrize(
        ("program_files", "expected"),
        [
            (["src/a.c", "src/b.c"], ["src/a.c", "src/b.c"]),
            ([], []),
            (None, None),
            (_ABSENT, None),
        ],
    )
    def test_program_files_are_entry_level(
        self, program_files: Any, expected: list[str] | None
    ) -> None:
        element = _element(
            programFiles=program_files,
            versions=[_version(version="1.0"), _version(version="2.0")],
        )

        entries = parse_affected_versions([element])

        assert [entry.program_files for entry in entries] == [expected, expected]

    def test_entry_level_fields_are_copied_to_every_version(self) -> None:
        element = _element(
            defaultStatus="unaffected",
            packageName="example-package",
            versions=[_version(version="1.0"), _version(version="2.0")],
        )

        entries = parse_affected_versions([element])

        assert [(e.version, e.package_name, e.default_status) for e in entries] == [
            ("1.0", "example-package", "unaffected"),
            ("2.0", "example-package", "unaffected"),
        ]

    def test_unbounded_fields_accept_long_values(self) -> None:
        long = "x" * 5000
        element = _element(
            product=long,
            programFiles=[long],
            versions=[_version(version=long, lessThan=long)],
        )

        (entry,) = parse_affected_versions([element])

        assert (entry.product, entry.version, entry.version_end) == (long, long, long)
        assert entry.program_files == [long]

    def test_ecosystem_is_never_set(self) -> None:
        element = _element(ecosystem="PyPI", versions=[_version()])

        (entry,) = parse_affected_versions([element])

        assert entry.ecosystem is None

    def test_empty_array_yields_no_entry(self) -> None:
        assert parse_affected_versions([]) == []


class TestAffectedDeduplication:
    @pytest.mark.parametrize(
        ("first", "second"),
        [
            pytest.param(
                _element(versions=[_version(versionType="", status="affected")]),
                _element(versions=[_version(status="unaffected")]),
                id="version_type-empty-vs-absent",
            ),
            pytest.param(
                _element(versions=[_version(version="n/a", status="affected")]),
                _element(versions=[{"status": "unaffected"}]),
                id="version-n/a-vs-absent",
            ),
            pytest.param(
                _element(versions=[_version(version="", status="affected")]),
                _element(versions=[_version(version=None, status="unaffected")]),
                id="version-empty-vs-null",
            ),
            pytest.param(
                _element(versions=[_version(lessThan="", status="affected")]),
                _element(versions=[_version(status="unaffected")]),
                id="version_end-empty-vs-absent",
            ),
            pytest.param(
                _element(versions=[_version(lessThan="2.0")]),
                _element(versions=[_version(lessThanOrEqual="2.0")]),
                id="inclusivity-not-in-key",
            ),
            pytest.param(
                _element(packageName="", defaultStatus="affected"),
                _element(defaultStatus="unaffected"),
                id="package_name-empty-vs-absent",
            ),
            pytest.param(
                _element(repo="", defaultStatus="affected"),
                _element(repo=None, defaultStatus="unaffected"),
                id="repo-empty-vs-null",
            ),
            pytest.param(
                _element(vendor="", defaultStatus="affected"),
                _element(vendor=_ABSENT, defaultStatus="unaffected"),
                id="vendor-empty-normalized-vs-absent",
            ),
            pytest.param(
                _element(product="n/a", defaultStatus="affected"),
                _element(product="", defaultStatus="unaffected"),
                id="product-n/a-vs-empty",
            ),
            pytest.param(
                _element(packageURL="pkg:generic/a"),
                _element(packageURL="pkg:generic/b"),
                id="package_url-not-in-key",
            ),
            pytest.param(
                _element(collectionURL="https://a.example.invalid"),
                _element(collectionURL="https://b.example.invalid"),
                id="collection_url-not-in-key",
            ),
            pytest.param(
                _element(cpes=["cpe:/a:example:a"]),
                _element(cpes=["cpe:/a:example:b"]),
                id="cpe-not-in-key",
            ),
            pytest.param(
                _element(programFiles=["a.c"]),
                _element(programFiles=["b.c"]),
                id="program_files-not-in-key",
            ),
            pytest.param(
                _element(defaultStatus="affected"),
                _element(defaultStatus="unaffected"),
                id="default_status-not-in-key",
            ),
            pytest.param(
                _element(versions=[_version(status="affected")]),
                _element(versions=[_version(status="unknown")]),
                id="status-not-in-key",
            ),
        ],
    )
    def test_same_key_keeps_the_last_occurrence(
        self, first: dict[str, Any], second: dict[str, Any]
    ) -> None:
        first_alone = parse_affected_versions([first])
        second_alone = parse_affected_versions([second])
        assert first_alone != second_alone  # differing content, one key
        assert affected_version_key(first_alone[0]) == affected_version_key(
            second_alone[0]
        )

        assert parse_affected_versions([first, second]) == second_alone
        assert parse_affected_versions([second, first]) == first_alone

    def test_unparsed_same_key_entries_would_be_rejected_by_the_payload(self) -> None:
        """Guards the meaning of the deduplication: without it, these
        same-key entries are contradictory canonical content."""
        entries = [
            _entry(version="1.0", version_type=""),
            _entry(version="1.0", version_type=None),
        ]

        with pytest.raises(ValidationError):
            CVEIngestPayload(affected_version_operations=[_replace_operation(entries)])

    def test_same_key_within_one_element_keeps_the_last_version(self) -> None:
        element = _element(
            versions=[
                _version(version="1.0", status="affected"),
                _version(version="2.0"),
                _version(version="1.0", status="unaffected"),
            ]
        )

        entries = parse_affected_versions([element])

        assert sorted((e.version, e.status) for e in entries) == [
            ("1.0", "unaffected"),
            ("2.0", "affected"),
        ]
        _assert_accepted_as_snapshot(entries)

    def test_identical_duplicates_collapse(self) -> None:
        element = _element(versions=[_version(), _version()])

        assert parse_affected_versions([element, element]) == [
            _entry(version="1.0", status="affected")
        ]

    @pytest.mark.parametrize(
        ("first", "second"),
        [
            pytest.param(_element(vendor="A"), _element(vendor="B"), id="vendor"),
            pytest.param(
                _element(vendor="n/a"), _element(vendor="N/A"), id="vendor-n/a"
            ),
            pytest.param(_element(product="A"), _element(product="B"), id="product"),
            pytest.param(
                _element(versions=[_version(versionType="git")]),
                _element(versions=[_version(versionType="semver")]),
                id="version_type",
            ),
            pytest.param(
                _element(versions=[_version(version="1.0")]),
                _element(versions=[_version(version="2.0")]),
                id="version",
            ),
            pytest.param(
                _element(versions=[_version(lessThan="2.0")]),
                _element(versions=[_version(lessThan="3.0")]),
                id="version_end",
            ),
            pytest.param(
                _element(packageName="a"), _element(packageName="b"), id="package_name"
            ),
            pytest.param(
                _element(repo="https://a.example.invalid"),
                _element(repo="https://b.example.invalid"),
                id="repo",
            ),
        ],
    )
    def test_different_keys_are_kept(
        self, first: dict[str, Any], second: dict[str, Any]
    ) -> None:
        entries = parse_affected_versions([first, second])

        assert entries == parse_affected_versions([first]) + parse_affected_versions(
            [second]
        )
        _assert_accepted_as_snapshot(entries)

    def test_last_of_three_occurrences_wins_and_others_survive(self) -> None:
        a1 = _element(defaultStatus="affected")
        b = _element(product="example-other")
        a2 = _element(defaultStatus="unknown")

        entries = parse_affected_versions([a1, b, a2])

        assert len(entries) == 2
        assert _entry(product="example-other") in entries
        assert _entry(default_status="unknown") in entries
        _assert_accepted_as_snapshot(entries)

    def test_crafted_duplicates_form_a_valid_payload(self) -> None:
        affected = [
            _element(versions=[_version(versionType="", lessThan="")]),
            _element(versions=[_version(lessThanOrEqual="")]),
            _element(vendor="", versions=[_version()]),
            _element(vendor=_ABSENT, versions=[_version(status="unknown")]),
            _element(packageName="", repo=""),
            _element(packageName=None, repo=None, defaultStatus="affected"),
            SIBLING,
            SIBLING,
        ]

        entries = parse_affected_versions(affected)

        assert len(entries) == 4
        _assert_accepted_as_snapshot(entries)


class TestAffectedInvalidInput:
    @pytest.mark.parametrize(
        ("key", "bound"),
        [
            ("vendor", 512),
            ("packageURL", 2048),
            ("collectionURL", 2048),
            ("packageName", 2048),
            ("repo", 2048),
            ("defaultStatus", 20),
        ],
    )
    def test_element_level_bound(self, key: str, bound: int) -> None:
        at_bound = _element(**{key: "x" * bound})
        over = _element(product="example-over", **{key: "x" * (bound + 1)})

        entries = parse_affected_versions([at_bound, over, SIBLING])

        assert len(entries) == 2
        assert entries[1] == SIBLING_ENTRY
        assert entries[0].product == PRODUCT

    def test_first_cpe_bound(self) -> None:
        bound = 2048
        at_bound = _element(cpes=["c" * bound])
        over = _element(product="example-over", cpes=["c" * (bound + 1)])

        entries = parse_affected_versions([at_bound, over, SIBLING])

        assert [e.product for e in entries] == [PRODUCT, "example-sibling"]

    def test_element_level_bound_skips_every_version_of_the_element(self) -> None:
        over = _element(
            defaultStatus="x" * 21,
            versions=[_version(version="1.0"), _version(version="2.0")],
        )

        assert parse_affected_versions([over, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize(("key", "bound"), [("versionType", 128), ("status", 20)])
    def test_version_level_bound_skips_only_that_version(
        self, key: str, bound: int
    ) -> None:
        element = _element(
            versions=[
                _version(version="1.0", **{key: "x" * bound}),
                _version(version="2.0", **{key: "x" * (bound + 1)}),
                _version(version="3.0"),
            ]
        )

        entries = parse_affected_versions([element, SIBLING])

        assert [e.version for e in entries] == ["1.0", "3.0", "1.0"]
        assert entries[-1] == SIBLING_ENTRY

    @pytest.mark.parametrize(
        "key",
        [
            "vendor",
            "product",
            "repo",
            "packageURL",
            "collectionURL",
            "packageName",
            "defaultStatus",
        ],
    )
    @pytest.mark.parametrize("value", [1, 1.5, True, [], {}, ["x"], {"x": "y"}])
    def test_non_string_element_field_skips_the_element(
        self, key: str, value: Any
    ) -> None:
        element = _element(versions=[_version()], **{key: value})

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize(
        "key", ["version", "versionType", "lessThan", "lessThanOrEqual", "status"]
    )
    @pytest.mark.parametrize("value", [1, 1.5, False, [], {}, ["x"]])
    def test_non_string_version_field_skips_only_that_version(
        self, key: str, value: Any
    ) -> None:
        invalid = _version(**{"version": "2.0", key: value})
        element = _element(versions=[_version(version="1.0"), invalid])

        entries = parse_affected_versions([element, SIBLING])

        assert entries == [_entry(version="1.0", status="affected"), SIBLING_ENTRY]

    def test_non_string_less_than_or_equal_beside_less_than_is_unparseable(
        self,
    ) -> None:
        """Both bounds are consumed fields, so a mistyped one skips the
        version even though `lessThan` would win."""
        element = _element(versions=[_version(lessThan="2.0", lessThanOrEqual=2)])

        assert parse_affected_versions([element]) == []

    @pytest.mark.parametrize(
        "versions", [{}, {"version": "1.0"}, "1.0", 1, True, False, 0]
    )
    def test_non_list_versions_skips_the_element(self, versions: Any) -> None:
        element = _element(versions=versions)

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    def test_non_object_version_element_is_skipped(self) -> None:
        element = _element(versions=[None, "1.0", 1, [], _version(version="2.0")])

        (entry,) = parse_affected_versions([element])

        assert entry.version == "2.0"

    def test_versions_of_only_non_objects_yield_no_entry(self) -> None:
        """A non-empty `versions` array is not the absent-or-empty case of
        step 4; its every element is skipped."""
        element = _element(versions=[None, "1.0"])

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize("element", [None, 1, "x", [], [SIBLING], True])
    def test_non_object_affected_element_is_skipped(self, element: Any) -> None:
        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize(
        "cpes", ["cpe:/a:example:product", {"0": "cpe:/a:x"}, 1, [1], [None], [["x"]]]
    )
    def test_malformed_cpes_skip_the_element(self, cpes: Any) -> None:
        element = _element(cpes=cpes)

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize(
        "program_files", ["src/example.c", {"a": "b"}, 1, [1], ["a.c", None], [["a.c"]]]
    )
    def test_malformed_program_files_skip_the_element(self, program_files: Any) -> None:
        element = _element(programFiles=program_files)

        assert parse_affected_versions([element, SIBLING]) == [SIBLING_ENTRY]

    @pytest.mark.parametrize("affected", [None, {}, {"0": SIBLING}, "x", 1, 1.5, True])
    def test_wrong_typed_argument_yields_empty_list(self, affected: Any) -> None:
        assert parse_affected_versions(affected) == []


class TestAffectedFixtures:
    def test_package_only_element_yields_xz_entries(self) -> None:
        entries = parse_affected_versions(
            _container("cvelistv5_5_2_package_only_affected", "cna")["affected"]
        )

        package_only = [e for e in entries if e.vendor is None and e.product is None]
        assert [(e.package_name, e.version, e.status) for e in package_only] == [
            ("xz", "5.6.0", "affected"),
            ("xz", "5.6.1", "affected"),
        ]
        assert {e.collection_url for e in package_only} == {
            "https://github.com/tukaani-project/xz"
        }
        assert {e.default_status for e in package_only} == {"unaffected"}

    def test_red_hat_elements_without_versions_carry_their_cpe(self) -> None:
        entries = parse_affected_versions(
            _container("cvelistv5_5_2_package_only_affected", "cna")["affected"]
        )

        red_hat = [e for e in entries if e.vendor == "Red Hat"]
        assert [e.cpe for e in red_hat] == [
            "cpe:/o:redhat:enterprise_linux:10",
            "cpe:/a:redhat:jboss_enterprise_application_platform:8",
        ]
        for entry in red_hat:
            assert entry.package_name == "xz"
            assert (entry.version, entry.status, entry.version_end) == (
                None,
                None,
                None,
            )

    def test_n_a_element_without_coordinate_is_skipped(self) -> None:
        affected = _container("cvelistv5_kev_ssvc_offset_n_a", "cna")["affected"]

        assert affected
        assert parse_affected_versions(affected) == []

    @pytest.mark.parametrize(
        "name", ["cvelistv5_v3_1_non_base_en_us_kev", "cvelistv5_lowercase_cwe_type"]
    )
    def test_uppercase_n_a_version_is_kept(self, name: str) -> None:
        entries = parse_affected_versions(_container(name, "cna")["affected"])

        assert "N/A" in {e.version for e in entries}

    def test_kernel_record_yields_program_files_and_version_types(self) -> None:
        entries = parse_affected_versions(
            _container("vulns_published_5_1_1", "cna")["affected"]
        )

        assert len(entries) == 6
        for entry in entries:
            assert (entry.vendor, entry.product) == ("Linux", "Linux")
            assert entry.program_files == [
                "net/ipv4/cipso_ipv4.c",
                "net/netlabel/netlabel_kapi.c",
            ]
            assert entry.repo == (
                "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
            )
        assert {e.version_type for e in entries} == {
            "git",
            "semver",
            "original_commit_for_fix",
            None,
        }
        assert {e.version_end_inclusive for e in entries} == {True, False, None}
        git = [e for e in entries if e.version_type == "git"]
        assert {e.version for e in git} == {"446fda4f26822b2d42ab3396aafcedf38a9ff2b6"}
        assert len({e.version_end for e in git}) == 2

    def test_kernel_element_without_versions_yields_one_entry(self) -> None:
        entries = parse_affected_versions(
            _container("vulns_published_affected_without_versions", "cna")["affected"]
        )

        unversioned = [e for e in entries if e.version is None]
        assert unversioned == [
            AffectedVersionEntry(
                vendor="Linux",
                product="Linux",
                repo="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
                program_files=["drivers/thermal/thermal_core.c"],
                default_status="unaffected",
            )
        ]

    def test_legacy_kernel_record_keeps_custom_version_type(self) -> None:
        entries = parse_affected_versions(
            _container("vulns_rejected_5_0_legacy_cve_id", "cna")["affected"]
        )

        assert "custom" in {e.version_type for e in entries}

    def test_package_url_on_a_package_only_element(self) -> None:
        (entry,) = parse_affected_versions(
            _container("cvelistv5_package_url_package_only", "cna")["affected"]
        )

        assert (entry.vendor, entry.product) == (None, None)
        assert entry.package_url == "pkg:cpan/HTML-FormHandler"
        assert entry.package_name == "HTML-FormHandler"
        assert entry.program_files == [
            "lib/HTML/FormHandler/Validate.pm",
            "lib/HTML/FormHandler/Field.pm",
        ]

    def test_package_url_with_vendor_and_product(self) -> None:
        (entry,) = parse_affected_versions(
            _container("cvelistv5_package_url_vendor", "cna")["affected"]
        )

        assert (entry.vendor, entry.product) == ("SuiteCRM", "SuiteCRM")
        assert entry.package_url == "pkg:github/SuiteCRM/SuiteCRM"

    def test_empty_cpes_fixture_yields_no_cpe(self) -> None:
        entries = parse_affected_versions(
            _container("cvelistv5_empty_cpes", "cna")["affected"]
        )

        assert entries
        assert {e.cpe for e in entries} == {None}

    def test_adp_affected_with_rpm_versions_and_cpes(self) -> None:
        entries = parse_affected_versions(
            _container("cvelistv5_program_files_adp_affected", "adp:redhat-SADP")[
                "affected"
            ]
        )

        assert len(entries) == 3
        assert all(e.cpe and e.package_name == "perl-XML-Parser" for e in entries)
        assert [e.version_type for e in entries] == ["rpm", "rpm", None]
        assert entries[2].version is None

    def test_less_than_or_equal_fixture_is_inclusive(self) -> None:
        (entry,) = parse_affected_versions(
            _container("cvelistv5_program_files_adp_affected", "cna")["affected"]
        )

        assert (entry.version_end, entry.version_end_inclusive) == ("2.47", True)
        assert entry.program_files == ["Expat.xs"]

    def test_unknown_status_is_kept(self) -> None:
        entries = parse_affected_versions(
            _container("cvelistv5_unknown_version_status", "cna")["affected"]
        )

        assert {e.status for e in entries} == {"affected", "unknown"}

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_scope_is_a_valid_replace_snapshot(self, name: str) -> None:
        for _, container in _containers(load_fixture(name)):
            entries = parse_affected_versions(container.get("affected"))
            assert all(isinstance(e, AffectedVersionEntry) for e in entries)
            assert all(e.ecosystem is None for e in entries)
            _assert_accepted_as_snapshot(entries)


# ---------------------------------------------------------------------------
# parse_cvss_assessments
# ---------------------------------------------------------------------------

_FIXTURE_CVSS: Final[dict[tuple[str, str], set[str]]] = {
    ("cvelistv5_5_2_package_only_affected", "cna"): {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    },
    ("cvelistv5_kev_ssvc_offset_n_a", "adp:CISA-ADP"): {
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H"
    },
    ("cvelistv5_all_cvss_keys_en_de", "cna"): {
        "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "AV:N/AC:H/Au:N/C:P/I:P/A:P",
    },
    ("cvelistv5_v4_supplemental_non_base", "cna"): {
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N"
    },
    ("cvelistv5_v3_1_non_base_en_us_kev", "cna"): {
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"
    },
    ("cvelistv5_all_cvss_keys_non_base", "cna"): {
        "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
        "AV:A/AC:M/Au:S/C:P/I:P/A:P",
    },
    ("cvelistv5_v3_0_non_base_unordered", "cna"): {
        "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
    },
    ("cvelistv5_package_url_package_only", "adp:CISA-ADP"): {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    ("cvelistv5_package_url_vendor", "cna"): {
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    },
    ("cvelistv5_program_files_adp_affected", "adp:CISA-ADP"): {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    ("cvelistv5_program_files_adp_affected", "adp:redhat-SADP"): {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    },
    ("cvelistv5_lowercase_cwe_type", "cna"): {
        "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N"
    },
    ("cvelistv5_cwe_id_without_type", "cna"): {
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
    },
    ("cvelistv5_adp_cvss_v4", "cna"): {"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"},
    ("cvelistv5_adp_cvss_v4", "adp:CISA-ADP"): {
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    },
    ("cvelistv5_repeated_cvss_v4", "cna"): {
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
    },
    ("cvelistv5_unknown_version_status", "adp:CISA-ADP"): {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    },
    ("cvelistv5_empty_cpes", "cna"): {"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N"},
    ("cvelistv5_coexisting_cvss_keys", "cna"): {
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
    },
    ("vulns_published_5_1_1", "cna"): {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H"},
}
"""(fixture, scope) → canonical Base vectors; every other scope yields none.
The non-Base received vectors are listed in the contract test."""


class TestCvssProvider:
    @pytest.mark.parametrize(
        "provider", ["SUSE", " suse ", "Suse", "SUSE\t", "sUsE", "\nSUSE\n"]
    )
    def test_reserved_provider_yields_no_candidate(self, provider: str) -> None:
        assert parse_cvss_assessments([_cvss("cvssV3_1", V31)], provider) == []

    @pytest.mark.parametrize(
        "provider", ["adp:SUSE", "SUSE Linux", "SUSE-CNA", "SU SE"]
    )
    def test_non_reserved_suse_like_provider_is_stamped(self, provider: str) -> None:
        (entry,) = parse_cvss_assessments([_cvss("cvssV3_1", V31)], provider)

        assert entry.provider_name == provider

    @pytest.mark.parametrize("provider", [None, 1, ["SUSE"], {"shortName": "x"}, b"x"])
    def test_non_string_provider_yields_no_candidate(self, provider: Any) -> None:
        assert parse_cvss_assessments([_cvss("cvssV3_1", V31)], provider) == []

    @pytest.mark.parametrize(
        ("provider", "stamped"),
        [
            ("  Example CNA  ", "Example CNA"),
            ("Example CNA\n", "Example CNA"),
            ("", ""),
        ],
    )
    def test_provider_is_stamped_trimmed(self, provider: str, stamped: str) -> None:
        (entry,) = parse_cvss_assessments([_cvss("cvssV3_1", V31)], provider)

        assert entry == CVSSAssessmentEntry(provider_name=stamped, vector_string=V31)


class TestCvssCandidates:
    def test_key_order_is_v4_v3_1_v3_0_v2(self) -> None:
        assert CVSS_VECTOR_KEYS == ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

    def test_every_key_of_one_metrics_entry_is_a_candidate(self) -> None:
        metric = {
            "cvssV2_0": {"vectorString": V20},
            "cvssV3_0": {"vectorString": V30},
            "cvssV3_1": {"vectorString": V31},
            "cvssV4_0": {"vectorString": V40},
        }

        entries = parse_cvss_assessments([metric], PROVIDER)

        assert _vectors(entries) == [V40, V31, V30, V20]
        assert {e.provider_name for e in entries} == {PROVIDER}

    def test_keys_in_separate_entries_are_candidates(self) -> None:
        metrics = [
            _cvss(key, v)
            for key, v in zip(CVSS_VECTOR_KEYS, [V40, V31, V30, V20], strict=True)
        ]

        assert set(_vectors(parse_cvss_assessments(metrics, PROVIDER))) == {
            V40,
            V31,
            V30,
            V20,
        }

    @pytest.mark.parametrize(
        ("key", "received", "canonical"),
        [
            (
                "cvssV3_1",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            (
                "cvssV3_0",
                "CVSS:3.0/C:H/AV:N/I:H/AC:L/A:H/PR:N/UI:N/S:U/MAV:L",
                V30,
            ),
            ("cvssV4_0", V40 + "/E:A/RE:L/U:Red", V40),
            ("cvssV2_0", V20 + "/E:POC/RL:OF/RC:C/CDP:L", V20),
            ("cvssV3_1", "  " + V31 + "\t", V31),
        ],
    )
    def test_vector_goes_through_the_external_base_reduction(
        self, key: str, received: str, canonical: str
    ) -> None:
        (entry,) = parse_cvss_assessments([_cvss(key, received)], PROVIDER)

        assert entry.vector_string == canonical

    @pytest.mark.parametrize(
        "vector",
        [
            pytest.param("CVSS:3.1/AV:N/AC:L", id="incomplete"),
            pytest.param("cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="case"),
            pytest.param(V31 + "/E:Z", id="invalid-non-base-value"),
            pytest.param(V31 + "/E:P/E:P", id="duplicate-non-base"),
            pytest.param(V31 + "/XX:Y", id="unknown-metric"),
            pytest.param("CVSS:3.2/AV:N", id="unsupported-version"),
            pytest.param(" " * (201 - len(V31)) + V31, id="over-200-before-trim"),
            pytest.param("x" * 5000, id="over-200"),
            pytest.param("CVSS:3.1/AV:N /AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", id="space"),
            pytest.param(V31.replace("/", "/\t", 1), id="tab"),
            pytest.param("", id="empty"),
            pytest.param("   ", id="blank"),
            pytest.param(V31 + "\x00", id="nul"),
            pytest.param(None, id="null"),
            pytest.param(3.1, id="number"),
            pytest.param([V31], id="list"),
            pytest.param({"v": V31}, id="object"),
            pytest.param(True, id="bool"),
        ],
    )
    def test_rejected_vector_is_skipped(self, vector: Any) -> None:
        metrics = [_cvss("cvssV3_1", vector), _cvss("cvssV4_0", V40)]

        assert _vectors(parse_cvss_assessments(metrics, PROVIDER)) == [V40]

    def test_vector_at_200_characters_before_trim_is_accepted(self) -> None:
        received = " " * (200 - len(V31)) + V31

        (entry,) = parse_cvss_assessments([_cvss("cvssV3_1", received)], PROVIDER)

        assert entry.vector_string == V31

    @pytest.mark.parametrize("cvss", [None, V31, 1, [{"vectorString": V31}], {}])
    def test_malformed_cvss_object_skips_only_that_candidate(self, cvss: Any) -> None:
        metric = {"cvssV3_1": cvss, "cvssV4_0": {"vectorString": V40}}

        assert _vectors(parse_cvss_assessments([metric], PROVIDER)) == [V40]

    def test_last_valid_candidate_per_version_wins(self) -> None:
        metrics = [
            _cvss("cvssV3_1", V31),
            _cvss("cvssV4_0", V40),
            _cvss("cvssV3_1", V31_ALT),
        ]

        entries = parse_cvss_assessments(metrics, PROVIDER)

        assert sorted(_vectors(entries)) == sorted([V31_ALT, V40])

    def test_later_invalid_candidate_does_not_displace_a_valid_one(self) -> None:
        metrics = [
            _cvss("cvssV3_1", V31),
            _cvss("cvssV3_1", "CVSS:3.1/AV:N"),
            _cvss("cvssV3_1", None),
        ]

        assert _vectors(parse_cvss_assessments(metrics, PROVIDER)) == [V31]

    def test_version_is_derived_from_the_vector_not_the_key(self) -> None:
        (entry,) = parse_cvss_assessments([_cvss("cvssV3_1", V30)], PROVIDER)

        assert entry.vector_string == V30

    def test_keys_deriving_one_version_keep_the_later_in_traversal_order(self) -> None:
        """`cvssV3_1` is inspected before `cvssV3_0`, so a v3.0 vector under
        `cvssV3_0` displaces one under `cvssV3_1` within one entry."""
        metric = {
            "cvssV3_0": {"vectorString": V30_ALT},
            "cvssV3_1": {"vectorString": V30},
        }

        assert _vectors(parse_cvss_assessments([metric], PROVIDER)) == [V30_ALT]

    def test_equal_canonical_vectors_collapse(self) -> None:
        metrics = [_cvss("cvssV3_1", V31), _cvss("cvssV3_1", V31 + "/E:P")]

        assert _vectors(parse_cvss_assessments(metrics, PROVIDER)) == [V31]

    def test_at_most_four_entries(self) -> None:
        metric = {
            "cvssV2_0": {"vectorString": V20},
            "cvssV3_0": {"vectorString": V30},
            "cvssV3_1": {"vectorString": V31},
            "cvssV4_0": {"vectorString": V40},
        }

        entries = parse_cvss_assessments([metric] * 10, PROVIDER)

        assert len(entries) == 4

    def test_numeric_score_without_vector_is_ignored(self) -> None:
        metric = {
            "cvssV3_1": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}
        }

        assert parse_cvss_assessments([metric], PROVIDER) == []

    def test_other_metrics_are_ignored(self) -> None:
        metrics = [
            _other("ssvc", _ssvc_content()),
            _other("kev", _kev_content()),
            _other(
                "Red Hat severity rating", {"value": "Important", "vectorString": V31}
            ),
            {"other": {"type": "cvss", "content": {"vectorString": V31}}},
            {"cvssV3_2": {"vectorString": V31}},
            {"vectorString": V31},
        ]

        assert parse_cvss_assessments(metrics, PROVIDER) == []

    @pytest.mark.parametrize("element", [None, 1, V31, [_cvss("cvssV3_1", V31)]])
    def test_non_object_metrics_element_is_skipped(self, element: Any) -> None:
        metrics = [element, _cvss("cvssV4_0", V40)]

        assert _vectors(parse_cvss_assessments(metrics, PROVIDER)) == [V40]

    @pytest.mark.parametrize(
        "metrics", [None, {}, _cvss("cvssV3_1", V31), "x", 1, True]
    )
    def test_wrong_typed_argument_yields_empty_list(self, metrics: Any) -> None:
        assert parse_cvss_assessments(metrics, PROVIDER) == []

    def test_empty_array_yields_no_entry(self) -> None:
        assert parse_cvss_assessments([], PROVIDER) == []


class TestCvssFixtures:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_scope_yields_its_canonical_base_vectors(self, name: str) -> None:
        record = load_fixture(name)
        for label, container in _containers(record):
            provider = _provider(label, container)

            entries = parse_cvss_assessments(container.get("metrics"), provider)

            assert set(_vectors(entries)) == _FIXTURE_CVSS.get((name, label), set())
            assert len(entries) == len(set(_vectors(entries)))
            assert {e.provider_name for e in entries} <= {provider}

    def test_all_four_keys_yield_all_four_versions_in_traversal_order(self) -> None:
        metrics = _container("cvelistv5_all_cvss_keys_non_base", "cna")["metrics"]

        entries = parse_cvss_assessments(metrics, "VulDB")

        assert [str(v)[:8] for v in _vectors(entries)] == [
            "CVSS:4.0",
            "CVSS:3.1",
            "CVSS:3.0",
            "AV:A/AC:",
        ]

    def test_repeated_v4_keeps_the_last_valid_vector(self) -> None:
        metrics = _container("cvelistv5_repeated_cvss_v4", "cna")["metrics"]
        first, last = [m["cvssV4_0"]["vectorString"] for m in metrics]
        assert first != last

        assert _vectors(parse_cvss_assessments(metrics, "Temporal")) == [last]

    def test_repeated_v4_with_an_invalid_last_keeps_the_first(self) -> None:
        metrics = _container("cvelistv5_repeated_cvss_v4", "cna")["metrics"]
        first = metrics[0]["cvssV4_0"]["vectorString"]
        metrics[1]["cvssV4_0"]["vectorString"] = first + "/E:Z"

        assert _vectors(parse_cvss_assessments(metrics, "Temporal")) == [first]

    def test_fixture_provider_is_stamped(self) -> None:
        metrics = _container("cvelistv5_adp_cvss_v4", "adp:CISA-ADP")["metrics"]

        entries = parse_cvss_assessments(metrics, "adp:CISA-ADP")

        assert {e.provider_name for e in entries} == {"adp:CISA-ADP"}

    def test_fixture_with_reserved_provider_yields_nothing(self) -> None:
        metrics = _container("cvelistv5_all_cvss_keys_en_de", "cna")["metrics"]

        assert parse_cvss_assessments(metrics, " SUSE ") == []


# ---------------------------------------------------------------------------
# parse_cwe_classifications
# ---------------------------------------------------------------------------


def _problem(*descriptions: Any) -> dict[str, Any]:
    return {"descriptions": list(descriptions)}


def _cwe(cwe_id: Any = _ABSENT, type_: Any = "CWE") -> dict[str, Any]:
    description: dict[str, Any] = {
        "lang": "en",
        "description": "Fictional weakness",
        "type": type_,
        "cweId": cwe_id,
    }
    return {k: v for k, v in description.items() if v is not _ABSENT}


def _cwe_ids(entries: list[CWEEntry]) -> list[str]:
    return [entry.cwe_id for entry in entries]


_FIXTURE_CWE: Final[dict[tuple[str, str], list[str]]] = {
    ("cvelistv5_5_2_package_only_affected", "cna"): ["CWE-506"],
    ("cvelistv5_kev_ssvc_offset_n_a", "adp:CISA-ADP"): ["CWE-119"],
    ("cvelistv5_all_cvss_keys_en_de", "cna"): ["CWE-78"],
    ("cvelistv5_v4_supplemental_non_base", "cna"): ["CWE-200"],
    ("cvelistv5_v3_1_non_base_en_us_kev", "cna"): ["CWE-347"],
    ("cvelistv5_all_cvss_keys_non_base", "cna"): ["CWE-416", "CWE-119"],
    ("cvelistv5_package_url_package_only", "cna"): ["CWE-1336", "CWE-470"],
    ("cvelistv5_package_url_vendor", "cna"): ["CWE-89"],
    ("cvelistv5_program_files_adp_affected", "cna"): ["CWE-193", "CWE-122"],
    ("cvelistv5_program_files_adp_affected", "adp:redhat-SADP"): ["CWE-193"],
    ("cvelistv5_lowercase_cwe_type", "cna"): ["CWE-79"],
    ("cvelistv5_cwe_id_without_type", "cna"): ["CWE-611"],
    ("cvelistv5_adp_cvss_v4", "cna"): ["CWE-451"],
    ("cvelistv5_repeated_cvss_v4", "cna"): ["CWE-129"],
    ("cvelistv5_unknown_version_status", "adp:CISA-ADP"): ["CWE-352"],
    ("cvelistv5_empty_cpes", "cna"): ["CWE-89"],
    ("cvelistv5_coexisting_cvss_keys", "adp:CISA-ADP"): ["CWE-451"],
}
"""(fixture, scope) → CWE identifiers in first-occurrence order; every other
scope yields none."""


class TestCweClassifications:
    @pytest.mark.parametrize("type_", ["CWE", "cwe", "Cwe", "cWe"])
    def test_cwe_type_is_case_insensitive(self, type_: str) -> None:
        entries = parse_cwe_classifications([_problem(_cwe("CWE-79", type_))], SOURCE)

        assert entries == [CWEEntry(cwe_id="CWE-79", source=SOURCE)]

    @pytest.mark.parametrize("type_", [_ABSENT, None, "text", 1])
    def test_present_cwe_id_selects_without_cwe_type(self, type_: Any) -> None:
        entries = parse_cwe_classifications([_problem(_cwe("CWE-79", type_))], SOURCE)

        assert _cwe_ids(entries) == ["CWE-79"]

    @pytest.mark.parametrize("type_", ["CWE", "cwe"])
    def test_cwe_type_without_cwe_id_is_skipped(self, type_: str) -> None:
        problem = _problem(_cwe(type_=type_), _cwe("CWE-89"))

        assert _cwe_ids(parse_cwe_classifications([problem], SOURCE)) == ["CWE-89"]

    def test_text_type_without_cwe_id_is_not_selected(self) -> None:
        problem = _problem({"lang": "en", "description": "Fictional", "type": "text"})

        assert parse_cwe_classifications([problem], SOURCE) == []

    @pytest.mark.parametrize(
        "cwe_id",
        [
            "CWE-0",
            "CWE-079",
            "CWE-79 ",
            " CWE-79",
            "CWE-79\n",
            "cwe-79",
            "Cwe-79",
            "CWE79",
            "CWE-",
            "CWE--79",
            "CWE-7a",
            "NVD-CWE-noinfo",
            "NVD-CWE-Other",
            "CWE-" + "1" * 17,
            "CWE-" + "1" * 100,
            "CWE-٧٩",
            "",
            None,
            79,
            7.9,
            True,
            ["CWE-79"],
            {"id": "CWE-79"},
        ],
    )
    def test_invalid_cwe_id_is_skipped(self, cwe_id: Any) -> None:
        problem = _problem(_cwe(cwe_id), _cwe("CWE-89"))

        assert _cwe_ids(parse_cwe_classifications([problem], SOURCE)) == ["CWE-89"]

    def test_cwe_id_at_twenty_characters_is_accepted(self) -> None:
        cwe_id = "CWE-" + "1" * 16

        entries = parse_cwe_classifications([_problem(_cwe(cwe_id))], SOURCE)

        assert _cwe_ids(entries) == [cwe_id]

    def test_first_occurrence_per_cwe_id_is_retained(self) -> None:
        problem_types = [
            _problem(_cwe("CWE-79"), _cwe("CWE-89")),
            _problem(_cwe("CWE-79", "text"), _cwe("CWE-416")),
        ]

        entries = parse_cwe_classifications(problem_types, SOURCE)

        assert _cwe_ids(entries) == ["CWE-79", "CWE-89", "CWE-416"]

    def test_source_is_stamped(self) -> None:
        entries = parse_cwe_classifications([_problem(_cwe("CWE-79"))], "adp:CISA-ADP")

        assert entries == [CWEEntry(cwe_id="CWE-79", source="adp:CISA-ADP")]

    def test_source_at_100_characters_is_accepted(self) -> None:
        entries = parse_cwe_classifications([_problem(_cwe("CWE-79"))], "s" * 100)

        assert [e.source for e in entries] == ["s" * 100]

    @pytest.mark.parametrize("source", ["s" * 101, "cna:\x00", "\x00", None, 1])
    def test_invalid_source_skips_every_cwe(self, source: Any) -> None:
        problem = _problem(_cwe("CWE-79"), _cwe("CWE-89"))

        assert parse_cwe_classifications([problem], source) == []

    @pytest.mark.parametrize("descriptions", [None, {}, "CWE-79", 1, _ABSENT])
    def test_malformed_descriptions_skip_only_that_problem_type(
        self, descriptions: Any
    ) -> None:
        malformed = {} if descriptions is _ABSENT else {"descriptions": descriptions}
        problem_types = [malformed, _problem(_cwe("CWE-89"))]

        assert _cwe_ids(parse_cwe_classifications(problem_types, SOURCE)) == ["CWE-89"]

    @pytest.mark.parametrize("element", [None, 1, "CWE-79", [_cwe("CWE-79")]])
    def test_non_object_elements_are_skipped(self, element: Any) -> None:
        problem_types = [element, _problem(element, _cwe("CWE-89"))]

        assert _cwe_ids(parse_cwe_classifications(problem_types, SOURCE)) == ["CWE-89"]

    @pytest.mark.parametrize(
        "problem_types", [None, {}, _problem(_cwe("CWE-79")), "x", 1]
    )
    def test_wrong_typed_argument_yields_empty_list(self, problem_types: Any) -> None:
        assert parse_cwe_classifications(problem_types, SOURCE) == []

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_scopes_yield_their_cwes(self, name: str) -> None:
        for label, container in _containers(load_fixture(name)):
            entries = parse_cwe_classifications(container.get("problemTypes"), label)

            assert _cwe_ids(entries) == _FIXTURE_CWE.get((name, label), [])
            assert {e.source for e in entries} <= {label}

    def test_problem_type_without_type_or_cwe_id_yields_nothing(self) -> None:
        problem_types = _container("vulns_rejected_5_1_problem_types", "cna")[
            "problemTypes"
        ]

        assert problem_types
        assert parse_cwe_classifications(problem_types, "cna:Linux") == []


# ---------------------------------------------------------------------------
# parse_description and parse_title
# ---------------------------------------------------------------------------


class TestDescription:
    @pytest.mark.parametrize("lang", ["en", "en-US", "en-GB", "eng"])
    def test_english_entry_is_selected_over_an_earlier_other(self, lang: str) -> None:
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": lang, "value": "Fictional description."},
        ]

        assert parse_description(descriptions) == "Fictional description."

    def test_first_english_entry_wins(self) -> None:
        descriptions = [
            {"lang": "en-US", "value": "First fictional description."},
            {"lang": "en", "value": "Second fictional description."},
        ]

        assert parse_description(descriptions) == "First fictional description."

    def test_without_english_the_first_entry_is_used(self) -> None:
        descriptions = [
            {"lang": "de", "value": "Fiktive Beschreibung."},
            {"lang": "es", "value": "Descripción ficticia."},
        ]

        assert parse_description(descriptions) == "Fiktive Beschreibung."

    @pytest.mark.parametrize("lang", ["EN", "En-us", " en", "fr-en", None, 1, _ABSENT])
    def test_non_english_or_mistyped_lang_falls_back(self, lang: Any) -> None:
        first = {"lang": lang, "value": "First fictional description."}
        first = {k: v for k, v in first.items() if v is not _ABSENT}
        descriptions = [first, {"lang": "de", "value": "Fiktive Beschreibung."}]

        assert parse_description(descriptions) == "First fictional description."

    @pytest.mark.parametrize("value", [None, 1, ["x"], {"x": "y"}, True, _ABSENT])
    def test_entry_with_non_string_value_is_ignored(self, value: Any) -> None:
        ignored = {
            k: v for k, v in {"lang": "en", "value": value}.items() if v is not _ABSENT
        }
        descriptions = [ignored, {"lang": "de", "value": "Fiktive Beschreibung."}]

        assert parse_description(descriptions) == "Fiktive Beschreibung."

    @pytest.mark.parametrize(
        "descriptions",
        [[], [{"lang": "en", "value": None}], [None, 1, "x"], [{"lang": "en"}]],
    )
    def test_no_string_value_yields_none(self, descriptions: list[Any]) -> None:
        assert parse_description(descriptions) is None

    @pytest.mark.parametrize("value", ["", "a\x00b", "\r\nFictional\r\n", "x" * 10000])
    def test_value_is_returned_unvalidated(self, value: str) -> None:
        assert parse_description([{"lang": "en", "value": value}]) == value

    @pytest.mark.parametrize(
        "descriptions", [None, {}, {"lang": "en", "value": "x"}, "x", 1]
    )
    def test_wrong_typed_argument_yields_none(self, descriptions: Any) -> None:
        assert parse_description(descriptions) is None

    @pytest.mark.parametrize(
        ("name", "prefix"),
        [
            (
                "cvelistv5_all_cvss_keys_en_de",
                "Fictional description of CVE-2005-10003",
            ),
            (
                "cvelistv5_v3_1_non_base_en_us_kev",
                "Fictional description of CVE-2013-3900",
            ),
            ("vulns_published_5_1_1", "In the Linux kernel"),
        ],
    )
    def test_fixture_english_description(self, name: str, prefix: str) -> None:
        cna = _container(name, "cna")

        assert str(parse_description(cna["descriptions"])).startswith(prefix)

    def test_fixture_crlf_is_preserved(self) -> None:
        cna = _container("cvelistv5_5_2_package_only_affected", "cna")

        assert "\r\n" in str(parse_description(cna["descriptions"]))


class TestTitle:
    @pytest.mark.parametrize(
        ("title", "expected"),
        [
            ("Fictional title", "Fictional title"),
            ("", ""),
            ("t" * 256, "t" * 256),
            ("t" * 257, "t" * 256),
            ("a" * 255 + "bc", "a" * 255 + "b"),
            ("x" * 5000, "x" * 256),
        ],
    )
    def test_title_is_truncated_to_256_characters(
        self, title: str, expected: str
    ) -> None:
        assert TITLE_MAX_LENGTH == 256

        assert parse_title({"title": title}) == expected

    @pytest.mark.parametrize("title", [None, 1, 1.5, True, ["x"], {"x": "y"}, _ABSENT])
    def test_non_string_title_is_none(self, title: Any) -> None:
        cna = {} if title is _ABSENT else {"title": title}

        assert parse_title(cna) is None

    @pytest.mark.parametrize("title", ["\x00", "a\x00b", "Fictional\x00"])
    def test_title_is_returned_unvalidated(self, title: str) -> None:
        assert parse_title({"title": title}) == title

    @pytest.mark.parametrize("cna", [None, [], "title", 1, [{"title": "x"}]])
    def test_wrong_typed_argument_yields_none(self, cna: Any) -> None:
        assert parse_title(cna) is None

    def test_fixture_title(self) -> None:
        cna = _container("vulns_published_5_1_1", "cna")

        assert parse_title(cna) == "example: fictional title of CVE-2019-25160"

    def test_fixture_without_title(self) -> None:
        assert (
            parse_title(_container("vulns_rejected_5_1_problem_types", "cna")) is None
        )


# ---------------------------------------------------------------------------
# validate_cve_id
# ---------------------------------------------------------------------------


class TestValidateCveId:
    @pytest.mark.parametrize(
        "metadata",
        [
            pytest.param({"cveId": CVE_ID}, id="match"),
            pytest.param({"cveID": CVE_ID}, id="legacy-match"),
            pytest.param({"cveId": CVE_ID, "cveID": "CVE-2026-9999"}, id="both"),
            pytest.param({}, id="neither"),
            pytest.param({"cveId": "CVE-2026-9999"}, id="mismatch"),
            pytest.param({"cveID": "CVE-2026-9999"}, id="legacy-mismatch"),
            pytest.param({"cveId": CVE_ID.lower()}, id="case-insensitive-match"),
            pytest.param({"cveId": None}, id="null"),
            pytest.param({"cveId": 2026}, id="non-string"),
            pytest.param({"cveId": CVE_ID + "\x00"}, id="nul"),
            pytest.param(None, id="null-metadata"),
            pytest.param([], id="list-metadata"),
            pytest.param(CVE_ID, id="string-metadata"),
        ],
    )
    def test_filename_id_is_always_returned(self, metadata: Any) -> None:
        assert validate_cve_id(CVE_ID, metadata) == CVE_ID

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_cve_id(self, name: str) -> None:
        metadata = load_fixture(name)["cveMetadata"]

        assert validate_cve_id(source_cve_id(name), metadata) == source_cve_id(name)

    def test_legacy_fixture_with_mismatching_file_name(self) -> None:
        metadata = load_fixture("vulns_rejected_5_0_legacy_cve_id")["cveMetadata"]
        assert "cveID" in metadata

        assert validate_cve_id("CVE-2026-0002", metadata) == "CVE-2026-0002"


# ---------------------------------------------------------------------------
# parse_ssvc_assessment
# ---------------------------------------------------------------------------


class TestSsvc:
    def test_complete_assessment(self) -> None:
        assert parse_ssvc_assessment([_other("ssvc", _ssvc_content())]) == _ssvc_entry()

    @pytest.mark.parametrize(
        ("timestamp", "expected"),
        [
            (
                "2024-04-02T04:00:23.138684Z",
                datetime(2024, 4, 2, 4, 0, 23, 138684, tzinfo=UTC),
            ),
            ("2022-03-14T00:00:00+00:00", datetime(2022, 3, 14, tzinfo=UTC)),
            ("2024-01-01T12:00:00", datetime(2024, 1, 1, 12, tzinfo=UTC)),
            ("2024-01-01T12:00:00+02:00", datetime(2024, 1, 1, 10, tzinfo=UTC)),
            ("2024-01-01T00:30:00-01:00", datetime(2024, 1, 1, 1, 30, tzinfo=UTC)),
        ],
    )
    def test_assessed_at_is_aware_utc(self, timestamp: str, expected: datetime) -> None:
        entry = parse_ssvc_assessment(
            [_other("ssvc", _ssvc_content(timestamp=timestamp))]
        )

        assert entry is not None
        assert entry.assessed_at == expected
        assert entry.assessed_at.tzinfo is UTC

    @pytest.mark.parametrize("timestamp", [_ABSENT, None])
    def test_absent_timestamp_yields_no_assessed_at(self, timestamp: Any) -> None:
        entry = parse_ssvc_assessment(
            [_other("ssvc", _ssvc_content(timestamp=timestamp))]
        )

        assert entry == _ssvc_entry(assessed_at=None)

    @pytest.mark.parametrize(
        "timestamp",
        [
            "",
            "2024-01-01",
            "2024-01-01 12:00:00",
            "garbage",
            "2024-13-01T00:00:00Z",
            "2024-01-01T12:00:00\x00",
            "\x00",
            "0001-01-01T00:00:00+01:00",
            1,
            1.5,
            True,
            [],
            {},
        ],
    )
    def test_malformed_timestamp_yields_none(self, timestamp: Any) -> None:
        metrics = [_other("ssvc", _ssvc_content(timestamp=timestamp))]

        assert parse_ssvc_assessment(metrics) is None

    def test_last_ssvc_entry_is_used(self) -> None:
        metrics = [
            _other("ssvc", _ssvc_content(exploitation="none")),
            _other("kev", _kev_content()),
            _other("ssvc", _ssvc_content(exploitation="poc")),
        ]

        entry = parse_ssvc_assessment(metrics)

        assert entry == _ssvc_entry(exploitation=SSVCExploitation.POC)

    @pytest.mark.parametrize(
        "last",
        [
            _ssvc_content(exploitation=_ABSENT),
            _ssvc_content(version=_ABSENT),
            _ssvc_content(timestamp="garbage"),
            None,
            [],
        ],
    )
    def test_incomplete_last_entry_wins_over_an_earlier_complete(
        self, last: Any
    ) -> None:
        metrics = [_other("ssvc", _ssvc_content()), _other("ssvc", last)]

        assert parse_ssvc_assessment(metrics) is None

    def test_complete_last_entry_wins_over_an_earlier_incomplete(self) -> None:
        metrics = [
            _other("ssvc", _ssvc_content(exploitation=_ABSENT)),
            _other("ssvc", _ssvc_content()),
        ]

        assert parse_ssvc_assessment(metrics) == _ssvc_entry()

    def test_options_are_found_by_key_in_any_order_and_shape(self) -> None:
        content = _ssvc_content()
        content["options"] = [
            {"Technical Impact": "partial", "Unrelated": "x"},
            "not-an-object",
            None,
            {"Automatable": "yes", "Exploitation": "poc"},
        ]

        entry = parse_ssvc_assessment([_other("ssvc", content)])

        assert entry == _ssvc_entry(
            exploitation=SSVCExploitation.POC,
            automatable=SSVCAutomatable.YES,
            technical_impact=SSVCTechnicalImpact.PARTIAL,
        )

    def test_first_object_carrying_a_key_supplies_it(self) -> None:
        content = _ssvc_content()
        content["options"].append({"Exploitation": "none"})

        entry = parse_ssvc_assessment([_other("ssvc", content)])

        assert entry is not None
        assert entry.exploitation is SSVCExploitation.ACTIVE

    def test_first_object_with_a_null_value_makes_the_point_missing(self) -> None:
        content = _ssvc_content()
        content["options"].insert(0, {"Exploitation": None})

        assert parse_ssvc_assessment([_other("ssvc", content)]) is None

    @pytest.mark.parametrize(
        "point", ["exploitation", "automatable", "technical_impact", "version"]
    )
    @pytest.mark.parametrize("missing", [_ABSENT, None, ""])
    def test_missing_field_yields_none(self, point: str, missing: Any) -> None:
        content = _ssvc_content(**{point: missing})

        assert parse_ssvc_assessment([_other("ssvc", content)]) is None

    @pytest.mark.parametrize(
        ("point", "value"),
        [
            ("exploitation", "Active"),
            ("exploitation", "ACTIVE"),
            ("exploitation", " active"),
            ("exploitation", "high"),
            ("exploitation", "public poc"),
            ("automatable", "Yes"),
            ("automatable", "true"),
            ("technical_impact", "Total"),
            ("technical_impact", "partial "),
            ("exploitation", 1),
            ("automatable", True),
            ("technical_impact", ["total"]),
            ("exploitation", {"value": "active"}),
        ],
    )
    def test_value_outside_its_enum_yields_none(self, point: str, value: Any) -> None:
        content = _ssvc_content(**{point: value})

        assert parse_ssvc_assessment([_other("ssvc", content)]) is None

    @pytest.mark.parametrize(
        ("exploitation", "automatable", "technical_impact"),
        [
            (e, a, t)
            for e in SSVCExploitation
            for a in SSVCAutomatable
            for t in SSVCTechnicalImpact
        ],
    )
    def test_every_enum_member_is_accepted(
        self,
        exploitation: SSVCExploitation,
        automatable: SSVCAutomatable,
        technical_impact: SSVCTechnicalImpact,
    ) -> None:
        content = _ssvc_content(
            exploitation=exploitation.value,
            automatable=automatable.value,
            technical_impact=technical_impact.value,
        )

        entry = parse_ssvc_assessment([_other("ssvc", content)])

        assert entry is not None
        assert (entry.exploitation, entry.automatable, entry.technical_impact) == (
            exploitation,
            automatable,
            technical_impact,
        )

    @pytest.mark.parametrize("version", ["1", "2.0.3", "v" * 10])
    def test_version_within_ten_characters_is_accepted(self, version: str) -> None:
        entry = parse_ssvc_assessment([_other("ssvc", _ssvc_content(version=version))])

        assert entry is not None
        assert entry.version == version

    @pytest.mark.parametrize("version", ["v" * 11, 2, 2.0, True, [], ["2.0.3"], {}])
    def test_invalid_version_yields_none(self, version: Any) -> None:
        metrics = [_other("ssvc", _ssvc_content(version=version))]

        assert parse_ssvc_assessment(metrics) is None

    @pytest.mark.parametrize("options", [None, {}, "Exploitation", 1, _ABSENT])
    def test_malformed_options_yield_none(self, options: Any) -> None:
        content = _ssvc_content()
        if options is _ABSENT:
            del content["options"]
        else:
            content["options"] = options

        assert parse_ssvc_assessment([_other("ssvc", content)]) is None

    @pytest.mark.parametrize("content", [None, [], "ssvc", 1, _ABSENT])
    def test_malformed_content_yields_none(self, content: Any) -> None:
        metric: dict[str, Any] = {"other": {"type": "ssvc"}}
        if content is not _ABSENT:
            metric["other"]["content"] = content

        assert parse_ssvc_assessment([metric]) is None

    @pytest.mark.parametrize(
        "metric",
        [
            _other("SSVC", _ssvc_content()),
            _other(" ssvc", _ssvc_content()),
            _other("kev", _ssvc_content()),
            {"other": [_ssvc_content()]},
            {"other": None},
            {"ssvc": _ssvc_content()},
            _cvss("cvssV3_1", V31),
        ],
    )
    def test_entry_not_typed_ssvc_is_ignored(self, metric: Any) -> None:
        assert parse_ssvc_assessment([metric]) is None

    def test_non_ssvc_entries_after_it_do_not_hide_it(self) -> None:
        metrics = [
            _other("ssvc", _ssvc_content()),
            {"other": None},
            None,
            "x",
            _other("SSVC", None),
        ]

        assert parse_ssvc_assessment(metrics) == _ssvc_entry()

    @pytest.mark.parametrize(
        "metrics", [None, {}, _other("ssvc", _ssvc_content()), "x", 1]
    )
    def test_wrong_typed_argument_yields_none(self, metrics: Any) -> None:
        assert parse_ssvc_assessment(metrics) is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            (
                "cvelistv5_kev_ssvc_offset_n_a",
                (
                    SSVCExploitation.ACTIVE,
                    SSVCAutomatable.NO,
                    SSVCTechnicalImpact.TOTAL,
                    datetime(2022, 3, 14, tzinfo=UTC),
                ),
            ),
            (
                "cvelistv5_5_2_package_only_affected",
                (
                    SSVCExploitation.NONE,
                    SSVCAutomatable.YES,
                    SSVCTechnicalImpact.TOTAL,
                    datetime(2024, 4, 2, 4, 0, 23, 138684, tzinfo=UTC),
                ),
            ),
            (
                "cvelistv5_adp_cvss_v4",
                (
                    SSVCExploitation.POC,
                    SSVCAutomatable.NO,
                    SSVCTechnicalImpact.PARTIAL,
                    datetime(2025, 12, 5, 16, 28, 14, 614877, tzinfo=UTC),
                ),
            ),
        ],
    )
    def test_fixture_assessment(self, name: str, expected: tuple[Any, ...]) -> None:
        entry = parse_ssvc_assessment(_container(name, "adp:CISA-ADP")["metrics"])

        assert entry is not None
        assert (
            entry.exploitation,
            entry.automatable,
            entry.technical_impact,
            entry.assessed_at,
        ) == expected
        assert entry.version == "2.0.3"

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_every_cisa_adp_fixture_parses_and_no_other_scope_does(
        self, name: str
    ) -> None:
        for label, container in _containers(load_fixture(name)):
            entry = parse_ssvc_assessment(container.get("metrics"))
            if label == "adp:CISA-ADP":
                assert entry is not None
                assert entry.version == "2.0.3"
                assert entry.assessed_at is not None
                assert entry.assessed_at.utcoffset() == timedelta(0)
            else:
                assert entry is None


# ---------------------------------------------------------------------------
# parse_kev_data
# ---------------------------------------------------------------------------


class TestKev:
    def test_complete_entry(self) -> None:
        entry = parse_kev_data([_other("kev", _kev_content())])

        assert entry == KEVEntry(
            date_added=date(2024, 1, 15), reference_url=KEV_REFERENCE
        )

    @pytest.mark.parametrize(
        ("date_added", "expected"),
        [
            ("2024-01-15", date(2024, 1, 15)),
            ("2024-01-01T23:30:00-05:00", date(2024, 1, 1)),
            ("2024-01-01T00:30:00+05:00", date(2024, 1, 1)),
            ("2024-01-01T12:00:00Z", date(2024, 1, 1)),
            ("2024-01-01T12:00:00.123456", date(2024, 1, 1)),
            ("9999-12-31T23:59:59-01:00", date(9999, 12, 31)),
        ],
    )
    def test_date_added_is_the_date_as_written(
        self, date_added: str, expected: date
    ) -> None:
        entry = parse_kev_data([_other("kev", _kev_content(date_added=date_added))])

        assert entry is not None
        assert entry.date_added == expected

    @pytest.mark.parametrize(
        "date_added",
        [
            _ABSENT,
            None,
            "",
            "garbage",
            "2024-13-01",
            "2024-02-30",
            "2024-01-01 00:00:00",
            "2024-01-01T",
            "2024-01-01Z",
            "2024-01-01\x00",
            "\x002024-01-01",
            "2024-01-01T00:00:00\x00",
            20240115,
            1.5,
            True,
            [],
            {},
        ],
    )
    def test_absent_or_unparseable_date_added_yields_none(
        self, date_added: Any
    ) -> None:
        metrics = [_other("kev", _kev_content(date_added=date_added))]

        assert parse_kev_data(metrics) is None

    @pytest.mark.parametrize("reference", [_ABSENT, None])
    def test_absent_reference_yields_no_reference_url(self, reference: Any) -> None:
        entry = parse_kev_data([_other("kev", _kev_content(reference=reference))])

        assert entry == KEVEntry(date_added=date(2024, 1, 15), reference_url=None)

    @pytest.mark.parametrize("reference", ["", "r" * 2048, "not a URL"])
    def test_string_reference_within_its_bound_is_stored_as_is(
        self, reference: str
    ) -> None:
        entry = parse_kev_data([_other("kev", _kev_content(reference=reference))])

        assert entry is not None
        assert entry.reference_url == reference

    @pytest.mark.parametrize(
        "reference",
        [
            "r" * 2049,
            KEV_REFERENCE + "\x00",
            "\x00",
            1,
            1.5,
            True,
            [],
            [KEV_REFERENCE],
            {},
        ],
    )
    def test_malformed_reference_yields_none(self, reference: Any) -> None:
        metrics = [_other("kev", _kev_content(reference=reference))]

        assert parse_kev_data(metrics) is None

    def test_last_kev_entry_is_used(self) -> None:
        metrics = [
            _other("kev", _kev_content(date_added="2024-01-01")),
            _other("ssvc", _ssvc_content()),
            _other("kev", _kev_content(date_added="2024-02-02")),
        ]

        entry = parse_kev_data(metrics)

        assert entry is not None
        assert entry.date_added == date(2024, 2, 2)

    @pytest.mark.parametrize(
        "last",
        [_kev_content(date_added="garbage"), _kev_content(reference=1), None, []],
    )
    def test_invalid_last_entry_wins_over_an_earlier_valid(self, last: Any) -> None:
        metrics = [_other("kev", _kev_content()), _other("kev", last)]

        assert parse_kev_data(metrics) is None

    @pytest.mark.parametrize(
        "metric",
        [
            _other("KEV", _kev_content()),
            _other("ssvc", _kev_content()),
            {"other": [_kev_content()]},
            {"kev": _kev_content()},
        ],
    )
    def test_entry_not_typed_kev_is_ignored(self, metric: Any) -> None:
        assert parse_kev_data([metric]) is None

    @pytest.mark.parametrize(
        "metrics", [None, {}, _other("kev", _kev_content()), "x", 1]
    )
    def test_wrong_typed_argument_yields_none(self, metrics: Any) -> None:
        assert parse_kev_data(metrics) is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("cvelistv5_kev_ssvc_offset_n_a", date(2022, 3, 15)),
            ("cvelistv5_v3_1_non_base_en_us_kev", date(2022, 1, 10)),
        ],
    )
    def test_fixture_kev(self, name: str, expected: date) -> None:
        entry = parse_kev_data(_container(name, "adp:CISA-ADP")["metrics"])

        assert entry is not None
        assert entry.date_added == expected
        assert entry.reference_url is not None
        assert entry.reference_url.startswith("https://www.cisa.gov/")
        assert source_cve_id(name) in entry.reference_url

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_only_kev_fixtures_yield_an_entry(self, name: str) -> None:
        kev_fixtures = {
            "cvelistv5_kev_ssvc_offset_n_a",
            "cvelistv5_v3_1_non_base_en_us_kev",
        }
        for label, container in _containers(load_fixture(name)):
            entry = parse_kev_data(container.get("metrics"))
            expected = name in kev_fixtures and label == "adp:CISA-ADP"
            assert (entry is not None) is expected


# ---------------------------------------------------------------------------
# extract_cve_state and extract_dates
# ---------------------------------------------------------------------------


class TestCveState:
    @pytest.mark.parametrize(
        ("state", "expected"),
        [("PUBLISHED", CveState.PUBLISHED), ("REJECTED", CveState.REJECTED)],
    )
    def test_member_is_returned(self, state: str, expected: CveState) -> None:
        assert extract_cve_state({"state": state}) is expected

    @pytest.mark.parametrize(
        "state",
        [
            "RESERVED",
            "published",
            "Rejected",
            " PUBLISHED",
            "PUBLISHED\n",
            "PUBLISHED\x00",
            "",
            None,
            1,
            True,
            ["PUBLISHED"],
            {"state": "PUBLISHED"},
        ],
    )
    def test_unrecognized_state_is_none(self, state: Any) -> None:
        assert extract_cve_state({"state": state}) is None

    def test_absent_state_is_none(self) -> None:
        assert extract_cve_state({"cveId": CVE_ID}) is None

    @pytest.mark.parametrize(
        "metadata", [None, [], "PUBLISHED", 1, [{"state": "PUBLISHED"}]]
    )
    def test_wrong_typed_argument_yields_none(self, metadata: Any) -> None:
        assert extract_cve_state(metadata) is None

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_state(self, name: str) -> None:
        metadata = load_fixture(name)["cveMetadata"]

        assert extract_cve_state(metadata) is CveState(metadata["state"])


_DATE_KEYS: Final = ("datePublished", "dateUpdated", "dateRejected")


class TestDates:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                "2024-10-17T14:00:16.571Z",
                datetime(2024, 10, 17, 14, 0, 16, 571000, tzinfo=UTC),
            ),
            ("2022-09-05T09:50:10", datetime(2022, 9, 5, 9, 50, 10, tzinfo=UTC)),
            ("2024-01-01T00:00:00+00:00", datetime(2024, 1, 1, tzinfo=UTC)),
            ("2024-01-01T02:00:00+02:00", datetime(2024, 1, 1, tzinfo=UTC)),
            ("2023-12-31T23:30:00-00:30", datetime(2024, 1, 1, tzinfo=UTC)),
            (
                "2024-01-01T12:00:00.123456Z",
                datetime(2024, 1, 1, 12, 0, 0, 123456, tzinfo=UTC),
            ),
            ("2024-01-01T12:00Z", datetime(2024, 1, 1, 12, tzinfo=UTC)),
            ("0001-01-01T00:00:00", datetime(1, 1, 1, tzinfo=UTC)),
        ],
    )
    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_each_date_is_aware_utc(
        self, index: int, value: str, expected: datetime
    ) -> None:
        dates = extract_dates({_DATE_KEYS[index]: value})

        parsed = dates[index]
        assert parsed == expected
        assert parsed is not None
        assert parsed.tzinfo is UTC
        assert [d for i, d in enumerate(dates) if i != index] == [None, None]

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "2024-01-01",
            "2024-01-01 12:00:00",
            "2024-01-01t12:00:00",
            "garbage",
            "T",
            "2024-01-01T",
            "2024-02-30T00:00:00Z",
            "2024-01-01T12:00:00Z\x00",
            "\x002024-01-01T12:00:00Z",
            "2024-01-01\x0012:00:00",
            "0001-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
            20240101,
            1.5,
            True,
            [],
            {},
        ],
    )
    @pytest.mark.parametrize("index", [0, 1, 2])
    def test_unparseable_date_is_none_independently(
        self, index: int, value: Any
    ) -> None:
        metadata = dict.fromkeys(_DATE_KEYS, "2024-01-01T00:00:00Z")
        metadata[_DATE_KEYS[index]] = value

        dates = extract_dates(metadata)

        assert dates[index] is None
        assert [d for i, d in enumerate(dates) if i != index] == [
            datetime(2024, 1, 1, tzinfo=UTC)
        ] * 2

    def test_absent_dates_are_none(self) -> None:
        assert extract_dates({"state": "PUBLISHED"}) == (None, None, None)

    @pytest.mark.parametrize("metadata", [None, [], "2024-01-01T00:00:00Z", 1])
    def test_wrong_typed_argument_yields_nones(self, metadata: Any) -> None:
        assert extract_dates(metadata) == (None, None, None)

    def test_offset_in_another_zone_converts_the_instant(self) -> None:
        zone = timezone(timedelta(hours=-5))

        published, _, _ = extract_dates({"datePublished": "2024-01-01T23:30:00-05:00"})

        assert published == datetime(2024, 1, 1, 23, 30, tzinfo=zone)
        assert published == datetime(2024, 1, 2, 4, 30, tzinfo=UTC)

    def test_naive_fixture_date_is_utc(self) -> None:
        metadata = load_fixture("cvelistv5_naive_date_published")["cveMetadata"]

        published, updated, rejected = extract_dates(metadata)

        assert published == datetime(2022, 9, 5, 9, 50, 10, tzinfo=UTC)
        assert updated == datetime(2024, 8, 3, 10, 54, 3, 893000, tzinfo=UTC)
        assert rejected is None

    @pytest.mark.parametrize(
        ("name", "present"),
        [
            ("cvelistv5_5_0_rejected_legacy", (True, True, True)),
            ("cvelistv5_5_2_rejected", (False, True, True)),
            ("cvelistv5_5_1_rejected_without_date_rejected", (True, True, False)),
        ],
    )
    def test_rejected_fixture_dates(self, name: str, present: tuple[bool, ...]) -> None:
        dates = extract_dates(load_fixture(name)["cveMetadata"])

        assert tuple(d is not None for d in dates) == present

    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_fixture_dates_are_present_exactly_when_upstream_and_aware_utc(
        self, name: str
    ) -> None:
        metadata = load_fixture(name)["cveMetadata"]

        dates = extract_dates(metadata)

        for key, value in zip(_DATE_KEYS, dates, strict=True):
            assert (value is not None) is (metadata.get(key) is not None)
            assert value is None or value.tzinfo is UTC

    @pytest.mark.parametrize("name", VULNS_FIXTURES)
    def test_kernel_records_have_no_dates(self, name: str) -> None:
        assert extract_dates(load_fixture(name)["cveMetadata"]) == (None, None, None)


# ---------------------------------------------------------------------------
# Caller Pattern and Schema Version Handling
# ---------------------------------------------------------------------------


class TestCallerPattern:
    @pytest.mark.parametrize("name", ALL_FIXTURES)
    def test_payload_from_the_parser_outputs_validates(self, name: str) -> None:
        payload = _caller_payload(name)

        record = load_fixture(name)
        assert payload.cve_state is CveState(record["cveMetadata"]["state"])
        scopes = [
            label
            for label, container in _containers(record)
            if container.get("affected") is not None
        ]
        operations = payload.affected_version_operations or []
        assert [op.source_container for op in operations] == scopes

    @pytest.mark.parametrize(
        "name",
        [
            "cvelistv5_5_0_rejected_legacy",
            "cvelistv5_5_2_rejected",
            "cvelistv5_5_1_rejected_without_date_rejected",
        ],
    )
    def test_legacy_rejected_structure_yields_empty_children(self, name: str) -> None:
        """Schema Version Handling: `rejectedReasons` instead of `affected`
        and `metrics` yields empty lists and `None`, and no scope."""
        cna = load_fixture(name)["containers"]["cna"]

        assert parse_affected_versions(cna.get("affected")) == []
        assert parse_cvss_assessments(cna.get("metrics"), "Example CNA") == []
        assert parse_cwe_classifications(cna.get("problemTypes"), SOURCE) == []
        assert parse_description(cna.get("descriptions")) is None
        assert parse_title(cna) is None
        assert parse_ssvc_assessment(cna.get("metrics")) is None
        assert parse_kev_data(cna.get("metrics")) is None
        payload = _caller_payload(name)
        assert payload.cve_state is CveState.REJECTED
        assert payload.affected_version_operations == []
        assert "title" not in payload.model_fields_set
        assert "description" not in payload.model_fields_set

    def test_rejected_payload_carries_its_date_rejected(self) -> None:
        payload = _caller_payload("cvelistv5_5_2_rejected")

        assert payload.date_rejected == datetime(
            2026, 4, 22, 14, 12, 14, 465000, tzinfo=UTC
        )
        assert "published_date" not in payload.model_fields_set

    def test_kernel_payload_omits_absent_dates(self) -> None:
        payload = _caller_payload("vulns_published_5_1_1")

        assert payload.model_fields_set.isdisjoint(
            {"published_date", "modified_date", "date_rejected"}
        )
        assert [c.provider_name for c in payload.cvss_assessments or []] == ["Linux"]
