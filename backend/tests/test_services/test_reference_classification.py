"""Unit tests for reference type classification in
backend/app/services/reference_service.py: URL-pattern classification
(`classify_reference_url()`) and upstream tag classification
(`classify_reference_tags()`).

Implements docs/features/tickets/ticket-references.md (Type
Auto-Classification):

- URL Pattern Mapping: patterns match the host and path of the
  normalized URL case-insensitively without altering the stored value,
  and an unmatched URL remains `NULL` (`None`).
- CVE Source Tag Mapping: the NVD Title Case and MITRE kebab-case forms
  of every table row map to the listed type or `NULL`; unknown tags do
  not fail; a tag mapped to `NULL` does not prevent a later recognized
  tag from supplying a type; and multiple recognized types resolve by
  the priority `patch`, `advisory`, `issue`, `article`.

Expected types are transcribed row by row from the specification tables,
never computed with the module under test. The table hosts are the
specification's literal hosts; every path, identifier, and other host is
fictional. The zero-outbound-call requirement comes from
docs/features/platform/testing-strategy.md (Ticket References). The
end-to-end classification precedence of automatic candidates (explicit
type, tags, URL pattern, `NULL`) is covered by
`tests/test_services/test_reference_ingestion.py`.

Some assertions pin behavior that the specification implies but does not
spell out (each is marked "Interpretation" below): `*` spans `/`, a table
host matches only exactly (no subdomains), the query and fragment never
participate, the empty root path matches as `/`, the first matching
table row wins when rows overlap, tags match only the exact listed forms
(case-sensitive, no trimming, no cross-form variants), and non-string
tags are ignored like unknown tags.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from app.core.enums import ReferenceType
from app.core.reference_urls import normalize_reference_url
from app.services.reference_service import (
    classify_reference_tags,
    classify_reference_url,
)
from tests.support.no_outbound import OutboundGuard

pytest_plugins = ["tests.support.no_outbound_fixtures"]

PATCH = ReferenceType.PATCH
ADVISORY = ReferenceType.ADVISORY
ISSUE = ReferenceType.ISSUE
ARTICLE = ReferenceType.ARTICLE

SPEC_ROWS: list[tuple[str, str, ReferenceType]] = [
    # (specification pattern, normalized URL, expected type)
    (
        "github.com/*/commit/*",
        "https://github.com/example-org/example-repo/commit/0123abcd",
        PATCH,
    ),
    (
        "github.com/*/pull/*",
        "https://github.com/example-org/example-repo/pull/42",
        PATCH,
    ),
    (
        "gitlab.com/*/commit/*",
        "https://gitlab.com/example-group/example-project/-/commit/0123abcd",
        PATCH,
    ),
    (
        "gitlab.com/*/-/merge_requests/*",
        "https://gitlab.com/example-group/example-project/-/merge_requests/7",
        PATCH,
    ),
    (
        "git.kernel.org/*/commit/*",
        "https://git.kernel.org/pub/scm/example/example.git/commit/?id=0123abcd",
        PATCH,
    ),
    (
        "github.com/advisories/GHSA-*",
        "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        ADVISORY,
    ),
    (
        "github.com/*/security/advisories/*",
        "https://github.com/example-org/example-repo/security/advisories/GHSA-xxxx-yyyy-zzzz",
        ADVISORY,
    ),
    (
        "nvd.nist.gov/vuln/detail/*",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        ADVISORY,
    ),
    ("cve.org/CVERecord*", "https://cve.org/CVERecord?id=CVE-2026-0001", ADVISORY),
    (
        "access.redhat.com/security/cve/*",
        "https://access.redhat.com/security/cve/CVE-2026-0001",
        ADVISORY,
    ),
    (
        "access.redhat.com/errata/*",
        "https://access.redhat.com/errata/RHSA-2026:0001",
        ADVISORY,
    ),
    (
        "ubuntu.com/security/CVE-*",
        "https://ubuntu.com/security/CVE-2026-0001",
        ADVISORY,
    ),
    (
        "www.debian.org/security/*",
        "https://www.debian.org/security/2026/dsa-0001",
        ADVISORY,
    ),
    (
        "security.gentoo.org/*",
        "https://security.gentoo.org/glsa/202601-01",
        ADVISORY,
    ),
    (
        "www.oracle.com/security-alerts/*",
        "https://www.oracle.com/security-alerts/cpujan2026.html",
        ADVISORY,
    ),
    (
        "security.netapp.com/advisory/*",
        "https://security.netapp.com/advisory/ntap-20260101-0001/",
        ADVISORY,
    ),
    (
        "www.zerodayinitiative.com/advisories/*",
        "https://www.zerodayinitiative.com/advisories/ZDI-26-001/",
        ADVISORY,
    ),
    (
        "msrc.microsoft.com/*",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0001",
        ADVISORY,
    ),
    ("support.apple.com/*", "https://support.apple.com/en-us/100000", ADVISORY),
    (
        "www.mozilla.org/*/security/advisories/*",
        "https://www.mozilla.org/en-US/security/advisories/mfsa2026-01/",
        ADVISORY,
    ),
    (
        "errata.almalinux.org/*",
        "https://errata.almalinux.org/9/ALSA-2026-0001.html",
        ADVISORY,
    ),
    (
        "bugzilla.suse.com/*",
        "https://bugzilla.suse.com/show_bug.cgi?id=1200000",
        ISSUE,
    ),
    (
        "bugzilla.redhat.com/*",
        "https://bugzilla.redhat.com/show_bug.cgi?id=2000000",
        ISSUE,
    ),
    (
        "bugs.launchpad.net/*",
        "https://bugs.launchpad.net/example-project/+bug/2000000",
        ISSUE,
    ),
    ("savannah.gnu.org/bugs/*", "https://savannah.gnu.org/bugs/?60000", ISSUE),
    (
        "sourceware.org/bugzilla/*",
        "https://sourceware.org/bugzilla/show_bug.cgi?id=30000",
        ISSUE,
    ),
    (
        "lists.fedoraproject.org/*",
        "https://lists.fedoraproject.org/archives/list/example-announce/message/EXAMPLE/",
        ARTICLE,
    ),
    (
        "www.openwall.com/lists/*",
        "https://www.openwall.com/lists/oss-security/2026/01/01/1",
        ARTICLE,
    ),
    ("seclists.org/*", "https://seclists.org/fulldisclosure/2026/Jan/1", ARTICLE),
    ("www.exploit-db.com/*", "https://www.exploit-db.com/exploits/50000", ARTICLE),
    ("lists.apache.org/*", "https://lists.apache.org/thread/example0123", ARTICLE),
]
"""One case per alternative of every URL Pattern Mapping row, in table order."""


@pytest.mark.unit
class TestSpecificationTable:
    def test_every_specification_pattern_has_a_case(self) -> None:
        # Transcribed from ticket-references.md (URL Pattern Mapping): 19
        # rows with 31 pattern alternatives.
        patterns = [pattern for pattern, _, _ in SPEC_ROWS]
        assert len(patterns) == len(set(patterns)) == 31

    @pytest.mark.parametrize(
        ("url", "expected"),
        [(url, expected) for _, url, expected in SPEC_ROWS],
        ids=[pattern for pattern, _, _ in SPEC_ROWS],
    )
    def test_specification_row(self, url: str, expected: ReferenceType) -> None:
        # The fixture value is already in normalized form.
        assert normalize_reference_url(url) == url
        assert classify_reference_url(url) is expected


@pytest.mark.unit
class TestMatchingRules:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com/EXAMPLE/COMMIT/X", PATCH),
            ("https://github.com/Example-Org/Repo/Pull/1", PATCH),
            ("https://github.com/ADVISORIES/ghsa-xxxx-yyyy-zzzz", ADVISORY),
            ("https://ubuntu.com/SECURITY/cve-2026-0001", ADVISORY),
            ("https://cve.org/cverecord?id=CVE-2026-0001", ADVISORY),
            (
                "https://www.mozilla.org/EN-US/SECURITY/ADVISORIES/MFSA2026-01/",
                ADVISORY,
            ),
            ("https://savannah.gnu.org/BUGS/", ISSUE),
            ("https://www.openwall.com/LISTS/oss-security/", ARTICLE),
        ],
    )
    def test_path_is_matched_case_insensitively(
        self, url: str, expected: ReferenceType
    ) -> None:
        assert classify_reference_url(url) is expected

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://GitHub.COM/example-org/example-repo/commit/0123abcd", PATCH),
            ("https://BUGZILLA.SUSE.COM/show_bug.cgi?id=1200000", ISSUE),
        ],
    )
    def test_host_is_matched_case_insensitively(
        self, url: str, expected: ReferenceType
    ) -> None:
        assert classify_reference_url(url) is expected

    def test_classification_of_raw_input_leaves_the_stored_path_untouched(
        self,
    ) -> None:
        stored = normalize_reference_url(
            "HTTP://GitHub.COM/Example-Org/Repo/COMMIT/AbC"
        )

        assert stored == "https://github.com/Example-Org/Repo/COMMIT/AbC"
        assert classify_reference_url(stored) is PATCH
        assert stored == "https://github.com/Example-Org/Repo/COMMIT/AbC"

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://github.com:8443/example-org/example-repo/commit/0123abcd", PATCH),
            ("https://bugzilla.suse.com:443/show_bug.cgi?id=1200000", ISSUE),
            ("https://msrc.microsoft.com:443", ADVISORY),
        ],
    )
    def test_port_does_not_participate(self, url: str, expected: ReferenceType) -> None:
        assert classify_reference_url(url) is expected

    @pytest.mark.parametrize(
        "url",
        [
            "https://unmatched.example.test?u=github.com/a/commit/b",
            "https://unmatched.example.test/?u=github.com/a/commit/b",
            "https://unmatched.example.test#github.com/a/commit/b",
            "https://unmatched.example.test/x?github.com/advisories/GHSA-x",
            "https://github.com/example-org/example-repo?path=/commit/0123abcd",
            "https://github.com/example-org/example-repo#/pull/42",
            "https://cve.org?CVERecord",
        ],
    )
    def test_query_and_fragment_do_not_participate(self, url: str) -> None:
        # Interpretation: only host and path are pattern subjects.
        assert classify_reference_url(url) is None

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://msrc.microsoft.com", ADVISORY),
            ("https://msrc.microsoft.com?id=CVE-2026-0001", ADVISORY),
            ("https://support.apple.com#example", ADVISORY),
            ("https://seclists.org", ARTICLE),
        ],
    )
    def test_empty_root_path_matches_as_slash(
        self, url: str, expected: ReferenceType
    ) -> None:
        # Interpretation: normalization removes the root slash (URL
        # Normalization step 5), yet `host/*` still matches the root.
        assert classify_reference_url(url) is expected

    def test_empty_root_path_does_not_match_a_longer_path_pattern(self) -> None:
        assert classify_reference_url("https://github.com") is None
        assert classify_reference_url("https://nvd.nist.gov") is None

    @pytest.mark.parametrize(
        "url",
        [
            "https://advisories.example.test/GHSA-xxxx-yyyy-zzzz",
            "https://issues.example.test/browse/EXAMPLE-1",
            "https://github.com/example-org/example-repo",
            "https://github.com/example-org/example-repo/issues/1",
            "https://gitlab.com/example-group/example-project/-/issues/1",
            "https://nvd.nist.gov/vuln/search",
            "https://access.redhat.com/articles/0000001",
            "https://ubuntu.com/security/notices/USN-0000-1",
            "https://savannah.gnu.org/projects/example",
            "https://www.openwall.com/john/",
            "https://[2001:db8::1]/example-org/example-repo/commit/0123abcd",
            "https://192.0.2.10/example-org/example-repo/commit/0123abcd",
        ],
    )
    def test_unmatched_url_is_none(self, url: str) -> None:
        assert classify_reference_url(url) is None

    @pytest.mark.parametrize(
        "url",
        [
            # The table host is exactly `cve.org`; `www.cve.org` is a
            # different host and is not listed (literal-table assertion).
            "https://www.cve.org/CVERecord?id=CVE-2026-0001",
            "https://www.github.com/example-org/example-repo/commit/0123abcd",
            "https://api.github.com/example-org/example-repo/pull/42",
            "https://debian.org/security/2026/dsa-0001",
            "https://www.ubuntu.com/security/CVE-2026-0001",
            "https://mirror.seclists.org/fulldisclosure/2026/Jan/1",
            # Neither a suffix nor a prefix of the table host matches.
            "https://examplegithub.com/example-org/example-repo/commit/0123abcd",
            "https://github.com.example.test/example-org/example-repo/commit/0123abcd",
            "https://bugzilla.suse.com.example.test/show_bug.cgi?id=1200000",
        ],
    )
    def test_table_host_matches_exactly_without_subdomains(self, url: str) -> None:
        # Interpretation: a table host is an exact host, not a suffix.
        assert classify_reference_url(url) is None

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            # `*` spans path segments: owner and repository together.
            ("https://github.com/a/b/c/commit/0123abcd", PATCH),
            ("https://git.kernel.org/pub/scm/a/b/c.git/commit/", PATCH),
            ("https://www.mozilla.org/en-US/firefox/security/advisories/x", ADVISORY),
        ],
    )
    def test_wildcard_spans_path_segments(
        self, url: str, expected: ReferenceType
    ) -> None:
        # Interpretation: required for `github.com/*/commit/*` to match the
        # two-segment `owner/repository` prefix of real commit URLs.
        assert classify_reference_url(url) is expected

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            # Matches `github.com/*/commit/*` (patch, table row 1) and
            # `github.com/*/security/advisories/*` (advisory, row 5).
            (
                "https://github.com/example-org/example-repo/security/advisories/GHSA-x/commit/0123abcd",
                PATCH,
            ),
            # Matches `github.com/*/pull/*` (patch, row 1) and
            # `github.com/advisories/GHSA-*` (advisory, row 4).
            ("https://github.com/advisories/GHSA-xxxx/pull/42", PATCH),
        ],
    )
    def test_first_matching_table_row_wins(
        self, url: str, expected: ReferenceType
    ) -> None:
        # Interpretation: overlapping rows resolve in table order.
        assert classify_reference_url(url) is expected


@pytest.mark.unit
class TestInputContract:
    @pytest.mark.parametrize(
        "value",
        [
            "http://github.com/example-org/example-repo/commit/0123abcd",
            "HTTPS://github.com/example-org/example-repo/commit/0123abcd",
            "github.com/example-org/example-repo/commit/0123abcd",
            "//github.com/example-org/example-repo/commit/0123abcd",
            "",
        ],
    )
    def test_non_normalized_input_raises_value_error(self, value: str) -> None:
        with pytest.raises(ValueError, match="normalized URL"):
            classify_reference_url(value)


# ---------------------------------------------------------------------------
# CVE Source Tag Mapping (classify_reference_tags())
# ---------------------------------------------------------------------------

TAG_ROWS: list[tuple[str | None, str | None, ReferenceType | None]] = [
    # (NVD tag, MITRE tag, expected type); `None` in a tag column is the
    # table's "-" (no form), `None` as the type is the table's `NULL`.
    ("Patch", "patch", PATCH),
    ("Vendor Advisory", "vendor-advisory", ADVISORY),
    ("Third Party Advisory", "third-party-advisory", ADVISORY),
    ("US Government Resource", "government-resource", ADVISORY),
    ("VDB Entry", "vdb-entry", ADVISORY),
    ("Issue Tracking", "issue-tracking", ISSUE),
    ("Exploit", "exploit", ARTICLE),
    ("Mailing List", "mailing-list", ARTICLE),
    ("Release Notes", "release-notes", ARTICLE),
    ("Technical Description", "technical-description", ARTICLE),
    ("Mitigation", "mitigation", ARTICLE),
    ("Press/Media Coverage", "media-coverage", ARTICLE),
    ("Tool Signature", "signature", ARTICLE),
    ("Broken Link", "broken-link", None),
    ("Not Applicable", "not-applicable", None),
    ("Permissions Required", "permissions-required", None),
    ("URL Repurposed", None, None),
    ("Product", "product", None),
    (None, "customer-entitlement", None),
    (None, "related", None),
]
"""Every row of the CVE Source Tag Mapping table, in table order."""

TAG_FORMS: list[tuple[str, str, ReferenceType | None]] = [
    (form, label, expected)
    for nvd, mitre, expected in TAG_ROWS
    for form, label in ((nvd, "nvd"), (mitre, "mitre"))
    if form is not None
]
"""`(tag, "nvd" | "mitre", expected type)` for every listed form."""

REPRESENTATIVE_TAG = {
    PATCH: "Patch",
    ADVISORY: "Vendor Advisory",
    ISSUE: "Issue Tracking",
    ARTICLE: "Exploit",
}
"""One recognized NVD tag per type (table rows 1, 2, 6, and 7)."""

TYPE_PRIORITY = [PATCH, ADVISORY, ISSUE, ARTICLE]
"""The documented multi-tag priority, highest first."""

PRIORITY_PAIRS: list[tuple[ReferenceType, ReferenceType]] = [
    (higher, lower)
    for index, higher in enumerate(TYPE_PRIORITY)
    for lower in TYPE_PRIORITY[index + 1 :]
]


@pytest.mark.unit
class TestTagSpecificationTable:
    def test_every_specification_row_has_a_case(self) -> None:
        # Transcribed from ticket-references.md (CVE Source Tag Mapping):
        # 20 rows; 17 with both forms, one NVD-only, and two MITRE-only.
        assert len(TAG_ROWS) == 20
        assert len(TAG_FORMS) == 37
        assert len({tag for tag, _, _ in TAG_FORMS}) == 37

    @pytest.mark.parametrize(
        ("tag", "expected"),
        [(tag, expected) for tag, _, expected in TAG_FORMS],
        ids=[f"{label}:{tag}" for tag, label, _ in TAG_FORMS],
    )
    def test_specification_form(self, tag: str, expected: ReferenceType | None) -> None:
        assert classify_reference_tags([tag]) is expected


@pytest.mark.unit
class TestTagMatchingRules:
    @pytest.mark.parametrize(
        "tag",
        [
            # Case variants of listed forms.
            "PATCH",
            "pAtch",
            "Vendor advisory",
            "vendor advisory",
            "VENDOR-ADVISORY",
            "Vendor-Advisory",
            "Issue tracking",
            "ISSUE-TRACKING",
            "MAILING LIST",
            "EXPLOIT",
            # Untrimmed forms.
            " Patch",
            "Patch ",
            "patch\n",
            # Cross-form variants that the table does not list.
            "Government Resource",
            "us-government-resource",
            "Media Coverage",
            "press-media-coverage",
            "Signature",
            "tool-signature",
            "Issue-Tracking",
            "issue tracking",
        ],
    )
    def test_only_the_exact_listed_forms_are_recognized(self, tag: str) -> None:
        # Interpretation: exact, case-sensitive matching of the listed NVD
        # and MITRE forms; any other spelling is an unknown tag.
        assert classify_reference_tags([tag]) is None

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            (["Patch"], PATCH),
            (["patch"], PATCH),
            (["PATCH"], None),
            (["PATCH", "patch"], PATCH),
            (["Exploit", "EXPLOIT"], ARTICLE),
        ],
    )
    def test_case_sensitivity(
        self, tags: list[str], expected: ReferenceType | None
    ) -> None:
        assert classify_reference_tags(tags) is expected

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            (["Unknown Example Tag"], None),
            (["x-example-label", "another-example"], None),
            (["Unknown Example Tag", "Issue Tracking"], ISSUE),
            (["Issue Tracking", "x-example-label"], ISSUE),
        ],
    )
    def test_unknown_tags_are_ignored(
        self, tags: list[str], expected: ReferenceType | None
    ) -> None:
        assert classify_reference_tags(tags) is expected

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            ([None], None),
            ([1, 2.5, b"Patch"], None),
            ([["Patch"]], None),
            ([{"tag": "Patch"}], None),
            ([None, 7, "Exploit"], ARTICLE),
            ([b"Patch", "Mailing List"], ARTICLE),
        ],
    )
    def test_non_string_tags_are_ignored(
        self, tags: list[object], expected: ReferenceType | None
    ) -> None:
        # Interpretation (tracking-issue decision): a non-string tag is
        # skipped like an unknown tag; it never fails the candidate.
        assert classify_reference_tags(tags) is expected

    @pytest.mark.parametrize("tags", [None, [], ()], ids=["none", "list", "tuple"])
    def test_absent_or_empty_tags_are_none(self, tags: Sequence[str] | None) -> None:
        assert classify_reference_tags(tags) is None

    def test_any_sequence_is_accepted(self) -> None:
        assert classify_reference_tags(("Mailing List", "Patch")) is PATCH

    def test_repeated_tag(self) -> None:
        assert classify_reference_tags(["Issue Tracking", "issue-tracking"]) is ISSUE


@pytest.mark.unit
class TestTagPriority:
    @pytest.mark.parametrize(
        ("higher", "lower"),
        PRIORITY_PAIRS,
        ids=[f"{h.value}-over-{lo.value}" for h, lo in PRIORITY_PAIRS],
    )
    @pytest.mark.parametrize("order", ["higher-first", "lower-first"])
    def test_higher_priority_type_wins_in_either_order(
        self, higher: ReferenceType, lower: ReferenceType, order: str
    ) -> None:
        tags = [REPRESENTATIVE_TAG[higher], REPRESENTATIVE_TAG[lower]]
        if order == "lower-first":
            tags.reverse()

        assert classify_reference_tags(tags) is higher

    def test_every_pair_of_types_is_covered(self) -> None:
        assert len(PRIORITY_PAIRS) == 6

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            (["Exploit", "Issue Tracking", "Vendor Advisory", "Patch"], PATCH),
            (["mailing-list", "issue-tracking", "vdb-entry"], ADVISORY),
            (["Release Notes", "issue-tracking"], ISSUE),
            (["exploit", "Third Party Advisory"], ADVISORY),
            (["signature", "Technical Description", "Mitigation"], ARTICLE),
            (["government-resource", "Patch"], PATCH),
        ],
    )
    def test_mixed_forms_and_several_types(
        self, tags: list[str], expected: ReferenceType
    ) -> None:
        assert classify_reference_tags(tags) is expected

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            (["Broken Link", "Exploit"], ARTICLE),
            (["Exploit", "broken-link"], ARTICLE),
            (["Not Applicable", "related", "Issue Tracking"], ISSUE),
            (["URL Repurposed", "Vendor Advisory"], ADVISORY),
            (["customer-entitlement", "product", "patch"], PATCH),
            (["Permissions Required", "permissions-required"], None),
            (["Broken Link", "Product", "related", "URL Repurposed"], None),
        ],
    )
    def test_null_mapped_tags_do_not_block_recognized_tags(
        self, tags: list[str], expected: ReferenceType | None
    ) -> None:
        """CVE Source Tag Mapping: a tag mapped to `NULL` does not prevent
        later recognized tags from supplying a type."""
        assert classify_reference_tags(tags) is expected


@pytest.mark.unit
class TestNoOutboundCalls:
    def test_classifying_a_batch_performs_no_outbound_call(
        self, no_outbound: OutboundGuard
    ) -> None:
        for _, url, expected in SPEC_ROWS:
            assert classify_reference_url(normalize_reference_url(url)) is expected
        for url in (
            "https://unmatched.example.test/?u=github.com/a/commit/b",
            "https://www.cve.org/CVERecord?id=CVE-2026-0001",
        ):
            assert classify_reference_url(url) is None

        assert no_outbound.attempts == []

    def test_classifying_tags_performs_no_outbound_call(
        self, no_outbound: OutboundGuard
    ) -> None:
        for tag, _, expected in TAG_FORMS:
            assert classify_reference_tags([tag]) is expected
        assert classify_reference_tags(["https://unknown.example.test/tag"]) is None

        assert no_outbound.attempts == []
