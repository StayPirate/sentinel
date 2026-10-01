"""Unit tests for URL-pattern type classification
(`classify_reference_url()` in backend/app/services/reference_service.py).

Implements docs/features/tickets/ticket-references.md (Type
Auto-Classification > URL Pattern Mapping): patterns match the host and
path of the normalized URL case-insensitively without altering the stored
value, and an unmatched URL remains `NULL` (`None`). Expected types are
transcribed row by row from the specification table, never computed with
the module under test. The table hosts are the specification's literal
hosts; every path, identifier, and other host is fictional. The
zero-outbound-call requirement comes from
docs/features/platform/testing-strategy.md (Ticket References).

Some assertions pin behavior that the specification implies but does not
spell out (each is marked "Interpretation" below): `*` spans `/`, a table
host matches only exactly (no subdomains), the query and fragment never
participate, the empty root path matches as `/`, and the first matching
table row wins when rows overlap.
"""

from __future__ import annotations

import pytest

from app.core.enums import ReferenceType
from app.core.reference_urls import normalize_reference_url
from app.services.reference_service import classify_reference_url
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
