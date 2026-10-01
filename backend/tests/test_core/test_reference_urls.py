"""Unit tests for the Ticket reference URL boundary
(backend/app/core/reference_urls.py).

Implements the "URL validity, normalization, and identity" matrix of
docs/features/platform/testing-strategy.md (Ticket References) for
docs/features/tickets/ticket-references.md (URL Boundary > URL
Normalization, steps 1-6; Automatic Rejection Logging for the closed
reason vocabulary; Security and Privacy for the no-dereference rule).
Expected normalized values are transcribed from those steps, never
computed with the module under test. Every host is fictional
(`example.com`, `*.example.test`, documentation address ranges).
"""

from __future__ import annotations

import pytest

from app.core.reference_urls import (
    MAX_REFERENCE_URL_LENGTH,
    ReferenceUrlError,
    ReferenceUrlRejection,
    normalize_reference_url,
)
from tests.support.module_imports import APP_ROOT, imported_modules
from tests.support.no_outbound import OutboundGuard

pytest_plugins = ["tests.support.no_outbound_fixtures"]

R = ReferenceUrlRejection

_ALL_CONTROL_CHARACTERS = [chr(code) for code in range(0x20)] + ["\x7f"]


def _rejection(value: object) -> ReferenceUrlRejection:
    with pytest.raises(ReferenceUrlError) as excinfo:
        normalize_reference_url(value)
    return excinfo.value.reason


# ---------------------------------------------------------------------------
# Accepted values (steps 3-5)
# ---------------------------------------------------------------------------

ACCEPTED: list[tuple[str, str]] = [
    # Scheme: http or https, case-insensitively; http is upgraded.
    ("https://example.com/a", "https://example.com/a"),
    ("http://example.com/a", "https://example.com/a"),
    ("HTTPS://example.com/a", "https://example.com/a"),
    ("HTTP://example.com/a", "https://example.com/a"),
    ("hTtPs://example.com/a", "https://example.com/a"),
    ("HtTp://example.com/a", "https://example.com/a"),
    # reg-name: unreserved, sub-delims, underscore, percent triplets.
    ("https://a-b.c_d~e.example.test/x", "https://a-b.c_d~e.example.test/x"),
    ("https://a!$&'()*+,;=b.example.test/x", "https://a!$&'()*+,;=b.example.test/x"),
    ("https://my_host.example.test/x", "https://my_host.example.test/x"),
    # Triplets are kept literally: no percent-decoding.
    ("https://ex%41%42mple.test/x", "https://ex%41%42mple.test/x"),
    ("https://%20.example.test/x", "https://%20.example.test/x"),
    # Punycode is plain ASCII and is accepted as written (no IDNA step).
    ("https://xn--bcher-kva.example/x", "https://xn--bcher-kva.example/x"),
    # Trailing-dot host.
    ("https://example.com./x", "https://example.com./x"),
    ("https://EXAMPLE.com./", "https://example.com."),
    # Valid dotted-quad IPv4.
    ("https://192.0.2.10/x", "https://192.0.2.10/x"),
    ("http://198.51.100.255:8080/x", "https://198.51.100.255:8080/x"),
    ("https://0.0.0.0/x", "https://0.0.0.0/x"),
    # Bracketed IPv6: lowercased, never compressed or canonicalized.
    ("https://[2001:DB8::1]/x", "https://[2001:db8::1]/x"),
    (
        "https://[2001:0DB8:0000:0000:0000:0000:0000:0001]/x",
        "https://[2001:0db8:0000:0000:0000:0000:0000:0001]/x",
    ),
    ("https://[::1]:8443/", "https://[::1]:8443"),
    ("https://[::FFFF:192.0.2.1]/x", "https://[::ffff:192.0.2.1]/x"),
    # Explicit ports are preserved, including the scheme default.
    ("https://example.com:443/x", "https://example.com:443/x"),
    ("http://example.com:80/x", "https://example.com:80/x"),
    ("https://example.com:0/x", "https://example.com:0/x"),
    ("https://example.com:65535/x", "https://example.com:65535/x"),
    ("https://example.com:00443/x", "https://example.com:00443/x"),
]


@pytest.mark.unit
class TestAcceptedUrls:
    @pytest.mark.parametrize(("value", "expected"), ACCEPTED)
    def test_accepted_url_normalizes_to_expected(
        self, value: str, expected: str
    ) -> None:
        assert normalize_reference_url(value) == expected


# ---------------------------------------------------------------------------
# Rejected values with their closed reason (steps 1-3 and 6)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestInputTypeAndEmptiness:
    @pytest.mark.parametrize(
        "value",
        [None, 0, 2048, b"https://example.com", ["https://example.com"], object()],
        ids=["none", "int-zero", "int", "bytes", "list", "object"],
    )
    def test_non_string_is_url_not_string(self, value: object) -> None:
        assert _rejection(value) is R.URL_NOT_STRING

    def test_empty_string_is_url_empty(self) -> None:
        assert _rejection("") is R.URL_EMPTY


@pytest.mark.unit
class TestControlCharacters:
    @pytest.mark.parametrize(
        "char", _ALL_CONTROL_CHARACTERS, ids=lambda c: f"U+{ord(c):04X}"
    )
    def test_every_control_character_is_rejected_not_stripped(self, char: str) -> None:
        # Stripping the character would yield this otherwise valid URL.
        assert normalize_reference_url("https://example.com/path") == (
            "https://example.com/path"
        )

        assert _rejection(f"https://example.com/pa{char}th") is R.CONTROL_CHARACTER

    @pytest.mark.parametrize("char", ["\x00", "\t", "\n", "\r", "\x1f", "\x7f"])
    @pytest.mark.parametrize(
        "template",
        [
            "{c}https://example.com/x",
            "ht{c}tps://example.com/x",
            "https://exa{c}mple.com/x",
            "https://example.com/x?q={c}",
            "https://example.com/x#{c}",
            "https://example.com/x{c}",
        ],
        ids=["leading", "scheme", "host", "query", "fragment", "trailing"],
    )
    def test_control_character_is_rejected_at_any_position(
        self, template: str, char: str
    ) -> None:
        assert _rejection(template.format(c=char)) is R.CONTROL_CHARACTER

    def test_characters_outside_the_specified_range_are_preserved(self) -> None:
        # Step 2 names exactly U+0000-U+001F and U+007F. U+0085 (a C1
        # control) and U+00A0 are outside that range; in the path they are
        # preserved literally.
        value = "https://example.com/a\u0085b\u00a0c"
        assert normalize_reference_url(value) == value


@pytest.mark.unit
class TestNoTrimming:
    def test_leading_space_is_not_trimmed(self) -> None:
        assert _rejection(" https://example.com") is R.INVALID_SCHEME

    @pytest.mark.parametrize(
        "value", ["https://example.com ", "https://example.com /x"]
    )
    def test_trailing_space_in_host_is_not_trimmed(self, value: str) -> None:
        assert _rejection(value) is R.INVALID_HOST


@pytest.mark.unit
class TestStructureAndScheme:
    @pytest.mark.parametrize(
        "value", ["example.com/x", "/path", "//example.com/x", "?q", "#f", "x"]
    )
    def test_relative_reference_is_invalid_url(self, value: str) -> None:
        assert _rejection(value) is R.INVALID_URL

    @pytest.mark.parametrize(
        "value",
        [
            "ftp://example.com/x",
            "javascript:alert(1)",
            "mailto:someone@example.com",
            "file:///tmp/example.txt",
            "data:text/plain,example",
            "ws://example.com/x",
            "hxxps://example.com/x",
            "https+x://example.com/x",
        ],
    )
    def test_other_scheme_is_invalid_scheme(self, value: str) -> None:
        assert _rejection(value) is R.INVALID_SCHEME


@pytest.mark.unit
class TestHost:
    @pytest.mark.parametrize(
        "value", ["https:example.com", "https:///x", "https://", "https://:443/"]
    )
    def test_missing_or_empty_host_is_invalid_host(self, value: str) -> None:
        assert _rejection(value) is R.INVALID_HOST

    @pytest.mark.parametrize(
        "value",
        [
            "https://b\u00fccher.example/x",  # non-ASCII (IDN) host
            "https://\u0435xample.com/x",  # Cyrillic homoglyph
            "https://exa mple.com/x",  # space
            "https://ex%4Gmple.test/x",  # invalid percent triplet
            "https://example%2.test/x",
            "https://example%.test/x",
            "https://example.com\\path",  # backslash is not a reg-name character
            'https://exa"mple.com/x',
            "https://exa<mple.com/x",
        ],
    )
    def test_invalid_reg_name_is_invalid_host(self, value: str) -> None:
        assert _rejection(value) is R.INVALID_HOST

    @pytest.mark.parametrize(
        "host",
        ["1.2.3", "01.2.3.4", "256.1.1.1", "1.2.3.4.5", "1.2.3.4.", ".", "..", "1234"],
    )
    def test_digits_and_dots_that_are_not_ipv4_are_invalid_host(
        self, host: str
    ) -> None:
        assert _rejection(f"https://{host}/x") is R.INVALID_HOST

    @pytest.mark.parametrize(
        "authority",
        [
            "[fe80::1%25eth0]",  # zone identifier
            "[fe80::1%eth0]",
            "[v1.x]",  # IPvFuture
            "[V1.x]",
            "[2001:db8::g]",  # malformed IPv6
            "[2001:db8:::1]",
            "[192.0.2.1]",  # IPv4 inside brackets is not IPv6
            "[]",
            "[::1",  # unclosed bracket
            "[::1]x",  # garbage after the closing bracket
            "[::1]]",
            "::1",  # unbracketed IPv6
        ],
    )
    def test_invalid_ip_literal_is_invalid_host(self, authority: str) -> None:
        assert _rejection(f"https://{authority}/x") is R.INVALID_HOST


@pytest.mark.unit
class TestUserInformation:
    @pytest.mark.parametrize(
        "value",
        [
            "https://someone@example.com/x",  # username only
            "https://someone:pa55word@example.com/x",  # username and password
            "https://:pa55word@example.com/x",  # password only
            "https://@example.com/x",  # empty user information
            "http://someone@example.com",
            "https://someone@[2001:db8::1]/x",
            "https://someone@example.com:8443/x",
            "https://trusted.example.test\\@other.example.test/x",
            "https://some%40one@example.com/x",
        ],
    )
    def test_user_information_is_forbidden(self, value: str) -> None:
        assert _rejection(value) is R.USERINFO_FORBIDDEN

    def test_at_sign_outside_the_authority_is_not_user_information(self) -> None:
        value = "https://example.com/users/@someone?by=someone@example.test#@x"
        assert normalize_reference_url(value) == value


@pytest.mark.unit
class TestPort:
    @pytest.mark.parametrize(
        "port", ["", "65536", "99999", "123456", "8a", "80:90", "-1", "+80", " 80"]
    )
    def test_invalid_port_is_invalid_url(self, port: str) -> None:
        assert _rejection(f"https://example.com:{port}/x") is R.INVALID_URL

    def test_empty_port_after_ipv6_is_invalid_url(self) -> None:
        assert _rejection("https://[::1]:/x") is R.INVALID_URL


# ---------------------------------------------------------------------------
# Length (steps 2 and 6)
# ---------------------------------------------------------------------------


def _padded(prefix: str, length: int) -> str:
    return prefix + "a" * (length - len(prefix))


@pytest.mark.unit
class TestLength:
    def test_maximum_is_2048(self) -> None:
        assert MAX_REFERENCE_URL_LENGTH == 2048

    def test_exactly_2048_before_and_after_normalization_is_accepted(self) -> None:
        value = _padded("https://example.com/", 2048)

        assert len(value) == 2048
        assert normalize_reference_url(value) == value

    def test_2049_is_rejected_before_parsing(self) -> None:
        value = _padded("https://example.com/", 2049)

        assert _rejection(value) is R.URL_TOO_LONG

    def test_overlength_takes_precedence_over_other_defects(self) -> None:
        # Pre-parse rejection: an overlength value is not parsed at all.
        assert _rejection(_padded("ftp://someone@example.com/", 2049)) is (
            R.URL_TOO_LONG
        )

    def test_http_upgrade_beyond_2048_is_rejected_after_normalization(self) -> None:
        value = _padded("http://example.com/", 2048)

        assert len(value) == 2048
        assert _rejection(value) is R.URL_TOO_LONG

    def test_uppercase_scheme_of_2048_whose_normalized_form_is_2048_is_accepted(
        self,
    ) -> None:
        value = _padded("HTTPS://Example.COM/", 2048)
        expected = _padded("https://example.com/", 2048)

        assert normalize_reference_url(value) == expected
        assert len(expected) == 2048

    def test_http_upgrade_offset_by_root_slash_removal_is_accepted(self) -> None:
        value = _padded("http://example.com/?", 2048)
        expected = _padded("https://example.com?", 2048)

        assert len(value) == 2048
        assert normalize_reference_url(value) == expected

    def test_2049_is_rejected_even_when_normalization_would_shorten_it(self) -> None:
        value = _padded("https://example.com/?", 2049)

        assert len(value) == 2049
        assert _rejection(value) is R.URL_TOO_LONG


# ---------------------------------------------------------------------------
# Normalization (steps 4-5)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNormalization:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            # Specification examples (URL Normalization).
            ("HTTP://Example.COM/", "https://example.com"),
            ("https://example.com/path/", "https://example.com/path/"),
            ("https://example.com?view=full", "https://example.com?view=full"),
            ("https://example.com#analysis", "https://example.com#analysis"),
        ],
    )
    def test_specification_examples(self, value: str, expected: str) -> None:
        assert normalize_reference_url(value) == expected

    def test_scheme_and_host_lowercased_path_query_fragment_preserved(self) -> None:
        assert normalize_reference_url(
            "HTTPS://Issues.EXAMPLE.Test/Browse/EXAMPLE-1?Sort=DESC&Q=A%2Fb#Comment-ID"
        ) == (
            "https://issues.example.test/Browse/EXAMPLE-1?Sort=DESC&Q=A%2Fb#Comment-ID"
        )

    def test_http_is_upgraded_to_https(self) -> None:
        assert normalize_reference_url("http://example.com/Path") == (
            "https://example.com/Path"
        )

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://example.com/", "https://example.com"),
            ("https://example.com", "https://example.com"),
            ("https://example.com/?q", "https://example.com?q"),
            ("https://example.com/#f", "https://example.com#f"),
            ("https://example.com/?q#f", "https://example.com?q#f"),
            ("https://example.com/?", "https://example.com?"),
            ("https://example.com/#", "https://example.com#"),
            ("https://example.com:8443/", "https://example.com:8443"),
            ("https://example.com:8443/?q", "https://example.com:8443?q"),
        ],
    )
    def test_only_the_empty_root_slash_is_removed(
        self, value: str, expected: str
    ) -> None:
        assert normalize_reference_url(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "https://example.com/path/",
            "https://example.com/a/b/",
            "https://example.com//",
            "https://example.com//x",
            "https://example.com/a//b",
            "https://example.com/a?",
            "https://example.com/a#",
            "https://example.com/a?#",
            "https://example.com?",
            "https://example.com#",
            "https://example.com/a?x=1&x=2&y",
            "https://example.com/a#frag/with/slashes?and=query",
            "https://example.com/%7Euser/%2e%2E/./../x",
            "https://example.com/a/../b/./c",
            "https://example.com:443/a/",
        ],
    )
    def test_non_root_components_are_preserved_literally(self, value: str) -> None:
        assert normalize_reference_url(value) == value

    @pytest.mark.parametrize(
        "value",
        [value for value, _ in ACCEPTED]
        + [
            "HTTP://Example.COM/",
            "https://example.com/?q",
            "https://example.com/#",
            "https://example.com/path/",
            _padded("https://example.com/", 2048),
        ],
    )
    def test_normalization_is_idempotent(self, value: str) -> None:
        normalized = normalize_reference_url(value)

        assert normalize_reference_url(normalized) == normalized


# ---------------------------------------------------------------------------
# Security and Privacy
# ---------------------------------------------------------------------------

_SECRET = "s3cr3t-token-value"


@pytest.mark.unit
class TestErrorsNeverEchoTheValue:
    @pytest.mark.parametrize(
        ("value", "reason"),
        [
            (f"https://someone:{_SECRET}@example.com/x", R.USERINFO_FORBIDDEN),
            (f"https://example.com/{_SECRET}\x00", R.CONTROL_CHARACTER),
            (f"ftp://example.com/{_SECRET}", R.INVALID_SCHEME),
            (f"https://{_SECRET}..example.com /x", R.INVALID_HOST),
            (f"https://example.com:{_SECRET}/x", R.INVALID_URL),
            (_padded(f"https://example.com/{_SECRET}/", 2049), R.URL_TOO_LONG),
            (f"https://1.2.3/{_SECRET}", R.INVALID_HOST),
            (f"https://[{_SECRET}]/x", R.INVALID_HOST),
        ],
    )
    def test_message_contains_no_part_of_the_value(
        self, value: str, reason: ReferenceUrlRejection
    ) -> None:
        with pytest.raises(ReferenceUrlError) as excinfo:
            normalize_reference_url(value)

        error = excinfo.value
        assert error.reason is reason
        assert isinstance(error, ValueError)
        rendered = " ".join([str(error), repr(error), *map(str, error.args)])
        assert _SECRET not in rendered
        assert "example.com" not in rendered
        # No chained exception (for example from `ipaddress`) carries it.
        assert error.__cause__ is None
        assert error.__suppress_context__ or error.__context__ is None


@pytest.mark.unit
class TestNoOutboundCalls:
    def test_normalizing_a_batch_performs_no_outbound_call(
        self, no_outbound: OutboundGuard
    ) -> None:
        rejected = [
            "https://someone@example.com/x",
            "ftp://example.com/x",
            "https://b\u00fccher.example/x",
            "https://[fe80::1%25eth0]/x",
            "https://example.com:65536/x",
            "https://1.2.3/x",
        ]
        for value, expected in ACCEPTED:
            assert normalize_reference_url(value) == expected
        for value in rejected:
            with pytest.raises(ReferenceUrlError):
                normalize_reference_url(value)

        assert no_outbound.attempts == []


@pytest.mark.unit
class TestModuleBoundary:
    def test_imports_no_application_or_network_module(self) -> None:
        modules = imported_modules(APP_ROOT / "core" / "reference_urls.py", "app.core")

        assert {m for m in modules if m == "app" or m.startswith("app.")} == set()
        assert not modules & {"socket", "httpx", "urllib.request", "http.client"}
