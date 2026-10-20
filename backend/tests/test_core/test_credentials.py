"""Tests for shared credential extraction (backend/app/core/credentials.py).

See docs/features/identity/authentication.md (Session cookie; Authentication
Dependencies, Shared Credential Resolution) for the cookie reading and
precedence contracts under test.
"""

from __future__ import annotations

import pytest

from app.core.credentials import (
    API_KEY_PREFIX,
    DUPLICATE_SESSION_COOKIE,
    SESSION_COOKIE_NAME,
    extract_credential,
    read_session_cookie,
)

_COOKIE = f"{SESSION_COOKIE_NAME}=cookie-token"


@pytest.mark.unit
class TestExtractCredential:
    def test_bearer_token_is_extracted(self) -> None:
        assert extract_credential("Bearer abc123", None) == "abc123"

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        assert extract_credential("bearer abc123", None) == "abc123"
        assert extract_credential("BEARER abc123", None) == "abc123"
        assert extract_credential("BeArEr abc123", None) == "abc123"

    def test_whitespace_only_bearer_value_falls_back_to_cookie(self) -> None:
        assert extract_credential("Bearer    ", _COOKIE) == "cookie-token"

    def test_empty_bearer_value_falls_back_to_cookie(self) -> None:
        assert extract_credential("Bearer", _COOKIE) == "cookie-token"

    def test_non_bearer_scheme_falls_back_to_cookie(self) -> None:
        assert extract_credential("Basic dXNlcjpwYXNz", _COOKIE) == "cookie-token"

    def test_unparseable_scheme_falls_back_to_cookie(self) -> None:
        assert extract_credential("garbage-no-scheme", _COOKIE) == "cookie-token"

    def test_absent_header_falls_back_to_cookie(self) -> None:
        assert extract_credential(None, _COOKIE) == "cookie-token"

    def test_neither_present_returns_none(self) -> None:
        assert extract_credential(None, None) is None

    def test_empty_session_cookie_selects_no_credential(self) -> None:
        assert extract_credential(None, f"{SESSION_COOKIE_NAME}=") is None

    def test_other_cookies_only_select_no_credential(self) -> None:
        assert extract_credential(None, "sentinel_session=cookie-token") is None

    def test_invalid_non_empty_bearer_does_not_fall_back_to_cookie(self) -> None:
        """A non-empty Bearer value is the final credential — even if
        it later fails validation, extraction never falls back to a
        present cookie."""
        assert extract_credential("Bearer some-invalid-token", _COOKIE) == (
            "some-invalid-token"
        )

    def test_bearer_value_is_stripped(self) -> None:
        assert extract_credential("Bearer   abc123   ", None) == "abc123"

    def test_api_key_credential_is_returned_verbatim(self) -> None:
        key = f"{API_KEY_PREFIX}abcdef1234567890"
        assert extract_credential(f"Bearer {key}", None) == key

    def test_duplicated_session_cookie_is_selected_when_cookie_is_the_source(
        self,
    ) -> None:
        duplicated = f"{_COOKIE}; {SESSION_COOKIE_NAME}=other-token"

        assert extract_credential(None, duplicated) is DUPLICATE_SESSION_COOKIE
        assert extract_credential("Basic dXNlcjpwYXNz", duplicated) is (
            DUPLICATE_SESSION_COOKIE
        )

    def test_bearer_precedence_ignores_a_duplicated_session_cookie(self) -> None:
        duplicated = f"{_COOKIE}; {SESSION_COOKIE_NAME}=other-token"

        assert extract_credential("Bearer abc123", duplicated) == "abc123"


@pytest.mark.unit
class TestReadSessionCookie:
    """The raw `Cookie` header reading of authentication.md (Session
    cookie): split on `;`, only spaces and horizontal tabs removed around
    each pair, exact name, verbatim value."""

    @pytest.mark.parametrize(
        "header",
        [
            pytest.param(None, id="no-header"),
            pytest.param("", id="empty-header"),
            pytest.param("theme=dark", id="other-cookie"),
            pytest.param(f"{SESSION_COOKIE_NAME}=", id="empty-value"),
            pytest.param(f"{SESSION_COOKIE_NAME}= \t", id="padding-only-value"),
            pytest.param(SESSION_COOKIE_NAME, id="segment-without-equals"),
        ],
    )
    def test_selects_nothing(self, header: str | None) -> None:
        assert read_session_cookie(header) == ""

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("sentinel_session", id="unprefixed"),
            pytest.param("__HOST-sentinel_session", id="capitalized-prefix"),
            pytest.param("__host-sentinel_session", id="lowercase-prefix"),
            pytest.param("\x85__Host-sentinel_session", id="leading-0x85"),
            pytest.param("\xa0__Host-sentinel_session", id="leading-0xA0"),
            pytest.param("__Host-sentinel_session\xa0", id="trailing-0xA0"),
            pytest.param("__Host-sentinel_session ", id="space-before-equals"),
            pytest.param("", id="nameless"),
        ],
    )
    def test_ignores_every_other_name(self, name: str) -> None:
        header = f"{name}=planted; {SESSION_COOKIE_NAME}=genuine"

        assert read_session_cookie(header) == "genuine"
        assert read_session_cookie(f"{name}=planted") == ""

    def test_removes_only_spaces_and_tabs_around_pairs(self) -> None:
        header = f"a=1;\t {SESSION_COOKIE_NAME}=genuine \t;b=2"

        assert read_session_cookie(header) == "genuine"

    def test_keeps_other_whitespace_in_the_value(self) -> None:
        """A value of other whitespace is non-empty: it selects an invalid
        credential, not anonymous access (Shared Credential Resolution
        step 2)."""
        assert read_session_cookie(f"{SESSION_COOKIE_NAME}=\x0b\xa0") == "\x0b\xa0"

    def test_value_is_verbatim(self) -> None:
        header = f'{SESSION_COOKIE_NAME}="quoted\\054value=with=equals"'

        assert read_session_cookie(header) == '"quoted\\054value=with=equals"'

    @pytest.mark.parametrize(
        "header",
        [
            pytest.param(f"{SESSION_COOKIE_NAME}=a; {SESSION_COOKIE_NAME}=b", id="two"),
            pytest.param(
                f"{SESSION_COOKIE_NAME}=a; {SESSION_COOKIE_NAME}=a", id="same"
            ),
            pytest.param(
                f"{SESSION_COOKIE_NAME}=a; {SESSION_COOKIE_NAME}=", id="empty"
            ),
        ],
    )
    def test_duplicated_name_is_reported(self, header: str) -> None:
        assert read_session_cookie(header) is DUPLICATE_SESSION_COOKIE
