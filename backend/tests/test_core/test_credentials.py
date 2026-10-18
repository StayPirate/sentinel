"""Tests for shared credential extraction (backend/app/core/credentials.py).

See docs/features/identity/authentication.md (Authentication
Dependencies, Shared Credential Resolution) for the precedence contract
under test.
"""

from __future__ import annotations

import pytest

from app.core.credentials import API_KEY_PREFIX, extract_credential


@pytest.mark.unit
class TestExtractCredential:
    def test_bearer_token_is_extracted(self) -> None:
        assert extract_credential("Bearer abc123", None) == "abc123"

    def test_bearer_scheme_is_case_insensitive(self) -> None:
        assert extract_credential("bearer abc123", None) == "abc123"
        assert extract_credential("BEARER abc123", None) == "abc123"
        assert extract_credential("BeArEr abc123", None) == "abc123"

    def test_whitespace_only_bearer_value_falls_back_to_cookie(self) -> None:
        assert extract_credential("Bearer    ", "cookie-token") == "cookie-token"

    def test_empty_bearer_value_falls_back_to_cookie(self) -> None:
        assert extract_credential("Bearer", "cookie-token") == "cookie-token"

    def test_non_bearer_scheme_falls_back_to_cookie(self) -> None:
        assert (
            extract_credential("Basic dXNlcjpwYXNz", "cookie-token") == "cookie-token"
        )

    def test_unparseable_scheme_falls_back_to_cookie(self) -> None:
        assert extract_credential("garbage-no-scheme", "cookie-token") == "cookie-token"

    def test_absent_header_falls_back_to_cookie(self) -> None:
        assert extract_credential(None, "cookie-token") == "cookie-token"

    def test_neither_present_returns_none(self) -> None:
        assert extract_credential(None, None) is None

    def test_invalid_non_empty_bearer_does_not_fall_back_to_cookie(self) -> None:
        """A non-empty Bearer value is the final credential — even if
        it later fails validation, extraction never falls back to a
        present cookie."""
        assert extract_credential("Bearer some-invalid-token", "cookie-token") == (
            "some-invalid-token"
        )

    def test_bearer_value_is_stripped(self) -> None:
        assert extract_credential("Bearer   abc123   ", None) == "abc123"

    def test_api_key_credential_is_returned_verbatim(self) -> None:
        key = f"{API_KEY_PREFIX}abcdef1234567890"
        assert extract_credential(f"Bearer {key}", None) == key
