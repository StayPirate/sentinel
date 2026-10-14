"""Tests for the pure records and field contracts of
`app.services.ibs_request_evidence`.

Contract under test: docs/features/integrations/ibs-integration.md (Service
Layer > IBSClient: `RequestEvidenceResult[T]` holds one complete value or
one bounded incomplete reason, never both; Request Point Detail and Package
Source History: revision and checksum forms). The parsers are tested
through `IBSClient` in `test_ibs_client_request_*.py` and
`test_ibs_client_source_history.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.ibs_request_evidence import (
    RequestEvidenceResult,
    RequestIdSearchResult,
    is_valid_request_revision,
    positive_int,
)

pytestmark = pytest.mark.unit


class TestRequestEvidenceResult:
    def test_complete_result(self) -> None:
        value = RequestIdSearchResult((), 0)
        result = RequestEvidenceResult(value=value)
        assert result.value is value
        assert result.incomplete_reason is None

    def test_incomplete_result(self) -> None:
        result: RequestEvidenceResult[RequestIdSearchResult] = RequestEvidenceResult(
            incomplete_reason="not_found"
        )
        assert result.value is None
        assert result.incomplete_reason == "not_found"

    @pytest.mark.parametrize(
        "arguments",
        [{}, {"value": RequestIdSearchResult((), 0), "incomplete_reason": "rejected"}],
        ids=["neither", "both"],
    )
    def test_exactly_one_of_value_and_reason(self, arguments: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            RequestEvidenceResult(**arguments)


class TestFieldContracts:
    @pytest.mark.parametrize(
        ("value", "valid"),
        [
            ("1", True),
            ("86", True),
            ("0123456789abcdef0123456789abcdef", True),
            ("0", False),
            ("01", False),
            ("-1", False),
            ("+1", False),
            ("1.0", False),
            (" 1", False),
            ("1\n", False),
            ("\u0661", False),
            ("0123456789ABCDEF0123456789ABCDEF", False),
            ("0123456789abcdef0123456789abcde", False),
            ("", False),
            (1, False),
            (None, False),
        ],
    )
    def test_request_revision(self, value: object, valid: bool) -> None:
        assert is_valid_request_revision(value) is valid

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("1", 1),
            ("2147483648", 2147483648),
            (None, None),
            ("0", None),
            ("x", None),
            ("9" * 5000, None),
        ],
        ids=["one", "beyond_integer_column", "absent", "zero", "text", "too_long"],
    )
    def test_positive_int_never_raises(
        self, value: str | None, expected: int | None
    ) -> None:
        assert positive_int(value) == expected
