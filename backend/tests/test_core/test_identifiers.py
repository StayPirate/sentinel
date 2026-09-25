"""Unit tests for public identifier syntax (backend/app/core/identifiers.py).

Covers `docs/api-spec.md` (Ticket Identifier Resolution — pure grammar and
range parser; CVE Identifier Resolution), `docs/features/tickets/tickets.md`
(SNTL-{n} Format), and `docs/features/tickets/cve-service.md` (Caller
Validation Responsibility). Database resolution and visibility are owned
by later service work and are not exercised here.
"""

from __future__ import annotations

import pytest

from app.core import identifiers
from app.core.identifiers import (
    CVE_ID_MAX_LENGTH,
    CVE_ID_PATTERN,
    TICKET_SEQUENCE_ID_MAX,
    format_ticket_id,
    is_valid_cve_id,
    parse_ticket_id,
)
from tests.support.module_imports import APP_ROOT, imported_modules


@pytest.mark.unit
class TestCveIdConstants:
    def test_pattern_is_the_specified_anchored_regex(self) -> None:
        assert CVE_ID_PATTERN.pattern == r"^CVE-[0-9]{4}-[0-9]{4,}$"

    def test_max_length_is_twenty(self) -> None:
        assert CVE_ID_MAX_LENGTH == 20


@pytest.mark.unit
class TestIsValidCveId:
    @pytest.mark.parametrize(
        "value",
        [
            "CVE-2024-1234",
            "CVE-1999-0001",
            "CVE-2024-12345678901",  # exactly 20 characters
        ],
    )
    def test_canonical_ids_are_valid(self, value: str) -> None:
        assert len(value) <= CVE_ID_MAX_LENGTH
        assert is_valid_cve_id(value) is True

    def test_twenty_character_boundary_is_valid(self) -> None:
        value = "CVE-2024-" + "1" * 11

        assert len(value) == 20
        assert is_valid_cve_id(value) is True

    def test_twenty_one_characters_is_invalid(self) -> None:
        value = "CVE-2024-" + "1" * 12

        assert len(value) == 21
        assert CVE_ID_PATTERN.fullmatch(value) is not None  # length alone rejects
        assert is_valid_cve_id(value) is False

    @pytest.mark.parametrize(
        "value",
        [
            "CVE-2024-123",  # 3-digit sequence
            "cve-2024-1234",  # lowercase
            "Cve-2024-1234",
            " CVE-2024-1234",  # leading whitespace
            "CVE-2024-1234 ",  # trailing whitespace
            "CVE-2024-1234\n",  # trailing newline
            "\nCVE-2024-1234",
            "CVE-2024-\u0661\u0662\u0663\u0664",  # non-ASCII (Arabic-Indic) digits
            "CVE-\uff12\uff10\uff12\uff14-1234",  # fullwidth digits
            "CVE-24-1234",
            "CVE-2024_1234",
            "CVE-2024-",
            "",
            "CVE-2024-1234x",
            "GHSA-xxxx-yyyy-zzzz",
        ],
    )
    def test_non_canonical_strings_are_invalid(self, value: str) -> None:
        assert is_valid_cve_id(value) is False

    @pytest.mark.parametrize(
        "value",
        [None, 20241234, 2024.1234, b"CVE-2024-1234", ["CVE-2024-1234"], object()],
    )
    def test_non_strings_are_invalid_without_raising(self, value: object) -> None:
        assert is_valid_cve_id(value) is False


@pytest.mark.unit
class TestParseTicketId:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("SNTL-1", 1),
            ("SNTL-42", 42),
            ("SNTL-1337", 1337),
            ("SNTL-2147483647", 2_147_483_647),
        ],
    )
    def test_canonical_values_parse_to_sequence_id(
        self, value: str, expected: int
    ) -> None:
        assert parse_ticket_id(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "SNTL-0",
            "SNTL-0042",
            "SNTL-01",
            "SNTL-2147483648",  # INTEGER overflow by one
            "SNTL-9999999999",  # ten digits, above the range
            "SNTL-99999999999",  # eleven digits
            "sntl-1",
            "Sntl-1",
            "SNTL-+1",
            "SNTL--1",
            "SNTL-1.0",
            " SNTL-1",
            "SNTL-1 ",
            "SNTL- 1",
            "SNTL-1\n",
            "SNTL-\u0661",  # non-ASCII digit
            "SNTL-\uff11",  # fullwidth digit
            "SNTL-",
            "SNTL",
            "1",
            "42",
            "",
            "0190c7a4-5b1e-7c3d-8e9f-0a1b2c3d4e5f",  # UUID
            "SNTL-0190c7a4-5b1e-7c3d-8e9f-0a1b2c3d4e5f",
        ],
    )
    def test_malformed_values_return_none(self, value: str) -> None:
        assert parse_ticket_id(value) is None

    def test_very_long_digit_string_returns_none_without_raising(self) -> None:
        # Longer than Python's default int() digit limit (4300): rejected by
        # the length pre-check before any integer conversion.
        assert parse_ticket_id("SNTL-" + "9" * 5000) is None

    def test_max_bound_is_positive_postgres_integer(self) -> None:
        assert TICKET_SEQUENCE_ID_MAX == 2**31 - 1


@pytest.mark.unit
class TestFormatTicketId:
    @pytest.mark.parametrize(
        ("sequence_id", "expected"),
        [
            (1, "SNTL-1"),
            (42, "SNTL-42"),
            (1337, "SNTL-1337"),
            (2_147_483_647, "SNTL-2147483647"),
        ],
    )
    def test_formats_without_padding(self, sequence_id: int, expected: str) -> None:
        assert format_ticket_id(sequence_id) == expected

    @pytest.mark.parametrize("sequence_id", [1, 9, 10, 42, 100000, 2_147_483_647])
    def test_round_trips_through_parser(self, sequence_id: int) -> None:
        assert parse_ticket_id(format_ticket_id(sequence_id)) == sequence_id

    @pytest.mark.parametrize("sequence_id", [0, -1, 2_147_483_648])
    def test_out_of_range_raises_value_error(self, sequence_id: int) -> None:
        with pytest.raises(ValueError, match="sequence_id"):
            format_ticket_id(sequence_id)


@pytest.mark.unit
class TestIdentifiersModuleBoundary:
    def test_imports_no_application_module(self) -> None:
        modules = imported_modules(APP_ROOT / "core" / "identifiers.py", "app.core")

        assert {m for m in modules if m == "app" or m.startswith("app.")} == set()

    def test_module_defines_the_specified_public_names(self) -> None:
        for name in ("CVE_ID_PATTERN", "CVE_ID_MAX_LENGTH", "is_valid_cve_id"):
            assert hasattr(identifiers, name)
