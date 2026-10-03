"""Unit tests for backend/app/core/external_strings.py.

Covers `docs/conventions.md` (External String Admissibility): a string
containing U+0000 is rejected, never stripped or replaced, and the error
never renders the value. Consumer outcomes are tested with each consumer.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.external_strings import NUL, NulFreeStr, contains_nul, reject_nul
from tests.support.module_imports import APP_ROOT, imported_modules

_MARKER = "FICTIONAL-SECRET-MARKER-5e11"
_WITH_NUL = [
    pytest.param("\x00", id="only"),
    pytest.param(f"\x00{_MARKER}", id="start"),
    pytest.param(f"{_MARKER}\x00{_MARKER}", id="middle"),
    pytest.param(f"{_MARKER}\x00", id="end"),
]
_WITHOUT_NUL = [
    pytest.param("", id="empty"),
    pytest.param("cpe:/o:example:product-a:1", id="plain"),
    pytest.param("\x01\t\n\r\x1f\x7f", id="other-control-characters"),
    pytest.param("\\u0000", id="escaped-text"),
    pytest.param("0", id="digit-zero"),
]


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    value: NulFreeStr = Field(min_length=1, max_length=8)


@pytest.mark.unit
class TestContainsNul:
    def test_nul_is_u_0000(self) -> None:
        assert NUL == "\u0000"

    @pytest.mark.parametrize("value", _WITH_NUL)
    def test_value_with_nul_is_detected(self, value: str) -> None:
        assert contains_nul(value) is True

    @pytest.mark.parametrize("value", _WITHOUT_NUL)
    def test_value_without_nul_is_not_detected(self, value: str) -> None:
        assert contains_nul(value) is False


@pytest.mark.unit
class TestRejectNul:
    @pytest.mark.parametrize("value", _WITH_NUL)
    def test_value_with_nul_raises_without_rendering_it(self, value: str) -> None:
        with pytest.raises(ValueError, match="must not contain U\\+0000") as raised:
            reject_nul(value)

        assert _MARKER not in str(raised.value)

    @pytest.mark.parametrize("value", _WITHOUT_NUL)
    def test_value_without_nul_is_returned_unchanged(self, value: str) -> None:
        assert reject_nul(value) is value


@pytest.mark.unit
class TestNulFreeStr:
    @pytest.mark.parametrize("value", ["a\x00", "\x00"], ids=["trailing", "only"])
    def test_nul_is_a_validation_error(self, value: str) -> None:
        with pytest.raises(ValidationError) as raised:
            _Model(value=value)

        assert [error["type"] for error in raised.value.errors()] == ["value_error"]

    def test_valid_value_is_preserved(self) -> None:
        assert _Model(value=" a\tb ").value == " a\tb "

    def test_field_length_constraints_keep_their_standard_error_types(self) -> None:
        for value, expected in (("", "string_too_short"), ("x" * 9, "string_too_long")):
            with pytest.raises(ValidationError) as raised:
                _Model(value=value)

            assert [error["type"] for error in raised.value.errors()] == [expected]

    def test_strict_mode_still_rejects_non_strings(self) -> None:
        with pytest.raises(ValidationError) as raised:
            _Model.model_validate({"value": 1})

        assert [error["type"] for error in raised.value.errors()] == ["string_type"]


@pytest.mark.unit
def test_module_has_no_application_imports() -> None:
    """Core is a leaf layer (docs/architecture.md, Backend Layer
    Architecture)."""
    modules = imported_modules(APP_ROOT / "core" / "external_strings.py", "app.core")

    assert {m for m in modules if m == "app" or m.startswith("app.")} == set()
