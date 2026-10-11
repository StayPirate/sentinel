"""Unit tests for backend/app/core/external_strings.py.

Covers `docs/conventions.md` (External String Admissibility): a string
containing an inadmissible character, U+0000 or a surrogate code point, is
rejected, never stripped or replaced, and the error never renders the
value. A supplementary character, including one decoded from a correctly
paired surrogate escape, is admissible. Consumer outcomes are tested with
each consumer.
"""

from __future__ import annotations

import json
import re

import pytest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.external_strings import (
    INADMISSIBLE_CHARACTER_MESSAGE,
    AdmissibleStr,
    contains_inadmissible_character,
    reject_inadmissible_characters,
)
from tests.support.inadmissible import INADMISSIBLE_CHARACTERS
from tests.support.module_imports import APP_ROOT, imported_modules

_MARKER = "FICTIONAL-SECRET-MARKER-5e11"
_WITH_INADMISSIBLE = [
    pytest.param("\x00", id="nul-only"),
    pytest.param(f"\x00{_MARKER}", id="nul-start"),
    pytest.param(f"{_MARKER}\x00{_MARKER}", id="nul-middle"),
    pytest.param(f"{_MARKER}\x00", id="nul-end"),
    pytest.param("\ud800", id="high-surrogate-only"),
    pytest.param(f"\udfff{_MARKER}", id="low-surrogate-start"),
    pytest.param(f"{_MARKER}\udbff{_MARKER}", id="surrogate-middle"),
    pytest.param(f"{_MARKER}\udc00", id="surrogate-end"),
    # Two code points, e.g. CESU-8 bytes decoded with `surrogatepass`:
    # still unencodable, although `jsonb` would silently merge them.
    pytest.param(f"{_MARKER}\ud83d\ude00", id="high-then-low-surrogate"),
    pytest.param(
        json.loads(b'"\xed\xa0\x80"'), id="surrogate-decoded-from-encoded-bytes"
    ),
    pytest.param(json.loads('"\\ud800"'), id="surrogate-decoded-from-json-escape"),
]
_ADMISSIBLE = [
    pytest.param("", id="empty"),
    pytest.param("cpe:/o:example:product-a:1", id="plain"),
    pytest.param("\x01\t\n\r\x1f\x7f", id="other-control-characters"),
    pytest.param("\\u0000 \\ud800", id="escaped-text"),
    pytest.param("0", id="digit-zero"),
    pytest.param("\ud7ff\ue000\uffff", id="code-points-bordering-surrogates"),
    pytest.param("\U0001f600\U00010000\U0010ffff", id="supplementary-characters"),
    pytest.param(json.loads('"\\ud83d\\ude00"'), id="paired-surrogate-escape"),
]


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    value: AdmissibleStr = Field(min_length=1, max_length=8)


class _UnconstrainedModel(BaseModel):
    model_config = ConfigDict(strict=True, hide_input_in_errors=True)

    value: AdmissibleStr


@pytest.mark.unit
class TestContainsInadmissibleCharacter:
    @pytest.mark.parametrize("value", _WITH_INADMISSIBLE)
    def test_inadmissible_value_is_detected(self, value: str) -> None:
        assert contains_inadmissible_character(value) is True

    @pytest.mark.parametrize("value", _ADMISSIBLE)
    def test_admissible_value_is_not_detected(self, value: str) -> None:
        assert contains_inadmissible_character(value) is False

    def test_every_surrogate_code_point_is_detected(self) -> None:
        assert all(
            contains_inadmissible_character(chr(code_point))
            for code_point in range(0xD800, 0xE000)
        )


@pytest.mark.unit
class TestRejectInadmissibleCharacters:
    @pytest.mark.parametrize("value", _WITH_INADMISSIBLE)
    def test_inadmissible_value_raises_without_rendering_it(self, value: str) -> None:
        with pytest.raises(
            ValueError, match=re.escape(INADMISSIBLE_CHARACTER_MESSAGE)
        ) as raised:
            reject_inadmissible_characters(value)

        assert _MARKER not in str(raised.value)

    @pytest.mark.parametrize("value", _ADMISSIBLE)
    def test_admissible_value_is_returned_unchanged(self, value: str) -> None:
        assert reject_inadmissible_characters(value) is value

    def test_message_names_both_characters(self) -> None:
        assert INADMISSIBLE_CHARACTER_MESSAGE == (
            "must not contain U+0000 or a surrogate code point"
        )


@pytest.mark.unit
class TestAdmissibleStr:
    @pytest.mark.parametrize("character", INADMISSIBLE_CHARACTERS)
    @pytest.mark.parametrize("position", ["trailing", "only"])
    def test_unconstrained_field_rejects_with_value_error(
        self, character: str, position: str
    ) -> None:
        """Without a length or pattern constraint Pydantic itself accepts
        a surrogate, so the rejection comes from this validator."""
        value = f"a{character}" if position == "trailing" else character

        with pytest.raises(ValidationError) as raised:
            _UnconstrainedModel(value=value)

        assert [error["type"] for error in raised.value.errors()] == ["value_error"]

    def test_valid_value_is_preserved(self) -> None:
        assert _Model(value=" a\tb ").value == " a\tb "

    def test_supplementary_character_is_preserved(self) -> None:
        assert _UnconstrainedModel(value="a\U0001f600").value == "a\U0001f600"

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
