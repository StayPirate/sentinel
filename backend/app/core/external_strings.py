"""Admissibility of strings received from external sources.

Implements `docs/conventions.md` (External String Admissibility):
PostgreSQL cannot represent the inadmissible characters, U+0000 and every
surrogate code point (U+D800 through U+DFFF), in `text`, `varchar`, or
`jsonb` values, including query parameters, so an external string
containing one is an invalid value of its field. The value is rejected,
never stripped or replaced; each consumer applies its owning contract's
invalid-data outcome. The same predicate backs the consumer-input rule of
`docs/api-spec.md` (Inadmissible Characters in Request Input).
"""

from __future__ import annotations

import re
from typing import Annotated, Final

from pydantic import AfterValidator

# U+0000 or a surrogate code point. A surrogate has no UTF-8 encoding; a
# correctly paired JSON surrogate escape decodes to one supplementary
# character, which is outside this range and therefore admissible.
_INADMISSIBLE_CHARACTER: Final = re.compile("[\x00\ud800-\udfff]")

INADMISSIBLE_CHARACTER_MESSAGE: Final = (
    "must not contain U+0000 or a surrogate code point"
)
"""The validation message; it never contains the rejected value."""


def contains_inadmissible_character(value: str) -> bool:
    """Whether `value` contains U+0000 or a surrogate code point.

    Pure predicate; never raises.
    """
    return _INADMISSIBLE_CHARACTER.search(value) is not None


def reject_inadmissible_characters(value: str) -> str:
    """Return `value` unchanged, or raise `ValueError` if it contains an
    inadmissible character.

    Usable as a Pydantic `AfterValidator`; the message never contains the
    value.
    """
    if contains_inadmissible_character(value):
        raise ValueError(INADMISSIBLE_CHARACTER_MESSAGE)
    return value


# A plain alias rather than a `type` statement: Pydantic applies a field's
# own string constraints (`min_length`, `max_length`) natively only through
# a plain `Annotated` alias, keeping their standard error types.
AdmissibleStr = Annotated[str, AfterValidator(reject_inadmissible_characters)]
"""A `str` field that rejects an inadmissible character with a validation
error."""
