"""Admissibility of strings received from external sources.

Implements `docs/conventions.md` (External String Admissibility):
PostgreSQL cannot represent U+0000 in `text`, `varchar`, or `jsonb`
values, including query parameters, so an external string containing it
is an invalid value of its field. The value is rejected, never stripped
or replaced; each consumer applies its owning contract's invalid-data
outcome.
"""

from __future__ import annotations

from typing import Annotated, Final

from pydantic import AfterValidator

NUL: Final = "\x00"
"""U+0000, the character PostgreSQL cannot store or compare."""


def contains_nul(value: str) -> bool:
    """Whether `value` contains U+0000. Pure predicate; never raises."""
    return NUL in value


def reject_nul(value: str) -> str:
    """Return `value` unchanged, or raise `ValueError` if it contains U+0000.

    Usable as a Pydantic `AfterValidator`; the message never contains the
    value.
    """
    if contains_nul(value):
        raise ValueError("must not contain U+0000")
    return value


# A plain alias rather than a `type` statement: Pydantic applies a field's
# own string constraints (`min_length`, `max_length`) natively only through
# a plain `Annotated` alias, keeping their standard error types.
NulFreeStr = Annotated[str, AfterValidator(reject_nul)]
"""A `str` field that rejects U+0000 with a validation error."""
