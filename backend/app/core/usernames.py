"""The Username Format rule (`docs/conventions.md`, Username Format).

Pure Core-layer module with no application imports. `user_service` (the
validation point every caller crosses), the admin request schemas, and the
`manage-user` CLI each apply the rule at their own boundary with their own
error outcome; this module is the single source of the pattern and the
reserved names they check.
"""

from __future__ import annotations

import re
from typing import Final

USERNAME_PATTERN: Final = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
"""1-64 characters, starting with a letter, from `[a-z0-9._-]`; matched with
`fullmatch()` against the normalized (trimmed, lowercased) value."""

RESERVED_USERNAMES: Final = frozenset({"me"})
"""Normalized usernames never assigned to a user: `GET /api/v1/users/me`
takes precedence over `GET /api/v1/users/{user}` (`docs/api-spec.md`, User
Identifier Resolution). User creation and renaming reject them; lookups do
not, since a reserved value simply matches no user."""
