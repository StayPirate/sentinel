"""Password hashing, verification, and validation utilities.

See `docs/features/identity/local-authentication.md` (Password
Management, Hashing configuration) for the authoritative contract this
module implements. Pure Core-layer module: no database or Redis
access, no application imports other than `app.core.exceptions` (also
Core) for the shared `ServiceError` root. All functions are
synchronous and CPU-bound (bcrypt) — callers on the async request path
MUST offload them via `asyncio.to_thread()` rather than awaiting them
inline, so a ~cost-12 bcrypt operation never blocks the event loop.

Module-level defaults (`docs/conventions.md`, Function Specification
Completeness): every function in this module is a Category B (pure)
function except `validate_password()`, which raises
`PasswordValidationError` and no other exception. None of these
functions perform I/O, create audit events, or require idempotency
documentation.
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt

from app.core.exceptions import ServiceError

MIN_PASSWORD_LENGTH = 16
MAX_PASSWORD_LENGTH = 128
BCRYPT_COST = 12

# A precomputed, valid bcrypt hash of a fixed, non-secret placeholder
# value, generated once at import time and reused for every dummy
# verification performed for the lifetime of the process. Not a real
# credential (see AGENTS.md Guardrail 23) and not derived from any
# request data. See local-authentication.md (login flow, steps 6-7)
# and the #105 Point 4 decision: "The spec does not prescribe how the
# dummy hash is obtained (pre-computed at boot, hardcoded, etc.) — only
# that an equivalent-cost bcrypt operation is performed."
_DUMMY_PASSWORD_PREHASH = base64.b64encode(
    hashlib.sha256(b"sentinel-dummy-password-for-timing-safety").digest()
)
_DUMMY_HASH = bcrypt.hashpw(_DUMMY_PASSWORD_PREHASH, bcrypt.gensalt(rounds=BCRYPT_COST))


class PasswordValidationError(ServiceError):
    """A candidate password fails the length policy.

    Raised by `validate_password()` when the password is shorter than
    `MIN_PASSWORD_LENGTH` or longer than `MAX_PASSWORD_LENGTH`
    characters. See `docs/features/identity/local-authentication.md`
    (Password validation). Shared exception per `docs/conventions.md`
    (Service Exception Conventions, Shared exceptions): inherits
    directly from `ServiceError`, not from any individual module's
    base class, because it is defined in Core and raised by any
    service that validates a candidate password. Callers that need the
    `422 USER_PASSWORD_POLICY_VIOLATION` mapping apply it themselves
    (see `docs/features/identity/user-service.md`) — this module does
    not perform HTTP-status mapping itself.
    """


def validate_password(password: str) -> None:
    """Enforce the 16-128 character password length policy.

    Q1: `password` is the candidate plaintext password.

    Q3: raises `PasswordValidationError` when `len(password)` is below
    `MIN_PASSWORD_LENGTH` (16) or above `MAX_PASSWORD_LENGTH` (128).
    Returns `None` otherwise. Performs no complexity checks — length is
    the only enforced rule (see local-authentication.md, Password
    validation).

    Q6: raises only `PasswordValidationError`.
    """
    length = len(password)
    if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
        msg = (
            f"Password must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters (got: {length})."
        )
        raise PasswordValidationError(msg)


def _prehash(password: str) -> bytes:
    """`base64(SHA-256(UTF-8(password)))`.

    See local-authentication.md (Hashing configuration, Pre-hash step):
    normalizes any password length to a fixed 44-byte ASCII input,
    avoiding bcrypt's native 72-byte input limit.
    """
    # False positive -- SHA-256 is only a length-normalizing pre-hash
    # step (see docstring above); the actual computationally-expensive
    # password hash is bcrypt(cost=12), applied afterwards in
    # hash_password(). Dismissed as alert #45.
    # codeql[py/weak-sensitive-data-hashing]
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """Hash `password` per the exact pipeline in local-authentication.md.

    Q1: `password` is the plaintext password. Callers apply
    `validate_password()` themselves beforehand — this function
    performs no length validation.

    Q3: computes `bcrypt(base64(SHA-256(UTF-8(password))), cost=12)`
    with a fresh random salt and returns the resulting 60-character
    bcrypt hash string (`$2b$12$...`).

    Q6: raises `UnicodeEncodeError` for a `password` containing a
    surrogate code point, which has no UTF-8 encoding; the request-input
    check (`docs/api-spec.md`, Inadmissible Characters in Request Input)
    and the CLI prompts reject such input first. Otherwise infallible.
    """
    hashed = bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=BCRYPT_COST))
    return hashed.decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify `password` against a stored bcrypt `password_hash`.

    Q1: `password` is the candidate plaintext password; `password_hash`
    is the stored hash (expected to be a valid `$2b$12$...` bcrypt
    hash — see Q3 for the malformed case).

    Q3: applies the same pre-hash pipeline as `hash_password()`, then
    calls `bcrypt.checkpw()`. Returns `True` only on an exact match.
    Returns `False` — never raises — when `password_hash` is not a
    well-formed bcrypt hash: a malformed stored hash is treated as a
    verification failure, not a system error.

    Q6: infallible — never raises.
    """
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("ascii"))
    except ValueError, TypeError:
        # Covers non-ASCII `password_hash` values too: `str.encode("ascii")`
        # raises `UnicodeEncodeError`, a `ValueError` subclass, for any
        # character outside the ASCII range.
        return False


def verify_dummy_password(password: str) -> None:
    """Perform a dummy bcrypt verification of equivalent cost.

    Q1: `password` is the candidate plaintext password. Its value only
    affects the (discarded) pre-hash input — the comparison is always
    against the fixed, process-reusable dummy hash, so the outcome is
    never meaningful.

    Q3: verifies `password` against `_DUMMY_HASH` (computed once at
    import time) and discards the result. Used for unknown usernames
    and ineligible users (inactive, external, no password set) so that
    every login failure path performs equivalent-cost bcrypt work —
    see local-authentication.md (login flow, steps 6-7) and the #105
    Point 4 decision (anti-enumeration via equal verification cost, not
    wall-clock timing equivalence).

    Q6: raises `UnicodeEncodeError` for a `password` containing a
    surrogate code point, like `hash_password()`; callers receive such
    input only after the same upstream rejection. Otherwise infallible.
    """
    bcrypt.checkpw(_prehash(password), _DUMMY_HASH)
