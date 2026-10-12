"""Format of the IBS API credential settings.

See docs/features/integrations/ibs-integration.md (Origins and
Authentication, IBS API Credentials). Both `Settings` validators and the
IBS API client use these functions, so a value accepted at startup is the
value the client signs with.

`IBS_USERNAME` is sent as the quoted `keyId` of every signature, so a
non-empty value consists only of printable ASCII characters other than
space, `"`, and `\\`.

`IBS_SSH_PRIVATE_KEY` is the standard padded base64 encoding, on one line,
of the complete OpenSSH private-key file of one unencrypted Ed25519 key.
`cryptography`'s OpenSSH loader searches for the armor, so it accepts text
around the key and a second key after the first; the armor is therefore
checked here first: the decoded file starts with its BEGIN line, ends with
its END line, optionally followed by one LF, and separates its lines with
LF.

Every rejection raises `ValueError` with a fixed message naming only the
variable. It is raised outside the failing parser's `except` block, so no
exception context derived from the value is attached.
"""

from __future__ import annotations

import base64
import binascii
from typing import Final

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

INVALID_USERNAME_MESSAGE: Final = (
    "Invalid IBS_USERNAME: must be printable ASCII without whitespace, "
    "double quotes, or backslashes."
)
INVALID_PRIVATE_KEY_MESSAGE: Final = (
    "Invalid IBS_SSH_PRIVATE_KEY: must be the one-line base64 encoding of "
    "one unencrypted OpenSSH Ed25519 private-key file."
)

_USERNAME_CHARACTERS: Final = frozenset(
    chr(code) for code in range(0x21, 0x7F) if chr(code) not in {'"', "\\"}
)
_BEGIN: Final = b"-----BEGIN OPENSSH PRIVATE KEY-----"
_END: Final = b"-----END OPENSSH PRIVATE KEY-----"


def is_valid_ibs_username(value: str) -> bool:
    """Return whether a non-empty `IBS_USERNAME` value is admissible.

    The empty value means "not configured" and is not judged here.
    """
    return bool(value) and all(character in _USERNAME_CHARACTERS for character in value)


def load_ibs_ssh_private_key(encoded: str) -> Ed25519PrivateKey:
    """Decode a non-empty `IBS_SSH_PRIVATE_KEY` value.

    Raises `ValueError` (`INVALID_PRIVATE_KEY_MESSAGE`) for invalid or
    non-canonical base64, a decoded value that is not exactly one OpenSSH
    private-key file, an encrypted key, and every key type other than
    Ed25519. The value is never trimmed or otherwise altered.
    """
    key = _decode(encoded)
    if key is None:
        raise ValueError(INVALID_PRIVATE_KEY_MESSAGE)
    return key


def _decode(encoded: str) -> Ed25519PrivateKey | None:
    if not encoded.isascii():
        return None
    try:
        data = base64.b64decode(encoded, validate=True)
    except binascii.Error, ValueError:
        return None
    # Canonical form only: rejects missing padding and non-zero padding bits.
    if base64.b64encode(data).decode("ascii") != encoded:
        return None
    if not _has_single_armor(data):
        return None
    try:
        key = load_ssh_private_key(data, password=None)
    except ValueError, TypeError, UnsupportedAlgorithm:
        # TypeError: the key is encrypted with a passphrase.
        return None
    return key if isinstance(key, Ed25519PrivateKey) else None


def _has_single_armor(data: bytes) -> bool:
    body = data[:-1] if data.endswith(b"\n") else data
    if b"\r" in body:
        return False
    lines = body.split(b"\n")
    return (
        len(lines) >= 3
        and lines[0] == _BEGIN
        and lines[-1] == _END
        and _BEGIN not in lines[1:]
        and _END not in lines[:-1]
    )
