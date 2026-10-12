"""Fictional SSH keys for the IBS API credential tests.

No key material is committed: every key is derived at run time, either
from a fixed fictional seed (so a signature over a fixed message is
reproducible: Ed25519 signing is deterministic) or freshly generated for
negative cases such as encrypted keys and other key types.

`encode_settings_value()` renders a key the way an operator supplies
`IBS_SSH_PRIVATE_KEY` (docs/features/integrations/ibs-integration.md, IBS API
Credentials): the standard padded base64 encoding, on one line, of the
complete OpenSSH private-key file.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

FICTIONAL_IBS_USERNAME = "jdoe"
"""An approved fictional username (docs/conventions.md, Example Data)."""


def fictional_ed25519_key(
    label: str = "sentinel-fictional-ibs-key",
) -> Ed25519PrivateKey:
    """A deterministic fictional Ed25519 key derived from `label`."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def openssh_file(
    material: PrivateKeyTypes, *, passphrase: bytes | None = None
) -> bytes:
    """The complete OpenSSH private-key file of `material`, LF-separated with
    one final LF, optionally encrypted with `passphrase`."""
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase is not None
        else serialization.NoEncryption()
    )
    return material.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption
    )


def encode_settings_value(data: bytes) -> str:
    """The one-line standard padded base64 form of a key file."""
    return base64.b64encode(data).decode("ascii")


def fictional_settings_value(label: str = "sentinel-fictional-ibs-key") -> str:
    """A valid `IBS_SSH_PRIVATE_KEY` value for the fictional key `label`."""
    return encode_settings_value(openssh_file(fictional_ed25519_key(label)))


def public_key_bytes(key: Ed25519PrivateKey) -> bytes:
    """The raw 32-byte Ed25519 public key."""
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
