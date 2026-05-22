"""AES-256-GCM field encryption with a SHA-256-derived key.

Storage layout
--------------
Each ciphertext is stored as one BYTEA blob:

    | nonce (12 bytes) | ciphertext | GCM auth tag (16 bytes) |

The nonce is generated with :func:`os.urandom` per call, so re-encrypting the
same plaintext produces a different blob — important for PII columns where an
adversary with read access shouldn't be able to bucket equal values.

Key handling
------------
``FIELD_ENCRYPTION_KEY`` may be any string (passphrase, base64, hex). We run
SHA-256 over the UTF-8 bytes to derive a 32-byte AES-256 key. Properties:

- Accepts arbitrary input length — no "must be exactly 32 bytes" foot-gun.
- The full key entropy is mixed in (no silent truncation).
- Deterministic — the same passphrase produces the same key on every host.

This is not a substitute for a KMS. For production:

- Store the passphrase in a secrets manager, not an env file.
- Rotate by decrypting under the old key and re-encrypting under the new one,
  then dropping the old key from the KMS.
- Consider per-row data keys wrapped by a single master key (envelope
  encryption) once you outgrow the demo.

Failure modes
-------------
- Tampered ciphertext, wrong key, or wrong nonce → ``InvalidTag`` from
  :mod:`cryptography`. We do not catch it — let the caller decide whether to
  fail-closed (refuse the request) or fail-open with an alarm.
- Plaintext is ``None`` → ciphertext is ``None``. Empty string *is* encrypted
  (callers can opt for ``None`` if they want NULL semantics).
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

_NONCE_BYTES = 12  # AES-GCM standard nonce length
_KEY_BYTES = 32  # AES-256
_TAG_BYTES = 16  # AES-GCM authentication tag


def _derived_key() -> bytes:
    """SHA-256(env_passphrase) → 32-byte AES-256 key."""
    return hashlib.sha256(settings.field_encryption_key.encode("utf-8")).digest()[:_KEY_BYTES]


def encrypt_field(plaintext: str | None) -> bytes | None:
    """Encrypt a plaintext string. ``None`` passes through.

    Returns ``nonce || ciphertext_with_tag``.
    """
    if plaintext is None:
        return None
    aesgcm = AESGCM(_derived_key())
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return nonce + ciphertext


def decrypt_field(ciphertext: bytes | None) -> str | None:
    """Decrypt a blob produced by :func:`encrypt_field`. ``None`` passes through.

    Raises:
        ValueError: ciphertext is too short to contain ``nonce + tag``.
        cryptography.exceptions.InvalidTag: tampered ciphertext or wrong key.
    """
    if ciphertext is None:
        return None
    if len(ciphertext) <= _NONCE_BYTES + _TAG_BYTES - 1:
        raise ValueError("Ciphertext too short to contain nonce + tag")
    aesgcm = AESGCM(_derived_key())
    nonce = ciphertext[:_NONCE_BYTES]
    body = ciphertext[_NONCE_BYTES:]
    plaintext = aesgcm.decrypt(nonce, body, associated_data=None)
    return plaintext.decode("utf-8")


__all__ = ["decrypt_field", "encrypt_field"]
