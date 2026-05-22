"""AES-256-GCM encryption tests."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from app.security import decrypt_field, encrypt_field
from app.security.encryption import _NONCE_BYTES


def test_round_trip_short_string() -> None:
    plaintext = "alice@example.com"
    ct = encrypt_field(plaintext)
    assert ct is not None
    assert decrypt_field(ct) == plaintext


def test_round_trip_unicode() -> None:
    plaintext = "捐赠备注 — donor note · résumé"
    ct = encrypt_field(plaintext)
    assert ct is not None
    assert decrypt_field(ct) == plaintext


def test_round_trip_empty_string() -> None:
    """Empty string round-trips; only ``None`` should pass through."""
    ct = encrypt_field("")
    assert ct is not None
    assert decrypt_field(ct) == ""


def test_none_passes_through() -> None:
    assert encrypt_field(None) is None
    assert decrypt_field(None) is None


def test_same_plaintext_produces_different_ciphertext() -> None:
    """Random nonce → equal plaintexts hash to different blobs.

    Important for PII columns: an attacker with read access shouldn't be able
    to bucket equal values together.
    """
    a = encrypt_field("constant")
    b = encrypt_field("constant")
    assert a is not None and b is not None
    assert a != b
    # But both still decrypt to the same plaintext.
    assert decrypt_field(a) == decrypt_field(b) == "constant"


def test_layout_has_12_byte_nonce_prefix() -> None:
    ct = encrypt_field("hi")
    assert ct is not None
    # nonce + at least 1 byte of body + 16-byte GCM tag
    assert len(ct) >= _NONCE_BYTES + 1 + 16


def test_tampered_ciphertext_raises_invalid_tag() -> None:
    ct = encrypt_field("hello")
    assert ct is not None
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01  # flip a bit in the GCM tag
    with pytest.raises(InvalidTag):
        decrypt_field(bytes(tampered))


def test_tampered_nonce_raises_invalid_tag() -> None:
    ct = encrypt_field("hello")
    assert ct is not None
    tampered = bytearray(ct)
    tampered[0] ^= 0x01  # flip a bit in the nonce
    with pytest.raises(InvalidTag):
        decrypt_field(bytes(tampered))


def test_wrong_key_raises_invalid_tag(monkeypatch) -> None:
    ct = encrypt_field("hello")
    assert ct is not None

    # Rebind the settings object's key for the next decrypt call.
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "field_encryption_key", "a-different-secret")
    with pytest.raises(InvalidTag):
        decrypt_field(ct)


def test_too_short_ciphertext_raises_value_error() -> None:
    with pytest.raises(ValueError):
        decrypt_field(b"\x00" * 4)
