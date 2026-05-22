"""Field-level encryption primitives.

Just AES-256-GCM with a SHA-256-derived key — kept in its own module so the
encryption layer can be swapped (e.g. for a KMS client) without touching the
rest of the codebase.
"""

from app.security.encryption import decrypt_field, encrypt_field

__all__ = ["decrypt_field", "encrypt_field"]
