"""Hash-chain audit primitives.

- ``chain``    — pure hash helpers + transactional append.
- ``verifier`` — walk a chain and report the first broken link.
"""

from app.audit.chain import append_audit, build_body, compute_hash
from app.audit.verifier import VerificationResult, verify_chain

__all__ = [
    "VerificationResult",
    "append_audit",
    "build_body",
    "compute_hash",
    "verify_chain",
]
