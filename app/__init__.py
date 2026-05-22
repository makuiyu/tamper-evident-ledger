"""tamper-evident-ledger — tamper-evident audit logging primitives.

Three building blocks designed to be lifted into your own project:

- ``app.audit``       — SHA-256 hash chain over canonicalised JSON bodies.
- ``app.security``    — AES-256-GCM field encryption with SHA-256 KDF.
- ``app.repositories``— Python-layer immutability guard (defence in depth).
"""

__version__ = "0.1.0"
