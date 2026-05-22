"""FastAPI entry point.

Run locally with::

    uvicorn app.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api import install_exception_handlers, router as ledger_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="tamper-evident-ledger",
        version="0.1.0",
        description=(
            "Tamper-evident audit logging demo. Showcases a SHA-256 hash chain, "
            "AES-256-GCM field encryption, and PL/pgSQL append-only triggers."
        ),
    )
    app.include_router(ledger_router)
    install_exception_handlers(app)

    @app.get("/health", tags=["meta"])
    async def health() -> dict[str, str]:  # pragma: no cover — trivial
        return {"status": "ok"}

    return app


app = create_app()
