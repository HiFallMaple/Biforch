#!/usr/bin/env python3
# core/cli.py

"""
Command-line interface for Biforch Core.
"""
import logging
import typer
import uvicorn

from .config import settings

app = typer.Typer(help="Biforch Core CLI")

@app.command()
def serve():
    """
    Start the Biforch Core API server
    (which runs background syncs, etc.).
    """
    logging.info("🔄 Starting API server …")
    uvicorn.run(
        f"{__package__}.api:app",
        host=settings.INTERNAL_HOST,
        port=settings.INTERNAL_PORT,
        reload=settings.RELOAD,
    )


if __name__ == "__main__":
    app()
