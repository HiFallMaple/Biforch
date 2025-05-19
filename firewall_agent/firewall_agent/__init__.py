"""Package entry‑point – re‑export the FastAPI application."""
from .api import app  # noqa: F401  (re‑export for `uvicorn firewall_agent:app`)