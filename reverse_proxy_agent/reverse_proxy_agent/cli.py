#!/usr/bin/env python3
# reverse proxy_agent/cli.py

"""
Command-line interface for Biforch Reverse Proxy Agent.
Provides commands to enqueue registration with Biforch Core
and to start the API server.
After registration, stores received UUID and token in local database.
"""
import threading
import logging

import typer
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Literal, Optional

from .config import settings
from .clients.core import CoreClient
from .database import SessionLocal
from .models import AgentCredentials

app = typer.Typer(help="Biforch Reverse Proxy Agent CLI")


class RegistrationCallback(BaseModel):
    """
    Model for Core's callback payload.
    Core will POST {"secret": "...", "action": "approve|reject", "uuid": "...", "token": "..."}
    """
    secret: str
    action: Literal["approve", "reject"]
    uuid: Optional[str]
    token: Optional[str]


@app.command()
def init():
    """
    1) If already registered, report existing credentials and exit.
    2) Launch temporary FastAPI server to receive Core's callback.
    3) Enqueue a reverse proxy registration request to Core (using settings.CORE_URL).
    4) Block until Core calls back, then store credentials & exit.
    """
    # Check for existing credentials
    db = SessionLocal()
    existing = db.query(AgentCredentials).first()
    if existing:
        typer.secho(
            f"🔒 Already registered:\n  UUID: {existing.uuid}\n  Token: {existing.token}",
            fg=typer.colors.YELLOW
        )
        db.close()
        return

    callback_data: Dict[str, str] = {}
    event = threading.Event()

    # Build temporary FastAPI app for callback
    server_app = FastAPI()

    @server_app.post(settings.CALLBACK_PATH)
    async def receive_callback(body: RegistrationCallback):
        # Validate secret
        if body.secret != callback_data.get("secret"):
            raise HTTPException(400, "Invalid secret")
        callback_data["action"] = body.action
        # On approval, capture uuid and token
        if body.action == "approve":
            callback_data["uuid"] = body.uuid or ""
            callback_data["token"] = body.token or ""
        # Signal shutdown and notifying main thread
        server.should_exit = True
        event.set()
        return {"status": "received"}

    # Start Uvicorn server in background
    config = uvicorn.Config(
        server_app,
        host=settings.INTERNAL_HOST,
        port=settings.INTERNAL_PORT,
        log_level="info",
        lifespan="on"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    typer.echo(
        f"🔄 Waiting for Core callback at http://{settings.INTERNAL_HOST}:{settings.INTERNAL_PORT}{settings.CALLBACK_PATH} …"
    )

    # Enqueue registration with Core
    client = CoreClient(base_url=str(settings.CORE_URL))
    pending = client.register_reverse_proxy(
        name=settings.AGENT_NAME,
        api_url=str(settings.AGENT_URL),
        ip=settings.REVERSE_PROXY_IP,
        ports=settings.REVERSE_PROXY_PORTS,
    )
    callback_data["secret"] = pending.secret
    typer.echo(
        f"📨 Sent registration → request_id={pending.request_id}, secret={pending.secret}"
    )

    # Block until callback arrives
    event.wait()

    # Shutdown server thread
    thread.join(timeout=1)

    # Report and store result
    action = callback_data.get("action")
    if action == "approve":
        uuid_str = callback_data.get("uuid", "")
        token_str = callback_data.get("token", "")
        # Persist credentials in DB
        db.add(AgentCredentials(uuid=uuid_str, token=token_str))
        db.commit()
        db.close()
        typer.secho(
            f"✅ Registration approved!\n  UUID: {uuid_str}\n  Token: {token_str}",
            fg=typer.colors.GREEN
        )
    else:
        typer.secho("❌ Registration was rejected by Core", fg=typer.colors.RED)


@app.command()
def serve():
    """
    Start the Biforch Reverse Proxy Agent API server
    (which runs background syncs, etc.).
    """
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    uvicorn.run(
        f"{__package__}.api:app",
        host=settings.INTERNAL_HOST,
        port=settings.INTERNAL_PORT,
        reload=settings.RELOAD,
    )


if __name__ == "__main__":
    app()
