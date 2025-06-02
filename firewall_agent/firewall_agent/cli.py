#!/usr/bin/env python3
# firewall_agent/cli.py

"""
Command-line interface for Biforch Firewall Agent.
Provides commands to enqueue registration with Biforch Core
and to start the API server.
After registration, stores received UUID and token in local database.
"""
import threading
from typing import Literal

import typer
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .clients.core import CoreClient
from .config import logging, settings
from .database import SessionLocal  # This is where the session is created
from .models import AgentCredentials

app = typer.Typer(help="Biforch Firewall Agent CLI")


class RegistrationCallback(BaseModel):
    """
    Model for Core's callback payload.
    Core will POST {"secret": "...", "action": "approve|reject", "uuid": "...", "token": "..."}.
    """
    secret: str
    action: Literal["approve", "reject"]
    uuid: str | None
    token: str | None


@app.command()
def init():
    """
    1) If already registered, report existing credentials and exit.
    2) Launch temporary FastAPI server to receive Core's callback.
    3) Enqueue a firewall registration request to Core (using settings.CORE_URL).
    4) Block until Core calls back, then store credentials & exit.
    """
    db = SessionLocal()  # This is where we manually create the session
    try:
        # Check for existing credentials
        existing = db.query(AgentCredentials).first()
        if existing:
            logging.info("🔒 Already registered:")
            logging.info(f"\tUUID: {existing.uuid}")
            logging.info(f"\tToken: {existing.token}")
            return

        callback_data: dict[str, str] = {}
        event = threading.Event()

        # Build temporary FastAPI app for callback
        server_app = FastAPI()

        @server_app.post("/registrations")
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
        logging.info(
            f"🔄 Waiting for Core callback at http://{settings.INTERNAL_HOST}:{settings.INTERNAL_PORT}/registrations …"
        )

        # Enqueue registration with Core
        client = CoreClient(base_url=str(settings.CORE_URL))
        pending = client.register_firewall(
            name=settings.AGENT_NAME,
            api_url=str(settings.AGENT_URL),
        )
        callback_data["secret"] = pending.secret
        logging.info(
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
            logging.info("✅ Registration approved!")
            logging.info(f"\tUUID: {uuid_str}")
            logging.info(f"\tToken: {token_str}")
        else:
            logging.error("❌ Registration was rejected by Core")
    finally:
        db.close()  # Close the session after usage


@app.command()
def serve():
    """
    Start the Biforch Firewall Agent API server
    (which runs background syncs, etc.).
    """
    uvicorn.run(
        f"{__package__}.api:app",
        host=settings.INTERNAL_HOST,
        port=settings.INTERNAL_PORT,
        reload=settings.RELOAD,
    )
    

@app.command("start")
def start():
    init()
    serve()


if __name__ == "__main__":
    app()
