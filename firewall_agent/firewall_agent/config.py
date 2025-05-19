# firewall_agent/config.py
"""
Central runtime configuration for Biforch Firewall Agent.

- Loads settings from environment variables via pydantic-settings
- Validates values on startup (fails fast)
- Includes both API (OPNsense/Core) and server (Uvicorn) parameters
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict

from pydantic import AnyHttpUrl, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment.

    Attributes:
        CORE_URL: URL of Biforch Core service
        REMOTE_URL: Base URL of OPNsense firewall
        AGENT_URL: Callback/API URL of this agent

        API_KEY: OPNsense API key
        API_SECRET: OPNsense API secret
        PREFIX: Prefix for firewall aliases
        AGENT_NAME: Logical name of this agent
        CALLBACK_PATH: Path to receive Core callbacks

        TIMEOUT: HTTP request timeout (seconds)
        DB_PATH: Path to SQLite database file

        INTERNAL_HOST: Uvicorn bind host
        INTERNAL_PORT: Uvicorn bind port
        RELOAD: Enable Uvicorn auto-reload in dev

        ACTION_MAP: Map firewall actions to Core contract
    """
    # External service URLs
    CORE_URL: AnyHttpUrl
    REMOTE_URL: AnyHttpUrl
    AGENT_URL: AnyHttpUrl

    # Firewall authentication
    API_KEY: str
    API_SECRET: str

    # Alias configuration
    PREFIX: str = Field("Biforch_", description="Prefix for OPNsense aliases")
    AGENT_NAME: str
    CALLBACK_PATH: str = Field("/registrations", description="Core callback endpoint path")

    # Runtime behavior
    TIMEOUT: int = Field(10, description="Outbound HTTP timeout in seconds")
    DB_PATH: Path = Field(Path("data/firewall.db"), description="Local SQLite DB file path")

    # Server settings
    INTERNAL_HOST: str = Field("0.0.0.0", description="Uvicorn server host")
    INTERNAL_PORT: int = Field(8000, description="Uvicorn server port")
    RELOAD: bool = Field(False, description="Enable Uvicorn auto-reload in development")

    # Internal mappings
    ACTION_MAP: Dict[str, str] = Field(
        default_factory=lambda: {"pass": "pass", "block": "block", "reject": "block"},
        description="Map OPNsense actions to Core contract"
    )

    # Pydantic settings
    model_config = {
        "extra": "ignore",
        "env_file": ".env",
        "case_sensitive": True,
    }

    # Validators
    @field_validator("TIMEOUT", mode="before")
    @classmethod
    def _ensure_positive_timeout(cls, v: int | str) -> int:
        value = int(v)
        if value <= 0:
            raise ValueError("TIMEOUT must be a positive integer")
        return value

    @field_validator("INTERNAL_PORT", mode="before")
    @classmethod
    def _ensure_valid_port(cls, v: int | str) -> int:
        port = int(v)
        if not (1 <= port <= 65535):
            raise ValueError("INTERNAL_PORT must be between 1 and 65535")
        return port

    @field_validator("RELOAD", mode="before")
    @classmethod
    def _parse_reload_flag(cls, v: bool | str) -> bool:
        if isinstance(v, str):
            val = v.lower()
            if val in ("true", "1", "yes"):
                return True
            if val in ("false", "0", "no"):
                return False
            raise ValueError("RELOAD must be a boolean value")
        return bool(v)


# Instantiate settings (fails on validation error)
try:
    settings = Settings()
except ValidationError as exc:
    print("🚨 Configuration error:\n", exc, file=sys.stderr)
    sys.exit(1)
