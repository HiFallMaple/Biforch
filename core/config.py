import os
from dotenv import load_dotenv

# Load environment variables from .env file once
load_dotenv()


def get_env_str(name: str) -> str:
    """
    Retrieve an environment variable or raise an error if missing.
    """
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Environment variable '{name}' must be set")
    return value


def get_env_int(name: str) -> int:
    """
    Retrieve an environment variable as int or raise error if missing/invalid.
    """
    val_str = get_env_str(name)
    try:
        return int(val_str)
    except ValueError:
        raise RuntimeError(f"Environment variable '{name}' must be an integer, got '{val_str}'")

# Required configuration variables
DB_PATH = get_env_str("DB_PATH")
TIMEOUT = get_env_int("TIMEOUT")
ADMIN_TOKEN = get_env_str("ADMIN_TOKEN")
