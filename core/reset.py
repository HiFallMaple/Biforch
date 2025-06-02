"""
reset.py

Delete the database file specified by settings.DB_PATH in config.py if it exists.
"""
import os
import sys

from core.config import settings


def main():
    """
    Remove the database file if it exists, otherwise report.
    """
    if os.path.exists(settings.DB_PATH):
        try:
            os.remove(settings.DB_PATH)
            print(f"Removed database file: {settings.DB_PATH}")
        except Exception as e:
            print(f"Error removing {settings.DB_PATH}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Database file does not exist: {settings.DB_PATH}")


if __name__ == "__main__":
    main()