"""
reset.py

Delete the database file specified by DB_PATH in config.py if it exists.
"""
import os
import sys

from config import DB_PATH


def main():
    """
    Remove the database file if it exists, otherwise report.
    """
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f"Removed database file: {DB_PATH}")
        except Exception as e:
            print(f"Error removing {DB_PATH}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Database file does not exist: {DB_PATH}")


if __name__ == "__main__":
    main()