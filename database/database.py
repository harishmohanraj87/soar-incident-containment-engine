import sqlite3
from pathlib import Path


# ==========================================================
# DATABASE CONFIGURATION
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_NAME = BASE_DIR / "soar.db"


# ==========================================================
# CREATE DATABASE CONNECTION
# ==========================================================

def create_connection():
    """
    Creates and returns a configured SQLite connection.
    """

    conn = sqlite3.connect(
        DATABASE_NAME,
        timeout=10,
        check_same_thread=False
    )

    # Return rows as dictionary-like objects
    conn.row_factory = sqlite3.Row

    # Enable foreign key support
    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    # Wait for a locked database instead of failing immediately
    conn.execute(
        "PRAGMA busy_timeout = 10000"
    )

    # Improve concurrent read/write behavior
    conn.execute(
        "PRAGMA journal_mode = WAL"
    )

    return conn