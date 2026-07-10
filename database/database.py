import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_NAME = BASE_DIR / "soar.db"


def create_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    return conn