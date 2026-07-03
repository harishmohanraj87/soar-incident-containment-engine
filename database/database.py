import sqlite3

DATABASE_NAME = "soar.db"


def create_connection():
    """
    Create and return a connection to the SQLite database.
    """

    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row

    return conn