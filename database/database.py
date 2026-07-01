import sqlite3

DATABASE_NAME = "soar.db"

def create_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    return conn