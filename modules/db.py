import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "toolkit.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            source TEXT,
            severity TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()


def add_alert(source, severity, details):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alerts (time, source, severity, details) VALUES (?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source, severity, details),
    )
    conn.commit()
    conn.close()


def get_alerts(limit=50):
    conn = get_connection()
    rows = conn.execute(
        "SELECT time, source, severity, details FROM alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def count_by_source():
    conn = get_connection()
    rows = conn.execute("SELECT source, COUNT(*) FROM alerts GROUP BY source").fetchall()
    conn.close()
    return rows


def count_by_severity():
    conn = get_connection()
    rows = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
    conn.close()
    return rows


def clear_alerts():
    conn = get_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    add_alert("Test", "low", "Hello from the test")
    print(get_alerts())