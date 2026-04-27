import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "cve.db")

def get_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            result_json TEXT NOT NULL,
            risk_score REAL,
            status TEXT DEFAULT 'done',
            scanned_by INTEGER,
            scanned_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (scanned_by) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            service TEXT NOT NULL,
            version TEXT,
            version_start TEXT,
            version_end TEXT,
            severity TEXT NOT NULL,
            cvss_score REAL,
            description TEXT,
            published_at TEXT,
            synced_at TEXT DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()