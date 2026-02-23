import sqlite3
import json
from datetime import datetime

DB_PATH = 'cyberdefense.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name        TEXT,
            features         TEXT,
            prediction       TEXT,
            threat_score     REAL,
            blockchain_hash  TEXT,
            timestamp        TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ Database initialized: cyberdefense.db")


def save_threat(data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO threats
        (file_name, features, prediction, threat_score, blockchain_hash, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        data['file_name'],
        data['features'],
        data['prediction'],
        data['threat_score'],
        data['blockchain_hash'],
        data['timestamp']
    ))
    conn.commit()
    conn.close()


def get_all_threats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM threats ORDER BY id DESC LIMIT 100')
    rows = c.fetchall()
    conn.close()
    return [
        {
            'id':              r[0],
            'file_name':       r[1],
            'features':        r[2],
            'prediction':      r[3],
            'threat_score':    r[4],
            'blockchain_hash': r[5],
            'timestamp':       r[6]
        }
        for r in rows
    ]


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM threats')
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE prediction = 'Ransomware'")
    threats = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE threat_score > 70")
    high_risk = c.fetchone()[0]

    c.execute('SELECT threat_score, timestamp FROM threats ORDER BY id DESC LIMIT 20')
    timeline = [{'score': r[0], 'time': r[1]} for r in c.fetchall()]

    conn.close()

    health = max(0, 100 - int((threats / total * 100) if total > 0 else 0))

    return {
        'total_scanned': total,
        'active_threats': threats,
        'high_risk_alerts': high_risk,
        'system_health': health,
        'timeline': timeline
    }