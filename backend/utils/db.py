import sqlite3
import json
import hashlib
import csv
import io
from datetime import datetime

DB_PATH = 'cyberdefense.db'

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

DEFAULT_USERS = [
    ('admin',   _hash('admin123'),   'admin'),
    ('analyst', _hash('analyst123'), 'analyst'),
]

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
            timestamp        TEXT,
            ai_summary       TEXT,
            mitre_tactics    TEXT
        )
    ''')
    # Migrate existing DB — add columns if they don't exist
    for col in [('ai_summary', 'TEXT'), ('mitre_tactics', 'TEXT')]:
        try:
            c.execute(f'ALTER TABLE threats ADD COLUMN {col[0]} {col[1]}')
        except Exception:
            pass
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'analyst'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username  TEXT,
            action    TEXT,
            details   TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS network_audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_type  TEXT,
            ip          TEXT,
            severity    TEXT,
            protocol    TEXT,
            port        INTEGER,
            description TEXT,
            details     TEXT
        )
    ''')
    # Seed default users if table is empty
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        c.executemany(
            'INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
            DEFAULT_USERS
        )
        print("✅ Default users seeded (admin, analyst)")
    conn.commit()
    conn.close()
    print("✅ Database initialized: cyberdefense.db")


# ── User CRUD ─────────────────────────────────────────────

def get_user(username: str):
    """Return user dict or None. Password is hashed."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute('SELECT username, password, role FROM users WHERE username = ?', (username,))
    row  = c.fetchone()
    conn.close()
    if not row:
        return None
    return {'username': row[0], 'password': row[1], 'role': row[2]}


def verify_user(username: str, password: str):
    """Return user dict if credentials are valid, else None."""
    user = get_user(username)
    if not user:
        return None
    if user['password'] == _hash(password):
        return user
    return None


def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute('SELECT username, role FROM users ORDER BY role, username')
    rows = c.fetchall()
    conn.close()
    return [{'username': r[0], 'role': r[1]} for r in rows]


def create_user(username: str, password: str, role: str = 'analyst'):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, _hash(password), role)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # already exists


def delete_user(username: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()


def change_password(username: str, new_password: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'UPDATE users SET password = ? WHERE username = ?',
        (_hash(new_password), username)
    )
    conn.commit()
    conn.close()


def save_threat(data):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO threats
        (file_name, features, prediction, threat_score, blockchain_hash, timestamp, ai_summary, mitre_tactics)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['file_name'],
        data['features'],
        data['prediction'],
        data['threat_score'],
        data['blockchain_hash'],
        data['timestamp'],
        data.get('ai_summary', ''),
        data.get('mitre_tactics', '')
    ))
    conn.commit()
    conn.close()


def update_threat_summary(threat_id: int, ai_summary: str):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('UPDATE threats SET ai_summary = ? WHERE id = ?', (ai_summary, threat_id))
    conn.commit()
    conn.close()


def get_all_threats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, file_name, features, prediction, threat_score, blockchain_hash, timestamp, ai_summary, mitre_tactics FROM threats ORDER BY id DESC LIMIT 100')
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
            'timestamp':       r[6],
            'ai_summary':      r[7] or '',
            'mitre_tactics':   r[8] or ''
        }
        for r in rows
    ]


def get_threats_csv():
    """Return CSV string of all threats."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, file_name, prediction, threat_score, blockchain_hash, timestamp, mitre_tactics FROM threats ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'File', 'Prediction', 'Threat Score', 'Hash', 'Timestamp', 'MITRE Tactics'])
    writer.writerows(rows)
    return output.getvalue()


# ── Audit Log ─────────────────────────────────────────────

def log_audit(username: str, action: str, details: str = ''):
    ts = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'INSERT INTO audit_log (timestamp, username, action, details) VALUES (?, ?, ?, ?)',
        (ts, username or 'system', action, details)
    )
    conn.commit()
    conn.close()
    # Emit real-time event to SOC live feed
    try:
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        if socketio:
            socketio.emit('audit_event', {
                'timestamp': ts,
                'username':  username or 'system',
                'action':    action,
                'details':   details
            })
    except Exception:
        pass


def get_audit_logs(limit: int = 500):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, timestamp, username, action, details FROM audit_log ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return [{'id': r[0], 'timestamp': r[1], 'username': r[2], 'action': r[3], 'details': r[4]} for r in rows]


# ── Network Audit Log ──────────────────────────────────────

def log_network_audit(event_type: str, ip: str, severity: str,
                      description: str, protocol: str = '', port: int = None,
                      details: str = ''):
    ts = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        'INSERT INTO network_audit_log '
        '(timestamp, event_type, ip, severity, protocol, port, description, details) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (ts, event_type, ip, severity, protocol, port, description, details)
    )
    conn.commit()
    conn.close()
    try:
        from flask import current_app
        socketio = current_app.extensions.get('socketio')
        if socketio:
            socketio.emit('network_audit_event', {
                'timestamp':   ts,
                'event_type':  event_type,
                'ip':          ip,
                'severity':    severity,
                'protocol':    protocol,
                'port':        port,
                'description': description,
                'details':     details,
            })
    except Exception:
        pass


def get_network_audit_logs(limit: int = 500):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        'SELECT id, timestamp, event_type, ip, severity, protocol, port, description, details '
        'FROM network_audit_log ORDER BY id DESC LIMIT ?',
        (limit,)
    )
    rows = c.fetchall()
    conn.close()
    return [
        {'id': r[0], 'timestamp': r[1], 'event_type': r[2], 'ip': r[3],
         'severity': r[4], 'protocol': r[5], 'port': r[6],
         'description': r[7], 'details': r[8]}
        for r in rows
    ]


def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('SELECT COUNT(*) FROM threats')
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE prediction = 'Ransomware'")
    threats = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE prediction = 'Suspicious'")
    medium = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE threat_score > 70")
    high_risk = c.fetchone()[0]

    c.execute('SELECT threat_score, timestamp FROM threats ORDER BY id DESC LIMIT 20')
    timeline = [{'score': r[0], 'time': r[1]} for r in c.fetchall()]

    conn.close()

    health = max(0, 100 - int((threats / total * 100) if total > 0 else 0))

    return {
        'total_scanned':    total,
        'active_threats':   threats,
        'medium_threats':   medium,
        'high_risk_alerts': high_risk,
        'system_health':    health,
        'timeline':         timeline
    }