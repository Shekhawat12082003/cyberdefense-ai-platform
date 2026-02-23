import os
import json
import hashlib
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / '.env')

import jwt
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from utils.db import init_db, save_threat
from models.threat_scorer import predict

app = Flask(__name__)
app.config['SECRET_KEY']       = os.getenv('SECRET_KEY', 'cyberdefense-secret')
app.config['THREAT_THRESHOLD'] = 70
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False)

init_db()

# ── Blockchain ────────────────────────────────────────────
try:
    from utils.blockchain_logger import logger as bc_logger
    from utils.blockchain_logger import log_threat as blockchain_log
    from utils.blockchain_logger import verify_hash as blockchain_verify_hash
    from utils.blockchain_logger import get_all_logs as blockchain_get_logs
    print(f"⛓  Blockchain mode : {bc_logger.mode}")
    if bc_logger.mode == 'core_testnet2':
        print(f"✅ Blockchain ready : {os.getenv('CONTRACT_ADDRESS')}")
    else:
        print(f"ℹ️  Blockchain      : local simulation")
except Exception as e:
    print(f"⚠️  Blockchain init failed: {e}")
    bc_logger              = None
    blockchain_log         = None
    blockchain_verify_hash = None
    blockchain_get_logs    = None

# ── Email ─────────────────────────────────────────────────
try:
    from utils.email_alerts import send_high_threat_alert, send_system_startup_email
    EMAIL_AVAILABLE = True
    print("✅ Email alerts ready")
except Exception as e:
    EMAIL_AVAILABLE           = False
    send_high_threat_alert    = None
    send_system_startup_email = None
    print(f"⚠️  Email init failed: {e}")

if EMAIL_AVAILABLE and send_system_startup_email:
    threading.Thread(target=send_system_startup_email, daemon=True).start()

# ── Users ─────────────────────────────────────────────────
USERS = {
    'admin':   {'password': 'admin123',   'role': 'admin'},
    'analyst': {'password': 'analyst123', 'role': 'analyst'}
}


# ── Token Helpers ─────────────────────────────────────────
def verify_token(req):
    auth = req.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return None
    try:
        return jwt.decode(
            auth[7:], app.config['SECRET_KEY'], algorithms=['HS256']
        )
    except Exception:
        return None


def admin_only(req):
    user = verify_token(req)
    if not user or user.get('role') != 'admin':
        return None
    return user


# ═════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════

@app.route('/api/verify-token', methods=['GET', 'OPTIONS'])
def verify_token_route():
    """
    Called by frontend on every page load.
    Verifies JWT is valid and not expired.
    OPTIONS method handles CORS preflight check.
    """
    # CORS preflight — must return 200 or browser blocks the real request
    if request.method == 'OPTIONS':
        return jsonify({'ok': True}), 200

    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Token missing'}), 401

    try:
        data = jwt.decode(
            auth[7:],
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return jsonify({
            'valid':    True,
            'username': data.get('username'),
            'role':     data.get('role')
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except Exception:
        return jsonify({'error': 'Invalid token'}), 401


@app.route('/api/login', methods=['POST'])
def login():
    data     = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    user     = USERS.get(username)
    if not user or user['password'] != password:
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({
        'username': username,
        'role':     user['role'],
        'exp':      datetime.utcnow() + timedelta(hours=8)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token, 'role': user['role'], 'username': username})


# ═════════════════════════════════════════════════════════
# PREDICTION
# ═════════════════════════════════════════════════════════

@app.route('/api/predict', methods=['POST'])
def predict_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    data     = request.get_json()
    features = data.get('features', {})
    result   = predict(features)

    hash_data = {
        'prediction':   result['prediction'],
        'threat_score': result['threat_score'],
        'risk_level':   result['risk_level'],
        'timestamp':    result['timestamp']
    }
    result['hash'] = hashlib.sha256(
        json.dumps(hash_data, sort_keys=True).encode()
    ).hexdigest()

    save_threat({
        'file_name':       features.get('file_name', 'unknown'),
        'features':        json.dumps(features),
        'prediction':      result['prediction'],
        'threat_score':    result['threat_score'],
        'blockchain_hash': result['hash'],
        'timestamp':       result['timestamp']
    })

    if blockchain_log:
        try:
            bc_result = blockchain_log({
                'threat_score': result['threat_score'],
                'prediction':   result['prediction'],
                'hash':         result['hash'],
                'timestamp':    result['timestamp']
            })
            result['blockchain'] = {
                'mode':       bc_result.get('mode'),
                'tx_hash':    bc_result.get('tx_hash'),
                'block':      bc_result.get('block'),
                'explorer':   bc_result.get('explorer'),
                'alert_hash': bc_result.get('alert_hash')
            }
            print(f"⛓  Blockchain logged — mode: {bc_result.get('mode')}")
        except Exception as e:
            print(f"⚠️  Blockchain log failed: {e}")

    threshold = app.config.get('THREAT_THRESHOLD', 70)
    if result['threat_score'] > threshold:
        if EMAIL_AVAILABLE and send_high_threat_alert:
            email_data = {**result, 'file_name': features.get('file_name', 'unknown')}
            threading.Thread(
                target=send_high_threat_alert,
                args=(email_data,),
                daemon=True
            ).start()

        socketio.emit('high_threat_alert', {
            'prediction':   result['prediction'],
            'threat_score': result['threat_score'],
            'risk_level':   result['risk_level'],
            'timestamp':    result['timestamp']
        })
        print(f"🚨 HIGH THREAT ALERT — score: {result['threat_score']}")

    return jsonify(result)


# ═════════════════════════════════════════════════════════
# DASHBOARD
# ═════════════════════════════════════════════════════════

@app.route('/api/threats', methods=['GET'])
def get_threats():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_all_threats
    return jsonify(get_all_threats())


@app.route('/api/stats', methods=['GET'])
def get_stats():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_stats
    return jsonify(get_stats())


@app.route('/api/shap', methods=['GET'])
def get_shap():
    shap_path = os.path.join('models', 'shap_values.json')
    if os.path.exists(shap_path):
        with open(shap_path) as f:
            return jsonify(json.load(f))
    return jsonify({})


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status':          'ok',
        'timestamp':       datetime.utcnow().isoformat(),
        'blockchain_mode': bc_logger.mode if bc_logger else 'unavailable',
        'email_enabled':   EMAIL_AVAILABLE
    })


# ═════════════════════════════════════════════════════════
# PDF REPORT
# ═════════════════════════════════════════════════════════

@app.route('/api/report', methods=['POST'])
def generate_report_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.report_generator import generate_report
    data     = request.get_json()
    filepath = generate_report(data)
    filename = os.path.basename(filepath)
    return send_file(
        filepath, as_attachment=True,
        download_name=filename, mimetype='application/pdf'
    )


# ═════════════════════════════════════════════════════════
# BLOCKCHAIN
# ═════════════════════════════════════════════════════════

@app.route('/api/blockchain/log', methods=['POST'])
def blockchain_log_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_log:
        return jsonify({'error': 'Blockchain not available'}), 503
    data   = request.get_json()
    result = blockchain_log(data)
    return jsonify(result)


@app.route('/api/blockchain/verify', methods=['POST'])
def blockchain_verify_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_verify_hash:
        return jsonify({'error': 'Blockchain not available'}), 503
    data   = request.get_json()
    result = blockchain_verify_hash(data.get('hash', ''))
    return jsonify(result)


@app.route('/api/blockchain/logs', methods=['GET'])
def blockchain_logs_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not blockchain_get_logs:
        return jsonify([])
    return jsonify(blockchain_get_logs())


@app.route('/api/blockchain/status', methods=['GET'])
def blockchain_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'mode':          bc_logger.mode if bc_logger else 'unavailable',
        'contract':      os.getenv('CONTRACT_ADDRESS', ''),
        'rpc':           os.getenv('ETH_RPC_URL', ''),
        'chain_id':      os.getenv('CHAIN_ID', ''),
        'wallet':        bc_logger.account.address if bc_logger and bc_logger.account else '',
        'explorer_base': 'https://scan.test2.btcs.network'
    })


# ═════════════════════════════════════════════════════════
# EMAIL
# ═════════════════════════════════════════════════════════

@app.route('/api/email/status', methods=['GET'])
def email_status():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'enabled':  os.getenv('EMAIL_ENABLED', 'false'),
        'sender':   os.getenv('EMAIL_SENDER', ''),
        'receiver': os.getenv('EMAIL_RECEIVER', ''),
        'ready':    EMAIL_AVAILABLE
    })


@app.route('/api/email/test', methods=['POST'])
def email_test():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if not EMAIL_AVAILABLE or not send_high_threat_alert:
        return jsonify({'error': 'Email not configured'}), 503
    test_data = {
        'threat_score':  99.0,
        'prediction':    'Ransomware',
        'risk_level':    'HIGH',
        'timestamp':     datetime.utcnow().isoformat(),
        'file_name':     'test_malware.dll',
        'hash':          'abc123def456test',
        'top_features':  ['BitcoinAddresses=1', 'DllCharacteristics=0', 'NumberOfSections=6'],
        'ml_confidence': 99.0,
        'dl_confidence': 98.0,
        'blockchain':    {'mode': 'test', 'block': 999999, 'explorer': None}
    }
    threading.Thread(
        target=send_high_threat_alert,
        args=(test_data,),
        daemon=True
    ).start()
    return jsonify({'status': 'Test email sent!'})


# ═════════════════════════════════════════════════════════
# ADMIN
# ═════════════════════════════════════════════════════════

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    return jsonify([
        {'username': k, 'role': v['role']}
        for k, v in USERS.items()
    ])


@app.route('/api/admin/users', methods=['POST'])
def admin_add_user():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data     = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role     = data.get('role', 'analyst')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if username in USERS:
        return jsonify({'error': 'User already exists'}), 409
    USERS[username] = {'password': password, 'role': role}
    print(f"👤 Admin added user: {username} ({role})")
    return jsonify({'status': 'User created', 'username': username})


@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete_user(username):
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    if username == 'admin':
        return jsonify({'error': 'Cannot delete admin'}), 400
    if username not in USERS:
        return jsonify({'error': 'User not found'}), 404
    del USERS[username]
    print(f"👤 Admin deleted user: {username}")
    return jsonify({'status': 'User deleted'})


@app.route('/api/admin/users/<username>/password', methods=['PUT'])
def admin_change_password(username):
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data     = request.get_json()
    password = data.get('password', '').strip()
    if not password:
        return jsonify({'error': 'Password required'}), 400
    if username not in USERS:
        return jsonify({'error': 'User not found'}), 404
    USERS[username]['password'] = password
    print(f"👤 Password changed for: {username}")
    return jsonify({'status': 'Password updated'})


@app.route('/api/admin/quarantine', methods=['GET'])
def admin_get_quarantine():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    log_path = os.path.join(os.path.dirname(__file__), 'quarantine', 'quarantine_log.json')
    if not os.path.exists(log_path):
        return jsonify([])
    with open(log_path) as f:
        try:
            return jsonify(json.load(f))
        except Exception:
            return jsonify([])


@app.route('/api/admin/quarantine/clear', methods=['DELETE'])
def admin_clear_quarantine():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    cleared = 0
    if os.path.exists(quarantine_dir):
        for f in os.listdir(quarantine_dir):
            if f != 'quarantine_log.json':
                try:
                    os.remove(os.path.join(quarantine_dir, f))
                    cleared += 1
                except Exception:
                    pass
    print(f"🗑️  Quarantine cleared: {cleared} files")
    return jsonify({'status': f'Cleared {cleared} files'})


@app.route('/api/admin/system', methods=['GET'])
def admin_system_info():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    import platform
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    q_files = len([
        f for f in os.listdir(quarantine_dir)
        if f != 'quarantine_log.json'
    ]) if os.path.exists(quarantine_dir) else 0
    bc_logs = len(blockchain_get_logs()) if blockchain_get_logs else 0
    return jsonify({
        'platform':         platform.system(),
        'python':           platform.python_version(),
        'blockchain_mode':  bc_logger.mode if bc_logger else 'unavailable',
        'email_enabled':    os.getenv('EMAIL_ENABLED', 'false'),
        'quarantine_files': q_files,
        'blockchain_logs':  bc_logs,
        'users_count':      len(USERS),
        'contract':         os.getenv('CONTRACT_ADDRESS', 'N/A'),
        'uptime':           datetime.utcnow().isoformat()
    })


@app.route('/api/admin/threats/clear', methods=['DELETE'])
def admin_clear_threats():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'cyberdefense.db')
        conn    = sqlite3.connect(db_path)
        conn.execute('DELETE FROM threats')
        conn.commit()
        conn.close()
        print("🗑️  Threat database cleared")
        return jsonify({'status': 'Threat database cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/settings', methods=['POST'])
def admin_update_settings():
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    data      = request.get_json()
    threshold = data.get('threat_threshold')
    if threshold is not None:
        app.config['THREAT_THRESHOLD'] = int(threshold)
        print(f"⚙️  Threat threshold updated: {threshold}")
    return jsonify({
        'status':    'Settings updated',
        'threshold': app.config.get('THREAT_THRESHOLD', 70)
    })


# ═════════════════════════════════════════════════════════
# TEST ALERT
# ═════════════════════════════════════════════════════════

@app.route('/api/test-alert', methods=['POST'])
def test_alert():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    socketio.emit('high_threat_alert', {
        'prediction':   'Ransomware',
        'threat_score': 95.0,
        'risk_level':   'HIGH',
        'timestamp':    datetime.utcnow().isoformat()
    })
    print("🚨 Test alert emitted!")
    return jsonify({'status': 'alert sent'})


# ═════════════════════════════════════════════════════════
# WEBSOCKET
# ═════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    emit('connected', {'message': '🛡️ CyberDefense SOC connected'})
    print("✅ Client connected via WebSocket")


@socketio.on('disconnect')
def on_disconnect():
    print("⚠️  Client disconnected")


# ═════════════════════════════════════════════════════════
# FILE MONITOR
# ═════════════════════════════════════════════════════════

def start_file_monitor():
    try:
        import time
        from watchdog.observers import Observer
        from models.file_monitor import ThreatHandler, WATCHED_DIR, reset_token
        os.makedirs(WATCHED_DIR, exist_ok=True)
        print(f"👁️  File monitor waiting for server...")
        time.sleep(3)
        reset_token()
        handler  = ThreatHandler()
        observer = Observer()
        observer.schedule(handler, WATCHED_DIR, recursive=False)
        observer.start()
        print(f"👁️  File monitor started: {WATCHED_DIR}")
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"⚠️  File monitor failed: {e}")

monitor_thread = threading.Thread(target=start_file_monitor, daemon=True)
monitor_thread.start()


# ═════════════════════════════════════════════════════════
# RUN
# ═════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("🛡️  CyberDefense Backend starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)