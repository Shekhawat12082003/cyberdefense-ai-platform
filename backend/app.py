import os
import json
import hashlib
import sqlite3
import threading
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent / '.env')

import jwt
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from utils.db import init_db, save_threat
from utils.db import get_user, verify_user, get_all_users, create_user, delete_user, change_password
from utils.db import log_audit, get_audit_logs, update_threat_summary, get_threats_csv
from models.threat_scorer import predict

app = Flask(__name__)
app.config['SECRET_KEY']       = os.getenv('SECRET_KEY', 'cyberdefense-secret')
app.config['THREAT_THRESHOLD'] = 70
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=False)

init_db()

# ── Rate Limiting ─────────────────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])
    LIMITER_AVAILABLE = True
    print("✅ Rate limiter ready")
except Exception:
    limiter = None
    LIMITER_AVAILABLE = False

# ── Webhook ───────────────────────────────────────────────
try:
    from utils.webhooks import send_webhook_alert
    WEBHOOK_AVAILABLE = bool(os.getenv('WEBHOOK_URL', '').strip())
except Exception:
    send_webhook_alert = None
    WEBHOOK_AVAILABLE  = False


# ── MITRE ATT&CK Mapping ──────────────────────────────────
def map_mitre(features: dict, prediction: str) -> list:
    """Return list of relevant MITRE ATT&CK technique dicts based on features."""
    tactics = []
    score = features.get('BitcoinAddresses', 0)
    sections = features.get('NumberOfSections', 0)
    dll_chars = features.get('DllCharacteristics', 0)
    stack = features.get('SizeOfStackReserve', 1048576)
    resource = features.get('ResourceSize', 0)
    iat = features.get('IatVRA', 0)

    if prediction == 'Ransomware' or score > 0:
        tactics.append({'id': 'T1486', 'name': 'Data Encrypted for Impact',
                        'tactic': 'Impact', 'reason': 'Bitcoin address embedded',
                        'url': 'https://attack.mitre.org/techniques/T1486/'})
    if dll_chars == 0:
        tactics.append({'id': 'T1027', 'name': 'Obfuscated Files or Information',
                        'tactic': 'Defense Evasion', 'reason': 'No DLL security features (no ASLR/DEP/CFG)',
                        'url': 'https://attack.mitre.org/techniques/T1027/'})
    if sections > 5 or sections < 2:
        tactics.append({'id': 'T1027.002', 'name': 'Software Packing',
                        'tactic': 'Defense Evasion', 'reason': f'Unusual section count ({sections})',
                        'url': 'https://attack.mitre.org/techniques/T1027/002/'})
    if stack < 500000:
        tactics.append({'id': 'T1055', 'name': 'Process Injection',
                        'tactic': 'Privilege Escalation', 'reason': 'Small stack reserve suggests injector',
                        'url': 'https://attack.mitre.org/techniques/T1055/'})
    if iat == 0:
        tactics.append({'id': 'T1129', 'name': 'Shared Modules',
                        'tactic': 'Execution', 'reason': 'Empty IAT — dynamic import resolution',
                        'url': 'https://attack.mitre.org/techniques/T1129/'})
    if resource == 0:
        tactics.append({'id': 'T1564', 'name': 'Hide Artifacts',
                        'tactic': 'Defense Evasion', 'reason': 'No resources section',
                        'url': 'https://attack.mitre.org/techniques/T1564/'})
    if prediction in ('Ransomware', 'Suspicious'):
        tactics.append({'id': 'T1490', 'name': 'Inhibit System Recovery',
                        'tactic': 'Impact', 'reason': 'Ransomware/suspicious file may delete shadow copies',
                        'url': 'https://attack.mitre.org/techniques/T1490/'})
    # Always add at least one baseline technique for any PE file
    if not tactics:
        tactics.append({'id': 'T1106', 'name': 'Native API',
                        'tactic': 'Execution', 'reason': 'PE file uses native Windows API calls',
                        'url': 'https://attack.mitre.org/techniques/T1106/'})
    return tactics[:5]  # cap at 5 most relevant

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
# Users are now persisted in SQLite via utils/db.py
# Default accounts (admin/admin123, analyst/analyst123) are seeded on first run


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
    user     = verify_user(username, password)
    if not user:
        log_audit(username, 'LOGIN_FAILED', f'IP: {request.remote_addr}')
        return jsonify({'error': 'Invalid credentials'}), 401
    token = jwt.encode({
        'username': username,
        'role':     user['role'],
        'exp':      datetime.utcnow() + timedelta(hours=8)
    }, app.config['SECRET_KEY'], algorithm='HS256')
    log_audit(username, 'LOGIN_SUCCESS', f'Role: {user["role"]} | IP: {request.remote_addr}')
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

    # ── MITRE ATT&CK Mapping ──────────────────────────────
    mitre_tactics = map_mitre(features, result['prediction'])
    result['mitre_tactics'] = mitre_tactics
    mitre_str = ', '.join(f"{t['id']} {t['name']}" for t in mitre_tactics)

    threat_id = None
    save_threat({
        'file_name':       features.get('file_name', 'unknown'),
        'features':        json.dumps(features),
        'prediction':      result['prediction'],
        'threat_score':    result['threat_score'],
        'blockchain_hash': result['hash'],
        'timestamp':       result['timestamp'],
        'mitre_tactics':   mitre_str
    })
    # Grab the ID of the just-inserted row
    try:
        import sqlite3 as _sq
        _conn = _sq.connect('cyberdefense.db')
        threat_id = _conn.execute('SELECT MAX(id) FROM threats').fetchone()[0]
        _conn.close()
    except Exception:
        pass

    log_audit(user.get('username'), 'SCAN',
              f'{features.get("file_name","?")} → {result["prediction"]} ({result["threat_score"]})')

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
    if result['threat_score'] > 30:  # generate AI summary for MEDIUM and HIGH
        full_data = {**result, 'file_name': features.get('file_name', 'unknown'), 'mitre_str': mitre_str}

        if result['threat_score'] > threshold:
            if EMAIL_AVAILABLE and send_high_threat_alert:
                threading.Thread(target=send_high_threat_alert, args=(full_data,), daemon=True).start()

            if WEBHOOK_AVAILABLE and send_webhook_alert:
                threading.Thread(target=send_webhook_alert, args=(full_data,), daemon=True).start()

        if result['threat_score'] > threshold:
            socketio.emit('high_threat_alert', {
                'prediction':   result['prediction'],
                'threat_score': result['threat_score'],
                'risk_level':   result['risk_level'],
                'timestamp':    result['timestamp']
            })
            print(f"🚨 HIGH THREAT ALERT — score: {result['threat_score']}")

        # ── Emit file_scanned for every scan (populates SOC Live Feed) ───
        socketio.emit('file_scanned', {
            'file_name':    features.get('file_name', 'unknown'),
            'prediction':   result['prediction'],
            'threat_score': result['threat_score'],
            'risk_level':   result['risk_level'],
            'timestamp':    result['timestamp']
        })

        # ── AI Incident Summary (async) ───────────────────
        if threat_id:
            def _gen_summary(tid, tdata):
                try:
                    from utils.chatbot import chat as ai_chat
                    prompt = (
                        f"Write a 3-sentence incident summary for a SOC analyst. "
                        f"File: {tdata.get('file_name','unknown')}. "
                        f"Prediction: {tdata['prediction']}. "
                        f"Threat score: {tdata['threat_score']}. "
                        f"MITRE tactics: {tdata.get('mitre_str','')}. "
                        f"Keep it concise and professional."
                    )
                    summary = ai_chat(prompt, context={}, history=[])
                    update_threat_summary(tid, summary)
                except Exception as ex:
                    print(f"⚠️  AI summary failed: {ex}")
            threading.Thread(target=_gen_summary, args=(threat_id, full_data), daemon=True).start()

    return jsonify(result)


# ═════════════════════════════════════════════════════════
# PE FILE UPLOAD SCAN
# ═════════════════════════════════════════════════════════

@app.route('/api/upload-scan', methods=['POST'])
def upload_scan():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    f         = request.files['file']
    file_name = f.filename or 'uploaded_file'
    ext       = os.path.splitext(file_name)[1].lower()

    # Save to temp file
    suffix = ext if ext else '.bin'
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name

    try:
        from models.file_monitor import extract_pe_features
        features = extract_pe_features(tmp_path)
        if not features:
            return jsonify({'error': 'Could not extract PE features from file'}), 422

        features['file_name'] = file_name
        result = predict(features)

        hash_data = {
            'prediction':   result['prediction'],
            'threat_score': result['threat_score'],
            'risk_level':   result['risk_level'],
            'timestamp':    result['timestamp']
        }
        result['hash'] = hashlib.sha256(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()

        mitre_tactics = map_mitre(features, result['prediction'])
        result['mitre_tactics'] = mitre_tactics
        mitre_str = ', '.join(f"{t['id']} {t['name']}" for t in mitre_tactics)

        save_threat({
            'file_name':       file_name,
            'features':        json.dumps(features),
            'prediction':      result['prediction'],
            'threat_score':    result['threat_score'],
            'blockchain_hash': result['hash'],
            'timestamp':       result['timestamp'],
            'mitre_tactics':   mitre_str
        })

        log_audit(user.get('username'), 'UPLOAD_SCAN',
                  f'{file_name} → {result["prediction"]} ({result["threat_score"]})')

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
            except Exception:
                pass

        threshold = app.config.get('THREAT_THRESHOLD', 70)
        if result['threat_score'] > threshold:
            if EMAIL_AVAILABLE and send_high_threat_alert:
                threading.Thread(target=send_high_threat_alert,
                                 args=({**result, 'file_name': file_name},), daemon=True).start()
            if WEBHOOK_AVAILABLE and send_webhook_alert:
                threading.Thread(target=send_webhook_alert,
                                 args=({**result, 'file_name': file_name},), daemon=True).start()
            socketio.emit('high_threat_alert', {
                'prediction':   result['prediction'],
                'threat_score': result['threat_score'],
                'risk_level':   result['risk_level'],
                'timestamp':    result['timestamp']
            })

        return jsonify(result)

    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


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
    log_audit(user.get('username'), 'REPORT_DOWNLOAD', filename)
    return send_file(
        filepath, as_attachment=True,
        download_name=filename, mimetype='application/pdf'
    )


# ═════════════════════════════════════════════════════════
# CSV EXPORT
# ═════════════════════════════════════════════════════════

@app.route('/api/threats/export/csv', methods=['GET'])
def export_threats_csv():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    from flask import Response
    csv_data = get_threats_csv()
    log_audit(user.get('username'), 'CSV_EXPORT', 'All threats exported')
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=threats_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'}
    )


# ═════════════════════════════════════════════════════════
# AUDIT LOG
# ═════════════════════════════════════════════════════════

@app.route('/api/audit-log', methods=['GET'])
def get_audit_log_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    limit = int(request.args.get('limit', 500))
    return jsonify(get_audit_logs(limit))


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
    return jsonify(get_all_users())


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
    if not create_user(username, password, role):
        return jsonify({'error': 'User already exists'}), 409
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'USER_CREATED', f'{username} ({role})')
    print(f"👤 Admin added user: {username} ({role})")
    return jsonify({'status': 'User created', 'username': username})


@app.route('/api/admin/users/<username>', methods=['DELETE'])
def admin_delete_user(username):
    if not admin_only(request):
        return jsonify({'error': 'Admin only'}), 403
    if username == 'admin':
        return jsonify({'error': 'Cannot delete admin'}), 400
    if not get_user(username):
        return jsonify({'error': 'User not found'}), 404
    delete_user(username)
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'USER_DELETED', username)
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
    if not get_user(username):
        return jsonify({'error': 'User not found'}), 404
    change_password(username, password)
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'PASSWORD_CHANGED', username)
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
    admin = verify_token(request)
    log_audit(admin.get('username') if admin else 'admin', 'QUARANTINE_CLEARED', f'{cleared} files removed')
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
        'webhook_enabled':  WEBHOOK_AVAILABLE,
        'rate_limiting':    LIMITER_AVAILABLE,
        'quarantine_files': q_files,
        'blockchain_logs':  bc_logs,
        'users_count':      len(get_all_users()),
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
        admin = verify_token(request)
        log_audit(admin.get('username') if admin else 'admin', 'THREATS_CLEARED', 'All threat records deleted')
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
        admin = verify_token(request)
        log_audit(admin.get('username') if admin else 'admin', 'SETTINGS_CHANGED', f'threshold={threshold}')
        print(f"⚙️  Threat threshold updated: {threshold}")
    return jsonify({
        'status':    'Settings updated',
        'threshold': app.config.get('THREAT_THRESHOLD', 70)
    })


# ═════════════════════════════════════════════════════════
# AI CHATBOT
# ═════════════════════════════════════════════════════════

@app.route('/api/chat', methods=['POST'])
def chat_route():
    user = verify_token(request)
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    from utils.chatbot import chat as ai_chat
    from utils.db import get_stats, get_all_threats, get_audit_logs, get_all_users
    body    = request.get_json()
    message = body.get('message', '').strip()
    history = body.get('history', [])

    if not message:
        return jsonify({'error': 'Message required'}), 400

    # ── Build rich live context server-side ───────────────
    try:
        db_stats   = get_stats()
        db_threats = get_all_threats()
        audit_logs = get_audit_logs(200)
        all_users  = get_all_users()

        # Failed login count (last 24 h worth)
        failed_logins = sum(1 for e in audit_logs if e.get('action') == 'LOGIN_FAILED')
        recent_logins = [e for e in audit_logs if e.get('action') in ('LOGIN_SUCCESS', 'LOGIN_FAILED')][:10]

        # Quarantine info
        quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
        q_log_path     = os.path.join(quarantine_dir, 'quarantine_log.json')
        quarantine_log = []
        if os.path.exists(q_log_path):
            try:
                with open(q_log_path) as _f:
                    quarantine_log = json.load(_f)
            except Exception:
                pass
        q_files = len([f for f in os.listdir(quarantine_dir)
                       if f != 'quarantine_log.json']) if os.path.exists(quarantine_dir) else 0

        # Recent audit events (non-login)
        recent_audit = [e for e in audit_logs
                        if e.get('action') not in ('LOGIN_SUCCESS', 'LOGIN_FAILED')][:10]

        context = {
            'stats':          db_stats,
            'threats':        db_threats[:10],
            'failed_logins':  failed_logins,
            'recent_logins':  recent_logins,
            'quarantine_count': q_files,
            'quarantine_log': quarantine_log[:10],
            'recent_audit':   recent_audit,
            'users_count':    len(all_users),
            'users':          all_users,
            'blockchain_mode': bc_logger.mode if bc_logger else 'unavailable',
            'threat_threshold': app.config.get('THREAT_THRESHOLD', 70),
            'email_enabled':  EMAIL_AVAILABLE,
            'current_user':   user.get('username'),
            'current_role':   user.get('role'),
        }
    except Exception:
        context = body.get('context', {})

    try:
        reply = ai_chat(message, context=context, history=history)
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        # Scan files that were already in watched/ before the monitor started
        from models.file_monitor import scan_existing_files
        scan_existing_files()
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"⚠️  File monitor failed: {e}")

monitor_thread = threading.Thread(target=start_file_monitor, daemon=True)
monitor_thread.start()


# ═════════════════════════════════════════════════════════
# NETWORK MONITOR
# ═════════════════════════════════════════════════════════

def start_network_monitor():
    try:
        from models.network_monitor import NetworkMonitor, set_monitor
        nm = NetworkMonitor(socketio, blockchain_log, send_high_threat_alert)
        set_monitor(nm)
        nm.start()
    except Exception as e:
        print(f"⚠️  Network monitor failed: {e}")

network_thread = threading.Thread(target=start_network_monitor, daemon=True)
network_thread.start()


@app.route('/api/network/connections')
@limiter.limit("30 per minute")
def network_connections():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'connections': [], 'error': 'Monitor not ready'})
    return jsonify({'connections': m.get_connections()})


@app.route('/api/network/stats')
@limiter.limit("30 per minute")
def network_stats():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'total_connections': 0, 'suspicious_ips': 0,
                        'alerts_today': 0, 'bytes_sent_mb': 0})
    return jsonify(m.get_stats())


@app.route('/api/network/alerts')
@limiter.limit("30 per minute")
def network_alerts():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'alerts': []})
    return jsonify({'alerts': m.get_alerts()})


@app.route('/api/network/packets')
@limiter.limit("30 per minute")
def network_packets():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from models.network_monitor import get_monitor
    m = get_monitor()
    if m is None:
        return jsonify({'packets': []})
    return jsonify({'packets': m.get_packets()})


@app.route('/api/network/audit-log')
@limiter.limit("30 per minute")
def network_audit_log_route():
    if not verify_token(request):
        return jsonify({'error': 'Unauthorized'}), 401
    from utils.db import get_network_audit_logs
    limit = min(int(request.args.get('limit', 500)), 1000)
    return jsonify(get_network_audit_logs(limit))


# ═════════════════════════════════════════════════════════
# RUN
# ═════════════════════════════════════════════════════════

if __name__ == '__main__':
    import socket as _socket
    _s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    _s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    _s.close()
    print("🛡️  CyberDefense Backend starting on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)