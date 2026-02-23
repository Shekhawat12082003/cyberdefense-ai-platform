import os
import time
import math
import hashlib
import json
import requests
from datetime import datetime
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Config ────────────────────────────────────────────────
WATCHED_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'watched')
QUARANTINE   = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'quarantine')
BACKEND_URL  = 'http://localhost:5000/api/predict'
LOGIN_URL    = 'http://localhost:5000/api/login'

SCAN_EXTENSIONS = {
    '.dll', '.exe', '.sys', '.bat', '.ps1',
    '.vbs', '.js', '.locked', '.enc', '.crypto'
}

# ── Auth ──────────────────────────────────────────────────
_token = None

def get_token():
    global _token
    if _token:
        return _token
    try:
        res = requests.post(LOGIN_URL, json={
            'username': 'admin',
            'password': 'admin123'
        }, timeout=5)
        if res.status_code == 200:
            _token = res.json().get('token', '')
            print(f"✅ File monitor authenticated")
            return _token
        else:
            print(f"⚠️  Auth failed: {res.text}")
            return ''
    except Exception as e:
        print(f"⚠️  Auth error: {e}")
        return ''


def reset_token():
    global _token
    _token = None


# ── File Analysis ─────────────────────────────────────────
def calculate_entropy(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(65536)
        if not data:
            return 0.0
        counter = Counter(data)
        length  = len(data)
        entropy = -sum(
            (c / length) * math.log2(c / length)
            for c in counter.values() if c > 0
        )
        return round(entropy, 4)
    except:
        return 0.0


def extract_pe_features(filepath):
    try:
        size    = os.path.getsize(filepath)
        entropy = calculate_entropy(filepath)
        ext     = os.path.splitext(filepath)[1].lower()
        fname   = os.path.basename(filepath)

        # Try real PE parsing
        try:
            import pefile
            pe = pefile.PE(filepath, fast_load=True)
            features = {
                'Machine':            pe.FILE_HEADER.Machine,
                'DebugSize':          0,
                'DebugRVA':           0,
                'MajorImageVersion':  pe.OPTIONAL_HEADER.MajorImageVersion,
                'MajorOSVersion':     pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'ExportRVA':          pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress,
                'ExportSize':         pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size,
                'IatVRA':             pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'NumberOfSections':   pe.FILE_HEADER.NumberOfSections,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'ResourceSize':       pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size,
                'BitcoinAddresses':   0,
            }
            pe.close()

        except:
            # Fallback: use file stats + entropy as proxy
            is_suspicious = (
                ext in {'.locked', '.enc', '.crypto'} or
                entropy > 7.0 or
                b'BTC' in open(filepath, 'rb').read(512)
            )

            features = {
                'Machine':            332,
                'DebugSize':          min(size // 1000, 9999),
                'DebugRVA':           min(size // 500,  9999),
                'MajorImageVersion':  0,
                'MajorOSVersion':     4  if not is_suspicious else 10,
                'ExportRVA':          0,
                'ExportSize':         0,
                'IatVRA':             8192 if not is_suspicious else 0,
                'MajorLinkerVersion': 8,
                'MinorLinkerVersion': 0,
                'NumberOfSections':   3  if not is_suspicious else 8,
                'SizeOfStackReserve': 1048576 if not is_suspicious else 262144,
                'DllCharacteristics': 34112   if not is_suspicious else 0,
                'ResourceSize':       min(size // 100, 9999),
                'BitcoinAddresses':   1 if is_suspicious else 0,
            }

        features['file_name'] = fname
        return features

    except Exception as e:
        print(f"⚠️  Feature extraction failed: {e}")
        return None


def scan_file(filepath):
    fname = os.path.basename(filepath)
    print(f"\n🔍 Auto-scanning: {fname}")

    features = extract_pe_features(filepath)
    if not features:
        print("   ❌ Could not extract features")
        return None

    try:
        token = get_token()
        if not token:
            reset_token()
            token = get_token()

        res = requests.post(
            BACKEND_URL,
            json={'features': features},
            headers={'Authorization': f'Bearer {token}'},
            timeout=15
        )

        if res.status_code == 401:
            print("   🔄 Token expired — refreshing...")
            reset_token()
            token = get_token()
            res   = requests.post(
                BACKEND_URL,
                json={'features': features},
                headers={'Authorization': f'Bearer {token}'},
                timeout=15
            )

        result = res.json()
        score      = result.get('threat_score', 0)
        prediction = result.get('prediction', 'Unknown')
        risk       = result.get('risk_level', 'LOW')

        # Risk indicator
        if score > 70:
            indicator = '🚨 HIGH THREAT'
        elif score > 30:
            indicator = '⚠️  MEDIUM'
        else:
            indicator = '✅ LOW'

        print(f"   File      : {fname}")
        print(f"   Score     : {score}")
        print(f"   Result    : {prediction} — {indicator}")
        print(f"   Risk      : {risk}")

        if score > 70:
            quarantine_file(filepath, result)

        return result

    except Exception as e:
        print(f"   ❌ Scan failed: {e}")
        reset_token()
        return None


def quarantine_file(filepath, result):
    try:
        os.makedirs(QUARANTINE, exist_ok=True)
        filename  = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dest      = os.path.join(QUARANTINE, f"{timestamp}_{filename}")

        os.rename(filepath, dest)
        print(f"   🔒 QUARANTINED: {filename}")

        log_path = os.path.join(QUARANTINE, 'quarantine_log.json')
        logs     = []
        if os.path.exists(log_path):
            with open(log_path) as f:
                try:
                    logs = json.load(f)
                except:
                    logs = []
        logs.append({
            'original':    filepath,
            'quarantined': dest,
            'score':       result.get('threat_score'),
            'prediction':  result.get('prediction'),
            'timestamp':   datetime.now().isoformat()
        })
        with open(log_path, 'w') as f:
            json.dump(logs, f, indent=2)

    except Exception as e:
        print(f"   ⚠️  Quarantine failed: {e}")


# ── Watchdog Handler ──────────────────────────────────────
class ThreatHandler(FileSystemEventHandler):

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        ext      = os.path.splitext(filepath)[1].lower()
        if ext in SCAN_EXTENSIONS:
            time.sleep(0.8)
            scan_file(filepath)

    def on_modified(self, event):
            pass  # Skip modified events — only scan on_created


# ── Standalone run ────────────────────────────────────────
if __name__ == '__main__':
    os.makedirs(WATCHED_DIR,  exist_ok=True)
    os.makedirs(QUARANTINE,   exist_ok=True)

    print("🛡️  CyberDefense File Monitor")
    print(f"   Watching  : {WATCHED_DIR}")
    print(f"   Quarantine: {QUARANTINE}")
    print(f"   Extensions: {', '.join(SCAN_EXTENSIONS)}")
    print("\n   Drop any file to auto-scan. Press Ctrl+C to stop.\n")

    handler  = ThreatHandler()
    observer = Observer()
    observer.schedule(handler, WATCHED_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n⛔ Monitor stopped.")
    observer.join()