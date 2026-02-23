import os
import json
import hashlib
from datetime import datetime

# ── Try Web3 connection (real blockchain) ─────────────────
WEB3_AVAILABLE = False
CONTRACT_AVAILABLE = False

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    pass

# ── Local log file (always works as fallback) ─────────────
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        'blockchain_log.json')


class BlockchainLogger:
    def __init__(self):
        self.mode     = 'local'
        self.w3       = None
        self.contract = None
        self._init_web3()

    def _init_web3(self):
        """Try to connect to Ethereum testnet."""
        rpc_url          = os.getenv('ETH_RPC_URL', '')
        contract_address = os.getenv('CONTRACT_ADDRESS', '')
        private_key      = os.getenv('WALLET_PRIVATE_KEY', '')

        if not WEB3_AVAILABLE:
            print("ℹ️  Web3 not available — using local blockchain simulation")
            return

        if not rpc_url or 'YOUR_KEY' in rpc_url:
            print("ℹ️  No ETH RPC URL configured — using local blockchain simulation")
            return

        try:
            self.w3 = Web3(Web3.HTTPProvider(rpc_url))
            if not self.w3.is_connected():
                print("⚠️  Blockchain connection failed — using local simulation")
                return

            if contract_address and contract_address != '':
                # Load ABI
                abi_path = os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    'blockchain', 'ThreatLogger_ABI.json'
                )
                if os.path.exists(abi_path):
                    with open(abi_path) as f:
                        abi = json.load(f)
                    self.contract = self.w3.eth.contract(
                        address=contract_address, abi=abi
                    )
                    self.mode = 'blockchain'
                    print(f"✅ Blockchain connected: {rpc_url[:40]}...")
                    print(f"✅ Contract: {contract_address}")
        except Exception as e:
            print(f"⚠️  Blockchain init failed: {e} — using local simulation")

    def hash_alert(self, alert_data: dict) -> str:
        """Create SHA-256 hash of alert data."""
        alert_str = json.dumps(alert_data, sort_keys=True)
        return hashlib.sha256(alert_str.encode()).hexdigest()

    def log_threat(self, alert_data: dict) -> dict:
        """Log threat to blockchain or local fallback."""
        alert_hash  = self.hash_alert(alert_data)
        threat_score = int(alert_data.get('threat_score', 0))
        prediction   = alert_data.get('prediction', 'Unknown')

        if self.mode == 'blockchain':
            return self._log_to_blockchain(alert_hash, prediction, threat_score)
        else:
            return self._log_locally(alert_hash, prediction, threat_score, alert_data)

    def _log_to_blockchain(self, alert_hash, prediction, threat_score) -> dict:
        """Log to real Ethereum blockchain."""
        try:
            private_key = os.getenv('WALLET_PRIVATE_KEY', '')
            account     = self.w3.eth.account.from_key(private_key)

            tx = self.contract.functions.logThreat(
                alert_hash, prediction, threat_score
            ).build_transaction({
                'from':     account.address,
                'nonce':    self.w3.eth.get_transaction_count(account.address),
                'gas':      200000,
                'gasPrice': self.w3.eth.gas_price,
            })

            signed = self.w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            result = {
                'mode':        'blockchain',
                'alert_hash':  alert_hash,
                'tx_hash':     receipt.transactionHash.hex(),
                'block':       receipt.blockNumber,
                'prediction':  prediction,
                'timestamp':   datetime.utcnow().isoformat()
            }
            print(f"⛓  Logged to blockchain — tx: {result['tx_hash'][:20]}...")
            self._save_local(result)
            return result

        except Exception as e:
            print(f"⚠️  Blockchain log failed: {e} — falling back to local")
            return self._log_locally(alert_hash, prediction, threat_score, {})

    def _log_locally(self, alert_hash, prediction, threat_score, alert_data) -> dict:
        """Log to local JSON file (blockchain simulation)."""
        result = {
            'mode':         'local_simulation',
            'alert_hash':   alert_hash,
            'tx_hash':      f"0x{alert_hash[:40]}",
            'block':        self._get_next_block(),
            'prediction':   prediction,
            'threat_score': threat_score,
            'timestamp':    datetime.utcnow().isoformat(),
            'verified':     True
        }
        self._save_local(result)
        print(f"📝 Logged locally (simulated blockchain) — hash: {alert_hash[:20]}...")
        return result

    def _get_next_block(self) -> int:
        logs = self._load_logs()
        return 1000000 + len(logs)

    def _save_local(self, entry: dict):
        logs = self._load_logs()
        logs.append(entry)
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)

    def _load_logs(self) -> list:
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE) as f:
                    return json.load(f)
            except:
                return []
        return []

    def verify_hash(self, alert_hash: str) -> dict:
        """Verify a hash exists in logs."""
        logs = self._load_logs()
        for log in logs:
            if log.get('alert_hash') == alert_hash:
                return {'verified': True, 'entry': log}
        return {'verified': False, 'entry': None}

    def get_all_logs(self) -> list:
        return self._load_logs()


# ── Singleton instance ────────────────────────────────────
logger = BlockchainLogger()


def log_threat(alert_data: dict) -> dict:
    return logger.log_threat(alert_data)

def verify_hash(alert_hash: str) -> dict:
    return logger.verify_hash(alert_hash)

def get_all_logs() -> list:
    return logger.get_all_logs()