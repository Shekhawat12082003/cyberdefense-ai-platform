import os
import sys
import time
import struct
import random

# ── Config ────────────────────────────────────────────────
WATCHED_DIR = os.path.join(os.path.dirname(__file__), 'watched')
os.makedirs(WATCHED_DIR, exist_ok=True)

XOR_KEY = b'RANSOMWARE_SIMULATOR_KEY_2024_CYBERDEFENSE'

BANNER = """
╔══════════════════════════════════════════════════════╗
║       🦠 RANSOMWARE SIMULATOR — FOR TESTING ONLY     ║
║         CyberDefense AI Platform — Safe Demo         ║
╚══════════════════════════════════════════════════════╝
"""

RANSOM_NOTE = """
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!          YOUR FILES ARE ENCRYPTED               !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

All your important files have been encrypted.

To recover your files send 0.5 BTC to:
1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na

Contact: ransom@darkweb.onion
You have 72 hours before deletion.

[THIS IS A SIMULATION - NOT REAL RANSOMWARE]

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
"""


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def add_fake_pe_header(data: bytes, ransomware_mode: bool = True) -> bytes:
    mz           = b'MZ'
    pe           = b'PE\x00\x00'
    machine      = struct.pack('<H', 0x014c)
    num_sections = struct.pack('<H', 6 if ransomware_mode else 3)
    dll_chars    = struct.pack('<H', 0x0000 if ransomware_mode else 0x8540)
    stack_size   = struct.pack('<I', 262144 if ransomware_mode else 1048576)
    btc_marker   = b'1BTC_RANSOM_PAY_NOW_' if ransomware_mode else b'\x00' * 20
    header = (
        mz + b'\x00' * 58 +
        pe + machine + num_sections +
        b'\x00' * 12 + dll_chars +
        stack_size + b'\x00' * 16 + btc_marker
    )
    return header + data


def drop_ransom_note():
    path = os.path.join(WATCHED_DIR, 'READ_ME_NOW.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(RANSOM_NOTE)
    print(f"   📝 Ransom note dropped: READ_ME_NOW.txt")


def clean_watched_folder():
    files = os.listdir(WATCHED_DIR)
    if not files:
        print("\n   Watched folder already empty\n")
        return
    for f in files:
        path = os.path.join(WATCHED_DIR, f)
        try:
            os.remove(path)
            print(f"   Removed: {f}")
        except Exception as e:
            print(f"   Could not remove {f}: {e}")
    print(f"\n   Cleaned {len(files)} files\n")


# ─────────────────────────────────────────────────────────
# ATTACK MODES
# ─────────────────────────────────────────────────────────

def simulate_full_ransomware_attack(delay: float = 2.0):
    """All HIGH threat files — tests auto-quarantine."""
    print(BANNER)
    print("🦠 FULL RANSOMWARE ATTACK SIMULATION")
    print("=" * 55)

    test_files = [
        ('document.txt',       b'Sensitive company data - employee records financial info'),
        ('financial_data.csv', b'Name,Amount,Account\nJohn,50000,ACC001\nJane,75000,ACC002'),
        ('config.json',        b'{"api_key": "secret123", "db_password": "admin456"}'),
        ('backup.db',          b'SQLite format 3\x00' + b'Database records ' * 20),
        ('secret_keys.pem',    b'-----BEGIN RSA PRIVATE KEY-----\nFAKE_KEY_DATA\n-----END RSA PRIVATE KEY-----'),
    ]

    print("\n📁 PHASE 1: Creating target files...")
    created = []
    for filename, content in test_files:
        path = os.path.join(WATCHED_DIR, filename)
        with open(path, 'wb') as f:
            f.write(content)
        created.append(path)
        print(f"   📄 Created: {filename}")

    print(f"   Waiting {delay}s before encryption...")
    time.sleep(delay)

    print("\n" + "=" * 55)
    print("🔒 PHASE 2: ENCRYPTING FILES...")
    for filepath in created:
        filename = os.path.basename(filepath)
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted  = xor_encrypt(data, XOR_KEY)
            final      = add_fake_pe_header(encrypted, ransomware_mode=True)
            locked_path = filepath + '.locked'
            with open(locked_path, 'wb') as f:
                f.write(final)
            os.remove(filepath)
            print(f"   🔒 {filename} → {filename}.locked")
            time.sleep(delay * 0.5)
        except Exception as e:
            print(f"   ❌ Failed: {filename} — {e}")

    print("\n📝 PHASE 3: Dropping ransom note...")
    drop_ransom_note()

    print(f"\n{'=' * 55}")
    print(f"🦠 ATTACK COMPLETE!")
    print(f"   Files encrypted : {len(created)}")
    print(f"   Watch backend for HIGH THREAT alerts!")
    print(f"{'=' * 55}\n")


def simulate_mixed_attack(delay: float = 1.5):
    """Mix of HIGH + MEDIUM + LOW — best for demo."""
    print(BANNER)
    print("🎯 MIXED ATTACK SIMULATION — Best for Demo")
    print("=" * 55)

    files = [
        # HIGH threat — ransomware indicators
        ('ransomware_payload.dll', True,  b'Malicious payload ' * 50,        'HIGH'),
        ('encrypted_locker.exe',   True,  b'Encrypted locker data ' * 40,    'HIGH'),
        ('crypto_miner.dll',       True,  b'Mining payload BTC wallet ' * 30,'HIGH'),
        # MEDIUM threat — suspicious
        ('suspicious_tool.exe',    False, b'Tool data medium risk ' * 40,     'MEDIUM'),
        ('unknown_packer.dll',     False, b'Packed data unknown origin ' * 30,'MEDIUM'),
        # LOW threat — benign
        ('calc.dll',               False, b'Normal calculator application ' * 50, 'LOW'),
        ('notepad_helper.dll',     False, b'Helper DLL safe content ' * 50,       'LOW'),
    ]

    print(f"\n📁 Creating {len(files)} files (HIGH + MEDIUM + LOW)...\n")

    for filename, is_ransomware, content, level in files:
        filepath = os.path.join(WATCHED_DIR, filename)
        if is_ransomware:
            encrypted = xor_encrypt(content, XOR_KEY)
            final     = add_fake_pe_header(encrypted, ransomware_mode=True)
        else:
            final = add_fake_pe_header(content, ransomware_mode=False)

        with open(filepath, 'wb') as f:
            f.write(final)

        icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
        print(f"   {icon} [{level}] {filename}")
        time.sleep(delay)

    print(f"\n{'=' * 55}")
    print(f"🎯 MIXED ATTACK COMPLETE!")
    print(f"   HIGH   : {sum(1 for f in files if f[3] == 'HIGH')} files")
    print(f"   MEDIUM : {sum(1 for f in files if f[3] == 'MEDIUM')} files")
    print(f"   LOW    : {sum(1 for f in files if f[3] == 'LOW')} files")
    print(f"   Watch dashboard for mixed threat levels!")
    print(f"{'=' * 55}\n")


def simulate_gradual_escalation(delay: float = 2.0):
    """APT simulation — LOW to HIGH escalation."""
    print(BANNER)
    print("📈 GRADUAL ESCALATION — APT Simulation")
    print("=" * 55)

    stages = [
        ('stage1_recon.dll',      False, b'Reconnaissance tool ' * 50,         'LOW',    "Stage 1: Reconnaissance"),
        ('stage2_dropper.dll',    False, b'Dropper payload medium ' * 40,       'MEDIUM', "Stage 2: Dropper"),
        ('stage3_persist.exe',    False, b'Persistence mechanism ' * 40,        'MEDIUM', "Stage 3: Persistence"),
        ('stage4_encrypt.dll',    True,  b'Encryption engine BTC ' * 50,        'HIGH',   "Stage 4: Encryption"),
        ('stage5_ransom.exe',     True,  b'Ransomware final payload ' * 50,     'HIGH',   "Stage 5: Ransom"),
    ]

    for filename, is_ransomware, content, level, stage_name in stages:
        print(f"\n   ⏳ {stage_name}")
        filepath = os.path.join(WATCHED_DIR, filename)

        if is_ransomware:
            encrypted = xor_encrypt(content, XOR_KEY)
            final     = add_fake_pe_header(encrypted, ransomware_mode=True)
        else:
            final = add_fake_pe_header(content, ransomware_mode=False)

        with open(filepath, 'wb') as f:
            f.write(final)

        icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
        print(f"   {icon} Deployed: {filename} [{level}]")
        print(f"   Waiting {delay}s for next stage...")
        time.sleep(delay)

    drop_ransom_note()

    print(f"\n{'=' * 55}")
    print(f"📈 APT SIMULATION COMPLETE!")
    print(f"   Watch dashboard — threat level should escalate!")
    print(f"{'=' * 55}\n")


def simulate_benign_files(count: int = 5):
    """All benign files — tests false positive rate."""
    print(BANNER)
    print(f"✅ BENIGN FILES SIMULATION ({count} files)")
    print("=" * 55)

    names = [
        'system32_helper.dll', 'winapi_wrapper.dll',
        'graphics_engine.dll', 'audio_driver.dll',
        'network_utils.dll',   'ui_framework.dll',
        'database_lib.dll',    'crypto_utils.dll',
    ]

    for i in range(count):
        filename = names[i % len(names)]
        filepath = os.path.join(WATCHED_DIR, f"benign_{i+1}_{filename}")
        content  = f'Normal application data safe content iteration {i} '.encode() * 50
        final    = add_fake_pe_header(content, ransomware_mode=False)
        with open(filepath, 'wb') as f:
            f.write(final)
        print(f"   ✅ Created: benign_{i+1}_{filename}")
        time.sleep(1.0)

    print(f"\n   Monitor should score ALL files LOW risk")
    print(f"   No quarantine should trigger\n")


def quick_single_file():
    """Create one file with chosen risk level."""
    print("\n  Risk level:")
    print("  1 — HIGH (ransomware)")
    print("  2 — MEDIUM (suspicious)")
    print("  3 — LOW (benign)")
    choice = input("  Choose: ").strip()

    if choice == '1':
        filename = f"malware_{int(time.time())}.dll"
        content  = xor_encrypt(b'Ransomware payload BTC address ' * 100, XOR_KEY)
        final    = add_fake_pe_header(content, ransomware_mode=True)
        level    = 'HIGH'
    elif choice == '2':
        filename = f"suspicious_{int(time.time())}.dll"
        content  = b'Suspicious tool data unknown origin medium risk ' * 60
        final    = add_fake_pe_header(content, ransomware_mode=False)
        level    = 'MEDIUM'
    else:
        filename = f"benign_{int(time.time())}.dll"
        content  = b'Normal safe application data benign content ' * 60
        final    = add_fake_pe_header(content, ransomware_mode=False)
        level    = 'LOW'

    filepath = os.path.join(WATCHED_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(final)

    icon = '🔴' if level == 'HIGH' else '🟡' if level == 'MEDIUM' else '🟢'
    print(f"\n   {icon} Created: {filename} [{level}]")
    print(f"   Watch backend terminal for auto-scan!\n")


def show_menu():
    print(BANNER)
    print(f"📁 Watched folder: {WATCHED_DIR}\n")
    print("  1 — 🎯 MIXED Attack       (HIGH + MEDIUM + LOW — best for demo)")
    print("  2 — 🦠 FULL Ransomware    (all HIGH — tests auto-quarantine)")
    print("  3 — 📈 GRADUAL Escalation (LOW → MEDIUM → HIGH — APT sim)")
    print("  4 — ✅ BENIGN Files Only  (all LOW — tests false positive rate)")
    print("  5 — ⚡ Quick Single File  (one file — pick risk level)")
    print("  6 — 🗑️  Clean Watched Folder")
    print("  0 — Exit\n")
    return input("Enter choice: ").strip()


if __name__ == '__main__':
    # CLI args
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == 'attack':
            simulate_full_ransomware_attack(delay=1.5)
        elif arg == 'mixed':
            simulate_mixed_attack()
        elif arg == 'gradual':
            simulate_gradual_escalation()
        elif arg == 'benign':
            simulate_benign_files()
        elif arg == 'quick':
            quick_single_file()
        elif arg == 'clean':
            clean_watched_folder()
        sys.exit(0)

    # Interactive menu
    while True:
        choice = show_menu()

        if choice == '1':
            delay = input("Delay between files in seconds (default 1.5): ").strip()
            delay = float(delay) if delay else 1.5
            simulate_mixed_attack(delay=delay)

        elif choice == '2':
            delay = input("Delay between files in seconds (default 2): ").strip()
            delay = float(delay) if delay else 2.0
            simulate_full_ransomware_attack(delay=delay)

        elif choice == '3':
            delay = input("Delay between stages in seconds (default 2): ").strip()
            delay = float(delay) if delay else 2.0
            simulate_gradual_escalation(delay=delay)

        elif choice == '4':
            count = input("How many benign files (default 5): ").strip()
            count = int(count) if count else 5
            simulate_benign_files(count=count)

        elif choice == '5':
            quick_single_file()

        elif choice == '6':
            clean_watched_folder()

        elif choice == '0':
            print("\nExiting simulator...\n")
            break

        else:
            print("\n   Invalid choice\n")

        input("Press Enter to continue...")