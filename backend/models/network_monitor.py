"""
Network Traffic Analyser
Detects: Port Scans, Brute Force, C2 Beaconing, Data Exfiltration
Alerts:  SOC Feed (socket), Email, Blockchain, Audit Log
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# RFC 1918 private address prefixes
_PRIVATE_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                     '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                     '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                     '172.30.', '172.31.', '192.168.', '127.', '::1', 'fe80')

# Known CDN / legitimate service IP prefixes — never flag as C2
_CDN_WHITELIST = (
    '142.250.', '142.251.',          # Google
    '216.58.',  '172.217.',          # Google
    '8.8.8.',   '8.8.4.',            # Google DNS
    '1.1.1.',   '1.0.0.',            # Cloudflare DNS
    '104.16.',  '104.17.',           # Cloudflare CDN
    '151.101.',                      # Fastly
    '13.107.',  '20.190.',           # Microsoft/Azure
    '52.',      '54.',               # AWS (broad — tighten if needed)
    '185.199.',                      # GitHub CDN
    '199.232.',                      # Fastly/NPM
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _is_cdn(ip: str) -> bool:
    return any(ip.startswith(p) for p in _CDN_WHITELIST)


# Detection thresholds
PORT_SCAN_THRESHOLD    = 10   # distinct dst ports from same IP in 60 s
BRUTE_FORCE_THRESHOLD  = 15   # connections to same auth port from same IP in 60 s
BEACON_MIN_CONNS       = 8    # minimum repeated connections to flag C2 (raised to reduce FP)
EXFIL_BYTES_THRESHOLD  = 50 * 1024 * 1024   # 50 MB outbound in 30 s
AUTH_PORTS             = {22, 23, 3389, 5900, 21, 25, 110, 143, 5000}
# Ports excluded from C2 detection (normal browser/HTTPS traffic)
_NORMAL_PORTS          = {80, 443, 8080, 8443}

# Alert dedup window — don't re-alert same (type, ip) within this many seconds
DEDUP_WINDOW_SECONDS = 300   # 5 minutes

WINDOW_SECONDS = 60          # sliding detection window
POLL_INTERVAL  = 2           # seconds between psutil polls (real-time)


class NetworkMonitor:
    def __init__(self, socketio, blockchain_log_fn, email_fn):
        self.socketio          = socketio
        self.blockchain_log_fn = blockchain_log_fn
        self.email_fn          = email_fn

        # Thread-safe state
        self._lock = threading.Lock()

        # Sliding-window connection event tracking: {src_ip: [(timestamp, dst_port), …]}
        self._ip_events: dict = defaultdict(list)

        # Dedup: {(alert_type, ip): last_alert_time}
        self._last_alert: dict = {}

        # Recent alerts list (capped at 100)
        self._alerts: list = []

        # Last known io counters for exfil delta
        self._last_io = None
        self._last_io_time = None

        # Latest snapshot of connections
        self._connections: list = []

        # Live packet stream (scapy)
        self._packets: list = []

        # Stats counters
        self._stats = {
            'total_connections':  0,
            'suspicious_ips':     set(),
            'alerts_today':       0,
            'bytes_sent_total':   0,
        }

    # ─────────────────────────────────────────────────────
    # Public API (called by Flask routes)
    # ─────────────────────────────────────────────────────

    def get_connections(self) -> list:
        with self._lock:
            return list(self._connections)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'total_connections': self._stats['total_connections'],
                'suspicious_ips':    len(self._stats['suspicious_ips']),
                'alerts_today':      self._stats['alerts_today'],
                'bytes_sent_mb':     round(self._stats['bytes_sent_total'] / (1024 * 1024), 2),
            }

    def get_alerts(self) -> list:
        with self._lock:
            return list(self._alerts[-50:])

    def get_packets(self) -> list:
        with self._lock:
            return list(self._packets[-200:])

    # ─────────────────────────────────────────────────────
    # Thread start
    # ─────────────────────────────────────────────────────

    def start(self):
        if not PSUTIL_AVAILABLE:
            print("⚠️  psutil not installed — network monitor disabled")
            return
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        print("🌐 Network monitor started")
        self._start_scapy_sniffer()

    def _start_scapy_sniffer(self):
        if not SCAPY_AVAILABLE:
            print("⚠️  scapy not available — using psutil fallback for packet view")
            return
        def _run_sniffer():
            try:
                sniffer = AsyncSniffer(
                    filter='ip and (tcp or udp)',
                    prn=self._on_packet,
                    store=False,
                )
                sniffer.start()
                print("📦 Scapy live capture active")
                sniffer.join()  # block this thread
            except Exception as e:
                print(f"⚠️  Scapy sniffer error (need admin for live capture): {e}")
            finally:
                print("⚠️  Scapy stopped — psutil synthesis continues")
        t = threading.Thread(target=_run_sniffer, daemon=True)
        t.start()

    def _on_packet(self, pkt):
        """Callback for each captured packet — builds Wireshark-style record."""
        if not pkt.haslayer(IP):
            return
        now = datetime.utcnow()
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = 'OTHER'
        sport = 0
        dport = 0
        flags = ''
        info = ''

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport, dport = tcp.sport, tcp.dport
            flag_bits = int(tcp.flags)
            flag_map = {0x02: 'SYN', 0x10: 'ACK', 0x04: 'RST',
                        0x01: 'FIN', 0x08: 'PSH', 0x20: 'URG'}
            flags = ' '.join(v for k, v in flag_map.items() if flag_bits & k)
            if dport in (443, 8443) or sport in (443, 8443):
                proto = 'HTTPS'
            elif dport in (80, 8080) or sport in (80, 8080):
                proto = 'HTTP'
            elif dport == 22 or sport == 22:
                proto = 'SSH'
            elif dport == 21 or sport == 21:
                proto = 'FTP'
            elif dport == 3389 or sport == 3389:
                proto = 'RDP'
            else:
                proto = 'TCP'
            info = flags if flags else 'Data'
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport, dport = udp.sport, udp.dport
            if dport == 53 or sport == 53:
                proto = 'DNS'
            else:
                proto = 'UDP'
            info = f'{proto} {sport}→{dport}'

        packet_rec = {
            'time':    now.isoformat(),
            'src':     f"{src_ip}:{sport}",
            'dst':     f"{dst_ip}:{dport}",
            'src_ip':  src_ip,
            'dst_ip':  dst_ip,
            'proto':   proto,
            'length':  len(pkt),
            'flags':   flags,
            'info':    info,
        }

        with self._lock:
            self._packets.append(packet_rec)
            if len(self._packets) > 1000:
                self._packets = self._packets[-1000:]

        # Feed external src IPs into detection events
        if not _is_private(src_ip):
            with self._lock:
                self._ip_events[src_ip].append((now, dport))

    def _synthesize_packets_from_conns(self, conns: list, now):
        """Fallback: build fake packet records from psutil connections so the UI shows data."""
        _PROTO_MAP = {
            443: 'HTTPS', 8443: 'HTTPS', 80: 'HTTP', 8080: 'HTTP',
            22: 'SSH', 21: 'FTP', 3389: 'RDP', 53: 'DNS',
        }
        new_pkts = []
        for c in conns[:50]:  # cap at 50 per poll
            rport = c.get('remote_port', 0)
            proto = _PROTO_MAP.get(rport) or _PROTO_MAP.get(c.get('local_port', 0), 'TCP')
            status = c.get('status', '')
            flags = 'ACK' if status == 'ESTABLISHED' else ('SYN' if status == 'SYN_SENT' else status)
            new_pkts.append({
                'time':    now.isoformat(),
                'src':     c.get('local', ''),
                'dst':     c.get('remote', ''),
                'src_ip':  c.get('local', '').split(':')[0],
                'dst_ip':  c.get('remote_ip', ''),
                'proto':   proto,
                'length':  0,
                'flags':   flags,
                'info':    f"{c.get('process','?')} → {proto}",
            })
        with self._lock:
            self._packets = (self._packets + new_pkts)[-1000:]

    # ─────────────────────────────────────────────────────
    # Main poll loop
    # ─────────────────────────────────────────────────────

    def _run(self):
        while True:
            try:
                self._poll()
            except Exception as e:
                print(f"⚠️  Network monitor poll error: {e}")
            time.sleep(POLL_INTERVAL)

    def _poll(self):
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=WINDOW_SECONDS)

        # ── Gather connections ──────────────────────────
        conns = []
        try:
            raw = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError):
            raw = []

        proc_cache: dict = {}

        for c in raw:
            if c.laddr and c.raddr:
                rip = c.raddr.ip
                rport = c.raddr.port
                lport = c.laddr.port

                # Resolve process name (cache pid lookups)
                pid = c.pid or 0
                if pid not in proc_cache:
                    proc_cache[pid] = _get_proc_name(pid)
                proc_name = proc_cache[pid]

                conn_info = {
                    'timestamp':  now.isoformat(),
                    'local':      f"{c.laddr.ip}:{c.laddr.port}",
                    'remote':     f"{rip}:{rport}",
                    'status':     c.status,
                    'pid':        pid,
                    'process':    proc_name,
                    'local_port': lport,
                    'remote_ip':  rip,
                    'remote_port': rport,
                }
                conns.append(conn_info)

                # Feed events into sliding window
                with self._lock:
                    self._ip_events[rip].append((now, lport))

        # ── Expire old events ───────────────────────────
        with self._lock:
            for ip in list(self._ip_events):
                self._ip_events[ip] = [
                    (t, p) for (t, p) in self._ip_events[ip] if t > cutoff
                ]
                if not self._ip_events[ip]:
                    del self._ip_events[ip]

            self._connections = conns
            self._stats['total_connections'] = len(conns)

        # ── Psutil packet synthesis (runs every poll — real scapy packets also append via _on_packet) ─
        self._synthesize_packets_from_conns(conns, now)

        # ── Detection passes ────────────────────────────
        with self._lock:
            snapshot = {ip: list(events) for ip, events in self._ip_events.items()}

        self._detect_port_scan(snapshot, now)
        self._detect_brute_force(snapshot, now)
        self._detect_c2_beacon(snapshot, now)
        self._detect_exfil(now)

        # ── Push live update to all connected clients ───
        try:
            with self._lock:
                live_stats = {
                    'total_connections': self._stats['total_connections'],
                    'suspicious_ips':    len(self._stats['suspicious_ips']),
                    'alerts_today':      self._stats['alerts_today'],
                    'bytes_sent_mb':     round(self._stats['bytes_sent_total'] / (1024 * 1024), 2),
                }
                # send at most 100 connections to keep payload small
                live_conns = list(self._connections[:100])
            with self._lock:
                live_packets = list(self._packets[-50:])  # last 50 packets for live stream
            self.socketio.emit('network_update', {
                'timestamp':   now.isoformat(),
                'stats':       live_stats,
                'connections': live_conns,
                'packets':     live_packets,
            })
        except Exception as e:
            print(f"⚠️  network_update emit failed: {e}")

    # ─────────────────────────────────────────────────────
    # Detectors
    # ─────────────────────────────────────────────────────

    def _detect_port_scan(self, snapshot: dict, now: datetime):
        """Detect a single remote IP hitting many local ports."""
        for src_ip, events in snapshot.items():
            distinct_ports = {port for _, port in events}
            if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
                self._raise_alert(
                    alert_type='PORT_SCAN',
                    ip=src_ip,
                    severity='HIGH',
                    description=(
                        f"Port scan detected from {src_ip}: "
                        f"{len(distinct_ports)} distinct ports targeted "
                        f"in {WINDOW_SECONDS}s"
                    ),
                    extra={'ports_hit': sorted(distinct_ports)[:20]},
                    now=now,
                )

    def _detect_brute_force(self, snapshot: dict, now: datetime):
        """Detect repeated connections from one IP to an auth port."""
        # Build: {(src_ip, dst_port): count}
        counts: dict = defaultdict(int)
        for src_ip, events in snapshot.items():
            for _, dst_port in events:
                if dst_port in AUTH_PORTS:
                    counts[(src_ip, dst_port)] += 1

        for (src_ip, dst_port), count in counts.items():
            if count >= BRUTE_FORCE_THRESHOLD:
                self._raise_alert(
                    alert_type='BRUTE_FORCE',
                    ip=src_ip,
                    severity='HIGH',
                    description=(
                        f"Brute force detected from {src_ip} "
                        f"on port {dst_port}: {count} connections in {WINDOW_SECONDS}s"
                    ),
                    extra={'target_port': dst_port, 'connection_count': count},
                    now=now,
                )

    def _detect_c2_beacon(self, snapshot: dict, now: datetime):
        """Detect repeated outbound connections to a single external IP on non-standard ports."""
        for remote_ip, events in snapshot.items():
            if _is_private(remote_ip):
                continue
            if _is_cdn(remote_ip):
                continue  # never flag known CDN/Google/Cloudflare IPs

            # Only consider non-standard ports (skip normal HTTPS/HTTP traffic)
            suspicious_events = [
                (t, p) for (t, p) in events
                if p not in _NORMAL_PORTS
            ]

            if len(suspicious_events) < BEACON_MIN_CONNS:
                continue

            times = sorted(t for t, _ in suspicious_events)
            gaps = [(times[i+1] - times[i]).total_seconds()
                    for i in range(len(times) - 1)]
            if not gaps:
                continue

            avg_gap = sum(gaps) / len(gaps)
            # Require beacon-like interval AND regularity (low stdev relative to mean)
            if avg_gap < 1 or avg_gap > 30:
                continue
            variance = sum((g - avg_gap) ** 2 for g in gaps) / len(gaps)
            stdev = variance ** 0.5
            # Real beacons are very regular; stdev must be < 40% of mean
            if avg_gap > 0 and (stdev / avg_gap) > 0.4:
                continue

            self._raise_alert(
                alert_type='C2_BEACON',
                ip=remote_ip,
                severity='CRITICAL',
                description=(
                    f"C2 beaconing to external IP {remote_ip}: "
                    f"{len(suspicious_events)} connections at ~{avg_gap:.1f}s interval "
                    f"(regularity: {stdev:.2f}s stdev)"
                ),
                extra={
                    'connection_count': len(suspicious_events),
                    'avg_interval_sec': round(avg_gap, 2),
                    'stdev_sec':        round(stdev, 2),
                },
                now=now,
            )

    def _detect_exfil(self, now: datetime):
        """Detect large outbound data chunks using io counter deltas."""
        try:
            io = psutil.net_io_counters()
        except Exception:
            return

        if self._last_io is not None:
            elapsed = (now - self._last_io_time).total_seconds()
            delta = io.bytes_sent - self._last_io.bytes_sent
            with self._lock:
                self._stats['bytes_sent_total'] = io.bytes_sent
            if elapsed > 0 and delta > EXFIL_BYTES_THRESHOLD:
                mb = round(delta / (1024 * 1024), 1)
                self._raise_alert(
                    alert_type='DATA_EXFIL',
                    ip='local',
                    severity='CRITICAL',
                    description=(
                        f"Possible data exfiltration: {mb} MB outbound "
                        f"in {elapsed:.0f}s"
                    ),
                    extra={'bytes_sent': delta, 'elapsed_sec': round(elapsed, 1)},
                    now=now,
                )

        self._last_io = io
        self._last_io_time = now

    # ─────────────────────────────────────────────────────
    # Alert dispatch
    # ─────────────────────────────────────────────────────

    def _raise_alert(self, alert_type: str, ip: str, severity: str,
                     description: str, extra: dict, now: datetime):
        """Deduplicate then dispatch alerts to all channels."""
        dedup_key = (alert_type, ip)
        with self._lock:
            last = self._last_alert.get(dedup_key)
            if last and (now - last).total_seconds() < DEDUP_WINDOW_SECONDS:
                return  # already alerted recently
            self._last_alert[dedup_key] = now
            self._stats['suspicious_ips'].add(ip)
            self._stats['alerts_today'] += 1

        alert = {
            'timestamp':   now.isoformat(),
            'type':        alert_type,
            'ip':          ip,
            'severity':    severity,
            'description': description,
            **extra,
        }

        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 100:
                self._alerts = self._alerts[-100:]

        print(f"🌐 NETWORK ALERT [{alert_type}] {description}")

        # 1 — SOC feed via socket
        try:
            self.socketio.emit('network_alert', alert)
        except Exception as e:
            print(f"⚠️  socket emit failed: {e}")

        # 2 — Network audit log (dedicated, richer record)
        try:
            from utils.db import log_network_audit
            log_network_audit(
                event_type=alert_type,
                ip=ip,
                severity=severity,
                description=description,
                protocol=extra.get('proto', ''),
                port=extra.get('dst_port') or extra.get('port'),
                details=str(extra) if extra else '',
            )
        except Exception as e:
            print(f"⚠️  network audit log failed: {e}")


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _get_proc_name(pid: int) -> str:
    if not pid:
        return 'unknown'
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 'unknown'


# Module-level singleton (populated by start_network_monitor() in app.py)
_monitor_instance: NetworkMonitor | None = None


def get_monitor() -> NetworkMonitor | None:
    return _monitor_instance


def set_monitor(m: NetworkMonitor):
    global _monitor_instance
    _monitor_instance = m
