"""
IDS Agent — Intrusion Detection System
========================================
NIST SP 800-207:
  Tenet 1 : All sources treated as threats — every packet inspected.
  Tenet 7 : Adaptive threshold = mean + 3×std_dev of traffic baseline.
  [NEW]   PORT_SCAN detection: tracks unique dst ports per IP in 10s window.

FIXES APPLIED IN THIS VERSION:
  [BUG-1] IDS no longer alerts on already-blocked IPs.
          Scapy captures packets BEFORE iptables drops them (AF_PACKET layer).
          When PDP responds action=BLOCKED, IDS suppresses that IP for the
          entire block duration so no duplicate alerts are generated.
  [BUG-2] Own machine IP (192.168.50.135) is whitelisted via config.json so
          IDS never alerts on its own outbound traffic.
  [ISSUE-8] File + console logging via logger_utils.py (replaces print()).

Runs on: Ubuntu target machine (192.168.50.135)
Run    : sudo python3 ids_agent.py
Install: pip3 install scapy requests
"""

import json
import math
import threading
import time
from collections import deque, defaultdict

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from scapy.all import ICMP, IP, TCP, UDP, sniff

from logger_utils import setup_agent_logger

# ─── Logger ─────────────────────────────────────────────────────────────────
logger = setup_agent_logger("IDS")

# ─── Configuration ───────────────────────────────────────────────────────────
with open("config.json") as f:
    CFG = json.load(f)

IDS_CFG         = CFG["ids"]
PDP_URL         = IDS_CFG["pdp_url"]
API_KEY         = IDS_CFG["api_key"]
FIXED_THRESHOLD = IDS_CFG["default_threshold"]
SNIFF_IFACE     = IDS_CFG.get("sniff_interface") or None
COOLDOWN_SEC    = float(IDS_CFG.get("alert_cooldown_seconds", 2.0))
BASELINE_MIN    = int(IDS_CFG.get("baseline_min_samples", 10))

# Permanently whitelisted IPs — PDP server + this machine's own IP
# [BUG-2]: 192.168.50.135 (own IP) must be here to prevent self-blocking.
WHITELIST: set = set(IDS_CFG.get("whitelist", ["192.168.50.1", "192.168.50.135"]))

# ─── Rate tracking ───────────────────────────────────────────────────────────
WINDOW_SIZE = 300   # 5-minute rolling window

rate_history:    dict[str, deque] = {}
packet_counts:   dict[str, int]   = {}
last_reset_time: dict[str, float] = {}
last_alert_time: dict[str, float] = {}

history_lock  = threading.Lock()
count_lock    = threading.Lock()
cooldown_lock = threading.Lock()

# ─── [BUG-1] Blocked IP suppression ─────────────────────────────────────────
# When PDP confirms action=BLOCKED / BLOCKED_PERMANENT, we store that IP here
# with its expiry time.  check_packet() skips IPs in this dict (like WHITELIST).
# After block_duration seconds the entry expires and monitoring resumes.
#
# WHY: Scapy uses AF_PACKET raw sockets which capture packets BEFORE the kernel
# netfilter (iptables) processes them.  So even after PEP adds iptables DROP,
# IDS sees all packets.  Without this suppression, IDS generates an alert every
# 2 seconds (cooldown) throughout the 60 s block window.
blocked_ips: dict[str, float] = {}   # ip → expiry_unix_timestamp
blocked_lock = threading.Lock()

# ─── Port scan detection tracking ────────────────────────────────────────────
# Tracks unique destination ports per source IP in a 10-second window.
# If a source hits PORT_SCAN_THRESHOLD unique ports → PORT_SCAN alert.
PORT_SCAN_THRESHOLD = 15          # unique dest ports in window = scan
PORT_SCAN_WINDOW    = 10.0        # seconds

port_scan_data: dict = defaultdict(list)  # ip → [(timestamp, dst_port), ...]
port_scan_lock  = threading.Lock()
port_scan_alerted: dict[str, float] = {}  # ip → last alert time


def detect_port_scan(src_ip: str, dst_port: int) -> bool:
    """
    Track unique destination ports per source IP.
    Returns True if this IP has scanned >= PORT_SCAN_THRESHOLD
    unique ports within PORT_SCAN_WINDOW seconds.
    Only fires once per COOLDOWN_SEC per IP (reuses existing cooldown logic).
    """
    now = time.time()
    with port_scan_lock:
        # Keep only events within the time window
        port_scan_data[src_ip] = [
            (ts, port) for (ts, port) in port_scan_data[src_ip]
            if now - ts < PORT_SCAN_WINDOW
        ]
        # Add this port if not already seen in window
        seen_ports = {port for (_, port) in port_scan_data[src_ip]}
        if dst_port not in seen_ports:
            port_scan_data[src_ip].append((now, dst_port))
            seen_ports.add(dst_port)

        unique_count = len(seen_ports)

    if unique_count >= PORT_SCAN_THRESHOLD:
        # Per-IP alert cooldown
        last = port_scan_alerted.get(src_ip, 0.0)
        if now - last < COOLDOWN_SEC:
            return False
        port_scan_alerted[src_ip] = now
        return True

    return False


def suppress_ip(ip: str, duration: float) -> None:
    """Mark an IP as blocked for `duration` seconds — IDS will ignore its packets."""
    expiry = time.time() + duration
    with blocked_lock:
        blocked_ips[ip] = expiry
    logger.info("SUPPRESSED %s for %.0fs (block active — no alerts until unblock)", ip, duration)


def is_suppressed(ip: str) -> bool:
    """Return True if this IP is currently in the suppression window."""
    with blocked_lock:
        expiry = blocked_ips.get(ip, 0.0)
        if expiry == 0.0:
            return False
        if time.time() < expiry:
            logger.debug("SUPPRESSED %s (%.0fs remaining)", ip, expiry - time.time())
            return True
        # Expiry has passed — remove and resume monitoring
        del blocked_ips[ip]
    logger.info("SUPPRESSION LIFTED for %s — resuming monitoring", ip)
    return False


# ─── Adaptive threshold (NIST Tenet 7) ───────────────────────────────────────

def compute_dynamic_threshold(ip: str) -> int:
    with history_lock:
        samples = rate_history.get(ip)
        if not samples or len(samples) < BASELINE_MIN:
            return FIXED_THRESHOLD
        rates = [count for (_, count) in samples]
    mean     = sum(rates) / len(rates)
    variance = sum((r - mean) ** 2 for r in rates) / len(rates)
    std_dev  = math.sqrt(variance)
    return max(10, int(mean + 3 * std_dev))


def record_rate_sample(ip: str, count: int) -> None:
    with history_lock:
        if ip not in rate_history:
            rate_history[ip] = deque(maxlen=WINDOW_SIZE)
        rate_history[ip].append((time.time(), count))


# ─── Alert delivery in daemon thread ─────────────────────────────────────────

def send_alert(attacker_ip: str, attack_type: str, packet_count: int,
               victim_ip: str, dynamic_threshold: int) -> None:
    """Spawn a daemon thread — sniff() is never blocked by network I/O."""
    threading.Thread(
        target=_do_http_alert,
        args=(attacker_ip, attack_type, packet_count,
              victim_ip, dynamic_threshold, time.time()),
        daemon=True,
    ).start()


def _do_http_alert(attacker_ip: str, attack_type: str, packet_count: int,
                   victim_ip: str, dynamic_threshold: int, send_time: float) -> None:
    ms            = int((send_time % 1) * 1000)
    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S") + f".{ms:03d}"

    # Severity: ≥1.5× threshold → HIGH (aggressive flood), else MEDIUM
    severity = "HIGH" if packet_count >= dynamic_threshold * 1.5 else "MEDIUM"

    payload = {
        "attacker_ip":       attacker_ip,
        "victim_ip":         victim_ip,
        "attack_type":       attack_type,
        "severity":          severity,
        "packet_count":      packet_count,
        "timestamp":         timestamp_str,
        "ids_send_time":     send_time,
        "fixed_threshold":   FIXED_THRESHOLD,
        "dynamic_threshold": dynamic_threshold,
    }
    headers = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

    try:
        response = requests.post(PDP_URL, json=payload, headers=headers, timeout=5, verify=False)
        logger.info(
            "ALERT at %.3f | %s → %s | %s | %dpkts | Sev:%s | Thresh:%d | HTTP:%d",
            send_time, attacker_ip, victim_ip, attack_type,
            packet_count, severity, dynamic_threshold, response.status_code,
        )

        # [BUG-1]: Parse PDP response and suppress IP if it was blocked.
        if response.status_code == 200:
            try:
                resp_data = response.json()
                action    = resp_data.get("action", "")
                block_dur = float(resp_data.get("block_duration", 60))
                
                if block_dur <= 0:
                    block_dur = 60
                
                logger.info("PDP response: action=%s block_dur=%s", action, block_dur)

                if action in ("BLOCKED", "BLOCKED_PERMANENT"):
                    suppress_ip(attacker_ip, block_dur)

            except Exception:
                pass  # JSON parse failure — suppression not applied, not critical

    except requests.exceptions.ConnectionError:
        logger.error("PDP unreachable — alert dropped for %s", attacker_ip)
    except requests.exceptions.Timeout:
        logger.error("PDP timed out — alert dropped for %s", attacker_ip)
    except Exception as exc:
        logger.error("Unexpected error sending alert: %s", exc)


# ─── Packet callback ──────────────────────────────────────────────────────────

def check_packet(packet) -> None:
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    now    = time.time()

    # Skip permanently whitelisted IPs (PDP server, own machine IP) — [BUG-2]
    if src_ip in WHITELIST:
        return

    # [BUG-1]: Skip IPs currently suppressed (block is active).
    # Without this, IDS would alert every 2 s during a 60 s block window.
    if is_suppressed(src_ip):
        return

    # Per-second rate tracking
    with count_lock:
        if src_ip not in packet_counts:
            packet_counts[src_ip]   = 0
            last_reset_time[src_ip] = now

        if now - last_reset_time[src_ip] >= 1.0:
            record_rate_sample(src_ip, packet_counts[src_ip])
            packet_counts[src_ip]   = 0
            last_reset_time[src_ip] = now

        packet_counts[src_ip] += 1
        current_count = packet_counts[src_ip]

    # ── Port scan detection (runs independently of flood threshold) ──────────
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        if detect_port_scan(src_ip, dst_port):
            with cooldown_lock:
                now2 = time.time()
                if now2 - last_alert_time.get(src_ip + "_scan", 0.0) >= COOLDOWN_SEC:
                    last_alert_time[src_ip + "_scan"] = now2
                    send_alert(src_ip, "PORT_SCAN",
                               PORT_SCAN_THRESHOLD, dst_ip,
                               PORT_SCAN_THRESHOLD)
    # ─────────────────────────────────────────────────────────────────────────

    threshold = compute_dynamic_threshold(src_ip)

    if current_count < threshold:
        return

    # Per-IP cooldown — at most one alert per COOLDOWN_SEC
    with cooldown_lock:
        if now - last_alert_time.get(src_ip, 0.0) < COOLDOWN_SEC:
            return
        last_alert_time[src_ip] = now

    # Classify attack type
    if packet.haslayer(ICMP):
        attack_type = "ICMP_FLOOD"
    elif packet.haslayer(TCP):
        attack_type = "SYN_FLOOD"
    elif packet.haslayer(UDP):
        attack_type = "UDP_FLOOD"
    else:
        attack_type = "UNKNOWN_FLOOD"

    send_alert(src_ip, attack_type, current_count, dst_ip, threshold)

    # Reset so the same burst doesn't re-trigger before thread delivers the alert
    with count_lock:
        packet_counts[src_ip]   = 0
        last_reset_time[src_ip] = now


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  IDS AGENT  —  Intrusion Detection System")
    logger.info("  Self-Healing Network Architecture | NIST SP 800-207")
    logger.info("=" * 60)
    logger.info("[CONFIG] PDP URL            : %s", PDP_URL)
    logger.info("[CONFIG] Fixed threshold    : %d pkt/s", FIXED_THRESHOLD)
    logger.info("[CONFIG] Adaptive threshold : enabled (baseline = %d samples)", BASELINE_MIN)
    logger.info("[CONFIG] Alert cooldown     : %.1fs per IP", COOLDOWN_SEC)
    logger.info("[CONFIG] Whitelisted IPs    : %s", WHITELIST)
    logger.info("[CONFIG] Sniff interface    : %s", SNIFF_IFACE or "default")
    logger.info("[BUG-1]  Blocked IP suppression: active")
    logger.info("[BUG-2]  Own IP whitelisted — machine will not block itself")
    logger.info("[NIST]   Tenet 1: every packet inspected | Tenet 7: adaptive threshold")
    logger.info("[FEAT]   Port scan detection: %d unique ports in %.0fs window",
                PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW)
    logger.info("[FEAT]   Severity: HIGH (>=1.5x) | MEDIUM (>=threshold)")
    logger.info("[READY]  Packet capture running ... Press Ctrl+C to stop.")

    # Build BPF filter to exclude whitelisted IPs at kernel level (performance)
    if WHITELIST:
        wl_filter = " and ".join(f"not src host {ip}" for ip in WHITELIST)
        bpf_filter = f"({wl_filter})"
    else:
        bpf_filter = None

    logger.info("BPF filter: %s", bpf_filter)
    sniff(
        prn=check_packet,
        store=False,
        iface=SNIFF_IFACE,
        filter=bpf_filter,
    )
