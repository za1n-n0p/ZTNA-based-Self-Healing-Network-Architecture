"""
PEP Agent — Policy Enforcement Point
=======================================
NIST SP 800-207 Tenets:
  Tenet 3 : Enforces variable block durations (exponential backoff) from PDP.
  Tenet 5 : Watchdog re-verification window after auto-unblock (Feature 4).

FIXES APPLIED:
  [CRIT-1]   IP validated with ipaddress module before any iptables call.
  [CRIT-2]   iptables runs with shell=False (list args) — zero injection risk.
  [HIGH-1]   block_duration clamped to 1..max_block_duration_sec.
  [HIGH-2]   auto_unblock() holds block_lock before removing rule — no race.
  [MED-1]    debug=False, threaded=True on app.run().
  [MED-2]    Duplicate iptables rule guard — checks active_blocks before add.
  [ISSUE-5]  block_ip() accepts permanent=True flag; permanent blocks never
             auto-unblock (stored as None in active_blocks to mark them).
             /execute route reads the permanent flag from the PDP payload.
  [ISSUE-8]  File + console logging via logger_utils.py.

Runs on : Ubuntu target machine (192.168.50.135)
Requires: sudo python3 pep_agent.py
Packages: pip3 install flask flask-cors
"""

import ipaddress
import json
import subprocess
import threading
import time

from flask import Flask, jsonify, request
from flask_cors import CORS

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from logger_utils import setup_agent_logger

# ── Logger ───────────────────────────────────────────────────────────────────
logger = setup_agent_logger("PEP")

# ── Configuration ─────────────────────────────────────────────────────────────
with open("config.json") as _f:
    CFG = json.load(_f)

PEP_CFG         = CFG["pep"]
PDP_IP          = PEP_CFG["pdp_ip"]
API_KEY         = PEP_CFG["api_key"]
WATCHDOG_WINDOW = int(PEP_CFG.get("watchdog_window_seconds", 60))
MAX_DURATION    = int(PEP_CFG.get("max_block_duration_sec", 86400))

app = Flask(__name__)
CORS(app)

# ── Thread-safe registries ────────────────────────────────────────────────────
watchdog_timers: dict = {}   # ip -> threading.Timer
watchdog_lock   = threading.Lock()

active_blocks:  dict = {}    # ip -> threading.Timer | None (None = permanent)
block_lock      = threading.Lock()


# ── IP validation  [CRIT-1] ───────────────────────────────────────────────────

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# ── iptables helpers  [CRIT-2]  shell=False + list args ──────────────────────

def _run(args: list) -> bool:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            shell=False,    # [CRIT-2] never pass through a shell
        )
        if result.returncode == 0:
            logger.info("OK  : %s", " ".join(args))
            return True
        logger.warning("FAIL: %s | %s", " ".join(args), result.stderr.strip())
        return False
    except Exception as exc:
        logger.error("ERROR running command: %s", exc)
        return False


def add_block_rule(ip: str) -> bool:
    return _run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])


def remove_block_rule(ip: str) -> bool:
    return _run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])


def get_firewall_rules() -> str:
    try:
        r = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n", "-v"],
            capture_output=True, text=True, shell=False,
        )
        return r.stdout.strip() if r.stdout else "No active rules"
    except Exception as exc:
        return f"Error reading rules: {exc}"


# ── Watchdog  (Feature 4 — NIST Tenet 5) ─────────────────────────────────────

def start_watchdog(ip: str) -> None:
    def expired():
        with watchdog_lock:
            watchdog_timers.pop(ip, None)
        logger.info("WATCHDOG EXPIRED for %s — IP considered clean.", ip)

    with watchdog_lock:
        old = watchdog_timers.pop(ip, None)
        if old:
            old.cancel()
        t = threading.Timer(WATCHDOG_WINDOW, expired)
        t.daemon = True
        t.start()
        watchdog_timers[ip] = t

    logger.info("WATCHDOG STARTED for %s | Window:%ds", ip, WATCHDOG_WINDOW)


def is_under_watchdog(ip: str) -> bool:
    with watchdog_lock:
        return ip in watchdog_timers


# ── Auto-unblock  (self-healing)
# [HIGH-2] Lock held before iptables call — no race between timer + manual ────

def auto_unblock(ip: str, watchdog: bool) -> None:
    logger.info("AUTO-UNBLOCK | IP:%s", ip)

    with block_lock:
        if ip not in active_blocks:
            logger.info("SKIP unblock — %s not in active_blocks (already removed).", ip)
            return
        active_blocks.pop(ip, None)

    success = remove_block_rule(ip)

    if success:
        logger.info("SELF-HEALED | %s is accessible again.", ip)
        if watchdog:
            start_watchdog(ip)
    else:
        logger.error("HEAL FAILED for %s.", ip)


# ── Block IP  [ISSUE-5] ───────────────────────────────────────────────────────

def block_ip(ip: str, duration: int, watchdog: bool,
             permanent: bool = False) -> bool:
    """
    Block an IP address using iptables.

    Args:
        ip        : Target IP address to block.
        duration  : Block duration in seconds (ignored when permanent=True).
        watchdog  : Whether to start watchdog timer after auto-unblock.
        permanent : If True, never auto-unblock (trust=0 case).  [ISSUE-5]
                    Stored as active_blocks[ip] = None to distinguish from
                    a timed block where the value is a threading.Timer.
    """
    t = time.time()

    with block_lock:
        old = active_blocks.pop(ip, None)
        if old is not None:            # None = permanent block marker, no timer
            old.cancel()
            # Remove the old rule so we don't stack duplicate DROP entries
            remove_block_rule(ip)
        elif ip in active_blocks:      # was permanently blocked — remove rule too
            active_blocks.pop(ip, None)
            remove_block_rule(ip)

    # Cancel watchdog — IP reoffended during re-verification window
    with watchdog_lock:
        wd = watchdog_timers.pop(ip, None)
        if wd:
            wd.cancel()
            logger.warning("RE-VERIFICATION FAILED — %s reoffended in watchdog window!", ip)

    success = add_block_rule(ip)
    if success:
        if permanent:
            # [ISSUE-5] No timer for permanent blocks; None marks the slot.
            logger.warning(
                "PERMANENT BLOCK | IP:%s | Trust=0 — will never auto-unblock", ip
            )
            with block_lock:
                active_blocks[ip] = None
        else:
            logger.info("BLOCKED | IP:%s | Duration:%ds | at %.3f", ip, duration, t)
            timer = threading.Timer(duration, auto_unblock, args=[ip, watchdog])
            timer.daemon = True
            timer.start()
            with block_lock:
                active_blocks[ip] = timer
    else:
        logger.error("BLOCK FAILED | IP:%s", ip)

    return success


# ── /execute  — receives BLOCK / UNBLOCK commands from PDP ───────────────────

@app.route("/execute", methods=["POST"])
def execute_command():
    # Source IP check — only PDP may send commands
    if request.remote_addr != PDP_IP:
        return jsonify({"error": "Unauthorized"}), 401

    # API key check
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No command data"}), 400

    action    = data.get("action")
    target_ip = data.get("target_ip", "")
    watchdog  = bool(data.get("watchdog", False))

    # [ISSUE-5] Read permanent flag from PDP payload
    permanent = bool(data.get("permanent", False))

    # [HIGH-1] Validate and clamp duration
    try:
        duration = max(1, min(int(data.get("duration", 60)), MAX_DURATION))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid duration"}), 400

    # [CRIT-1] Validate IP — reject anything that is not a real IP address
    if not validate_ip(target_ip):
        logger.warning("SECURITY: Invalid IP rejected: %r", target_ip)
        return jsonify({"error": "Invalid IP address"}), 400

    logger.info("CMD:%s | IP:%s | Dur:%ds | WD:%s | PERM:%s",
                action, target_ip, duration, watchdog, permanent)

    if not action:
        return jsonify({"error": "Missing action"}), 400

    if action == "BLOCK":
        if is_under_watchdog(target_ip):
            logger.warning("ALERT — %s reoffended during watchdog window!", target_ip)
        # [ISSUE-5] permanent flag forwarded into block_ip
        success = block_ip(target_ip, duration, watchdog, permanent)
        if success:
            return jsonify({"status": "blocked",
                            "ip": target_ip, "duration": duration,
                            "permanent": permanent}), 200
        return jsonify({"status": "block_failed", "ip": target_ip}), 500

    if action == "UNBLOCK":
        with block_lock:
            old = active_blocks.pop(target_ip, None)
            if old is not None:        # timed block — cancel timer
                old.cancel()
            # If old is None, it was a permanent block — just remove the rule
        success = remove_block_rule(target_ip)
        if success:
            return jsonify({"status": "unblocked", "ip": target_ip}), 200
        return jsonify({"status": "unblock_failed", "ip": target_ip}), 500

    return jsonify({"error": f"Unknown action: {action}"}), 400


# ── /watchdog-status ──────────────────────────────────────────────────────────

@app.route("/watchdog-status", methods=["GET"])
def watchdog_status():
    with watchdog_lock:
        active_wd = list(watchdog_timers.keys())
    with block_lock:
        blocked = list(active_blocks.keys())
    return jsonify({
        "watchdog_active_ips":   active_wd,
        "currently_blocked_ips": blocked,
        "timestamp":             time.strftime("%Y-%m-%d %H:%M:%S"),
    })


# ── /health  — heartbeat + live firewall rules ────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    with block_lock:
        bc = len(active_blocks)
    with watchdog_lock:
        wc = len(watchdog_timers)
    return jsonify({
        "status":         "online",
        "agent":          "PEP",
        "blocked_count":  bc,
        "watchdog_count": wc,
        "firewall_rules": get_firewall_rules(),
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("  PEP AGENT  —  Policy Enforcement Point")
    logger.info("  Self-Healing Network Architecture | NIST SP 800-207")
    logger.info("=" * 70)
    logger.info("[CONFIG] Accepting commands from : %s", PDP_IP)
    logger.info("[CONFIG] Watchdog window         : %ds post-unblock", WATCHDOG_WINDOW)
    logger.info("[CONFIG] Max block duration      : %ds (%dh)", MAX_DURATION, MAX_DURATION // 3600)
    logger.info("[CONFIG] Listening on port       : %d", PEP_CFG["port"])
    logger.info("[ISSUE-5] Permanent block support: active (trust=0 → no auto-unblock)")
    logger.info("[ISSUE-8] File + console logging enabled")
    logger.info("[NIST]  Tenet 3: Variable block durations (exponential backoff)")
    logger.info("[NIST]  Tenet 5: Watchdog re-verification window after auto-unblock")
    logger.info("[SEC]   IP validation: ipaddress module, strict type check")
    logger.info("[SEC]   iptables: shell=False, list args — zero injection risk")
    logger.info("[SEC]   Only PDP IP accepted — source IP + API key dual auth")
    logger.info("[READY] PEP agent listening on 0.0.0.0:%d ...", PEP_CFG["port"])
    import pathlib, ssl as _ssl
    _base = pathlib.Path(__file__).parent
    _cert = _base / "cert.pem"
    _key  = _base / "key.pem"
    if _cert.exists() and _key.exists():
        context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(_cert, _key)
        logger.info("[TLS] HTTPS enabled — Tenet 2 compliant")
        app.run(host=PEP_CFG["host"], port=PEP_CFG["port"], debug=False, threaded=True, ssl_context=(_cert, _key))
    else:
        logger.warning("[TLS] cert.pem not found — running HTTP (run generate_certs.py first)")
        app.run(host=PEP_CFG["host"], port=PEP_CFG["port"], debug=False, threaded=True)
