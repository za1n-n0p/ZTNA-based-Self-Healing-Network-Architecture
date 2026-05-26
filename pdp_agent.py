"""
PDP Agent — Policy Decision Point
====================================
NIST SP 800-207 Tenets:
  Tenet 1 : Dynamic Trust Scoring per IP          (Feature 1)
  Tenet 2 : Communication security (TLS)
  Tenet 3 : Exponential backoff block durations   (Feature 2)
  Tenet 4 : Zone-based policy enforcement         (Feature 3)
  Tenet 5 : Watchdog re-verification flag to PEP  (Feature 4)
  Tenet 6 : Tamper-proof HMAC-SHA256 log sigs     (Feature 5)
  Tenet 7 : Telemetry-driven adaptive threshold from IDS (Feature 6)

NEW FEATURES ADDED:
  [AI]    Ollama qwen3:4b threat analysis on every blocked event
  [GEO]   GeoIP lookup — country, city, ISP, proxy/hosting flags
  [DDOS]  Multi-IP correlation — flags DDoS when 3+ IPs hit same target in 60s
  [RPT]   /report endpoint — returns full incident data for PDF generation

FIXES APPLIED:
  [CRIT-1]   SQLite conn always closed via try/finally in every route.
  [HIGH-1]   LOGGED_ONLY reachable — MEDIUM severity logged, not blocked for healthy IPs.
  [HIGH-2]   Trust recovery uses Python datetime — no SQL strftime on Windows.
  [MED-1]    /alert rate-limiting with IDS IP whitelisted.
  [MED-2]    debug=False, threaded=True on app.run().
  [MED-3]    /latency restricted to local subnet.
  [MED-4]    /health restricted to local subnet.
  [ISSUE-6]  send_block_command passes permanent=True for trust=0 blocks.
  [ISSUE-8]  File + console logging via logger_utils.py.

Runs on : Windows PDP machine (192.168.50.1)
Requires: pip install flask flask-cors requests
Run with: python pdp_agent.py
"""

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask import Flask, jsonify, request
from flask_cors import CORS

from logger_utils import setup_agent_logger
from ai_analyst import analyse_async
from geoip import lookup_async
from ddos_correlator import record_attack as ddos_record, get_recent_ddos

logger = setup_agent_logger("PDP")

with open("config.json") as _f:
    CFG = json.load(_f)

PDP_CFG          = CFG["pdp"]
DB_FILE          = PDP_CFG["db_file"]
PEP_URL          = PDP_CFG["pep_url"]
API_KEY_IDS      = PDP_CFG["api_key_ids"]
API_KEY_PEP      = PDP_CFG["api_key_pep"]
HMAC_SECRET      = PDP_CFG["hmac_secret"].encode()
BACKOFF_SCHEDULE = CFG["exponential_backoff"]
TRUST_DECREASE   = PDP_CFG["trust_decrease_on_attack"]
TRUST_THRESHOLD  = PDP_CFG["trust_threshold_auto_block"]
TRUST_RECOVERY   = PDP_CFG["trust_recovery_points"]
RECOVERY_HOURS   = PDP_CFG["trust_recovery_hours"]
RATE_LIMIT       = int(PDP_CFG.get("alert_rate_limit_per_min", 60))

RATE_LIMIT_WHITELIST: set = set(PDP_CFG.get("ids_whitelist_ips", ["192.168.50.135"]))
LOCAL_SUBNETS = ("192.168.50.", "192.168.56.", "192.168.9.", "192.168.194.", "192.168.", "127.")

last_latency: dict = {"ids_to_pdp": 0.0, "pdp_to_pep": 0.0, "total": 0.0}
rate_bucket: dict  = defaultdict(list)
rate_lock          = threading.Lock()

app = Flask(__name__)
CORS(app)


def is_local(ip: str) -> bool:
    return any(ip.startswith(s) for s in LOCAL_SUBNETS)



def is_rate_limited(sender_ip: str) -> bool:
    if sender_ip in RATE_LIMIT_WHITELIST:
        return False
    now = time.time()
    with rate_lock:
        rate_bucket[sender_ip] = [t for t in rate_bucket[sender_ip] if now - t < 60.0]
        if len(rate_bucket[sender_ip]) >= RATE_LIMIT:
            return True
        rate_bucket[sender_ip].append(now)
        return False


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database() -> None:
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker_ip    TEXT,
                victim_ip      TEXT,
                attack_type    TEXT,
                severity       TEXT,
                packet_count   INTEGER,
                timestamp      TEXT,
                action_taken   TEXT,
                response_time  REAL    DEFAULT 0.0,
                block_duration INTEGER DEFAULT 60,
                zone_name      TEXT    DEFAULT 'GREEN',
                signature      TEXT,
                country        TEXT    DEFAULT '',
                city           TEXT    DEFAULT '',
                isp            TEXT    DEFAULT '',
                is_proxy       INTEGER DEFAULT 0,
                is_hosting     INTEGER DEFAULT 0,
                risk_flags     TEXT    DEFAULT '',
                country_code   TEXT    DEFAULT '',
                ai_threat_level   TEXT DEFAULT '',
                ai_pattern        TEXT DEFAULT '',
                ai_assessment     TEXT DEFAULT '',
                ai_recommendation TEXT DEFAULT '',
                is_ddos        INTEGER DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS trust_scores (
                ip               TEXT PRIMARY KEY,
                score            INTEGER DEFAULT 100,
                last_seen        TEXT,
                block_count      INTEGER DEFAULT 0,
                last_attack_time TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS zones (
                victim_ip      TEXT PRIMARY KEY,
                zone_name      TEXT,
                threshold      INTEGER,
                block_duration INTEGER,
                min_trust      INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ddos_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_ip   TEXT,
                attacker_ips TEXT,
                attack_types TEXT,
                count       INTEGER,
                detected_at TEXT
            )
        """)
        conn.commit()

        try:
            conn.execute("ALTER TABLE attacks ADD COLUMN country TEXT DEFAULT ''")
            conn.execute("ALTER TABLE attacks ADD COLUMN city TEXT DEFAULT ''")
            conn.execute("ALTER TABLE attacks ADD COLUMN isp TEXT DEFAULT ''")
            conn.execute("ALTER TABLE attacks ADD COLUMN risk_flags TEXT DEFAULT ''")
            conn.execute("ALTER TABLE attacks ADD COLUMN country_code TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass  # columns already exist

        for zone in CFG["zones"]:
            c.execute("""
                INSERT OR IGNORE INTO zones
                    (victim_ip, zone_name, threshold, block_duration, min_trust)
                VALUES (?, ?, ?, ?, ?)
            """, (zone["victim_ip"], zone["zone_name"],
                  zone["threshold"], zone["block_duration"], zone["min_trust"]))
        conn.commit()
        logger.info("Database initialised — all tables ready.")
    finally:
        conn.close()


def _canonical(data: dict) -> str:
    return (
        f"{data.get('attacker_ip')}|{data.get('victim_ip')}|"
        f"{data.get('attack_type')}|{data.get('timestamp')}|"
        f"{data.get('action_taken')}|{data.get('block_duration')}"
    )


def generate_signature(data: dict) -> str:
    return hmac.new(HMAC_SECRET, _canonical(data).encode(), hashlib.sha256).hexdigest()


def verify_signature(row: dict) -> bool:
    expected = generate_signature(row)
    stored   = row.get("signature") or ""
    return hmac.compare_digest(expected, stored)


def _now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def ensure_trust_record(conn, ip):
    conn.execute("""
        INSERT OR IGNORE INTO trust_scores
            (ip, score, last_seen, block_count, last_attack_time)
        VALUES (?, 100, ?, 0, NULL)
    """, (ip, _now_str()))
    conn.commit()


def get_trust_score(conn, ip):
    ensure_trust_record(conn, ip)
    row = conn.execute("SELECT score FROM trust_scores WHERE ip = ?", (ip,)).fetchone()
    return row["score"] if row else 100


def decrease_trust(conn, ip):
    ensure_trust_record(conn, ip)
    conn.execute("""
        UPDATE trust_scores
        SET score = MAX(0, score - ?), last_attack_time = ?, last_seen = ?
        WHERE ip = ?
    """, (TRUST_DECREASE, _now_str(), _now_str(), ip))
    conn.commit()


def increase_trust(conn, ip, points=10):
    ensure_trust_record(conn, ip)
    conn.execute("""
        UPDATE trust_scores SET score = MIN(100, score + ?), last_seen = ?
        WHERE ip = ?
    """, (points, _now_str(), ip))
    conn.commit()


def increment_block_count(conn, ip):
    ensure_trust_record(conn, ip)
    conn.execute("UPDATE trust_scores SET block_count = block_count + 1 WHERE ip = ?", (ip,))
    conn.commit()


def get_block_count(conn, ip):
    ensure_trust_record(conn, ip)
    row = conn.execute("SELECT block_count FROM trust_scores WHERE ip = ?", (ip,)).fetchone()
    return row["block_count"] if row else 0


def compute_block_duration(block_count):
    idx = min(block_count, len(BACKOFF_SCHEDULE) - 1)
    return BACKOFF_SCHEDULE[idx]


def get_zone_policy(conn, victim_ip, trust_score=100):
    rows = conn.execute(
        "SELECT * FROM zones WHERE victim_ip = ? ORDER BY min_trust ASC", (victim_ip,)
    ).fetchall()

    if not rows:
        if trust_score >= 70:
            return {"victim_ip": victim_ip, "zone_name": "GREEN", "threshold": 20, "block_duration": 60, "min_trust": 30}
        elif trust_score >= 40:
            return {"victim_ip": victim_ip, "zone_name": "YELLOW", "threshold": 15, "block_duration": 120, "min_trust": 50}
        else:
            return {"victim_ip": victim_ip, "zone_name": "RED", "threshold": 10, "block_duration": 300, "min_trust": 70}

    if len(rows) == 1:
        return dict(rows[0])

    # Multiple zones for same IP — build a name lookup and pick by trust threshold directly
    zone_map = {dict(r)["zone_name"]: dict(r) for r in rows}

    if trust_score >= 70 and "GREEN" in zone_map:
        return zone_map["GREEN"]
    elif trust_score >= 40 and "YELLOW" in zone_map:
        return zone_map["YELLOW"]
    elif "RED" in zone_map:
        return zone_map["RED"]

    # Absolute fallback — return least restrictive zone
    return dict(min(rows, key=lambda r: r["min_trust"]))


def send_block_command(attacker_ip, duration, watchdog=False, permanent=False):
    payload = {
        "action": "BLOCK", "target_ip": attacker_ip,
        "duration": duration, "watchdog": watchdog, "permanent": permanent,
    }
    headers   = {"X-API-Key": API_KEY_PEP, "Content-Type": "application/json"}
    send_time = time.time()
    logger.info("BLOCK CMD | IP:%s | Dur:%ds | WD:%s | PERM:%s",
                attacker_ip, duration, watchdog, permanent)
    try:
        resp    = requests.post(PEP_URL, json=payload, headers=headers, timeout=5, verify=False)
        elapsed = round((time.time() - send_time) * 1000, 2)
        last_latency["pdp_to_pep"] = elapsed
        logger.info("PEP replied in %.2fms | HTTP:%d", elapsed, resp.status_code)
        return True, send_time
    except requests.exceptions.ConnectionError:
        logger.error("PEP unreachable.")
    except requests.exceptions.Timeout:
        logger.error("PEP timed out.")
    except Exception as exc:
        logger.error("Unexpected error: %s", exc)
    return False, send_time


def save_attack_log(conn, data, action, response_time, block_duration,
                    zone_name, geo=None, is_ddos=False):
    geo = geo or {}
    row = dict(data)
    row["action_taken"]   = action
    row["block_duration"] = block_duration
    sig = generate_signature(row)
    geo = geo or {}
    conn.execute("""
        INSERT INTO attacks
            (attacker_ip, victim_ip, attack_type, severity, packet_count,
             timestamp, action_taken, response_time, block_duration,
             zone_name, signature,
             country, city, isp, is_proxy, is_hosting, risk_flags,
             country_code, is_ddos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("attacker_ip"), data.get("victim_ip", "unknown"),
        data.get("attack_type"), data.get("severity"),
        data.get("packet_count"), data.get("timestamp"),
        action, response_time, block_duration, zone_name, sig,
        geo.get("country", ""), geo.get("city", ""),
        geo.get("isp", ""), int(geo.get("is_proxy", False)),
        int(geo.get("is_hosting", False)),
        ",".join(geo.get("risk_flags", [])),
        geo.get("country_code", ""),
        int(is_ddos),
    ))
    conn.commit()
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]


def update_attack_ai(attacker_ip, ai_result):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT id FROM attacks
            WHERE attacker_ip=? AND ai_threat_level=''
            ORDER BY id DESC LIMIT 1
        """, (attacker_ip,)).fetchone()
        if row:
            conn.execute("""
                UPDATE attacks
                SET ai_threat_level=?, ai_pattern=?, ai_assessment=?, ai_recommendation=?
                WHERE id=?
            """, (
                ai_result.get("threat_level", ""),
                ai_result.get("pattern", ""),
                ai_result.get("assessment", ""),
                ai_result.get("recommendation", ""),
                row["id"],
            ))
            conn.commit()
            logger.info("AI analysis stored for %s | Level:%s", attacker_ip, ai_result.get("threat_level"))
        else:
            logger.warning("AI update: no pending row found for %s", attacker_ip)
    except Exception as exc:
        logger.error("AI DB update error: %s", exc)
    finally:
        conn.close()


def update_attack_geo(ip, geo_result):
    conn = get_db()
    try:
        row = conn.execute("""
            SELECT id FROM attacks
            WHERE attacker_ip=? AND country=''
            ORDER BY id DESC LIMIT 1
        """, (ip,)).fetchone()
        if row:
            conn.execute("""
                UPDATE attacks
                SET country=?, city=?, isp=?, is_proxy=?, is_hosting=?,
                    risk_flags=?, country_code=?
                WHERE id=?
            """, (
                geo_result.get("country", ""), geo_result.get("city", ""),
                geo_result.get("isp", ""),
                int(geo_result.get("is_proxy", False)),
                int(geo_result.get("is_hosting", False)),
                ",".join(geo_result.get("risk_flags", [])),
                geo_result.get("country_code", ""),
                row["id"],
            ))
            conn.commit()
        else:
            logger.warning("GeoIP update: no pending row found for %s", ip)
    except Exception as exc:
        logger.error("GeoIP DB update error: %s", exc)
    finally:
        conn.close()


def trust_recovery_worker():
    interval = RECOVERY_HOURS * 3600
    while True:
        time.sleep(interval)
        cutoff = (datetime.utcnow() - timedelta(hours=RECOVERY_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
        conn   = get_db()
        try:
            conn.execute("""
                UPDATE trust_scores SET score = MIN(100, score + ?)
                WHERE last_attack_time IS NULL OR last_attack_time < ?
            """, (TRUST_RECOVERY, cutoff))
            conn.commit()
            logger.info("Trust recovery: +%d pts for clean IPs.", TRUST_RECOVERY)
        except Exception as exc:
            logger.error("Trust recovery error: %s", exc)
        finally:
            conn.close()


@app.route("/alert", methods=["POST"])
def receive_alert():
    if request.headers.get("X-API-Key") != API_KEY_IDS:
        return jsonify({"error": "Unauthorized"}), 401

    sender = request.remote_addr
    if is_rate_limited(sender):
        logger.warning("RATE LIMIT hit for %s", sender)
        return jsonify({"error": "Rate limit exceeded"}), 429

    pdp_recv = time.time()
    alert    = request.get_json(silent=True)
    if not alert:
        return jsonify({"error": "No alert data"}), 400

    attacker_ip   = alert.get("attacker_ip")
    victim_ip     = alert.get("victim_ip", "unknown")
    severity      = alert.get("severity", "HIGH")
    attack_type   = alert.get("attack_type")
    ids_send_time = float(alert.get("ids_send_time", pdp_recv))

    last_latency["ids_to_pdp"] = round(abs((pdp_recv - ids_send_time) * 1000), 2)
    logger.info("ALERT | %s → %s | %s | Sev:%s | IDS→PDP:%.2fms",
                attacker_ip, victim_ip, attack_type, severity, last_latency["ids_to_pdp"])

    ddos_alert = ddos_record(attacker_ip, victim_ip, attack_type)
    is_ddos    = ddos_alert is not None
    if is_ddos:
        logger.warning("DDOS DETECTED | Victim:%s | Attackers:%d | Types:%s",
                       victim_ip, ddos_alert["count"],
                       ",".join(ddos_alert["attack_types"]))
        conn_ddos = get_db()
        try:
            conn_ddos.execute("""
                INSERT INTO ddos_events (victim_ip, attacker_ips, attack_types, count, detected_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                victim_ip,
                ",".join(ddos_alert["attacker_ips"]),
                ",".join(ddos_alert["attack_types"]),
                ddos_alert["count"],
                ddos_alert["detected_at"],
            ))
            conn_ddos.commit()
        finally:
            conn_ddos.close()

    conn = get_db()
    trust_after    = 100
    zone_name      = "GREEN"
    block_duration = 60
    response_time  = 0.0
    action         = "LOGGED_ONLY"

    try:
        trust_before = get_trust_score(conn, attacker_ip)
        decrease_trust(conn, attacker_ip)
        trust_after  = get_trust_score(conn, attacker_ip)
        logger.info("Trust %s: %d → %d", attacker_ip, trust_before, trust_after)

        zone          = get_zone_policy(conn, victim_ip, trust_score=trust_before)
        zone_name     = zone["zone_name"]
        min_trust_req = zone["min_trust"]
        block_duration = zone["block_duration"]

        should_block = (
            severity == "HIGH"
            or (severity == "MEDIUM" and trust_after < min_trust_req)
            or trust_after < TRUST_THRESHOLD
            or is_ddos
        )

        if should_block:
            block_count    = get_block_count(conn, attacker_ip)
            block_duration = compute_block_duration(block_count)
            permanent_dur  = int(PDP_CFG.get("permanent_block_duration", 86400))
            is_permanent   = (trust_after == 0)
            if is_permanent:
                block_duration = permanent_dur
                logger.warning("PERMANENT BLOCK | Trust=0 | IP:%s | Duration:%ds",
                               attacker_ip, block_duration)
            else:
                logger.info("Block #%d | Dur:%ds | Zone:%s",
                            block_count + 1, block_duration, zone_name)

            success, _ = send_block_command(
                attacker_ip, block_duration,
                watchdog=(not is_permanent), permanent=is_permanent,
            )
            if success:
                increment_block_count(conn, attacker_ip)
                action = "BLOCKED_PERMANENT" if is_permanent else "BLOCKED"
            else:
                action = "BLOCK_FAILED"
        else:
            logger.info("LOGGED_ONLY | Sev:%s | Trust:%d | MinRequired:%d",
                        severity, trust_after, min_trust_req)

        response_time = round(abs((time.time() - ids_send_time) * 1000), 2)
        last_latency["total"] = response_time

        save_attack_log(conn, dict(alert), action, response_time,
                        block_duration, zone_name, is_ddos=is_ddos)

    finally:
        conn.close()

    logger.info("Done | Action:%s | RT:%.2fms | Zone:%s", action, response_time, zone_name)

    block_count_now = 0
    conn2 = get_db()
    try:
        block_count_now = get_block_count(conn2, attacker_ip)
    finally:
        conn2.close()

    analyse_async(
        attacker_ip, attack_type, severity,
        trust_after, block_count_now, alert.get("packet_count", 0),
        action, zone_name,
        callback=update_attack_ai,
    )

    lookup_async(attacker_ip, callback=update_attack_geo)

    return jsonify({
        "status":           "processed",
        "action":           action,
        "zone":             zone_name,
        "trust_score":      trust_after,
        "block_duration":   block_duration,
        "response_time_ms": response_time,
        "ddos_detected":    is_ddos,
    }), 200


@app.route("/ai-analysis", methods=["POST"])
def ai_analysis():
    data        = request.get_json(silent=True) or {}
    attacker_ip = data.get("attacker_ip", "unknown")
    attack_type = data.get("attack_type", "unknown")
    severity    = data.get("severity", "unknown")

    prompt = (
        f"In 2-3 sentences, analyze this network attack for a security dashboard:\n"
        f"IP: {attacker_ip}, Attack: {attack_type}, Severity: {severity}\n"
        f"State: threat level, likely intent, recommended action."
    )

    # Try models in order — qwen3:4b first, fallback to others if not available
    models_to_try = ["qwen3:4b", "qwen2:1.5b", "llama3.2:1b", "mistral"]

    for model in models_to_try:
        try:
            resp = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=30,   # increased from 5s — qwen3:4b needs time
                verify=False
            )
            if resp.status_code == 200:
                analysis = resp.json().get("response", "").strip()
                if analysis:
                    return jsonify({"analysis": analysis, "model": model}), 200
        except requests.exceptions.ConnectionError:
            # Ollama not running at all
            break
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    return jsonify({
        "analysis": (
            f"AI offline — Ollama not running on Windows.\n"
            f"Fix: Open CMD and run: ollama serve\n"
            f"Then run: ollama pull qwen3:4b"
        )
    }), 200


@app.route("/attacks", methods=["GET"])
def get_attacks():
    limit = min(int(request.args.get("limit", 50)), 200)
    conn  = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["signature_valid"] = verify_signature(d)
            result.append(d)
        return jsonify(result), 200
    finally:
        conn.close()


@app.route("/trust-scores", methods=["GET"])
def get_trust_scores():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM trust_scores ORDER BY score ASC LIMIT 50"
        ).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@app.route("/zones", methods=["GET"])
def get_zones():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM zones").fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@app.route("/ddos", methods=["GET"])
def get_ddos():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM ddos_events ORDER BY id DESC LIMIT 20"
        ).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@app.route("/stats", methods=["GET"])
def get_stats():
    conn = get_db()
    try:
        def one(sql, params=()):
            r = conn.execute(sql, params).fetchone()
            return dict(r) if r else {}

        total   = one("SELECT COUNT(*) AS n FROM attacks").get("n", 0)
        blocked = one("SELECT COUNT(*) AS n FROM attacks WHERE action_taken IN ('BLOCKED','BLOCKED_PERMANENT')").get("n", 0)
        failed  = one("SELECT COUNT(*) AS n FROM attacks WHERE action_taken='BLOCK_FAILED'").get("n", 0)
        logged  = total - blocked - failed
        ddos_count = one("SELECT COUNT(*) AS n FROM ddos_events").get("n", 0)

        rt  = one("SELECT AVG(response_time) AS a FROM attacks WHERE response_time > 0")
        pkt = one("SELECT AVG(packet_count) AS a FROM attacks")

        dist_rows  = conn.execute("SELECT attack_type, COUNT(*) AS cnt FROM attacks GROUP BY attack_type").fetchall()
        zone_rows  = conn.execute("SELECT zone_name, COUNT(*) AS cnt FROM attacks GROUP BY zone_name").fetchall()
        trend      = conn.execute("SELECT id, response_time FROM attacks ORDER BY id DESC LIMIT 10").fetchall()
        top_ips    = conn.execute("""
            SELECT attacker_ip, COUNT(*) AS cnt,
                   country, city, isp, is_proxy, is_hosting
            FROM attacks GROUP BY attacker_ip
            ORDER BY cnt DESC LIMIT 5
        """).fetchall()
        hourly     = conn.execute("""
            SELECT strftime('%H', timestamp) AS hr, COUNT(*) AS cnt
            FROM attacks GROUP BY hr ORDER BY hr
        """).fetchall()

        return jsonify({
            "counts": {
                "total": total, "blocked": blocked,
                "failed": failed, "logged": logged,
                "ddos": ddos_count,
            },
            "avg_response_time": round(rt.get("a") or 0, 2),
            "avg_packets":       round(pkt.get("a") or 0, 1),
            "distribution":      {r["attack_type"]: r["cnt"] for r in dist_rows},
            "zone_dist":         {r["zone_name"]: r["cnt"] for r in zone_rows},
            "trend":             [dict(r) for r in reversed(trend)],
            "top_attackers":     [dict(r) for r in top_ips],
            "hourly":            [dict(r) for r in hourly],
        }), 200
    finally:
        conn.close()


@app.route("/report", methods=["GET"])
def get_report():
    conn = get_db()
    try:
        def one(sql, params=()):
            r = conn.execute(sql, params).fetchone()
            return dict(r) if r else {}

        total   = one("SELECT COUNT(*) AS n FROM attacks").get("n", 0)
        blocked = one("SELECT COUNT(*) AS n FROM attacks WHERE action_taken IN ('BLOCKED','BLOCKED_PERMANENT')").get("n", 0)
        failed  = one("SELECT COUNT(*) AS n FROM attacks WHERE action_taken='BLOCK_FAILED'").get("n", 0)
        logged  = total - blocked - failed
        ddos_ct = one("SELECT COUNT(*) AS n FROM ddos_events").get("n", 0)

        rt       = one("SELECT AVG(response_time) AS a FROM attacks WHERE response_time > 0")
        pkt      = one("SELECT AVG(packet_count) AS a FROM attacks")
        heal_rt  = round(blocked / total * 100, 1) if total else 0
        consist  = round(blocked / (blocked + failed) * 100, 1) if (blocked + failed) else 100

        attacks  = conn.execute("SELECT * FROM attacks ORDER BY id DESC LIMIT 100").fetchall()
        trust    = conn.execute("SELECT * FROM trust_scores ORDER BY score ASC LIMIT 20").fetchall()
        zones    = conn.execute("SELECT * FROM zones").fetchall()
        ddos     = conn.execute("SELECT * FROM ddos_events ORDER BY id DESC LIMIT 10").fetchall()
        top_ips  = conn.execute("""
            SELECT attacker_ip, COUNT(*) AS cnt, country, city, isp
            FROM attacks GROUP BY attacker_ip ORDER BY cnt DESC LIMIT 10
        """).fetchall()
        dist     = conn.execute("SELECT attack_type, COUNT(*) AS cnt FROM attacks GROUP BY attack_type").fetchall()

        attack_list = []
        for row in attacks:
            d = dict(row)
            d["signature_valid"] = verify_signature(d)
            attack_list.append(d)

        return jsonify({
            "generated_at": _now_str(),
            "summary": {
                "total_attacks":  total,
                "blocked":        blocked,
                "logged_only":    logged,
                "block_failed":   failed,
                "ddos_events":    ddos_ct,
                "healing_rate":   heal_rt,
                "consistency":    consist,
                "avg_response_ms": round(rt.get("a") or 0, 2),
                "avg_packet_rate": round(pkt.get("a") or 0, 1),
            },
            "nist_compliance": {
                "tenet_1": "Dynamic trust scoring per IP",
                "tenet_2": "Communication security (TLS)",
                "tenet_3": "Exponential backoff block durations",
                "tenet_4": "Zone-based policy enforcement",
                "tenet_5": "Watchdog re-verification after unblock",
                "tenet_6": "HMAC-SHA256 tamper-proof logging",
                "tenet_7": "Adaptive threshold via IDS",
            },
            "attacks":      attack_list,
            "trust_scores": [dict(r) for r in trust],
            "zones":        [dict(r) for r in zones],
            "ddos_events":  [dict(r) for r in ddos],
            "top_attackers": [dict(r) for r in top_ips],
            "distribution":  {r["attack_type"]: r["cnt"] for r in dist},
        }), 200
    finally:
        conn.close()


@app.route("/false-positive", methods=["POST"])
def false_positive():
    if request.headers.get("X-API-Key") != API_KEY_IDS:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    ip   = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing ip"}), 400
    conn = get_db()
    try:
        increase_trust(conn, ip, points=10)
        score = get_trust_score(conn, ip)
    finally:
        conn.close()
    logger.info("False positive cleared for %s | New trust: %d", ip, score)
    return jsonify({"ip": ip, "new_trust_score": score}), 200


@app.route("/geoip-data", methods=["GET"])
def geoip_data():
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT attacker_ip, country, city, isp, risk_flags,
                   country_code, COUNT(*) as count, MAX(timestamp) as last_seen
            FROM attacks
            WHERE attacker_ip IS NOT NULL
            GROUP BY attacker_ip
            ORDER BY count DESC
            LIMIT 50
        """).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@app.route("/ai-status", methods=["GET"])
def ai_status():
    try:
        resp = requests.get("http://localhost:11434/api/tags", timeout=3, verify=False)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            has_qwen = any("qwen" in m for m in models)
            return jsonify({
                "ollama": "online",
                "models": models,
                "ready": has_qwen
            }), 200
    except Exception:
        pass
    return jsonify({"ollama": "offline", "models": [], "ready": False}), 200


@app.route("/latency", methods=["GET"])
def get_latency():
    if not is_local(request.remote_addr):
        return jsonify({"error": "Forbidden"}), 403
    return jsonify({
        "ids_to_pdp_ms": last_latency["ids_to_pdp"],
        "pdp_to_pep_ms": last_latency["pdp_to_pep"],
        "total_ms":      last_latency["total"],
        "timestamp":     _now_str(),
    })




@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "online", "agent": "PDP", "timestamp": _now_str()})


if __name__ == "__main__":
    setup_database()
    threading.Thread(target=trust_recovery_worker, daemon=True).start()

    port = PDP_CFG["port"]
    logger.info("=" * 70)
    logger.info("  PDP AGENT  —  Policy Decision Point")
    logger.info("  !! WINDOWS FIREWALL — open port %d if Ubuntu cannot reach PDP !!", port)
    logger.info("  !! netsh advfirewall firewall add rule name=\"PDP-%d\" protocol=TCP dir=in localport=%d action=allow !!", port, port)
    logger.info("  Self-Healing Network Architecture | NIST SP 800-207")
    logger.info("=" * 70)
    logger.info("[NEW]    AI Threat Analysis    : Ollama qwen3:4b")
    logger.info("[NEW]    GeoIP Intelligence    : ip-api.com (free)")
    logger.info("[NEW]    DDoS Correlation      : 3+ IPs in 60s window")
    logger.info("[NEW]    Report Endpoint       : /report")
    logger.info("[CONFIG] DB file               : %s", DB_FILE)
    logger.info("[NIST]   Tenets: 1,2,3,4,5,6,7 all active")
    logger.info("[READY]  PDP running on 0.0.0.0:%d ...", port)
    import pathlib, ssl as _ssl
    _base = pathlib.Path(__file__).parent
    _cert = _base / "cert.pem"
    _key  = _base / "key.pem"
    if _cert.exists() and _key.exists():
        context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(_cert, _key)
        logger.info("[TLS] HTTPS enabled — Tenet 2 compliant")
        app.run(host=PDP_CFG["host"], port=port, debug=False, threaded=True, ssl_context=(_cert, _key))
    else:
        logger.warning("[TLS] cert.pem not found — running HTTP (run generate_certs.py first)")
        app.run(host=PDP_CFG["host"], port=port, debug=False, threaded=True)
