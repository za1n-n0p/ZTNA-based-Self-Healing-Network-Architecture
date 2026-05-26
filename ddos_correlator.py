"""
ddos_correlator.py — DDoS Correlation Engine
==============================================
Tracks multiple attacker IPs hitting the same victim within a time window.
If 3+ unique IPs attack the same victim within 60 seconds, flags it as DDoS.

Used by: pdp_agent.py
"""

import threading
import time
from collections import defaultdict

WINDOW_SECONDS  = 60
DDOS_THRESHOLD  = 3

_events: dict   = defaultdict(list)
_lock           = threading.Lock()
_ddos_alerts: list = []
_alert_lock     = threading.Lock()


def record_attack(attacker_ip: str, victim_ip: str, attack_type: str) -> dict | None:
    now = time.time()

    with _lock:
        _events[victim_ip] = [
            e for e in _events[victim_ip]
            if now - e["time"] < WINDOW_SECONDS
        ]

        already = any(e["ip"] == attacker_ip for e in _events[victim_ip])
        if not already:
            _events[victim_ip].append({
                "ip":   attacker_ip,
                "time": now,
                "type": attack_type,
            })

        attackers = _events[victim_ip]
        count     = len(attackers)

    if count >= DDOS_THRESHOLD:
        alert = {
            "victim_ip":    victim_ip,
            "attacker_ips": [e["ip"]   for e in attackers],
            "attack_types": list({e["type"] for e in attackers}),
            "count":        count,
            "detected_at":  time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with _alert_lock:
            existing = any(
                a["victim_ip"] == victim_ip and
                now - time.mktime(time.strptime(a["detected_at"], "%Y-%m-%d %H:%M:%S")) < WINDOW_SECONDS
                for a in _ddos_alerts
            )
            if not existing:
                _ddos_alerts.append(alert)
                if len(_ddos_alerts) > 50:
                    _ddos_alerts.pop(0)
        return alert

    return None


def get_recent_ddos(limit: int = 10) -> list:
    with _alert_lock:
        return list(reversed(_ddos_alerts[-limit:]))


def get_active_attackers(victim_ip: str) -> list:
    now = time.time()
    with _lock:
        return [
            e["ip"] for e in _events.get(victim_ip, [])
            if now - e["time"] < WINDOW_SECONDS
        ]
