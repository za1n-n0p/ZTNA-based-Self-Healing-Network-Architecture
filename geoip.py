"""
geoip.py — GeoIP + Threat Intelligence
========================================
Looks up attacker IP location and threat flags using ip-api.com (free, no key).
Results are cached in memory to avoid repeat lookups for the same IP.

FIXED: Increased timeout, added retry, better private IP detection.

Used by: pdp_agent.py
"""

import threading
import time

import requests

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,proxy,hosting,query"
TIMEOUT   = 6    # increased from 4
RETRIES   = 2    # retry once on failure

_cache: dict = {}
_lock         = threading.Lock()


def lookup(ip: str) -> dict:
    with _lock:
        if ip in _cache:
            return _cache[ip]

    result = _do_lookup(ip)

    with _lock:
        _cache[ip] = result

    return result


def _do_lookup(ip: str) -> dict:
    if _is_private(ip):
        return {
            "country":      "Local Network",
            "country_code": "LAN",
            "city":         "Local",
            "isp":          "Internal Network",
            "org":          "",
            "is_proxy":     False,
            "is_hosting":   False,
            "risk_flags":   [],
        }

    for attempt in range(RETRIES):
        try:
            resp = requests.get(
                GEOIP_URL.format(ip=ip),
                timeout=TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 429:
                # Rate limited — wait and retry
                time.sleep(1.5)
                continue
            if resp.status_code != 200:
                continue

            d = resp.json()
            if d.get("status") != "success":
                continue

            flags = []
            if d.get("proxy"):
                flags.append("PROXY")
            if d.get("hosting"):
                flags.append("HOSTING/DATACENTER")

            return {
                "country":      d.get("country", "Unknown"),
                "country_code": d.get("countryCode", "??"),
                "city":         d.get("city", "Unknown"),
                "isp":          d.get("isp", "Unknown"),
                "org":          d.get("org", ""),
                "is_proxy":     bool(d.get("proxy")),
                "is_hosting":   bool(d.get("hosting")),
                "risk_flags":   flags,
            }

        except requests.exceptions.Timeout:
            time.sleep(0.5)
            continue
        except Exception:
            break

    return _unknown()


def _is_private(ip: str) -> bool:
    private_prefixes = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "169.254.",
    )
    return any(ip.startswith(p) for p in private_prefixes)


def _unknown() -> dict:
    return {
        "country":      "Unknown",
        "country_code": "??",
        "city":         "Unknown",
        "isp":          "Unknown",
        "org":          "",
        "is_proxy":     False,
        "is_hosting":   False,
        "risk_flags":   [],
    }


def lookup_async(ip: str, callback) -> None:
    def run():
        result = lookup(ip)
        try:
            callback(ip, result)
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
