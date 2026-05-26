"""
ai_analyst.py — Ollama AI Threat Analysis
==========================================
Sends attack event data to local Ollama (qwen3:4b) and returns
a structured threat assessment stored in the database.

Used by: pdp_agent.py
Model  : qwen3:4b (must be pulled: ollama pull qwen3:4b)
Runs on: Windows (same machine as PDP)
"""

import json
import threading
import time

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen3:4b"
TIMEOUT      = 25


def analyse_threat(attacker_ip: str, attack_type: str, severity: str,
                   trust_score: int, block_count: int, packet_count: int,
                   action_taken: str, zone_name: str) -> dict:
    prompt = f"""You are a network security analyst in a Zero Trust Architecture SOC.
Analyze this attack event and respond in JSON only. No explanation outside JSON.

Attack data:
- Attacker IP: {attacker_ip}
- Attack Type: {attack_type}
- Severity: {severity}
- Trust Score: {trust_score}/100
- Times Blocked Before: {block_count}
- Packet Rate: {packet_count} pkt/s
- Action Taken: {action_taken}
- Network Zone: {zone_name}

Respond with this exact JSON structure:
{{
  "threat_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "pattern": "one short phrase describing attack pattern",
  "assessment": "2 sentence threat assessment",
  "recommendation": "one specific action recommendation"
}}"""

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1},
                "think": False,
            },
            timeout=TIMEOUT,
            verify=False
        )
        if resp.status_code != 200:
            return _fallback(severity, block_count, action_taken)

        raw = resp.json().get("response", "")

        # Strip <think>...</think> block that qwen3:4b prepends before JSON.
        # Must do this BEFORE searching for { } so we never parse braces
        # that appear inside the thinking block.
        import re as _re
        raw = _re.sub(r"<think>.*?</think>", "", raw, flags=_re.DOTALL).strip()

        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start == -1 or end == 0:
            return _fallback(severity, block_count, action_taken)

        parsed = json.loads(raw[start:end])
        return {
            "threat_level":   str(parsed.get("threat_level", "MEDIUM")),
            "pattern":        str(parsed.get("pattern", "Unknown pattern")),
            "assessment":     str(parsed.get("assessment", "")),
            "recommendation": str(parsed.get("recommendation", "")),
            "model":          OLLAMA_MODEL,
            "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    except Exception:
        return _fallback(severity, block_count, action_taken)


def _fallback(severity: str, block_count: int, action_taken: str) -> dict:
    if severity == "HIGH" and block_count >= 3:
        tl = "CRITICAL"
        pat = "Repeat high-severity attacker"
        ass = "This IP has repeatedly attacked with high packet rates. Escalating threat."
        rec = "Maintain permanent block and monitor for IP rotation."
    elif severity == "HIGH":
        tl = "HIGH"
        pat = "Aggressive flood attack"
        ass = "Packet rate significantly exceeds threshold. System blocked automatically."
        rec = "Monitor for follow-up attacks from same subnet."
    else:
        tl = "MEDIUM"
        pat = "Threshold-crossing traffic"
        ass = "Traffic exceeded detection threshold. Logged for review."
        rec = "Watch for escalation to higher packet rates."

    return {
        "threat_level":   tl,
        "pattern":        pat,
        "assessment":     ass,
        "recommendation": rec,
        "model":          "fallback",
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def analyse_async(attacker_ip: str, attack_type: str, severity: str,
                  trust_score: int, block_count: int, packet_count: int,
                  action_taken: str, zone_name: str,
                  callback) -> None:
    def run():
        result = analyse_threat(
            attacker_ip, attack_type, severity,
            trust_score, block_count, packet_count,
            action_taken, zone_name,
        )
        try:
            callback(attacker_ip, result)
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
