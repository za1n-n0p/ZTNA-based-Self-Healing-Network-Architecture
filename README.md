# Zero Trust Self-Healing Network
### NIST SP 800-207 Compliant IDS/PDP/PEP System

A working multi-machine network security system that automatically detects attacks, blocks threats, and self-heals — all without human intervention. Built as a university project to practically implement Zero Trust Architecture principles from NIST SP 800-207.

---

## What It Does

The system runs across three machines and works like a mini SOC (Security Operations Center):

- **IDS** watches all incoming network traffic and raises an alert when it spots something suspicious
- **PDP** receives the alert, checks the attacker's trust score and zone, then decides what to do
- **PEP** carries out the decision — blocks the IP using iptables, then automatically unblocks it after the timeout

If the same attacker keeps coming back, the block duration increases automatically (exponential backoff). If their trust score hits zero, they get permanently blocked.

---

## Attack Types Detected

| Attack | How It's Detected |
|---|---|
| ICMP Flood | Ping flood exceeds adaptive threshold |
| SYN Flood | TCP SYN packets exceed threshold |
| UDP Flood | UDP packets exceed threshold |
| Port Scan | 15+ unique ports hit within 10 seconds |
| DDoS | 3+ different IPs attacking same target within 60s |

---

## Key Features

- **Adaptive Thresholding** — IDS learns normal traffic baseline (mean + 3×std_dev) instead of using a fixed number
- **Dynamic Trust Scoring** — every IP gets a score (0–100) that drops on attacks and recovers over time
- **Zone-Based Policies** — RED/YELLOW/GREEN zones each have different thresholds and block durations
- **Exponential Backoff** — block durations: 60s → 120s → 300s → 600s → 1 hour
- **AI Threat Analysis** — Ollama (qwen3:4b) classifies every threat as CRITICAL/HIGH/MEDIUM/LOW with recommendations
- **HMAC-SHA256 Audit Logs** — every log entry is signed to prevent tampering
- **GeoIP Intelligence** — country, city, ISP, proxy/datacenter detection per attacker IP
- **Real-Time SOC Dashboard** — live charts, GeoIP map, DDoS alerts, and one-click PDF reports
- **TLS Encrypted Communication** — all agent-to-agent traffic is encrypted

---

## NIST SP 800-207 Compliance

| Tenet | Implementation |
|---|---|
| Tenet 1 — Treat all sources as threats | Every packet inspected regardless of source |
| Tenet 2 — Secure all communication | TLS between all agents |
| Tenet 3 — Per-session access | Auto-unblock after block duration — no permanent implicit trust |
| Tenet 5 — Continuous monitoring | IDS runs 24/7 + 60s watchdog re-verification after every unblock |
| Tenet 6 — Strict authentication | API key required on every IDS alert and PEP command |
| Tenet 7 — Collect telemetry | HMAC-signed logs, adaptive thresholds, AI analysis per event |

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet Capture | Python, Scapy |
| Policy Engine | Python, Flask |
| Firewall Enforcement | iptables |
| AI Threat Analysis | Ollama (qwen3:4b) |
| SOC Dashboard | HTML, Chart.js, JavaScript |
| Database | SQLite |
| Security | HMAC-SHA256, TLS (self-signed) |

---

## Lab Setup

Three machines running in a virtual network:

```
Windows (PDP)   192.168.x.x    — Decision engine + AI analysis
Ubuntu  (IDS/PEP) 192.168.x.x  — Packet capture + firewall enforcement + dashboard
Kali    (Attacker) 192.168.x.x   — Attack simulation
```

---

## How to Run

### Requirements

**Windows (PDP machine):**
```bash
pip install flask flask-cors requests cryptography
```

**Ubuntu (IDS/PEP machine):**
```bash
pip3 install flask flask-cors requests scapy cryptography
```

**Ollama (AI engine):**
```bash
# Install from https://ollama.com then:
ollama pull qwen3:4b
```

### Startup Order

Run these in order — sequence matters:

```bash
# 1. Windows — start AI engine
ollama serve

# 2. Windows — start PDP
python pdp_agent.py

# 3. Ubuntu — start PEP (needs sudo for iptables)
sudo python3 pep_agent.py

# 4. Ubuntu — start IDS (needs sudo for packet capture)
sudo python3 ids_agent.py

# 5. Ubuntu — open dashboard in browser
# Open dashboard.html in any browser

# 6. Kali — run attack simulator
sudo python3 attack_simulator.py
```

> **First time only:** Delete `security.db` before starting for a clean database.

### Attack Simulator Modes

```
1. Quick Demo    — 10s ICMP burst, fastest way to trigger the pipeline
2. Full Demo     — All attack types across all zones
3. Custom        — Choose IP, type, and rate manually
4. Stealth Test  — Traffic below threshold, verifies no false positives
5. Escalation    — Slowly ramps up, shows adaptive threshold in action
6. Port Scan     — Simulates nmap-style reconnaissance
```

---

## How the Pipeline Works

```
Kali sends attack
      ↓
IDS detects threshold breach → classifies attack type
      ↓
IDS sends JSON alert to PDP (HTTPS + API key)
      ↓
PDP checks trust score + zone policy → decides action
      ↓
PDP sends BLOCK command to PEP (HTTPS + API key)
      ↓
PEP adds iptables DROP rule
      ↓
Auto-unblock after block duration (self-healing)
```

---

## Notes

- Dashboard shows a browser warning because TLS uses a self-signed certificate. Click **Advanced → Proceed** to continue.
- This project was built and tested in a controlled lab environment for educational purposes.
- Config files with IP addresses and API keys have been removed from this repository.


