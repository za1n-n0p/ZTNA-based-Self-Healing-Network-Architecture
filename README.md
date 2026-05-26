# ZTNA-based Self-Healing Network Architecture

NIST SP 800-207 compliant Zero Trust Network Architecture with automated threat detection and response.

## What is this project?

A complete security system that automatically detects cyber attacks, blocks them, and analyzes threats using AI. Think of it as your own mini-SOC (Security Operations Center).

**What it does:**
- Detects DDoS attacks, port scans, and floods in real-time
- Automatically blocks attackers using firewall rules
- Analyzes threats using local AI (no internet needed)
- Shows everything on a live dashboard

## Tech Stack

| Category | Technologies |
|----------|--------------|
| Language | Python |
| Detection | Scapy (packet sniffing) |
| Backend | Flask, SQLite |
| AI | Ollama (qwen3:4b) |
| Firewall | iptables |
| Dashboard | HTML, CSS, JavaScript, Chart.js |
| Security | TLS/SSL, HMAC-SHA256 |

## How It Works
Attacker → IDS (detects) → PDP (decides) → PEP (blocks) → Dashboard (shows)
↓
AI Analysis

text

**Three main components:**

| Component | What it does | Where it runs |
|-----------|--------------|---------------|
| IDS | Sniffs network packets, detects attacks | Ubuntu |
| PDP | Makes policy decisions, tracks trust scores | Windows |
| PEP | Blocks IPs using firewall rules | Ubuntu |

## Key Features

### Detection
- Real-time packet capture on network interface
- Detects ICMP, SYN, and UDP floods
- Detects port scans (15+ ports in 10 seconds)
- Adaptive threshold that learns normal traffic patterns

### Intelligent Decision Making
- Each IP has a trust score (0 to 100)
- Trust decreases when IP attacks, recovers over time
- Three security zones (RED, YELLOW, GREEN) with different rules
- Block duration increases for repeat offenders (exponential backoff)

### AI-Powered Analysis
- Local Ollama LLM (qwen3:4b) - completely free, no API key
- Analyzes every blocked attack automatically
- Provides threat level, attack pattern, assessment, and recommendation

### SOC Dashboard
- Real-time attack feed with HMAC signatures
- Live charts and graphs
- Network map showing attack path
- GeoIP intelligence (shows attacker location)
- DDoS detection (3+ IPs attacking same target)
- PDF report generation

## Quick Start

### Prerequisites

| Machine | IP Address | Role |
|---------|------------|------|
| Windows | 192.168.50.1 | PDP + Dashboard |
| Ubuntu | 192.168.50.135 | IDS + PEP |

### Step 1: Install Dependencies

**Windows:**
```bash
pip install flask flask-cors requests
Ubuntu:

bash
sudo apt update
sudo apt install python3-pip iptables tcpdump
pip3 install scapy requests flask flask-cors
Step 2: Generate Certificates (for HTTPS)
bash
python generate_certs.py
Step 3: Run All Components
Open 3 terminals:

Terminal 1 (Windows - PDP):

bash
python pdp_agent.py
Terminal 2 (Ubuntu - PEP):

bash
sudo python3 pep_agent.py
Terminal 3 (Ubuntu - IDS):

bash
sudo python3 ids_agent.py
Step 4: Open Dashboard
text
https://192.168.50.1:8080
Step 5: Test with Attack Simulator (Optional)
On Kali or any Linux machine:

bash
sudo python3 attack_simulator.py
Project Structure
text
├── ids_agent.py          # Packet sniffer - detects attacks
├── pdp_agent.py          # Policy engine - makes decisions
├── pep_agent.py          # Firewall controller - blocks IPs
├── ai_analyst.py         # LLM integration for threat analysis
├── geoip.py              # GeoIP lookup for attackers
├── ddos_correlator.py    # DDoS detection engine
├── dashboard.html        # Web dashboard UI
├── dashboard_server.py   # Dashboard server
├── attack_simulator.py   # Demo attack tool
├── generate_certs.py     # TLS certificate generator
├── logger_utils.py       # Logging utility
├── config.json           # Configuration file
└── requirements.txt      # Python dependencies
Configuration
Edit config.json to change:

Setting	What it controls
threshold	Packets per second needed to trigger alert
block_duration	How long an IP stays blocked (seconds)
trust_decrease	Points deducted when IP attacks
zones	RED/YELLOW/GREEN policy settings
Sample Attack Demo
Run the attack simulator and select:

Mode 1: Quick 10-second ICMP burst (fastest trigger)

Mode 2: Full demo (all attack types, all zones)

Mode 4: Stealth test (below threshold - should NOT trigger)

Mode 5: Escalation (slowly ramps up - shows adaptive threshold)

Mode 6: Port scan (triggers PORT_SCAN detection)

NIST SP 800-207 Compliance (Zero Trust)
Tenet	How it's implemented
1	Every IP has dynamic trust score
2	TLS/SSL between all agents
3	Block durations increase with repeat offenses
4	Zone-based policies (RED/YELLOW/GREEN)
5	Watchdog re-verification after unblock
6	HMAC-SHA256 signatures on all logs
7	Adaptive threshold based on traffic baseline
Why This Project Matters for My Internship

This project demonstrates:

Blue Team Skills: Detection, blocking, monitoring, incident response
NIST Knowledge: Zero Trust architecture implementation
AI Integration: Using LLMs for security analysis
Full Stack Development: Python backend + web dashboard
System Design: Distributed architecture with 3 agents
Security Standards: OWASP, NIST, secure coding practices

Author
Muhammad Zain Tanveer
BS Cyber Security, Air University Islamabad
