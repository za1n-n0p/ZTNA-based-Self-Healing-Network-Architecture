"""
Attack Simulator — NS Project Demo Tool
=========================================
Sends test floods to the Ubuntu target machine to trigger the IDS → PDP → PEP pipeline.

NIST SP 800-207 Demo coverage:
  - Triggers all 3 attack types: ICMP, SYN, UDP
  - Covers all 3 zones: RED/YELLOW/GREEN → all targeting 192.168.50.135
  - Escalation mode demonstrates adaptive threshold (Feature 6)
  - Stealth mode tests false-positive resistance

Runs on : Kali / any Linux machine (192.168.50.100 or any attacker IP)
Requires: sudo python3 attack_simulator.py
Packages: pip3 install scapy
"""

import sys
import time
import threading

try:
    from scapy.all import IP, ICMP, TCP, UDP, Raw, send, RandShort
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

# ---------------------------------------------------------------------------
# CONFIG — change TARGET_IP to your Ubuntu machine IP if different
# ---------------------------------------------------------------------------
TARGET_IP   = "192.168.50.135"   # Ubuntu (GREEN zone default)
RED_IP      = "192.168.50.135"    # RED zone victim
YELLOW_IP   = "192.168.50.135"    # YELLOW zone victim
SOURCE_IP   = None               # None = use real source IP (recommended)

# ---------------------------------------------------------------------------
# Packet senders
# ---------------------------------------------------------------------------

def icmp_flood(target: str, count: int, interval: float = 0.01):
    """Send ICMP echo flood."""
    pkt = IP(dst=target) / ICMP()
    print(f"  [SIM] ICMP flood → {target} | {count} packets")
    send(pkt, count=count, inter=interval, verbose=False)


def syn_flood(target: str, count: int, interval: float = 0.01):
    """Send TCP SYN flood."""
    pkt = IP(dst=target) / TCP(dport=80, flags="S", sport=RandShort())
    print(f"  [SIM] SYN flood → {target} | {count} packets")
    send(pkt, count=count, inter=interval, verbose=False)


def udp_flood(target: str, count: int, interval: float = 0.01):
    """Send UDP flood."""
    pkt = IP(dst=target) / UDP(dport=53, sport=RandShort()) / Raw(b"X" * 64)
    print(f"  [SIM] UDP flood → {target} | {count} packets")
    send(pkt, count=count, inter=interval, verbose=False)


# ---------------------------------------------------------------------------
# Mode 1 — Quick Demo (10-second burst, fastest pipeline trigger)
# ---------------------------------------------------------------------------

def mode_quick():
    print("\n[MODE 1] Quick Demo — 10-second ICMP burst to GREEN zone")
    print(f"         Target: {TARGET_IP}")
    print("         This should trigger: IDS alert → PDP BLOCK → PEP iptables rule")
    print("         Watch your dashboard at http://192.168.50.135:8080\n")
    input("         Press ENTER to start...")

    for i in range(10):
        icmp_flood(TARGET_IP, count=60, interval=0.005)
        print(f"  [SIM] Burst {i+1}/10 sent")
        time.sleep(0.8)

    print("\n[MODE 1] Done. Check dashboard for the block entry.")
    print("         The IP should auto-unblock after 60 seconds (GREEN zone default).")


# ---------------------------------------------------------------------------
# Mode 2 — Full Demo (all zones, all attack types)
# ---------------------------------------------------------------------------

def mode_full():
    print("\n[MODE 2] Full Demo — Heavy attacks on all types\n")
    print(f"  [CHECK] Verifying target {TARGET_IP} is reachable...")
    import subprocess
    result = subprocess.run(["ping", "-c", "2", "-W", "1", TARGET_IP],
                           capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [WARN] Target {TARGET_IP} not responding to ping.")
        print("         Make sure Ubuntu IDS is running and IP is correct.")
        cont = input("         Continue anyway? [y/N]: ").strip().lower()
        if cont != 'y':
            return
    else:
        print(f"  [OK]  Target reachable.\n")
    input("         Press ENTER to start...")
    steps = [
        ("ICMP flood HIGH", icmp_flood, TARGET_IP, 500, 0.001),
        ("SYN flood HIGH",  syn_flood,  TARGET_IP, 300, 0.002),
        ("UDP flood HIGH",  udp_flood,  TARGET_IP, 300, 0.002),
        ("ICMP flood RED",  icmp_flood, RED_IP,    500, 0.001),
        ("SYN flood RED",   syn_flood,  RED_IP,    300, 0.002),
        ("UDP flood RED",   udp_flood,  RED_IP,    300, 0.002),
    ]
    for (label, fn, ip, count, interval) in steps:
        print(f"\n  Sending: {label} → {ip}")
        for burst in range(8):
            fn(ip, count=count, interval=interval)
            print(f"    burst {burst+1}/8")
            time.sleep(0.3)
        print(f"  Waiting 5s...")
        time.sleep(5)
    print("\n[MODE 2] Done.")


# ---------------------------------------------------------------------------
# Mode 3 — Custom
# ---------------------------------------------------------------------------

def mode_custom():
    print("\n[MODE 3] Custom Attack\n")
    ip    = input(f"  Target IP [{TARGET_IP}]: ").strip() or TARGET_IP
    atype = input("  Attack type (icmp/syn/udp) [icmp]: ").strip().lower() or "icmp"
    try:
        pps = int(input("  Packets per burst [100]: ").strip() or "100")
        dur = int(input("  Duration in seconds [10]: ").strip() or "10")
    except ValueError:
        pps, dur = 100, 10

    fn = {"icmp": icmp_flood, "syn": syn_flood, "udp": udp_flood}.get(atype, icmp_flood)
    interval = 1.0 / max(pps, 1)

    print(f"\n  Sending {atype.upper()} flood to {ip} for {dur} seconds...")
    end_time = time.time() + dur
    burst = 0
    while time.time() < end_time:
        fn(ip, count=pps, interval=interval)
        burst += 1
        print(f"    burst {burst} — {int(end_time - time.time())}s remaining")
        time.sleep(0.5)

    print("\n[MODE 3] Custom attack complete.")


# ---------------------------------------------------------------------------
# Mode 4 — Stealth Test (below threshold, tests false-positive resistance)
# ---------------------------------------------------------------------------

def mode_stealth():
    print("\n[MODE 4] Stealth Test — traffic BELOW threshold")
    print("         Sends 5 packets/sec (threshold is 10)")
    print("         Expected result: NO block, NO alert — traffic treated as normal")
    print(f"         Target: {TARGET_IP}\n")
    input("         Press ENTER to start (runs 30 seconds)...")

    end_time = time.time() + 30
    burst = 0
    while time.time() < end_time:
        icmp_flood(TARGET_IP, count=4, interval=0.2)    # ~5 pkt/s — safely below threshold=10
        burst += 1
        print(f"  [SIM] Low-rate burst {burst} — {int(end_time - time.time())}s remaining")
        time.sleep(0.7)

    print("\n[MODE 4] Done. No block should have triggered.")
    print("         This demonstrates the threshold is not too sensitive (low false-positive rate).")


# ---------------------------------------------------------------------------
# Mode 5 — Escalation (ramps up slowly, shows adaptive threshold)
# ---------------------------------------------------------------------------

def mode_escalation():
    print("\n[MODE 5] Escalation — slowly ramps packet rate from 10 to 200 pkt/s")
    print("         Watch the IDS terminal — DynThresh value will adapt to baseline")
    print("         After ~10 seconds of baseline traffic, the adaptive threshold kicks in")
    print(f"         Target: {TARGET_IP}\n")
    input("         Press ENTER to start (runs ~60 seconds)...")

    rates = [10, 20, 30, 40, 50, 60, 80, 100, 120, 150, 200]
    for rate in rates:
        interval = 1.0 / rate
        print(f"\n  [SIM] Rate: {rate} pkt/s")
        for _ in range(5):
            icmp_flood(TARGET_IP, count=rate, interval=interval)
            time.sleep(0.8)
        print(f"  [SIM] Holding at {rate} pkt/s for 3 seconds...")
        time.sleep(3)

    print("\n[MODE 5] Escalation complete.")
    print("         The adaptive threshold should have risen above the fixed 10 pkt/s")
    print("         as the baseline traffic increased.")


# ---------------------------------------------------------------------------
# Mode 6 — Port Scan (triggers PORT_SCAN detection in IDS)
# ---------------------------------------------------------------------------

def mode_port_scan():
    print("\n[MODE 6] Port Scan — simulates nmap-style reconnaissance")
    print(f"         Target: {TARGET_IP}")
    print("         Sends TCP SYN to 20 different ports in 10 seconds")
    print("         Expected: IDS detects PORT_SCAN → PDP logs it\n")
    input("         Press ENTER to start...")

    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
             445, 3306, 3389, 5900, 6379, 8080, 8443, 27017, 5432, 1433]

    print(f"\n  [SIM] Scanning {len(ports)} ports on {TARGET_IP}...")
    for i, port in enumerate(ports):
        pkt = IP(dst=TARGET_IP) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, count=1, verbose=False)
        print(f"  [SIM] SYN → port {port:5d}  ({i+1}/{len(ports)})")
        time.sleep(0.4)

    print("\n[MODE 6] Port scan complete.")
    print("         Check IDS terminal for PORT_SCAN alert.")
    print("         Check dashboard Attacks tab for PORT_SCAN entry.")


# ---------------------------------------------------------------------------
# Entry point — interactive menu
# ---------------------------------------------------------------------------

MENU = """
╔══════════════════════════════════════════════════════════╗
║         NS Project — Attack Simulator                    ║
║         NIST SP 800-207 Demo Tool                        ║
╠══════════════════════════════════════════════════════════╣
║  1. Quick Demo    — 10s ICMP burst, fastest trigger      ║
║  2. Full Demo     — All zones + types (best for demo)    ║
║  3. Custom        — Choose IP, type, rate manually       ║
║  4. Stealth Test  — Below threshold, no block expected   ║
║  5. Escalation    — Ramps up, shows adaptive threshold   ║
║  6. Port Scan     — nmap-style scan, triggers PORT_SCAN  ║
║  0. Exit                                                 ║
╚══════════════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print(MENU)
    print(f"  Current target: {TARGET_IP} (GREEN zone)")
    print(f"  RED zone:       {RED_IP}")
    print(f"  YELLOW zone:    {YELLOW_IP}")
    print()

    choice = input("  Select mode [1-5]: ").strip()

    dispatch = {
        "1": mode_quick,
        "2": mode_full,
        "3": mode_custom,
        "4": mode_stealth,
        "5": mode_escalation,
        "6": mode_port_scan,
    }

    fn = dispatch.get(choice)
    if fn:
        fn()
    else:
        print("  Exiting.")
