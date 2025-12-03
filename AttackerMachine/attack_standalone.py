#!/usr/bin/env python3
"""
===========================================
STANDALONE FLOOD ATTACK SCRIPT
===========================================
Copy this single file to another laptop and run it to test the IDS.

Usage:
    python3 attack_standalone.py <TARGET_IP>
    
Example:
    python3 attack_standalone.py 192.168.1.100
    
This will send 100 rapid requests to trigger the IDS rate limiting.
The IDS should detect and block your IP after ~50 requests.
"""

import sys
import time
import requests

def flood_attack(target_ip, target_port=8000, num_requests=100, delay=0.1):
    """
    Send rapid HTTP requests to trigger the IDS rate limiting detection.
    
    The IDS will:
    - Warn at 60 requests/minute
    - Throttle at 100 requests/minute  
    - Auto-BLOCK at 200 requests/minute OR 50 requests in 10 seconds (burst)
    """
    base_url = f"http://{target_ip}:{target_port}"
    
    print("=" * 60)
    print("FLOOD ATTACK SIMULATOR")
    print("=" * 60)
    print(f"Target: {base_url}")
    print(f"Requests: {num_requests}")
    print(f"Delay: {delay}s between requests")
    print()
    print("Expected behavior:")
    print("  - After ~50 requests in 10s: IP will be BLOCKED")
    print("  - You'll start seeing 429 (Too Many Requests) errors")
    print("  - Check the IDS dashboard to see your IP in quarantine")
    print("=" * 60)
    print()
    
    blocked = False
    block_count = 0
    
    for i in range(1, num_requests + 1):
        try:
            # Try hitting different endpoints to also trigger endpoint scanning detection
            endpoints = [
                "/api/system/status",
                "/api/dashboard/stats",
                "/api/alerts",
                "/",
            ]
            url = f"{base_url}{endpoints[i % len(endpoints)]}"
            
            resp = requests.get(url, timeout=3)
            
            if resp.status_code == 429:
                if not blocked:
                    print(f"\n[!] REQUEST {i}: GOT 429 - YOUR IP HAS BEEN BLOCKED!")
                    blocked = True
                block_count += 1
                print(f"[{i}] BLOCKED (429) - {block_count} blocked requests")
            elif resp.status_code == 403:
                print(f"[{i}] FORBIDDEN (403) - IP is quarantined")
                block_count += 1
            else:
                print(f"[{i}] Status: {resp.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"[{i}] Connection Error - Server may have blocked you at firewall level")
        except Exception as e:
            print(f"[{i}] Error: {e}")
            
        time.sleep(delay)
    
    print()
    print("=" * 60)
    print("ATTACK COMPLETE")
    print("=" * 60)
    if blocked:
        print(f"[✓] SUCCESS: Your IP was blocked after detecting the attack!")
        print(f"    Total blocked requests: {block_count}")
        print()
        print("On the IDS machine, check:")
        print(f"  1. Web Dashboard: http://{target_ip}:5173 -> IP Quarantine")
        print(f"  2. API: curl http://{target_ip}:8000/api/ip-quarantine/blocked")
    else:
        print("[?] Your IP was not blocked. Try:")
        print("    - Reducing the delay (faster attack)")
        print("    - Running the script multiple times")
        print("    - Checking if the IDS backend is running")


def burst_attack(target_ip, target_port=8000, num_requests=60):
    """
    Ultra-fast burst attack with NO delay.
    This should trigger burst detection (50 requests in 10 seconds).
    """
    base_url = f"http://{target_ip}:{target_port}"
    
    print("=" * 60)
    print("BURST ATTACK (No Delay)")
    print("=" * 60)
    print(f"Target: {base_url}")
    print(f"Sending {num_requests} requests as fast as possible...")
    print()
    
    blocked = False
    
    for i in range(1, num_requests + 1):
        try:
            resp = requests.get(f"{base_url}/api/system/status", timeout=3)
            
            if resp.status_code == 429:
                print(f"[!] Request {i}: BLOCKED (429) - Burst attack detected!")
                blocked = True
                break
            else:
                print(f"[{i}] {resp.status_code}", end=" ")
                if i % 10 == 0:
                    print()
                    
        except Exception as e:
            print(f"[{i}] Error: {e}")
    
    print()
    if blocked:
        print(f"\n[✓] SUCCESS: Burst attack detected at request {i}!")
    else:
        print("\n[?] Completed without being blocked")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nError: Please provide the target IP address")
        print("\nExample:")
        print("  python3 attack_standalone.py 192.168.1.100")
        print()
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    
    # Check if target is reachable
    print(f"Testing connection to {target_ip}:{target_port}...")
    try:
        resp = requests.get(f"http://{target_ip}:{target_port}/", timeout=5)
        print(f"[✓] Target is reachable! (Status: {resp.status_code})")
        print()
    except Exception as e:
        print(f"[✗] Cannot reach target: {e}")
        print()
        print("Make sure:")
        print("  1. The IDS backend is running on the target machine")
        print("  2. It's listening on 0.0.0.0 (not just localhost)")
        print("  3. Firewall allows port 8000")
        print()
        sys.exit(1)
    
    print("Select attack type:")
    print("  1. Flood Attack (100 requests with 0.1s delay)")
    print("  2. Burst Attack (60 rapid requests, no delay)")
    print("  3. Both attacks")
    print()
    
    choice = input("Enter choice (1/2/3) [default: 3]: ").strip() or "3"
    print()
    
    if choice in ["1", "3"]:
        flood_attack(target_ip, target_port)
        print()
    
    if choice in ["2", "3"]:
        if choice == "3":
            print("\nWaiting 5 seconds before burst attack...")
            time.sleep(5)
        burst_attack(target_ip, target_port)


if __name__ == "__main__":
    main()
