# 02_port_hit_loop.py
"""
Repeatedly sends HTTP GET requests to a harmless endpoint on the IDS.
Use this to simulate a noisy / abusive client hitting the same port.
"""

import time
import requests
from config import BASE_URL

# How many total requests to send
TOTAL_REQUESTS = 100  # keep this small for testing
DELAY_SECONDS = 0.1   # pause between requests to avoid freezing your system

def main():
    url = f"{BASE_URL}/api/system/status"  # harmless status endpoint
    print(f"Starting attack simulation on: {url}")
    print(f"Total requests: {TOTAL_REQUESTS}, delay: {DELAY_SECONDS} sec\n")

    for i in range(1, TOTAL_REQUESTS + 1):
        try:
            resp = requests.get(url, timeout=3)
            print(f"[{i}] Status: {resp.status_code}")
        except Exception as e:
            print(f"[{i}] Error: {e}")
        time.sleep(DELAY_SECONDS)

    print("\nSimulation finished. Check IDS logs / dashboard for anomalies.")

if __name__ == "__main__":
    main()
