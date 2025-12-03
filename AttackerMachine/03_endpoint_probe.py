# 03_endpoint_probe.py
"""
Probe multiple IDS endpoints quickly to simulate
a basic 'reconnaissance' or scanning behavior.
"""

import time
import requests
from config import BASE_URL

ENDPOINTS = [
    "/",  # root
    "/api/system/status",
    "/api/dashboard/stats",
    "/api/detection/alerts",
    "/api/realtime/connections",
    "/api/quarantine/status",
]

DELAY_SECONDS = 0.05
ROUNDS = 10  # how many times to loop over all endpoints

def main():
    print("Starting endpoint probe...")
    for round_no in range(1, ROUNDS + 1):
        print(f"\n=== Round {round_no}/{ROUNDS} ===")
        for ep in ENDPOINTS:
            url = f"{BASE_URL}{ep}"
            try:
                resp = requests.get(url, timeout=3)
                print(f"GET {ep} -> {resp.status_code}")
            except Exception as e:
                print(f"GET {ep} -> ERROR: {e}")
            time.sleep(DELAY_SECONDS)

    print("\nProbe finished. This should look like scanning / enumeration in the logs.")

if __name__ == "__main__":
    main()
