# 01_health_check.py
"""
Simple script to verify that attacker machine
can reach the IDS backend.
"""

import requests
from config import BASE_URL

def main():
    url = f"{BASE_URL}/api/system/status"  # one of the endpoints in main.py
    try:
        print(f"Sending GET {url}")
        resp = requests.get(url, timeout=5)
        print("Status code:", resp.status_code)
        print("Response:", resp.text[:300])  # print first 300 chars
    except Exception as e:
        print("Error talking to IDS:", e)

if __name__ == "__main__":
    main()
