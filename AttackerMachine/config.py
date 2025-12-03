# config.py
# Common configuration for attacker scripts

import sys
import os

# ===== CONFIGURE YOUR TARGET HERE =====
# Change TARGET_IP to the IP address of the machine running the IDS
# To find the IDS machine's IP, run on that machine: hostname -I
#
# Examples:
#   TARGET_IP = "192.168.1.100"  # If IDS is on 192.168.1.100
#   TARGET_IP = "10.0.0.5"       # If IDS is on 10.0.0.5

TARGET_IP = os.environ.get("TARGET_IP", "127.0.0.1")  # Set via env or change this directly
TARGET_PORT = int(os.environ.get("TARGET_PORT", "8000"))

# Full base URL of your IDS backend
BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}"

# Print target info when imported
if __name__ != "__main__":
    print(f"[CONFIG] Target: {BASE_URL}")
