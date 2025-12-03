# attacker_cli.py
"""
Interactive attacker CLI for your lab setup.

This script lets you choose different types of 'attacks'
against your IDS backend, such as:
- Endpoint scanning
- Repeated low-volume flood (DoS-like)
- Mixed pattern attack

IMPORTANT:
- This is ONLY for your own systems in a controlled environment.
- Keep the intensity low to avoid freezing your own machine.
"""

import threading
import time
import random
import requests

from config import BASE_URL


# ------------- Helper Functions ------------- #

def safe_get(url, timeout=3):
    """Wrapper to safely send GET requests and handle errors."""
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code, resp.text
    except Exception as e:
        return None, str(e)


# ------------- Attack Modes ------------- #

def endpoint_scan(rounds=5, delay=0.1):
    """
    Simulates a reconnaissance scan by repeatedly
    hitting multiple endpoints quickly.
    """
    endpoints = [
        "/",  # root
        "/api/system/status",
        "/api/dashboard/stats",
        "/api/detection/alerts",
        "/api/realtime/connections",
        "/api/quarantine/status",
    ]

    print(f"\n[SCAN] Starting endpoint scan for {rounds} rounds, delay={delay}s\n")

    for r in range(1, rounds + 1):
        print(f"--- Round {r}/{rounds} ---")
        for ep in endpoints:
            url = f"{BASE_URL}{ep}"
            status, msg = safe_get(url)
            if status is not None:
                print(f"GET {ep} -> {status}")
            else:
                print(f"GET {ep} -> ERROR: {msg[:80]}")
            time.sleep(delay)

    print("\n[SCAN] Completed endpoint scan.\n")


def flood_single_thread(total_requests=200, delay=0.05):
    """
    Simulates a simple low-volume flood on a single endpoint.
    This is intentionally mild for safety.
    """
    endpoint = "/api/system/status"
    url = f"{BASE_URL}{endpoint}"

    print(f"\n[FLOOD] Starting single-thread flood to {endpoint}")
    print(f"Total requests: {total_requests}, delay: {delay}s\n")

    for i in range(1, total_requests + 1):
        status, msg = safe_get(url)
        if status is not None:
            print(f"[{i}] Status: {status}")
        else:
            print(f"[{i}] ERROR: {msg[:80]}")
        time.sleep(delay)

    print("\n[FLOOD] Completed single-thread flood.\n")


def _flood_worker(name, endpoint, requests_per_thread, delay):
    """Worker for multi-thread flood."""
    url = f"{BASE_URL}{endpoint}"
    print(f"[THREAD-{name}] Starting, target={endpoint}, requests={requests_per_thread}")
    for i in range(1, requests_per_thread + 1):
        status, msg = safe_get(url)
        if status is not None:
            print(f"[THREAD-{name}] [{i}] Status: {status}")
        else:
            print(f"[THREAD-{name}] [{i}] ERROR: {msg[:80]}")
        time.sleep(delay)
    print(f"[THREAD-{name}] Finished.")


def flood_multi_thread(
    threads=5,
    requests_per_thread=50,
    delay=0.05,
):
    """
    Simulates a stronger flood using multiple threads.
    Still controlled and relatively low intensity,
    but enough to look like malicious behavior.
    """
    endpoint = "/api/system/status"

    print(
        f"\n[FLOOD-MT] Starting multi-thread flood:"
        f" threads={threads}, requests/thread={requests_per_thread}, delay={delay}s\n"
    )

    thread_list = []

    for t in range(1, threads + 1):
        th = threading.Thread(
            target=_flood_worker,
            args=(t, endpoint, requests_per_thread, delay),
            daemon=True,
        )
        thread_list.append(th)
        th.start()

    # Wait for all threads
    for th in thread_list:
        th.join()

    print("\n[FLOOD-MT] Completed multi-thread flood.\n")


def mixed_attack(
    rounds=5,
    max_requests_per_round=50,
):
    """
    Mixed behavior: random choice of endpoint scanning,
    small floods, and varied delays.
    This looks more like a real-world noisy attacker.
    """
    endpoints = [
        "/",
        "/api/system/status",
        "/api/dashboard/stats",
        "/api/detection/alerts",
        "/api/realtime/connections",
        "/api/quarantine/status",
    ]

    print(
        f"\n[MIXED] Starting mixed attack: rounds={rounds}, "
        f"max_requests_per_round={max_requests_per_round}\n"
    )

    for r in range(1, rounds + 1):
        print(f"\n=== MIXED ROUND {r}/{rounds} ===")

        # Randomly decide how many requests this round
        req_count = random.randint(10, max_requests_per_round)
        print(f"[MIXED] This round will send ~{req_count} requests.")

        for i in range(1, req_count + 1):
            ep = random.choice(endpoints)
            url = f"{BASE_URL}{ep}"

            # Random delay between 10ms and 200ms
            delay = random.uniform(0.01, 0.2)

            status, msg = safe_get(url)
            if status is not None:
                print(f"[MIXED] [{i}/{req_count}] GET {ep} -> {status}")
            else:
                print(f"[MIXED] [{i}/{req_count}] GET {ep} -> ERROR: {msg[:80]}")

            time.sleep(delay)

    print("\n[MIXED] Completed mixed attack.\n")


# ------------- Menu / CLI ------------- #

def print_menu():
    print("""
==================== ATTACKER MENU ====================
1. Endpoint Scan (recon style)
2. Single-Thread Flood (mild DoS-like)
3. Multi-Thread Flood (stronger pattern, still controlled)
4. Mixed Attack (scan + random flood behavior)
5. Exit
=======================================================
""")


def main():
    while True:
        print_menu()
        choice = input("Enter your choice (1-5): ").strip()

        if choice == "1":
            try:
                rounds = int(input("Enter number of scan rounds (default 5): ") or "5")
                delay = float(input("Delay between requests in seconds (default 0.1): ") or "0.1")
            except ValueError:
                print("Invalid input, using defaults (rounds=5, delay=0.1)")
                rounds, delay = 5, 0.1
            endpoint_scan(rounds=rounds, delay=delay)

        elif choice == "2":
            try:
                total = int(input("Total requests (default 200): ") or "200")
                delay = float(input("Delay between requests in seconds (default 0.05): ") or "0.05")
            except ValueError:
                print("Invalid input, using defaults (total=200, delay=0.05)")
                total, delay = 200, 0.05
            flood_single_thread(total_requests=total, delay=delay)

        elif choice == "3":
            try:
                threads = int(input("Number of threads (default 5): ") or "5")
                rpt = int(input("Requests per thread (default 50): ") or "50")
                delay = float(input("Delay between requests in seconds (default 0.05): ") or "0.05")
            except ValueError:
                print("Invalid input, using defaults (threads=5, rpt=50, delay=0.05)")
                threads, rpt, delay = 5, 50, 0.05
            flood_multi_thread(threads=threads, requests_per_thread=rpt, delay=delay)

        elif choice == "4":
            try:
                rounds = int(input("Number of mixed rounds (default 5): ") or "5")
                max_req = int(input("Max requests per round (default 50): ") or "50")
            except ValueError:
                print("Invalid input, using defaults (rounds=5, max_req=50)")
                rounds, max_req = 5, 50
            mixed_attack(rounds=rounds, max_requests_per_round=max_req)

        elif choice == "5":
            print("Exiting attacker CLI.")
            break

        else:
            print("Invalid choice, please select 1-5.")


if __name__ == "__main__":
    main()
