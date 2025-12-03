# Attack from Another Laptop - Setup Guide

## Overview
This guide explains how to set up the IDS to detect and automatically quarantine attacks coming from another laptop on your network.

## Step 1: Find Your IDS Machine's IP Address

On this laptop (the IDS machine), run one of these commands:
```bash
hostname -I
# OR
ip addr show | grep "inet "
# OR
ifconfig | grep "inet "
```

Note down the IP address (e.g., `192.168.1.100`)

## Step 2: Start the Backend (Accept External Connections)

The backend must listen on `0.0.0.0` (all interfaces), not just `localhost`.

```bash
cd /home/galactose/pyhton/intrusion_detecion/Intrusion_detection_system/backend

# Option 1: Use the startup script
./start_server.sh

# Option 2: Run directly
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Important**: The `--host 0.0.0.0` flag is crucial for accepting external connections!

## Step 3: Verify External Access

From your other laptop, test the connection:
```bash
curl http://<IDS_IP>:8000/
# Example: curl http://192.168.1.100:8000/
```

If you get a response, the IDS is reachable.

## Step 4: Run Attack from Other Laptop

### Option A: Copy the standalone script (Easiest)
Copy `AttackerMachine/attack_standalone.py` to your other laptop and run:
```bash
python3 attack_standalone.py <IDS_IP>
# Example: python3 attack_standalone.py 192.168.1.100
```

### Option B: Copy the entire AttackerMachine folder
1. Copy the `AttackerMachine/` folder to your other laptop
2. Edit `config.py` and change `TARGET_IP` to the IDS machine's IP
3. Run any attack script:
   ```bash
   python3 02_port_hit_loop.py
   python3 03_random_endpoint_requests.py
   ```

### Option C: Simple curl attack
From your other laptop:
```bash
# Rapid requests to trigger rate limiting
for i in {1..100}; do curl -s http://<IDS_IP>:8000/api/system/status; done
```

## Step 5: Verify Quarantine

On the IDS machine, check if the attacking IP was blocked:

### Via Web Dashboard
1. Open http://localhost:5173 (or http://<IDS_IP>:5173)
2. Click "IP Quarantine" in the sidebar
3. You should see the attacker's IP in the "Blocked IPs" tab

### Via API
```bash
curl http://localhost:8000/api/ip-quarantine/blocked | python3 -m json.tool
curl http://localhost:8000/api/ip-quarantine/alerts | python3 -m json.tool
```

## IP Quarantine Thresholds

The IDS automatically quarantines IPs based on:

| Detection Type | Threshold | Action |
|----------------|-----------|--------|
| Burst Attack | 50 requests in 10 seconds | Auto-Block for 1 hour |
| Rate Limit (Warn) | 60 requests/minute | Warning alert |
| Rate Limit (Throttle) | 100 requests/minute | Throttling |
| Rate Limit (Block) | 200 requests/minute | Auto-Block for 30 min |
| Endpoint Scanning | 10+ different endpoints in 1 min | Auto-Block |

## Firewall Note

If attacks aren't getting through, check your firewall:
```bash
# Allow port 8000 (Linux)
sudo ufw allow 8000/tcp

# Or temporarily disable firewall for testing
sudo ufw disable
```

## Troubleshooting

### "Connection refused"
- Make sure backend is running with `--host 0.0.0.0`
- Check firewall settings

### "IP not getting blocked"
- Verify the IP isn't in the whitelist
- Check attack thresholds are being exceeded
- Look at backend logs for rate limiting messages

### "Can't see attacker IP"
- The attacker's real IP should show (not localhost)
- If using a proxy, the original IP might be hidden
