#!/bin/bash
# Start the IDS backend server
# Use --host 0.0.0.0 to accept connections from other machines on the network

cd "$(dirname "$0")"

# Get this machine's IP for display
MY_IP=$(hostname -I | awk '{print $1}')

echo "======================================"
echo "Intrusion Detection System - Backend"
echo "======================================"
echo ""
echo "Starting server on all network interfaces..."
echo ""
echo "Access from:"
echo "  - Local:   http://localhost:8000"
echo "  - Network: http://${MY_IP}:8000"
echo ""
echo "To test from another machine, run:"
echo "  curl http://${MY_IP}:8000/"
echo ""
echo "======================================"
echo ""

# Run uvicorn with host 0.0.0.0 to accept external connections
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
