// frontend/src/components/SetupView.jsx
import React, { useState, useEffect } from 'react';

// Access environment variable from Vite
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

function SetupView() {
    // Basic state for form fields
    const [networkName, setNetworkName] = useState('');
    const [networkRange, setNetworkRange] = useState('');
    const [monitoringType, setMonitoringType] = useState('full');
    const [enablePacketCapture, setEnablePacketCapture] = useState(false);
    const [networkInterface, setNetworkInterface] = useState('');
    const [alertThresholds, setAlertThresholds] = useState('{"anomaly_threshold": 0.7, "threat_score_threshold": 6}');
    const [statusMessage, setStatusMessage] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [systemInfo, setSystemInfo] = useState(null);

    // Detect local network on mount
    useEffect(() => {
        const fetchSystemInfo = async () => {
            try {
                const response = await fetch(`${BACKEND_URL}/api/system/status`);
                const data = await response.json();
                setSystemInfo(data);
                
                // Auto-detect network interface
                if (data.system_resources?.network_interfaces?.length > 0) {
                    const iface = data.system_resources.network_interfaces.find(i => 
                        i !== 'lo' && !i.startsWith('docker') && !i.startsWith('veth')
                    ) || data.system_resources.network_interfaces[0];
                    setNetworkInterface(iface);
                }
            } catch (error) {
                console.error('Error fetching system info:', error);
            }
        };
        fetchSystemInfo();
    }, []);

    const handleSubmit = async (event) => {
        event.preventDefault();
        if (!BACKEND_URL) {
            setStatusMessage('Error: Backend URL is not configured.');
            return;
        }
        setStatusMessage('Configuring REAL network monitoring...');
        setIsSubmitting(true);

        let parsedThresholds = {};

        try {
            if (alertThresholds.trim()) {
                parsedThresholds = JSON.parse(alertThresholds);
            } else {
                parsedThresholds = {
                    "anomaly_threshold": 0.7,
                    "threat_score_threshold": 6
                };
            }
        } catch (e) {
            setStatusMessage(`Error: Invalid JSON in Alert Thresholds. ${e.message}`);
            setIsSubmitting(false);
            return;
        }

        const networkConfig = {
            name: networkName,
            network_range: networkRange,
            monitoring_type: monitoringType,
            alert_thresholds: parsedThresholds,
            enable_packet_capture: enablePacketCapture,
            interface: networkInterface || null
        };

        try {
            const response = await fetch(`${BACKEND_URL}/api/network/setup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(networkConfig),
            });

            const result = await response.json();

            if (response.ok) {
                setStatusMessage(`✅ Success: ${result.message || 'REAL network monitoring configured!'}`);
            } else {
                setStatusMessage(`Error ${response.status}: ${result.detail || 'Failed to save setup.'}`);
            }
        } catch (error) {
            console.error("Error submitting setup:", error);
            setStatusMessage(`Network Error: Could not connect to backend at ${BACKEND_URL}. (${error.message})`);
        } finally {
            setIsSubmitting(false);
        }
    };


  return (
    <div className="view-container setup-view">
      <h2>🔴 Real Network Security Setup</h2>
      <p>Configure monitoring for <strong>ACTUAL network traffic</strong> - no simulations.</p>
      
      <div className="info-banner">
        <span>ℹ️</span>
        <div>
          <strong>Production Mode Active</strong>
          <p>This IDS monitors real network connections, processes, and traffic patterns on your system.</p>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="networkName">Configuration Name:</label>
          <input
            type="text"
            id="networkName"
            value={networkName}
            onChange={(e) => setNetworkName(e.target.value)}
            required
            placeholder="e.g., Home Network, Office LAN"
          />
        </div>

        <div className="form-group">
          <label htmlFor="networkRange">Network Range (CIDR):</label>
          <input
            type="text"
            id="networkRange"
            value={networkRange}
            onChange={(e) => setNetworkRange(e.target.value)}
            required
            placeholder="e.g., 192.168.1.0/24 or 10.0.0.0/8"
          />
          <small>Enter your local network range to focus monitoring</small>
        </div>

        <div className="form-group">
          <label htmlFor="monitoringType">Monitoring Type:</label>
          <select
            id="monitoringType"
            value={monitoringType}
            onChange={(e) => setMonitoringType(e.target.value)}
          >
            <option value="full">Full Monitoring (Connections + Processes)</option>
            <option value="connections">Connection Monitoring Only</option>
            <option value="processes">Process Monitoring Only</option>
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="networkInterface">Network Interface:</label>
          <select
            id="networkInterface"
            value={networkInterface}
            onChange={(e) => setNetworkInterface(e.target.value)}
          >
            <option value="">Auto-detect</option>
            {systemInfo?.system_resources?.network_interfaces?.map(iface => (
              <option key={iface} value={iface}>{iface}</option>
            ))}
          </select>
        </div>

        <div className="form-group checkbox-group">
          <label>
            <input
              type="checkbox"
              checked={enablePacketCapture}
              onChange={(e) => setEnablePacketCapture(e.target.checked)}
            />
            Enable Deep Packet Capture
          </label>
          <small>⚠️ Requires running with root/sudo privileges</small>
        </div>

        <div className="form-group">
          <label htmlFor="alertThresholds">Alert Thresholds (JSON):</label>
          <textarea
            id="alertThresholds"
            value={alertThresholds}
            onChange={(e) => setAlertThresholds(e.target.value)}
            placeholder='{ "anomaly_threshold": 0.7, "threat_score_threshold": 6 }'
            rows="4"
          />
          <small>ML model sensitivity and alert thresholds</small>
        </div>

        <button type="submit" disabled={isSubmitting} className="submit-btn">
          {isSubmitting ? '⏳ Configuring...' : '🚀 Start Real Monitoring'}
        </button>
      </form>

      {statusMessage && (
        <p className={`status-message ${statusMessage.startsWith('Error') ? 'error' : 'success'}`}>
          {statusMessage}
        </p>
      )}

      <style>{`
        .info-banner {
          background: rgba(0, 188, 212, 0.1);
          border: 1px solid #00bcd4;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 20px;
          display: flex;
          gap: 15px;
          align-items: flex-start;
        }
        .info-banner span { font-size: 1.5em; }
        .info-banner p { margin: 5px 0 0 0; color: #aaa; font-size: 0.9em; }
        .checkbox-group {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }
        .checkbox-group label {
          display: flex;
          align-items: center;
          gap: 10px;
          cursor: pointer;
        }
        .checkbox-group input[type="checkbox"] {
          width: 18px;
          height: 18px;
        }
        .submit-btn {
          background: linear-gradient(135deg, #00bcd4, #0097a7);
          font-size: 1.1em;
          padding: 12px 30px;
        }
        .submit-btn:hover:not(:disabled) {
          background: linear-gradient(135deg, #00acc1, #00838f);
        }
        .status-message {
          margin-top: 15px;
          padding: 12px;
          border-radius: 6px;
          font-weight: bold;
        }
        .status-message.success {
          background: rgba(0, 200, 83, 0.1);
          border: 1px solid #00c853;
          color: #00c853;
        }
        .status-message.error {
          background: rgba(255, 68, 68, 0.1);
          border: 1px solid #ff4444;
          color: #ff4444;
        }
      `}</style>
    </div>
  );
}

export default SetupView;