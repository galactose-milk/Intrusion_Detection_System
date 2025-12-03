// frontend/src/components/MainScreen.jsx
import React, { useState, useEffect } from 'react';
import VisualizerView from './VisualizerView';
import AlertsView from './AlertsView';
import RealTimeMonitor from './RealTimeMonitor';
import ThreatTester from './ThreatTester';
import IPQuarantineView from './IPQuarantineView';
import UserManagement from './UserManagement';
import LoginSecurityView from './LoginSecurityView';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

function SystemStatus() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/system/status`);
        const data = await response.json();
        setStatus(data);
      } catch (error) {
        console.error('Error fetching system status:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="loading">Loading system status...</div>;

  return (
    <div className="system-status">
      <h3>🖥️ System Status</h3>
      
      <div className="status-grid">
        <div className="status-card">
          <h4>IDS Status</h4>
          <div className="status-items">
            <div className="status-item">
              <span>ML Model:</span>
              <span className={status?.ids_status?.ml_model_active ? 'status-active' : 'status-inactive'}>
                {status?.ids_status?.ml_model_active ? '✅ Active' : '❌ Inactive'}
              </span>
            </div>
            <div className="status-item">
              <span>Network Monitoring:</span>
              <span className={status?.ids_status?.network_monitoring ? 'status-active' : 'status-inactive'}>
                {status?.ids_status?.network_monitoring ? '✅ Active' : '❌ Inactive'}
              </span>
            </div>
            <div className="status-item">
              <span>Packet Capture:</span>
              <span className={status?.ids_status?.packet_capture_available ? 'status-active' : 'status-warning'}>
                {status?.ids_status?.packet_capture_available ? '✅ Available' : '⚠️ Requires Root'}
              </span>
            </div>
            <div className="status-item">
              <span>WebSocket Clients:</span>
              <span>{status?.ids_status?.websocket_clients || 0}</span>
            </div>
          </div>
        </div>

        <div className="status-card">
          <h4>System Resources</h4>
          <div className="status-items">
            <div className="status-item">
              <span>CPU Usage:</span>
              <span className={status?.system_resources?.cpu_percent > 80 ? 'status-warning' : ''}>
                {status?.system_resources?.cpu_percent?.toFixed(1)}%
              </span>
            </div>
            <div className="status-item">
              <span>Memory Usage:</span>
              <span className={status?.system_resources?.memory_percent > 80 ? 'status-warning' : ''}>
                {status?.system_resources?.memory_percent?.toFixed(1)}%
              </span>
            </div>
            <div className="status-item">
              <span>Network Interfaces:</span>
              <span>{status?.system_resources?.network_interfaces?.length || 0}</span>
            </div>
          </div>
        </div>

        <div className="status-card">
          <h4>Monitoring Stats</h4>
          <div className="status-items">
            <div className="status-item">
              <span>Connections Tracked:</span>
              <span>{status?.monitoring_stats?.total_connections_tracked || 0}</span>
            </div>
            <div className="status-item">
              <span>Active Connections:</span>
              <span>{status?.monitoring_stats?.active_connections || 0}</span>
            </div>
            <div className="status-item">
              <span>Network Events:</span>
              <span>{status?.monitoring_stats?.total_network_events || 0}</span>
            </div>
            <div className="status-item">
              <span>Suspicious Activities:</span>
              <span className={status?.monitoring_stats?.suspicious_activities > 0 ? 'status-warning' : ''}>
                {status?.monitoring_stats?.suspicious_activities || 0}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="mode-indicator">
        <span className="live-dot"></span>
        Mode: <strong>REAL TRAFFIC ONLY</strong> - No Simulations
      </div>

      <style>{`
        .system-status {
          padding: 20px;
        }
        .status-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 20px;
          margin-top: 20px;
        }
        .status-card {
          background: #1e1e2e;
          border-radius: 10px;
          padding: 20px;
          border: 1px solid #333;
        }
        .status-card h4 {
          margin-bottom: 15px;
          color: #00bcd4;
        }
        .status-items {
          display: flex;
          flex-direction: column;
          gap: 10px;
        }
        .status-item {
          display: flex;
          justify-content: space-between;
          padding: 8px 0;
          border-bottom: 1px solid #333;
        }
        .status-active { color: #00c853; }
        .status-inactive { color: #ff4444; }
        .status-warning { color: #ffa500; }
        .mode-indicator {
          margin-top: 30px;
          padding: 15px;
          background: rgba(0, 188, 212, 0.1);
          border: 1px solid #00bcd4;
          border-radius: 10px;
          text-align: center;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
        }
        .live-dot {
          width: 12px;
          height: 12px;
          background: #ff4444;
          border-radius: 50%;
          animation: pulse 1s infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.1); }
        }
        .loading {
          text-align: center;
          padding: 50px;
          color: #888;
        }
      `}</style>
    </div>
  );
}

function MainScreen({ activeView }) {
  const renderView = () => {
    switch (activeView) {
      case 'monitor':
        return (
          <div className="view-container">
            <h2>📊 Real-Time Network Monitor</h2>
            <p>🔴 Live analysis of ACTUAL network traffic - no simulations</p>
            <RealTimeMonitor />
          </div>
        );
      case 'visualizer':
        return <VisualizerView />;
      case 'alerts':
        return <AlertsView />;
      case 'loginsecurity':
        return (
          <div className="view-container">
            <h2>🔐 Login Security Monitor</h2>
            <p>Track login attempts, brute force attacks, and locked IPs</p>
            <LoginSecurityView />
          </div>
        );
      case 'ipquarantine':
        return (
          <div className="view-container">
            <h2>🛡️ IP Quarantine System</h2>
            <p>Monitor and block attacking IP addresses in real-time</p>
            <IPQuarantineView />
          </div>
        );
      case 'threats':
        return (
          <div className="view-container">
            <h2>⚡ Threat Testing & Quarantine</h2>
            <p>Generate REAL threats to test IDS detection and response capabilities</p>
            <ThreatTester />
          </div>
        );
      case 'system':
        return (
          <div className="view-container">
            <h2>⚙️ System Status</h2>
            <p>IDS system health and configuration</p>
            <SystemStatus />
          </div>
        );
      case 'users':
        return (
          <div className="view-container">
            <h2>👥 User Management</h2>
            <p>Manage IDS users and access control</p>
            <UserManagement />
          </div>
        );
      default:
        return <div className="view-container"><h2>Welcome</h2><p>Select an option from the side panel.</p></div>;
    }
  };

  return (
    <main className="main-screen">
      {renderView()}
    </main>
  );
}

export default MainScreen;