// frontend/src/components/LoginSecurityView.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

function LoginSecurityView() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [trackedIPs, setTrackedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  
  const { getAuthHeader } = useAuth();

  const fetchData = useCallback(async () => {
    try {
      const headers = getAuthHeader();
      
      // Fetch stats
      const statsRes = await fetch(`${BACKEND_URL}/api/login-security/status`, { headers });
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        setStats(statsData);
      }
      
      // Fetch alerts
      const alertsRes = await fetch(`${BACKEND_URL}/api/login-security/alerts?limit=50`, { headers });
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData.alerts || []);
      }
      
      // Fetch tracked IPs
      const ipsRes = await fetch(`${BACKEND_URL}/api/login-security/tracked-ips?limit=20`, { headers });
      if (ipsRes.ok) {
        const ipsData = await ipsRes.json();
        setTrackedIPs(ipsData.tracked_ips || []);
      }
      
      setError(null);
    } catch (err) {
      console.error('Error fetching login security data:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [getAuthHeader]);

  useEffect(() => {
    fetchData();
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchData, 5000);
    }
    return () => clearInterval(interval);
  }, [fetchData, autoRefresh]);

  const handleUnlockIP = async (ip) => {
    if (!window.confirm(`Unlock IP ${ip}?`)) return;
    
    try {
      const res = await fetch(`${BACKEND_URL}/api/login-security/unlock/${ip}`, {
        method: 'POST',
        headers: getAuthHeader()
      });
      
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error('Error unlocking IP:', err);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return '#ff4444';
      case 'HIGH': return '#ff8800';
      case 'MEDIUM': return '#ffcc00';
      case 'LOW': return '#00c853';
      default: return '#888';
    }
  };

  const getAlertIcon = (type) => {
    switch (type) {
      case 'brute_force_detected': return '🚨';
      case 'credential_stuffing_detected': return '👥';
      case 'login_failures_warning': return '⚠️';
      case 'login_success_after_failures': return '🔓';
      default: return '🔐';
    }
  };

  if (loading) {
    return <div className="loading">Loading login security data...</div>;
  }

  return (
    <div className="login-security-view">
      <div className="header-row">
        <h3>🔐 Login Security Monitor</h3>
        <div className="header-actions">
          <label className="auto-refresh">
            <input 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={(e) => setAutoRefresh(e.target.checked)} 
            />
            Auto-refresh
          </label>
          <button className="refresh-btn" onClick={fetchData}>🔄 Refresh</button>
        </div>
      </div>

      {error && <div className="error-banner">⚠️ {error}</div>}

      {/* Stats Summary */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats?.total_tracked_ips || 0}</div>
          <div className="stat-label">Tracked IPs</div>
        </div>
        <div className="stat-card danger">
          <div className="stat-value">{stats?.currently_locked || 0}</div>
          <div className="stat-label">Currently Locked</div>
        </div>
        <div className="stat-card warning">
          <div className="stat-value">{stats?.total_lockouts || 0}</div>
          <div className="stat-label">Total Lockouts</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats?.total_blocked_attempts || 0}</div>
          <div className="stat-label">Blocked Attempts</div>
        </div>
      </div>

      {/* Thresholds */}
      <div className="thresholds-info">
        <span>⚙️ Thresholds:</span>
        <span>Max Attempts: <strong>{stats?.thresholds?.max_attempts || 5}</strong></span>
        <span>Lockout: <strong>{stats?.thresholds?.lockout_minutes || 15} min</strong></span>
      </div>

      <div className="two-columns">
        {/* Login Attack Alerts */}
        <div className="column">
          <h4>🚨 Login Attack Alerts</h4>
          <div className="alerts-list">
            {alerts.length === 0 ? (
              <div className="no-data">✅ No login attacks detected</div>
            ) : (
              alerts.map((alert, idx) => (
                <div 
                  key={idx} 
                  className="alert-card"
                  style={{ borderLeftColor: getSeverityColor(alert.severity) }}
                >
                  <div className="alert-header">
                    <span className="alert-icon">{getAlertIcon(alert.type)}</span>
                    <span className="alert-type">
                      {alert.type?.replace(/_/g, ' ').toUpperCase()}
                    </span>
                    <span 
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(alert.severity) }}
                    >
                      {alert.severity}
                    </span>
                  </div>
                  <div className="alert-body">
                    <p className="alert-message">{alert.message}</p>
                    <div className="alert-details">
                      <span>🌐 IP: <strong>{alert.ip}</strong></span>
                      {alert.failed_attempts && (
                        <span>❌ Failed: <strong>{alert.failed_attempts}</strong></span>
                      )}
                      {alert.attempted_usernames?.length > 0 && (
                        <span>👤 Users: {alert.attempted_usernames.slice(0, 3).join(', ')}</span>
                      )}
                    </div>
                    <div className="alert-time">
                      {new Date(alert.timestamp).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Tracked IPs */}
        <div className="column">
          <h4>📊 Tracked IPs</h4>
          <div className="ips-list">
            {trackedIPs.length === 0 ? (
              <div className="no-data">No IPs tracked yet</div>
            ) : (
              trackedIPs.map((ipData, idx) => (
                <div 
                  key={idx} 
                  className={`ip-card ${ipData.is_locked ? 'locked' : ''}`}
                >
                  <div className="ip-header">
                    <span className="ip-address">
                      {ipData.is_locked ? '🔒' : '🌐'} {ipData.ip}
                    </span>
                    {ipData.is_locked && (
                      <button 
                        className="unlock-btn"
                        onClick={() => handleUnlockIP(ipData.ip)}
                      >
                        🔓 Unlock
                      </button>
                    )}
                  </div>
                  <div className="ip-stats">
                    <span className={ipData.failed_attempts > 0 ? 'danger' : ''}>
                      ❌ Failed: {ipData.failed_attempts}
                    </span>
                    <span className="success">
                      ✅ Success: {ipData.successful_attempts}
                    </span>
                  </div>
                  {ipData.is_locked && ipData.time_until_unlock && (
                    <div className="unlock-timer">
                      ⏱️ Unlocks in: {Math.ceil(ipData.time_until_unlock / 60)} min
                    </div>
                  )}
                  {ipData.attempted_usernames?.length > 0 && (
                    <div className="attempted-users">
                      👤 Tried: {ipData.attempted_usernames.slice(0, 5).join(', ')}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <style>{`
        .login-security-view {
          padding: 20px;
        }

        .header-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }

        .header-actions {
          display: flex;
          gap: 15px;
          align-items: center;
        }

        .auto-refresh {
          display: flex;
          align-items: center;
          gap: 5px;
          color: #888;
          cursor: pointer;
        }

        .refresh-btn {
          background: #00bcd4;
          border: none;
          padding: 8px 15px;
          border-radius: 5px;
          color: white;
          cursor: pointer;
        }

        .error-banner {
          background: rgba(255, 68, 68, 0.1);
          border: 1px solid #ff4444;
          padding: 10px 15px;
          border-radius: 5px;
          color: #ff4444;
          margin-bottom: 20px;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 15px;
          margin-bottom: 20px;
        }

        .stat-card {
          background: #1e1e2e;
          border-radius: 10px;
          padding: 20px;
          text-align: center;
          border: 1px solid #333;
        }

        .stat-card.danger {
          border-color: #ff4444;
          background: rgba(255, 68, 68, 0.1);
        }

        .stat-card.warning {
          border-color: #ffa500;
          background: rgba(255, 165, 0, 0.1);
        }

        .stat-value {
          font-size: 2em;
          font-weight: bold;
          color: #00bcd4;
        }

        .stat-card.danger .stat-value { color: #ff4444; }
        .stat-card.warning .stat-value { color: #ffa500; }

        .stat-label {
          color: #888;
          font-size: 0.85em;
          margin-top: 5px;
        }

        .thresholds-info {
          display: flex;
          gap: 20px;
          padding: 10px 15px;
          background: rgba(0, 188, 212, 0.1);
          border-radius: 5px;
          margin-bottom: 20px;
          color: #888;
          font-size: 0.9em;
        }

        .thresholds-info strong {
          color: #00bcd4;
        }

        .two-columns {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 20px;
        }

        @media (max-width: 900px) {
          .two-columns {
            grid-template-columns: 1fr;
          }
        }

        .column h4 {
          margin-bottom: 15px;
          color: #00bcd4;
        }

        .alerts-list, .ips-list {
          display: flex;
          flex-direction: column;
          gap: 10px;
          max-height: 500px;
          overflow-y: auto;
        }

        .no-data {
          text-align: center;
          padding: 30px;
          color: #666;
          background: #1e1e2e;
          border-radius: 10px;
        }

        .alert-card {
          background: #1e1e2e;
          border-radius: 8px;
          padding: 12px;
          border-left: 4px solid #333;
        }

        .alert-header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 8px;
        }

        .alert-icon {
          font-size: 1.2em;
        }

        .alert-type {
          font-weight: 600;
          font-size: 0.85em;
        }

        .severity-badge {
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 0.7em;
          font-weight: bold;
          color: #000;
        }

        .alert-message {
          color: #ccc;
          font-size: 0.9em;
          margin: 5px 0;
        }

        .alert-details {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          font-size: 0.8em;
          color: #888;
          margin: 8px 0;
        }

        .alert-details strong {
          color: #fff;
        }

        .alert-time {
          font-size: 0.75em;
          color: #666;
        }

        .ip-card {
          background: #1e1e2e;
          border-radius: 8px;
          padding: 12px;
          border: 1px solid #333;
        }

        .ip-card.locked {
          border-color: #ff4444;
          background: rgba(255, 68, 68, 0.05);
        }

        .ip-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 8px;
        }

        .ip-address {
          font-weight: 600;
        }

        .unlock-btn {
          background: #ff4444;
          border: none;
          padding: 4px 10px;
          border-radius: 4px;
          color: white;
          font-size: 0.8em;
          cursor: pointer;
        }

        .ip-stats {
          display: flex;
          gap: 15px;
          font-size: 0.85em;
          color: #888;
        }

        .ip-stats .danger { color: #ff4444; }
        .ip-stats .success { color: #00c853; }

        .unlock-timer {
          margin-top: 8px;
          font-size: 0.8em;
          color: #ffa500;
        }

        .attempted-users {
          margin-top: 5px;
          font-size: 0.8em;
          color: #666;
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

export default LoginSecurityView;
