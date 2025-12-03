// frontend/src/components/IPQuarantineView.jsx
import React, { useState, useEffect, useCallback } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;

function IPQuarantineView() {
    const [blockedIPs, setBlockedIPs] = useState([]);
    const [allIPStats, setAllIPStats] = useState([]);
    const [ipAlerts, setIPAlerts] = useState([]);
    const [statistics, setStatistics] = useState(null);
    const [thresholds, setThresholds] = useState({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState('blocked');
    const [manualBlockIP, setManualBlockIP] = useState('');
    const [manualBlockReason, setManualBlockReason] = useState('');
    const [autoRefresh, setAutoRefresh] = useState(true);

    const fetchData = useCallback(async () => {
        if (!BACKEND_URL) {
            setError('Error: Backend URL is not configured.');
            setLoading(false);
            return;
        }

        try {
            // Fetch blocked IPs
            const blockedRes = await fetch(`${BACKEND_URL}/api/ip-quarantine/blocked`);
            if (blockedRes.ok) {
                const data = await blockedRes.json();
                setBlockedIPs(data.blocked_ips || []);
            }

            // Fetch all IP stats
            const statsRes = await fetch(`${BACKEND_URL}/api/ip-quarantine/all-stats?limit=100`);
            if (statsRes.ok) {
                const data = await statsRes.json();
                setAllIPStats(data.ip_stats || []);
            }

            // Fetch IP alerts
            const alertsRes = await fetch(`${BACKEND_URL}/api/ip-quarantine/alerts?limit=50`);
            if (alertsRes.ok) {
                const data = await alertsRes.json();
                setIPAlerts(data.alerts || []);
            }

            // Fetch statistics
            const statusRes = await fetch(`${BACKEND_URL}/api/ip-quarantine/status`);
            if (statusRes.ok) {
                const data = await statusRes.json();
                setStatistics(data);
            }

            // Fetch thresholds
            const threshRes = await fetch(`${BACKEND_URL}/api/ip-quarantine/thresholds`);
            if (threshRes.ok) {
                const data = await threshRes.json();
                setThresholds(data.thresholds || {});
            }

            setError(null);
        } catch (err) {
            console.error("Failed to fetch IP quarantine data:", err);
            setError(`Failed to load data: ${err.message}`);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchData();
        let intervalId;
        if (autoRefresh) {
            intervalId = setInterval(fetchData, 3000);
        }
        return () => {
            if (intervalId) clearInterval(intervalId);
        };
    }, [fetchData, autoRefresh]);

    const handleUnblockIP = async (ip) => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/ip-quarantine/unblock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            if (response.ok) {
                fetchData();
            } else {
                alert('Failed to unblock IP');
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleManualBlock = async (e) => {
        e.preventDefault();
        if (!manualBlockIP) return;

        try {
            const response = await fetch(`${BACKEND_URL}/api/ip-quarantine/block`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip: manualBlockIP,
                    reason: manualBlockReason || 'Manual block',
                    duration: 900  // 15 minutes default
                })
            });
            if (response.ok) {
                setManualBlockIP('');
                setManualBlockReason('');
                fetchData();
            } else {
                alert('Failed to block IP');
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    };

    const handleUnblockAll = async () => {
        if (!window.confirm('Are you sure you want to unblock ALL IPs?')) return;
        
        try {
            const response = await fetch(`${BACKEND_URL}/api/ip-quarantine/unblock-all`, {
                method: 'DELETE'
            });
            if (response.ok) {
                fetchData();
            }
        } catch (err) {
            alert(`Error: ${err.message}`);
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

    const getAttackTypeIcon = (type) => {
        switch (type) {
            case 'dos_flood': return '🌊';
            case 'ddos_flood': return '🌀';
            case 'endpoint_scan': return '🔍';
            case 'brute_force': return '🔓';
            case 'rate_limit': return '⏱️';
            default: return '⚠️';
        }
    };

    const formatTimeRemaining = (unblockTime) => {
        if (!unblockTime) return 'Permanent';
        const remaining = new Date(unblockTime) - new Date();
        if (remaining <= 0) return 'Expiring...';
        const minutes = Math.floor(remaining / 60000);
        const seconds = Math.floor((remaining % 60000) / 1000);
        return `${minutes}m ${seconds}s`;
    };

    const styles = `
        .ip-quarantine-view { padding: 20px; }
        .header-section { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
        .header-actions { display: flex; gap: 10px; align-items: center; }
        .auto-refresh-toggle { display: flex; align-items: center; gap: 5px; cursor: pointer; }
        .refresh-btn { padding: 8px 15px; border: none; border-radius: 5px; background: #667eea; color: white; cursor: pointer; }
        .refresh-btn:hover { background: #5a6fd6; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 25px; }
        .stat-card { background: rgba(255,255,255,0.05); border-radius: 10px; padding: 20px; text-align: center; }
        .stat-card.danger { border-left: 4px solid #ff4444; }
        .stat-card.warning { border-left: 4px solid #ff8800; }
        .stat-card.info { border-left: 4px solid #667eea; }
        .stat-number { display: block; font-size: 2.5em; font-weight: bold; }
        .stat-label { color: #888; font-size: 0.9em; }
        
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .tab-btn { padding: 10px 20px; border: none; border-radius: 5px 5px 0 0; background: rgba(255,255,255,0.05); color: #888; cursor: pointer; transition: all 0.2s; }
        .tab-btn.active { background: #667eea; color: white; }
        .tab-btn:hover:not(.active) { background: rgba(255,255,255,0.1); }
        
        .manual-block-form { background: rgba(255,255,255,0.05); padding: 20px; border-radius: 10px; margin-bottom: 20px; display: flex; gap: 15px; align-items: end; flex-wrap: wrap; }
        .form-group { display: flex; flex-direction: column; gap: 5px; }
        .form-group label { font-size: 0.85em; color: #888; }
        .form-group input { padding: 10px; border: 1px solid #333; border-radius: 5px; background: #1a1a2e; color: white; min-width: 150px; }
        .block-btn { padding: 10px 20px; border: none; border-radius: 5px; background: #ff4444; color: white; cursor: pointer; font-weight: bold; }
        .block-btn:hover { background: #ff2222; }
        .unblock-all-btn { padding: 10px 20px; border: none; border-radius: 5px; background: #00c853; color: white; cursor: pointer; margin-left: auto; }
        .unblock-all-btn:hover { background: #00b048; }
        
        .blocked-list { display: flex; flex-direction: column; gap: 15px; }
        .blocked-card { background: rgba(255,68,68,0.1); border: 1px solid #ff4444; border-radius: 10px; padding: 15px; }
        .blocked-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .blocked-ip { font-size: 1.3em; font-weight: bold; color: #ff4444; }
        .blocked-actions { display: flex; gap: 10px; }
        .unblock-btn { padding: 6px 15px; border: none; border-radius: 5px; background: #00c853; color: white; cursor: pointer; }
        .blocked-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; font-size: 0.9em; }
        .detail-item { background: rgba(0,0,0,0.2); padding: 8px; border-radius: 5px; }
        .detail-label { color: #888; font-size: 0.85em; }
        .detail-value { font-weight: bold; }
        
        .ip-stats-table { width: 100%; border-collapse: collapse; }
        .ip-stats-table th, .ip-stats-table td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        .ip-stats-table th { background: rgba(255,255,255,0.05); color: #888; font-weight: normal; }
        .ip-stats-table tr:hover { background: rgba(255,255,255,0.03); }
        .rpm-badge { padding: 3px 8px; border-radius: 10px; font-size: 0.85em; font-weight: bold; }
        .rpm-high { background: #ff4444; }
        .rpm-medium { background: #ff8800; }
        .rpm-low { background: #333; }
        
        .alert-card { background: rgba(255,255,255,0.03); border-radius: 10px; padding: 15px; margin-bottom: 15px; border-left: 4px solid; }
        .alert-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .alert-type { display: flex; align-items: center; gap: 8px; font-weight: bold; }
        .alert-time { color: #888; font-size: 0.9em; }
        .alert-details { display: flex; gap: 20px; font-size: 0.9em; color: #aaa; }
        
        .no-data { text-align: center; padding: 50px; color: #888; }
        .no-data-icon { font-size: 3em; margin-bottom: 15px; }
        
        .thresholds-panel { background: rgba(255,255,255,0.05); border-radius: 10px; padding: 20px; margin-top: 20px; }
        .thresholds-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .threshold-item { background: rgba(0,0,0,0.2); padding: 15px; border-radius: 8px; }
        .threshold-name { color: #888; font-size: 0.85em; margin-bottom: 5px; }
        .threshold-value { font-size: 1.5em; font-weight: bold; color: #667eea; }
        
        .error-message { background: rgba(255,68,68,0.1); border: 1px solid #ff4444; padding: 15px; border-radius: 5px; color: #ff4444; }
        .loading { text-align: center; padding: 50px; color: #888; }
    `;

    return (
        <div className="view-container ip-quarantine-view">
            <style>{styles}</style>
            
            <div className="header-section">
                <h2>🛡️ IP Quarantine System</h2>
                <div className="header-actions">
                    <label className="auto-refresh-toggle">
                        <input 
                            type="checkbox" 
                            checked={autoRefresh} 
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                        />
                        Auto-refresh
                    </label>
                    <button className="refresh-btn" onClick={fetchData} disabled={loading}>
                        🔄 Refresh
                    </button>
                </div>
            </div>

            {/* Statistics Cards */}
            {statistics && (
                <div className="stats-grid">
                    <div className="stat-card danger">
                        <span className="stat-number">{blockedIPs.length}</span>
                        <span className="stat-label">Currently Blocked</span>
                    </div>
                    <div className="stat-card warning">
                        <span className="stat-number">{statistics.total_attacks_detected || 0}</span>
                        <span className="stat-label">Attacks Detected</span>
                    </div>
                    <div className="stat-card info">
                        <span className="stat-number">{statistics.total_ips_tracked || 0}</span>
                        <span className="stat-label">IPs Tracked</span>
                    </div>
                    <div className="stat-card">
                        <span className="stat-number">{statistics.total_blocked_ever || 0}</span>
                        <span className="stat-label">Total Blocks</span>
                    </div>
                </div>
            )}

            {/* Tabs */}
            <div className="tabs">
                <button 
                    className={`tab-btn ${activeTab === 'blocked' ? 'active' : ''}`}
                    onClick={() => setActiveTab('blocked')}
                >
                    🚫 Blocked IPs ({blockedIPs.length})
                </button>
                <button 
                    className={`tab-btn ${activeTab === 'alerts' ? 'active' : ''}`}
                    onClick={() => setActiveTab('alerts')}
                >
                    🚨 Attack Alerts ({ipAlerts.length})
                </button>
                <button 
                    className={`tab-btn ${activeTab === 'stats' ? 'active' : ''}`}
                    onClick={() => setActiveTab('stats')}
                >
                    📊 All IP Stats
                </button>
                <button 
                    className={`tab-btn ${activeTab === 'settings' ? 'active' : ''}`}
                    onClick={() => setActiveTab('settings')}
                >
                    ⚙️ Thresholds
                </button>
            </div>

            {loading && <div className="loading">Loading...</div>}
            {error && <div className="error-message">{error}</div>}

            {!loading && !error && (
                <>
                    {/* Blocked IPs Tab */}
                    {activeTab === 'blocked' && (
                        <div className="blocked-tab">
                            {/* Manual Block Form */}
                            <form className="manual-block-form" onSubmit={handleManualBlock}>
                                <div className="form-group">
                                    <label>IP Address</label>
                                    <input 
                                        type="text" 
                                        placeholder="192.168.1.100"
                                        value={manualBlockIP}
                                        onChange={(e) => setManualBlockIP(e.target.value)}
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label>Reason (optional)</label>
                                    <input 
                                        type="text" 
                                        placeholder="Suspicious activity"
                                        value={manualBlockReason}
                                        onChange={(e) => setManualBlockReason(e.target.value)}
                                    />
                                </div>
                                <button type="submit" className="block-btn">🚫 Block IP</button>
                                {blockedIPs.length > 0 && (
                                    <button type="button" className="unblock-all-btn" onClick={handleUnblockAll}>
                                        ✅ Unblock All
                                    </button>
                                )}
                            </form>

                            {/* Blocked IPs List */}
                            <div className="blocked-list">
                                {blockedIPs.length > 0 ? (
                                    blockedIPs.map((ip, index) => (
                                        <div key={ip.ip || index} className="blocked-card">
                                            <div className="blocked-header">
                                                <span className="blocked-ip">🚫 {ip.ip}</span>
                                                <div className="blocked-actions">
                                                    <span style={{ color: '#888', marginRight: '10px' }}>
                                                        ⏱️ {formatTimeRemaining(ip.unblock_time)}
                                                    </span>
                                                    <button 
                                                        className="unblock-btn"
                                                        onClick={() => handleUnblockIP(ip.ip)}
                                                    >
                                                        Unblock
                                                    </button>
                                                </div>
                                            </div>
                                            <div className="blocked-details">
                                                <div className="detail-item">
                                                    <div className="detail-label">Reason</div>
                                                    <div className="detail-value">{ip.block_reason || 'N/A'}</div>
                                                </div>
                                                <div className="detail-item">
                                                    <div className="detail-label">Total Requests</div>
                                                    <div className="detail-value">{ip.total_requests}</div>
                                                </div>
                                                <div className="detail-item">
                                                    <div className="detail-label">Requests/Min</div>
                                                    <div className="detail-value">{ip.requests_per_minute}</div>
                                                </div>
                                                <div className="detail-item">
                                                    <div className="detail-label">Endpoints Hit</div>
                                                    <div className="detail-value">{ip.endpoints_accessed}</div>
                                                </div>
                                                <div className="detail-item">
                                                    <div className="detail-label">Attack Types</div>
                                                    <div className="detail-value">{ip.attack_types?.join(', ') || 'N/A'}</div>
                                                </div>
                                                <div className="detail-item">
                                                    <div className="detail-label">Blocked Since</div>
                                                    <div className="detail-value">
                                                        {ip.block_time ? new Date(ip.block_time).toLocaleString() : 'N/A'}
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                ) : (
                                    <div className="no-data">
                                        <div className="no-data-icon">✅</div>
                                        <p>No blocked IPs</p>
                                        <p style={{ fontSize: '0.9em' }}>
                                            When attacking IPs are detected, they will appear here
                                        </p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Alerts Tab */}
                    {activeTab === 'alerts' && (
                        <div className="alerts-tab">
                            {ipAlerts.length > 0 ? (
                                ipAlerts.map((alert, index) => (
                                    <div 
                                        key={alert.id || index} 
                                        className="alert-card"
                                        style={{ borderLeftColor: getSeverityColor(alert.severity) }}
                                    >
                                        <div className="alert-header">
                                            <div className="alert-type">
                                                <span>{getAttackTypeIcon(alert.attack_type)}</span>
                                                <span>{alert.attack_type?.replace('_', ' ').toUpperCase()}</span>
                                                <span 
                                                    style={{ 
                                                        padding: '3px 10px', 
                                                        borderRadius: '10px', 
                                                        fontSize: '0.8em',
                                                        background: getSeverityColor(alert.severity) 
                                                    }}
                                                >
                                                    {alert.severity}
                                                </span>
                                            </div>
                                            <span className="alert-time">
                                                {new Date(alert.timestamp).toLocaleString()}
                                            </span>
                                        </div>
                                        <p>{alert.description}</p>
                                        <div className="alert-details">
                                            <span><strong>Source:</strong> {alert.source_ip}</span>
                                            <span><strong>Requests:</strong> {alert.request_count}</span>
                                            <span><strong>Action:</strong> {alert.action_taken?.toUpperCase()}</span>
                                        </div>
                                    </div>
                                ))
                            ) : (
                                <div className="no-data">
                                    <div className="no-data-icon">🔍</div>
                                    <p>No attack alerts yet</p>
                                    <p style={{ fontSize: '0.9em' }}>
                                        Attacks will be logged here when detected
                                    </p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* All Stats Tab */}
                    {activeTab === 'stats' && (
                        <div className="stats-tab">
                            {allIPStats.length > 0 ? (
                                <table className="ip-stats-table">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Total Requests</th>
                                            <th>Req/Min</th>
                                            <th>Endpoints</th>
                                            <th>Failed</th>
                                            <th>Status</th>
                                            <th>Last Seen</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {allIPStats.map((stat, index) => (
                                            <tr key={stat.ip || index}>
                                                <td><strong>{stat.ip}</strong></td>
                                                <td>{stat.total_requests}</td>
                                                <td>
                                                    <span className={`rpm-badge ${
                                                        stat.requests_per_minute >= 100 ? 'rpm-high' :
                                                        stat.requests_per_minute >= 50 ? 'rpm-medium' : 'rpm-low'
                                                    }`}>
                                                        {stat.requests_per_minute}
                                                    </span>
                                                </td>
                                                <td>{stat.endpoints_accessed}</td>
                                                <td style={{ color: stat.failed_requests > 10 ? '#ff4444' : '#888' }}>
                                                    {stat.failed_requests}
                                                </td>
                                                <td>
                                                    {stat.is_blocked ? (
                                                        <span style={{ color: '#ff4444' }}>🚫 Blocked</span>
                                                    ) : (
                                                        <span style={{ color: '#00c853' }}>✅ Active</span>
                                                    )}
                                                </td>
                                                <td style={{ fontSize: '0.85em', color: '#888' }}>
                                                    {new Date(stat.last_seen).toLocaleTimeString()}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="no-data">
                                    <div className="no-data-icon">📊</div>
                                    <p>No IP statistics yet</p>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Settings Tab */}
                    {activeTab === 'settings' && (
                        <div className="settings-tab">
                            <div className="thresholds-panel">
                                <h3 style={{ marginBottom: '15px' }}>⚙️ Detection Thresholds</h3>
                                <p style={{ color: '#888', marginBottom: '20px' }}>
                                    These thresholds determine when an IP is flagged or blocked
                                </p>
                                <div className="thresholds-grid">
                                    <div className="threshold-item">
                                        <div className="threshold-name">Warning (req/min)</div>
                                        <div className="threshold-value">{thresholds.requests_per_minute_warn || 'N/A'}</div>
                                    </div>
                                    <div className="threshold-item">
                                        <div className="threshold-name">Throttle (req/min)</div>
                                        <div className="threshold-value">{thresholds.requests_per_minute_throttle || 'N/A'}</div>
                                    </div>
                                    <div className="threshold-item">
                                        <div className="threshold-name">Block (req/min)</div>
                                        <div className="threshold-value">{thresholds.requests_per_minute_block || 'N/A'}</div>
                                    </div>
                                    <div className="threshold-item">
                                        <div className="threshold-name">Endpoint Scan</div>
                                        <div className="threshold-value">{thresholds.endpoint_scan_threshold || 'N/A'}</div>
                                    </div>
                                    <div className="threshold-item">
                                        <div className="threshold-name">Failed Requests</div>
                                        <div className="threshold-value">{thresholds.failed_requests_threshold || 'N/A'}</div>
                                    </div>
                                    <div className="threshold-item">
                                        <div className="threshold-name">Burst Detection</div>
                                        <div className="threshold-value">{thresholds.burst_requests || 'N/A'} in {thresholds.burst_window || 'N/A'}s</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

export default IPQuarantineView;
