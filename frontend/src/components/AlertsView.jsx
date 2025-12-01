// frontend/src/components/AlertsView.jsx
import React, { useState, useEffect, useCallback } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;

function AlertsView() {
    const [alerts, setAlerts] = useState([]);
    const [statistics, setStatistics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [filterSeverity, setFilterSeverity] = useState('');
    const [filterType, setFilterType] = useState('');
    const [searchTerm, setSearchTerm] = useState('');
    const [autoRefresh, setAutoRefresh] = useState(true);

    const fetchAlerts = useCallback(async () => {
        if (!BACKEND_URL) {
            setError('Error: Backend URL is not configured.');
            setLoading(false);
            return;
        }

        try {
            const alertsResponse = await fetch(`${BACKEND_URL}/api/detection/alerts?limit=100`);
            if (alertsResponse.ok) {
                const alertsData = await alertsResponse.json();
                setAlerts(alertsData.alerts || []);
            }

            const statsResponse = await fetch(`${BACKEND_URL}/api/detection/statistics`);
            if (statsResponse.ok) {
                const statsData = await statsResponse.json();
                setStatistics(statsData);
            }

            setError(null);
        } catch (err) {
            console.error("Failed to fetch alerts:", err);
            setError(`Failed to load alerts. Is the backend running? (${err.message})`);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchAlerts();
        let intervalId;
        if (autoRefresh) {
            intervalId = setInterval(fetchAlerts, 5000);
        }
        return () => {
            if (intervalId) clearInterval(intervalId);
        };
    }, [fetchAlerts, autoRefresh]);

    const alertTypes = [...new Set(alerts.map(a => a.type || a.alert_type).filter(Boolean))];

    const filteredAlerts = alerts.filter(alert => {
        const matchesSeverity = !filterSeverity || alert.severity === filterSeverity;
        const matchesType = !filterType || alert.type === filterType || alert.alert_type === filterType;
        const matchesSearch = !searchTerm || 
            alert.message?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            alert.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            alert.source_ip?.includes(searchTerm) ||
            alert.target_ip?.includes(searchTerm);
        return matchesSeverity && matchesType && matchesSearch;
    });

    const getSeverityColor = (severity) => {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL': return '#ff4444';
            case 'HIGH': return '#ff8800';
            case 'MEDIUM': return '#ffcc00';
            case 'LOW': return '#00c853';
            default: return '#888';
        }
    };

    const getSeverityIcon = (severity) => {
        switch (severity?.toUpperCase()) {
            case 'CRITICAL': return '🔴';
            case 'HIGH': return '🟠';
            case 'MEDIUM': return '🟡';
            case 'LOW': return '🟢';
            default: return '⚪';
        }
    };

    const styles = `
        .alerts-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header-actions { display: flex; gap: 10px; align-items: center; }
        .auto-refresh-toggle { display: flex; align-items: center; gap: 5px; cursor: pointer; }
        .refresh-btn { padding: 8px 15px; border: none; border-radius: 5px; background: #667eea; color: white; cursor: pointer; }
        .stats-summary { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        .stat-box { flex: 1; min-width: 100px; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 10px; text-align: center; }
        .stat-box.critical { border-bottom: 3px solid #ff4444; }
        .stat-box.high { border-bottom: 3px solid #ff8800; }
        .stat-box.medium { border-bottom: 3px solid #ffcc00; }
        .stat-number { display: block; font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.85em; color: #888; }
        .filter-controls { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; padding: 15px; background: rgba(255,255,255,0.03); border-radius: 10px; }
        .filter-group { display: flex; flex-direction: column; gap: 5px; }
        .filter-group.search { flex: 1; min-width: 200px; }
        .filter-group label { font-size: 0.85em; color: #888; }
        .filter-group select, .filter-group input { padding: 8px 12px; border: 1px solid #333; border-radius: 5px; background: #1a1a2e; color: white; }
        .alerts-count { margin-bottom: 15px; color: #888; font-size: 0.9em; }
        .alert-card { background: rgba(255,255,255,0.03); border-radius: 10px; padding: 15px; margin-bottom: 15px; border-left: 4px solid; }
        .alert-header-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
        .alert-title { display: flex; align-items: center; gap: 10px; }
        .severity-icon { font-size: 1.2em; }
        .alert-type { font-weight: bold; font-size: 1.1em; }
        .severity-badge { padding: 3px 10px; border-radius: 15px; font-size: 0.75em; font-weight: bold; }
        .alert-time { color: #888; font-size: 0.9em; }
        .alert-message { margin: 10px 0; line-height: 1.5; }
        .alert-meta { display: flex; gap: 15px; flex-wrap: wrap; font-size: 0.9em; margin: 10px 0; }
        .meta-item { color: #aaa; }
        .meta-item.mitre { color: #667eea; }
        .recommended-action { background: rgba(102,126,234,0.1); padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 0.9em; }
        .no-alerts { text-align: center; padding: 50px; }
        .no-alerts-icon { font-size: 3em; display: block; margin-bottom: 15px; }
        .loading-spinner { text-align: center; padding: 50px; color: #888; }
        .error-message { background: rgba(255,68,68,0.1); border: 1px solid #ff4444; padding: 15px; border-radius: 5px; color: #ff4444; }
    `;

    return (
        <div className="view-container alerts-view">
            <style>{styles}</style>
            <div className="alerts-header">
                <h2>🚨 Security Alerts</h2>
                <div className="header-actions">
                    <label className="auto-refresh-toggle">
                        <input 
                            type="checkbox" 
                            checked={autoRefresh} 
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                        />
                        Auto-refresh
                    </label>
                    <button className="refresh-btn" onClick={fetchAlerts} disabled={loading}>
                        🔄 Refresh
                    </button>
                </div>
            </div>

            {statistics && (
                <div className="stats-summary">
                    <div className="stat-box">
                        <span className="stat-number">{statistics.alerts_generated || 0}</span>
                        <span className="stat-label">Total Alerts</span>
                    </div>
                    <div className="stat-box critical">
                        <span className="stat-number">{statistics.attacks_by_severity?.CRITICAL || 0}</span>
                        <span className="stat-label">Critical</span>
                    </div>
                    <div className="stat-box high">
                        <span className="stat-number">{statistics.attacks_by_severity?.HIGH || 0}</span>
                        <span className="stat-label">High</span>
                    </div>
                    <div className="stat-box medium">
                        <span className="stat-number">{statistics.attacks_by_severity?.MEDIUM || 0}</span>
                        <span className="stat-label">Medium</span>
                    </div>
                </div>
            )}

            <div className="filter-controls">
                <div className="filter-group">
                    <label>Severity:</label>
                    <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
                        <option value="">All</option>
                        <option value="CRITICAL">🔴 Critical</option>
                        <option value="HIGH">🟠 High</option>
                        <option value="MEDIUM">🟡 Medium</option>
                        <option value="LOW">🟢 Low</option>
                    </select>
                </div>
                <div className="filter-group">
                    <label>Type:</label>
                    <select value={filterType} onChange={(e) => setFilterType(e.target.value)}>
                        <option value="">All Types</option>
                        {alertTypes.map(type => (
                            <option key={type} value={type}>{type}</option>
                        ))}
                    </select>
                </div>
                <div className="filter-group search">
                    <label>Search:</label>
                    <input
                        type="text"
                        placeholder="Search alerts, IPs..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
            </div>

            {loading && <div className="loading-spinner">Loading alerts...</div>}
            {error && <div className="error-message">{error}</div>}

            {!loading && !error && (
                <div className="alerts-list">
                    <div className="alerts-count">
                        Showing {filteredAlerts.length} of {alerts.length} alerts
                    </div>
                    
                    {filteredAlerts.length > 0 ? (
                        filteredAlerts.map((alert, index) => (
                            <div 
                                key={alert.id || index} 
                                className="alert-card"
                                style={{ borderLeftColor: getSeverityColor(alert.severity) }}
                            >
                                <div className="alert-header-row">
                                    <div className="alert-title">
                                        <span className="severity-icon">{getSeverityIcon(alert.severity)}</span>
                                        <span className="alert-type">{alert.attack_type || alert.type}</span>
                                        <span 
                                            className="severity-badge"
                                            style={{ backgroundColor: getSeverityColor(alert.severity) }}
                                        >
                                            {alert.severity}
                                        </span>
                                    </div>
                                    <span className="alert-time">
                                        {new Date(alert.timestamp).toLocaleString()}
                                    </span>
                                </div>
                                
                                <div className="alert-body">
                                    <p className="alert-message">{alert.description || alert.message}</p>
                                    
                                    <div className="alert-meta">
                                        {alert.source_ip && (
                                            <span className="meta-item">
                                                <strong>Source:</strong> {alert.source_ip}
                                                {alert.source_port && `:${alert.source_port}`}
                                            </span>
                                        )}
                                        {alert.destination_ip && (
                                            <span className="meta-item">
                                                <strong>Target:</strong> {alert.destination_ip}
                                                {alert.destination_port && `:${alert.destination_port}`}
                                            </span>
                                        )}
                                        {alert.mitre_tactics && (
                                            <span className="meta-item mitre">
                                                <strong>MITRE:</strong> {alert.mitre_tactics.join(', ')}
                                            </span>
                                        )}
                                    </div>
                                    
                                    {alert.recommended_actions && alert.recommended_actions.length > 0 && (
                                        <div className="recommended-action">
                                            <strong>💡 Action:</strong> {alert.recommended_actions[0]}
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="no-alerts">
                            <span className="no-alerts-icon">✅</span>
                            <p>No alerts matching current filters</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

export default AlertsView;
