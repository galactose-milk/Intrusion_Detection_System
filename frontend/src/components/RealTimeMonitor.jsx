// frontend/src/components/RealTimeMonitor.jsx
import React, { useState, useEffect, useRef } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
const WS_URL = BACKEND_URL?.replace('http', 'ws') + '/ws/live';

function RealTimeMonitor() {
    const [connected, setConnected] = useState(false);
    const [stats, setStats] = useState(null);
    const [recentAlerts, setRecentAlerts] = useState([]);
    const [recentConnections, setRecentConnections] = useState([]);
    const wsRef = useRef(null);
    const reconnectTimeoutRef = useRef(null);

    useEffect(() => {
        connectWebSocket();
        fetchRecentConnections();
        
        const interval = setInterval(fetchRecentConnections, 5000);
        
        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
            if (reconnectTimeoutRef.current) {
                clearTimeout(reconnectTimeoutRef.current);
            }
            clearInterval(interval);
        };
    }, []);

    const fetchRecentConnections = async () => {
        try {
            const response = await fetch(`${BACKEND_URL}/api/realtime/connections`);
            const data = await response.json();
            setRecentConnections(data.recent_data?.slice(0, 20) || []);
        } catch (e) {
            console.error('Error fetching connections:', e);
        }
    };

    const connectWebSocket = () => {
        if (!WS_URL || WS_URL.includes('undefined')) {
            console.error('WebSocket URL not configured');
            return;
        }

        try {
            wsRef.current = new WebSocket(WS_URL);

            wsRef.current.onopen = () => {
                console.log('WebSocket connected');
                setConnected(true);
            };

            wsRef.current.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleMessage(data);
                } catch (e) {
                    console.error('Error parsing WebSocket message:', e);
                }
            };

            wsRef.current.onclose = () => {
                console.log('WebSocket disconnected');
                setConnected(false);
                reconnectTimeoutRef.current = setTimeout(connectWebSocket, 5000);
            };

            wsRef.current.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
        } catch (e) {
            console.error('Failed to connect WebSocket:', e);
        }
    };

    const handleMessage = (data) => {
        switch (data.type) {
            case 'stats_update':
                setStats(data);
                break;
            case 'high_severity_alert':
                setRecentAlerts(prev => [...data.alerts, ...prev].slice(0, 20));
                break;
            case 'heartbeat':
                break;
            default:
                console.log('Message:', data.type);
        }
    };

    const formatNumber = (num) => {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num?.toString() || '0';
    };

    return (
        <div className="realtime-monitor">
            <div className="monitor-header">
                <h3>🔴 LIVE Network Monitor</h3>
                <div className={`connection-status ${connected ? 'connected' : 'disconnected'}`}>
                    <span className="status-dot"></span>
                    {connected ? 'REAL TRAFFIC' : 'Reconnecting...'}
                </div>
            </div>

            <div className="mode-banner">
                <span>📡</span> Monitoring ACTUAL network connections on your system - no simulations
            </div>

            {stats && (
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-icon">🔗</div>
                        <div className="stat-value">{formatNumber(stats.network_events?.active_connections)}</div>
                        <div className="stat-label">Active Connections</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-icon">📊</div>
                        <div className="stat-value">{formatNumber(stats.network_events?.total_network_events)}</div>
                        <div className="stat-label">Network Events</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-icon">🌐</div>
                        <div className="stat-value">{formatNumber(stats.network_events?.unique_remote_ips)}</div>
                        <div className="stat-label">Unique IPs</div>
                    </div>
                    <div className="stat-card alert">
                        <div className="stat-icon">⚠️</div>
                        <div className="stat-value">{formatNumber(stats.network_events?.suspicious_activities)}</div>
                        <div className="stat-label">Suspicious</div>
                    </div>
                </div>
            )}

            {stats?.threat_summary && (
                <div className="severity-breakdown">
                    <div className="severity-item critical">
                        <span className="severity-count">{stats.threat_summary.critical_alerts}</span>
                        <span className="severity-label">Critical</span>
                    </div>
                    <div className="severity-item high">
                        <span className="severity-count">{stats.threat_summary.high_alerts}</span>
                        <span className="severity-label">High</span>
                    </div>
                    <div className="severity-item medium">
                        <span className="severity-count">{stats.threat_summary.medium_alerts}</span>
                        <span className="severity-label">Medium</span>
                    </div>
                    <div className="severity-item low">
                        <span className="severity-count">{stats.threat_summary.low_alerts}</span>
                        <span className="severity-label">Low</span>
                    </div>
                </div>
            )}

            {recentConnections.length > 0 && (
                <div className="connections-section">
                    <h4>🔗 Live Connections (Real Traffic)</h4>
                    <div className="connections-list">
                        {recentConnections.filter(c => c.event_type === 'connection').slice(0, 15).map((conn, idx) => (
                            <div key={idx} className={`connection-item ${conn.is_new_connection ? 'new' : ''}`}>
                                <span className="conn-local">{conn.local_addr}</span>
                                <span className="conn-arrow">→</span>
                                <span className="conn-remote">{conn.remote_addr}</span>
                                <span className={`conn-protocol ${conn.protocol?.toLowerCase()}`}>{conn.protocol}</span>
                                <span className="conn-status">{conn.status}</span>
                                {conn.process_name && (
                                    <span className="conn-process">{conn.process_name}</span>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {recentAlerts.length > 0 && (
                <div className="recent-alerts">
                    <h4>🚨 Recent High-Severity Alerts (Real Threats)</h4>
                    <div className="alerts-list">
                        {recentAlerts.map((alert, idx) => (
                            <div key={`${alert.id}-${idx}`} className={`alert-item ${alert.severity?.toLowerCase()}`}>
                                <span className="alert-type">{alert.type}</span>
                                <span className="alert-source">{alert.source_ip}</span>
                                <span className={`alert-severity ${alert.severity?.toLowerCase()}`}>
                                    {alert.severity}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <style>{`
                .realtime-monitor {
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    border-radius: 15px;
                    padding: 20px;
                    margin: 20px 0;
                    border: 1px solid #0f3460;
                }
                
                .monitor-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }
                
                .monitor-header h3 {
                    margin: 0;
                    color: #ff4444;
                }
                
                .mode-banner {
                    background: rgba(255, 68, 68, 0.1);
                    border: 1px solid #ff4444;
                    border-radius: 8px;
                    padding: 10px 15px;
                    margin-bottom: 20px;
                    text-align: center;
                    font-size: 0.9em;
                    color: #ff8888;
                }
                
                .connection-status {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }
                
                .connection-status.connected {
                    background: rgba(255, 68, 68, 0.2);
                    color: #ff4444;
                }
                
                .connection-status.disconnected {
                    background: rgba(255, 204, 0, 0.2);
                    color: #ffcc00;
                }
                
                .status-dot {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    background: currentColor;
                    animation: pulse 1s infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { opacity: 1; transform: scale(1); }
                    50% { opacity: 0.5; transform: scale(1.2); }
                }
                
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                    gap: 15px;
                    margin-bottom: 20px;
                }
                
                .stat-card {
                    background: rgba(255, 255, 255, 0.05);
                    border-radius: 10px;
                    padding: 15px;
                    text-align: center;
                    transition: transform 0.3s ease;
                }
                
                .stat-card:hover { transform: translateY(-3px); }
                .stat-card.alert { border-left: 3px solid #ff4444; }
                .stat-icon { font-size: 1.5em; margin-bottom: 5px; }
                .stat-value { font-size: 1.8em; font-weight: bold; color: #00bcd4; }
                .stat-label { font-size: 0.8em; color: #888; margin-top: 5px; }
                
                .severity-breakdown {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 20px;
                    flex-wrap: wrap;
                }
                
                .severity-item {
                    flex: 1;
                    min-width: 80px;
                    padding: 10px;
                    border-radius: 8px;
                    text-align: center;
                }
                
                .severity-item.critical { background: rgba(255, 68, 68, 0.2); border: 1px solid #ff4444; }
                .severity-item.high { background: rgba(255, 136, 0, 0.2); border: 1px solid #ff8800; }
                .severity-item.medium { background: rgba(255, 204, 0, 0.2); border: 1px solid #ffcc00; }
                .severity-item.low { background: rgba(0, 200, 83, 0.2); border: 1px solid #00c853; }
                
                .severity-count { display: block; font-size: 1.5em; font-weight: bold; }
                .severity-label { font-size: 0.8em; color: #888; }
                
                .connections-section, .recent-alerts { margin-top: 20px; }
                .connections-section h4, .recent-alerts h4 { margin-bottom: 10px; color: #00bcd4; }
                
                .connections-list, .alerts-list {
                    max-height: 250px;
                    overflow-y: auto;
                }
                
                .connection-item {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 10px;
                    background: rgba(255, 255, 255, 0.03);
                    border-radius: 5px;
                    margin-bottom: 4px;
                    font-family: monospace;
                    font-size: 0.85em;
                    border-left: 3px solid transparent;
                }
                
                .connection-item.new { border-left-color: #00c853; background: rgba(0, 200, 83, 0.05); }
                .conn-local { color: #00bcd4; }
                .conn-arrow { color: #666; }
                .conn-remote { color: #ff8888; }
                .conn-protocol { padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }
                .conn-protocol.tcp { background: rgba(0, 188, 212, 0.2); color: #00bcd4; }
                .conn-protocol.udp { background: rgba(156, 39, 176, 0.2); color: #9c27b0; }
                .conn-status { color: #888; font-size: 0.8em; }
                .conn-process { color: #ffa500; margin-left: auto; }
                
                .alert-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 10px;
                    background: rgba(255, 255, 255, 0.03);
                    border-radius: 5px;
                    margin-bottom: 5px;
                    border-left: 3px solid transparent;
                }
                
                .alert-item.critical { border-left-color: #ff4444; }
                .alert-item.high { border-left-color: #ff8800; }
                .alert-type { flex: 1; font-weight: 500; }
                .alert-source { color: #888; font-family: monospace; }
                .alert-severity { padding: 2px 8px; border-radius: 10px; font-size: 0.8em; margin-left: 10px; }
                .alert-severity.critical { background: #ff4444; }
                .alert-severity.high { background: #ff8800; }
            `}</style>
        </div>
    );
}

export default RealTimeMonitor;
