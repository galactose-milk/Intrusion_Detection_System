// frontend/src/components/VisualizerView.jsx
import React, { useState, useEffect } from 'react';

// --- IMPORTANT: Charting Library ---
// You need to install a charting library. Chart.js is a popular choice.
// Run: npm install chart.js react-chartjs-2
// Then uncomment the lines below:
import { Line } from 'react-chartjs-2';
import {
    Chart as ChartJS,
    CategoryScale, // x axis
    LinearScale, // y axis
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
} from 'chart.js';

ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);
// -----------------------------------

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL;

function VisualizerView() {
    const [chartData, setChartData] = useState(null);
    const [rawData, setRawData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [timeRange, setTimeRange] = useState('1h');
    const [severityFilter, setSeverityFilter] = useState('');

    useEffect(() => {
        const fetchThreatData = async () => {
            if (!BACKEND_URL) {
                 setError('Error: Backend URL is not configured.');
                 setLoading(false);
                 return;
            }
            setLoading(true);
            setError(null);
            setChartData(null);
            setRawData(null);

            try {
                const params = new URLSearchParams({ time_range: timeRange });
                if (severityFilter) {
                    params.append('severity_filter', severityFilter);
                }

                const response = await fetch(`${BACKEND_URL}/api/threats/analyze?${params.toString()}`);

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({}));
                    throw new Error(`HTTP error! status: ${response.status} - ${errorData.detail || response.statusText}`);
                }
                const result = await response.json();
                setRawData(result);

                 // Prepare threat data for visualization
                 if (result.security_alerts && result.security_alerts.length > 0) {
                    const labels = result.security_alerts.map(alert => 
                        new Date(alert.timestamp).toLocaleTimeString([], { 
                            hour: '2-digit', 
                            minute: '2-digit', 
                            second: '2-digit'
                        })
                    );
                    
                    // Map severity to numeric values for visualization
                    const severityMap = { 'LOW': 1, 'MEDIUM': 3, 'HIGH': 6, 'CRITICAL': 10 };
                    const threatScores = result.security_alerts.map(alert => 
                        alert.threat_score || severityMap[alert.severity] || 1
                    );

                    setChartData({
                        labels: labels,
                        datasets: [
                            {
                                label: `Threat Severity Over Time (${timeRange})`,
                                data: threatScores,
                                fill: true,
                                borderColor: 'rgb(220, 38, 127)',
                                backgroundColor: 'rgba(220, 38, 127, 0.2)',
                                tension: 0.1,
                                pointRadius: 4,
                                pointHoverRadius: 6,
                                pointBackgroundColor: result.security_alerts.map(alert => {
                                    switch(alert.severity) {
                                        case 'CRITICAL': return 'red';
                                        case 'HIGH': return 'orange';
                                        case 'MEDIUM': return 'yellow';
                                        default: return 'green';
                                    }
                                })
                            },
                        ],
                    });
                 }

            } catch (err) {
                console.error("Failed to fetch threat data:", err);
                setError(`Failed to load threat analysis. Is the backend running? (${err.message})`);
            } finally {
                setLoading(false);
            }
        };

        fetchThreatData();
    }, [timeRange, severityFilter]);


  return (
    <div className="view-container visualizer-view">
      <h2>Threat Analysis & Visualization</h2>

        {/* Filters */}
         <div className="form-group" style={{ maxWidth: '200px', display: 'inline-block', marginRight: '20px'}}>
            <label htmlFor="timeRange">Time Range:</label>
            <select id="timeRange" value={timeRange} onChange={(e) => setTimeRange(e.target.value)}>
                <option value="5m">Last 5 Minutes</option>
                <option value="15m">Last 15 Minutes</option>
                <option value="1h">Last 1 Hour</option>
                <option value="6h">Last 6 Hours</option>
                <option value="1d">Last 1 Day</option>
            </select>
        </div>

        <div className="form-group" style={{ maxWidth: '200px', display: 'inline-block'}}>
            <label htmlFor="severityFilter">Severity Filter:</label>
            <select id="severityFilter" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical Only</option>
                <option value="HIGH">High & Above</option>
                <option value="MEDIUM">Medium & Above</option>
                <option value="LOW">Low & Above</option>
            </select>
        </div>

       {loading && <p>Loading threat analysis...</p>}
       {error && <p style={{ color: 'red', fontWeight: 'bold' }}>{error}</p>}

      {/* Threat Summary Cards */}
      {!loading && !error && rawData && rawData.threat_summary && (
        <div style={{ marginTop: '20px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap' }}>
                <div className="threat-card critical">
                    <h4>Critical Threats</h4>
                    <div className="threat-number">{rawData.threat_summary.alert_breakdown?.CRITICAL || 0}</div>
                </div>
                <div className="threat-card high">
                    <h4>High Threats</h4>
                    <div className="threat-number">{rawData.threat_summary.alert_breakdown?.HIGH || 0}</div>
                </div>
                <div className="threat-card medium">
                    <h4>Medium Threats</h4>
                    <div className="threat-number">{rawData.threat_summary.alert_breakdown?.MEDIUM || 0}</div>
                </div>
                <div className="threat-card low">
                    <h4>Network Events</h4>
                    <div className="threat-number">{rawData.threat_summary.total_network_events || 0}</div>
                </div>
            </div>
        </div>
      )}

      {/* Chart Component Area */}
      <div style={{ marginTop: '20px' }}>
        {!loading && !error && !chartData && (
             <p>No threat visualization data available for the selected time range/severity.</p>
        )}
        {!loading && !error && chartData && (
            <div style={{ height: '400px', position: 'relative' }}>
                 <Line options={{ 
                    responsive: true, 
                    maintainAspectRatio: false,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Security Threat Timeline'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Threat Score'
                            }
                        }
                    }
                 }} data={chartData} />
            </div>
         )}
      </div>

      {/* Recent Threats List */}
      {!loading && !error && rawData && rawData.security_alerts && (
        <div style={{ marginTop: '30px' }}>
            <h3>Recent Security Alerts</h3>
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
                {rawData.security_alerts.map((alert, index) => (
                    <div key={index} className={`threat-entry ${alert.severity.toLowerCase()}`} style={{ 
                        margin: '10px 0', 
                        padding: '10px', 
                        border: '1px solid #ddd', 
                        borderRadius: '5px',
                        borderLeft: `4px solid ${alert.severity === 'CRITICAL' ? 'red' : 
                                                  alert.severity === 'HIGH' ? 'orange' : 
                                                  alert.severity === 'MEDIUM' ? 'yellow' : 'green'}`
                    }}>
                        <div><strong>Severity:</strong> {alert.severity}</div>
                        <div><strong>Time:</strong> {new Date(alert.timestamp).toLocaleString()}</div>
                        <div><strong>Source IP:</strong> {alert.source_ip || 'Unknown'}</div>
                        <div><strong>Alert:</strong> {alert.description}</div>
                        <div><strong>Threat Score:</strong> {alert.threat_score}/10</div>
                        {alert.ml_confidence && <div><strong>ML Confidence:</strong> {(alert.ml_confidence * 100).toFixed(1)}%</div>}
                    </div>
                ))}
            </div>
        </div>
      )}
    </div>
  );
}

export default VisualizerView;