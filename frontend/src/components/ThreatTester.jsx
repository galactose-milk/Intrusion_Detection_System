import React, { useState, useEffect, useCallback } from 'react';

const ThreatTester = () => {
  // State for threat generation
  const [threatType, setThreatType] = useState('cpu_miner');
  const [intensity, setIntensity] = useState('medium');
  const [duration, setDuration] = useState(30);
  const [isGenerating, setIsGenerating] = useState(false);
  const [activeThreats, setActiveThreats] = useState([]);
  
  // State for quarantine
  const [suspiciousProcesses, setSuspiciousProcesses] = useState([]);
  const [quarantineHistory, setQuarantineHistory] = useState([]);
  const [systemResources, setSystemResources] = useState(null);
  
  // State for UI
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(null);
  const [activeTab, setActiveTab] = useState('generate');

  const API_BASE = 'http://localhost:8000/api';

  // Fetch active threats
  const fetchActiveThreats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/threats/active`);
      if (response.ok) {
        const data = await response.json();
        setActiveThreats(data.threats || []);
      }
    } catch (error) {
      console.error('Error fetching active threats:', error);
    }
  }, []);

  // Fetch suspicious processes
  const fetchSuspiciousProcesses = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/quarantine/detect`);
      if (response.ok) {
        const data = await response.json();
        setSuspiciousProcesses(data.processes || []);
      }
    } catch (error) {
      console.error('Error fetching suspicious processes:', error);
    }
  }, []);

  // Fetch system resources
  const fetchSystemResources = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/system/resources`);
      if (response.ok) {
        const data = await response.json();
        setSystemResources(data);
      }
    } catch (error) {
      console.error('Error fetching system resources:', error);
    }
  }, []);

  // Fetch quarantine history
  const fetchQuarantineHistory = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/quarantine/history`);
      if (response.ok) {
        const data = await response.json();
        setQuarantineHistory(data.history || []);
      }
    } catch (error) {
      console.error('Error fetching quarantine history:', error);
    }
  }, []);

  // Auto-refresh data
  useEffect(() => {
    fetchActiveThreats();
    fetchSuspiciousProcesses();
    fetchSystemResources();
    fetchQuarantineHistory();

    const interval = setInterval(() => {
      fetchActiveThreats();
      fetchSuspiciousProcesses();
      fetchSystemResources();
    }, 3000);

    return () => clearInterval(interval);
  }, [fetchActiveThreats, fetchSuspiciousProcesses, fetchSystemResources, fetchQuarantineHistory]);

  // Generate threat
  const generateThreat = async () => {
    setIsGenerating(true);
    setMessage(null);
    
    try {
      const response = await fetch(`${API_BASE}/threats/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threat_type: threatType,
          intensity: intensity,
          duration: duration
        })
      });

      const data = await response.json();
      
      if (response.ok) {
        setMessage({ type: 'success', text: `Threat started: ${threatType} (ID: ${data.process?.threat_id})` });
        fetchActiveThreats();
      } else {
        setMessage({ type: 'error', text: data.detail || 'Failed to generate threat' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: `Error: ${error.message}` });
    } finally {
      setIsGenerating(false);
    }
  };

  // Stop a specific threat
  const stopThreat = async (threatId) => {
    try {
      const response = await fetch(`${API_BASE}/threats/stop/${threatId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setMessage({ type: 'success', text: `Threat ${threatId} stopped` });
        fetchActiveThreats();
      }
    } catch (error) {
      setMessage({ type: 'error', text: `Error stopping threat: ${error.message}` });
    }
  };

  // Stop all threats
  const stopAllThreats = async () => {
    try {
      const response = await fetch(`${API_BASE}/threats/stop-all`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setMessage({ type: 'success', text: 'All threats stopped' });
        fetchActiveThreats();
      }
    } catch (error) {
      setMessage({ type: 'error', text: `Error: ${error.message}` });
    }
  };

  // Quarantine/Kill a process
  const handleProcessAction = async (pid, action) => {
    try {
      const response = await fetch(`${API_BASE}/quarantine/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid, action })
      });

      const data = await response.json();
      
      if (data.status === 'success') {
        setMessage({ type: 'success', text: `Process ${pid} ${action}ed successfully` });
        fetchSuspiciousProcesses();
        fetchQuarantineHistory();
        fetchActiveThreats();
      } else {
        setMessage({ type: 'error', text: data.result?.error || 'Action failed' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: `Error: ${error.message}` });
    }
  };

  const threatTypes = [
    { value: 'cpu_miner', label: 'CPU Miner', desc: 'High CPU consumption' },
    { value: 'memory_hog', label: 'Memory Hog', desc: 'High RAM consumption' },
    { value: 'disk_abuse', label: 'Disk Abuse', desc: 'Heavy disk I/O' },
    { value: 'network_flood', label: 'Network Flood', desc: 'Network packet flood' },
    { value: 'crypto_miner', label: 'Crypto Miner', desc: 'Simulated mining' },
    { value: 'data_exfil', label: 'Data Exfiltration', desc: 'Suspicious data access' }
  ];

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>🛡️ Threat Testing & Quarantine</h2>
      <p style={styles.subtitle}>
        Generate REAL threat processes to test IDS detection and quarantine capabilities
      </p>

      {/* Message Display */}
      {message && (
        <div style={{
          ...styles.message,
          backgroundColor: message.type === 'success' ? '#10b981' : '#ef4444'
        }}>
          {message.text}
        </div>
      )}

      {/* System Resources Overview */}
      {systemResources && (
        <div style={styles.resourcesCard}>
          <h3 style={styles.cardTitle}>📊 System Resources</h3>
          <div style={styles.resourcesGrid}>
            <div style={styles.resourceItem}>
              <span style={styles.resourceLabel}>CPU</span>
              <div style={styles.progressBar}>
                <div style={{
                  ...styles.progressFill,
                  width: `${systemResources.cpu?.total_percent || 0}%`,
                  backgroundColor: (systemResources.cpu?.total_percent || 0) > 80 ? '#ef4444' : '#10b981'
                }} />
              </div>
              <span style={styles.resourceValue}>{systemResources.cpu?.total_percent?.toFixed(1)}%</span>
            </div>
            <div style={styles.resourceItem}>
              <span style={styles.resourceLabel}>Memory</span>
              <div style={styles.progressBar}>
                <div style={{
                  ...styles.progressFill,
                  width: `${systemResources.memory?.percent || 0}%`,
                  backgroundColor: (systemResources.memory?.percent || 0) > 80 ? '#ef4444' : '#10b981'
                }} />
              </div>
              <span style={styles.resourceValue}>{systemResources.memory?.percent?.toFixed(1)}%</span>
            </div>
            <div style={styles.resourceItem}>
              <span style={styles.resourceLabel}>Active Test Threats</span>
              <span style={{
                ...styles.resourceValue,
                color: systemResources.test_threats_active > 0 ? '#f59e0b' : '#6b7280'
              }}>
                {systemResources.test_threats_active || 0}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div style={styles.tabs}>
        <button
          style={{ ...styles.tab, ...(activeTab === 'generate' ? styles.activeTab : {}) }}
          onClick={() => setActiveTab('generate')}
        >
          🚀 Generate Threat
        </button>
        <button
          style={{ ...styles.tab, ...(activeTab === 'active' ? styles.activeTab : {}) }}
          onClick={() => setActiveTab('active')}
        >
          ⚡ Active Threats ({activeThreats.length})
        </button>
        <button
          style={{ ...styles.tab, ...(activeTab === 'quarantine' ? styles.activeTab : {}) }}
          onClick={() => setActiveTab('quarantine')}
        >
          🔒 Quarantine ({suspiciousProcesses.length})
        </button>
        <button
          style={{ ...styles.tab, ...(activeTab === 'history' ? styles.activeTab : {}) }}
          onClick={() => setActiveTab('history')}
        >
          📜 History
        </button>
      </div>

      {/* Tab Content */}
      <div style={styles.tabContent}>
        {/* Generate Threat Tab */}
        {activeTab === 'generate' && (
          <div style={styles.generateSection}>
            <div style={styles.formGroup}>
              <label style={styles.label}>Threat Type</label>
              <div style={styles.threatTypeGrid}>
                {threatTypes.map(type => (
                  <div
                    key={type.value}
                    style={{
                      ...styles.threatTypeCard,
                      ...(threatType === type.value ? styles.threatTypeCardSelected : {})
                    }}
                    onClick={() => setThreatType(type.value)}
                  >
                    <strong>{type.label}</strong>
                    <small style={styles.threatDesc}>{type.desc}</small>
                  </div>
                ))}
              </div>
            </div>

            <div style={styles.formRow}>
              <div style={styles.formGroup}>
                <label style={styles.label}>Intensity</label>
                <select
                  style={styles.select}
                  value={intensity}
                  onChange={(e) => setIntensity(e.target.value)}
                >
                  <option value="low">Low (20% target)</option>
                  <option value="medium">Medium (50% target)</option>
                  <option value="high">High (80% target)</option>
                </select>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.label}>Duration (seconds)</label>
                <input
                  type="number"
                  style={styles.input}
                  value={duration}
                  onChange={(e) => setDuration(Math.min(300, Math.max(5, parseInt(e.target.value) || 30)))}
                  min={5}
                  max={300}
                />
              </div>
            </div>

            <button
              style={{
                ...styles.generateButton,
                opacity: isGenerating ? 0.6 : 1
              }}
              onClick={generateThreat}
              disabled={isGenerating}
            >
              {isGenerating ? '⏳ Starting...' : '🚀 Generate Threat'}
            </button>

            <div style={styles.warningBox}>
              <strong>⚠️ Warning:</strong> This will create REAL processes that consume system resources.
              The IDS should detect these as suspicious activities. Use responsibly.
            </div>
          </div>
        )}

        {/* Active Threats Tab */}
        {activeTab === 'active' && (
          <div style={styles.activeSection}>
            {activeThreats.length > 0 && (
              <button style={styles.stopAllButton} onClick={stopAllThreats}>
                🛑 Stop All Threats
              </button>
            )}

            {activeThreats.length === 0 ? (
              <div style={styles.emptyState}>
                <span style={styles.emptyIcon}>✅</span>
                <p>No active test threats running</p>
              </div>
            ) : (
              <div style={styles.threatList}>
                {activeThreats.map(threat => (
                  <div key={threat.threat_id} style={styles.threatItem}>
                    <div style={styles.threatInfo}>
                      <span style={styles.threatPid}>ID: {threat.threat_id}</span>
                      <span style={styles.threatType}>{threat.threat_type}</span>
                      <span style={styles.threatIntensity}>{threat.intensity}</span>
                      <span style={{
                        ...styles.threatStatus,
                        color: threat.is_active ? '#10b981' : '#ef4444'
                      }}>
                        {threat.is_active ? '🟢 Running' : '🔴 Stopped'}
                      </span>
                    </div>
                    <button
                      style={styles.stopButton}
                      onClick={() => stopThreat(threat.threat_id)}
                    >
                      🛑 Stop
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Quarantine Tab */}
        {activeTab === 'quarantine' && (
          <div style={styles.quarantineSection}>
            <button
              style={styles.refreshButton}
              onClick={() => {
                fetchSuspiciousProcesses();
                fetchSystemResources();
              }}
            >
              🔄 Refresh Detection
            </button>

            {suspiciousProcesses.length === 0 ? (
              <div style={styles.emptyState}>
                <span style={styles.emptyIcon}>🛡️</span>
                <p>No suspicious processes detected</p>
                <small style={styles.emptyHint}>
                  Generate a threat to test detection capabilities
                </small>
              </div>
            ) : (
              <div style={styles.processList}>
                {suspiciousProcesses.map(proc => (
                  <div key={proc.pid} style={styles.processItem}>
                    <div style={styles.processInfo}>
                      <div style={styles.processHeader}>
                        <span style={styles.processPid}>PID: {proc.pid}</span>
                        <span style={styles.processName}>{proc.name}</span>
                        <span style={{
                          ...styles.threatLevel,
                          backgroundColor: proc.threat_level === 'CRITICAL' ? '#ef4444' :
                            proc.threat_level === 'HIGH' ? '#f59e0b' : '#3b82f6'
                        }}>
                          {proc.threat_level}
                        </span>
                      </div>
                      <div style={styles.processDetails}>
                        <span>CPU: {proc.cpu_percent?.toFixed(1)}%</span>
                        <span>RAM: {proc.memory_percent?.toFixed(1)}%</span>
                      </div>
                      <div style={styles.reasons}>
                        {proc.reasons?.map((reason, idx) => (
                          <span key={idx} style={styles.reasonTag}>{reason}</span>
                        ))}
                      </div>
                    </div>
                    <div style={styles.processActions}>
                      <button
                        style={styles.quarantineButton}
                        onClick={() => handleProcessAction(proc.pid, 'quarantine')}
                      >
                        🔒 Quarantine
                      </button>
                      <button
                        style={styles.killButton}
                        onClick={() => handleProcessAction(proc.pid, 'kill')}
                      >
                        ❌ Kill
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div style={styles.historySection}>
            {quarantineHistory.length === 0 ? (
              <div style={styles.emptyState}>
                <span style={styles.emptyIcon}>📜</span>
                <p>No quarantine actions recorded yet</p>
              </div>
            ) : (
              <div style={styles.historyList}>
                {quarantineHistory.map((entry, idx) => (
                  <div key={idx} style={styles.historyItem}>
                    <span style={{
                      ...styles.historyType,
                      backgroundColor: entry.type === 'killed' ? '#ef4444' : '#f59e0b'
                    }}>
                      {entry.type === 'killed' ? '❌ Killed' : '🔒 Quarantined'}
                    </span>
                    <span style={styles.historyPid}>PID: {entry.pid}</span>
                    <span style={styles.historyName}>{entry.name}</span>
                    <span style={styles.historyTime}>
                      {new Date(entry.action_time).toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

const styles = {
  container: {
    padding: '24px',
    maxWidth: '1200px',
    margin: '0 auto',
    color: '#e5e7eb'
  },
  title: {
    fontSize: '24px',
    fontWeight: 'bold',
    marginBottom: '8px',
    color: '#fff'
  },
  subtitle: {
    color: '#9ca3af',
    marginBottom: '24px'
  },
  message: {
    padding: '12px 16px',
    borderRadius: '8px',
    marginBottom: '16px',
    color: '#fff',
    fontWeight: '500'
  },
  resourcesCard: {
    backgroundColor: '#1f2937',
    borderRadius: '12px',
    padding: '20px',
    marginBottom: '24px',
    border: '1px solid #374151'
  },
  cardTitle: {
    fontSize: '16px',
    fontWeight: '600',
    marginBottom: '16px',
    color: '#fff'
  },
  resourcesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '20px'
  },
  resourceItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  resourceLabel: {
    fontSize: '12px',
    color: '#9ca3af',
    textTransform: 'uppercase'
  },
  resourceValue: {
    fontSize: '18px',
    fontWeight: '600'
  },
  progressBar: {
    height: '8px',
    backgroundColor: '#374151',
    borderRadius: '4px',
    overflow: 'hidden'
  },
  progressFill: {
    height: '100%',
    transition: 'width 0.3s ease'
  },
  tabs: {
    display: 'flex',
    gap: '8px',
    marginBottom: '20px',
    borderBottom: '1px solid #374151',
    paddingBottom: '12px'
  },
  tab: {
    padding: '10px 16px',
    backgroundColor: 'transparent',
    border: 'none',
    color: '#9ca3af',
    cursor: 'pointer',
    borderRadius: '8px',
    fontSize: '14px',
    transition: 'all 0.2s'
  },
  activeTab: {
    backgroundColor: '#3b82f6',
    color: '#fff'
  },
  tabContent: {
    backgroundColor: '#1f2937',
    borderRadius: '12px',
    padding: '24px',
    minHeight: '400px',
    border: '1px solid #374151'
  },
  generateSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px'
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  formRow: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '20px'
  },
  label: {
    fontSize: '14px',
    fontWeight: '500',
    color: '#d1d5db'
  },
  threatTypeGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '12px'
  },
  threatTypeCard: {
    padding: '16px',
    backgroundColor: '#374151',
    borderRadius: '8px',
    cursor: 'pointer',
    border: '2px solid transparent',
    transition: 'all 0.2s',
    display: 'flex',
    flexDirection: 'column',
    gap: '4px'
  },
  threatTypeCardSelected: {
    borderColor: '#3b82f6',
    backgroundColor: '#1e3a5f'
  },
  threatDesc: {
    fontSize: '12px',
    color: '#9ca3af'
  },
  select: {
    padding: '12px',
    backgroundColor: '#374151',
    border: '1px solid #4b5563',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '14px'
  },
  input: {
    padding: '12px',
    backgroundColor: '#374151',
    border: '1px solid #4b5563',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '14px'
  },
  generateButton: {
    padding: '16px 24px',
    backgroundColor: '#ef4444',
    border: 'none',
    borderRadius: '8px',
    color: '#fff',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.2s'
  },
  warningBox: {
    padding: '16px',
    backgroundColor: '#451a03',
    border: '1px solid #f59e0b',
    borderRadius: '8px',
    color: '#fbbf24',
    fontSize: '14px'
  },
  activeSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  stopAllButton: {
    padding: '12px 20px',
    backgroundColor: '#dc2626',
    border: 'none',
    borderRadius: '8px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
    alignSelf: 'flex-end'
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '60px',
    color: '#6b7280'
  },
  emptyIcon: {
    fontSize: '48px',
    marginBottom: '16px'
  },
  emptyHint: {
    marginTop: '8px',
    color: '#4b5563'
  },
  threatList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  threatItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px',
    backgroundColor: '#374151',
    borderRadius: '8px',
    border: '1px solid #4b5563'
  },
  threatInfo: {
    display: 'flex',
    gap: '16px',
    alignItems: 'center'
  },
  threatPid: {
    fontWeight: '600',
    color: '#fff'
  },
  threatType: {
    padding: '4px 8px',
    backgroundColor: '#1e3a5f',
    borderRadius: '4px',
    fontSize: '12px'
  },
  threatIntensity: {
    color: '#9ca3af',
    fontSize: '12px'
  },
  threatStatus: {
    fontSize: '12px'
  },
  stopButton: {
    padding: '8px 16px',
    backgroundColor: '#dc2626',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '12px'
  },
  quarantineSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px'
  },
  refreshButton: {
    padding: '10px 16px',
    backgroundColor: '#3b82f6',
    border: 'none',
    borderRadius: '8px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    alignSelf: 'flex-end'
  },
  processList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  processItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '16px',
    backgroundColor: '#374151',
    borderRadius: '8px',
    border: '1px solid #ef4444'
  },
  processInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  processHeader: {
    display: 'flex',
    gap: '12px',
    alignItems: 'center'
  },
  processPid: {
    fontWeight: '600',
    color: '#fff'
  },
  processName: {
    color: '#d1d5db'
  },
  threatLevel: {
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: '600',
    color: '#fff'
  },
  processDetails: {
    display: 'flex',
    gap: '16px',
    fontSize: '13px',
    color: '#9ca3af'
  },
  reasons: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap'
  },
  reasonTag: {
    padding: '2px 8px',
    backgroundColor: '#451a03',
    borderRadius: '4px',
    fontSize: '11px',
    color: '#fbbf24'
  },
  processActions: {
    display: 'flex',
    gap: '8px'
  },
  quarantineButton: {
    padding: '8px 12px',
    backgroundColor: '#f59e0b',
    border: 'none',
    borderRadius: '6px',
    color: '#000',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: '500'
  },
  killButton: {
    padding: '8px 12px',
    backgroundColor: '#dc2626',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: '500'
  },
  historySection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  historyList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  historyItem: {
    display: 'flex',
    gap: '16px',
    alignItems: 'center',
    padding: '12px 16px',
    backgroundColor: '#374151',
    borderRadius: '8px'
  },
  historyType: {
    padding: '4px 8px',
    borderRadius: '4px',
    fontSize: '12px',
    color: '#fff',
    fontWeight: '500'
  },
  historyPid: {
    fontWeight: '600',
    color: '#fff'
  },
  historyName: {
    color: '#d1d5db',
    flex: 1
  },
  historyTime: {
    fontSize: '12px',
    color: '#6b7280'
  }
};

export default ThreatTester;
