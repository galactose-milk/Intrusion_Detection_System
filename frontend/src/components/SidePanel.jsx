// frontend/src/components/SidePanel.jsx
import React from 'react';

// Destructure props for easier access
function SidePanel({ onViewChange, currentView }) {

  const handleNavClick = (viewName) => {
    onViewChange(viewName); // Call the function passed from App.jsx
  };

  return (
    <aside className="side-panel">
      <h2>🛡️ IDS Dashboard</h2>
      <div className="mode-badge">🔴 LIVE MONITORING</div>
      <nav>
        <ul>
          {/* Add 'active' class based on currentView prop */}
          <li
            className={currentView === 'setup' ? 'active' : ''}
            onClick={() => handleNavClick('setup')}
          >
            📡 Network Setup
          </li>
          <li
            className={currentView === 'monitor' ? 'active' : ''}
            onClick={() => handleNavClick('monitor')}
          >
            📊 Real-Time Monitor
          </li>
          <li
            className={currentView === 'visualizer' ? 'active' : ''}
            onClick={() => handleNavClick('visualizer')}
          >
            🔍 Threat Analysis
          </li>
          <li
            className={currentView === 'alerts' ? 'active' : ''}
            onClick={() => handleNavClick('alerts')}
          >
            🚨 Security Alerts
          </li>
          <li
            className={currentView === 'threats' ? 'active' : ''}
            onClick={() => handleNavClick('threats')}
          >
            ⚡ Threat Testing
          </li>
          <li
            className={currentView === 'system' ? 'active' : ''}
            onClick={() => handleNavClick('system')}
          >
            ⚙️ System Status
          </li>
        </ul>
      </nav>
      <div className="panel-footer">
        <p>Intrusion Detection System</p>
        <small>ML-Powered • Real Traffic Only</small>
      </div>
      <style>{`
        .mode-badge {
          background: linear-gradient(135deg, #ff4444, #cc0000);
          color: white;
          padding: 8px 15px;
          border-radius: 20px;
          font-size: 0.8em;
          font-weight: bold;
          text-align: center;
          margin: 10px 15px;
          animation: pulse 2s infinite;
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.7; }
        }
      `}</style>
    </aside>
  );
}

export default SidePanel;