// frontend/src/components/SidePanel.jsx
import React from 'react';

// Destructure props for easier access
function SidePanel({ onViewChange, currentView, user, onLogout }) {

  const handleNavClick = (viewName) => {
    onViewChange(viewName); // Call the function passed from App.jsx
  };

  const handleLogout = () => {
    if (window.confirm('Are you sure you want to logout?')) {
      onLogout();
    }
  };

  return (
    <aside className="side-panel">
      <h2>🛡️ IDS Dashboard</h2>
      <div className="mode-badge">🔴 LIVE MONITORING</div>
      
      {/* User Info */}
      {user && (
        <div className="user-info">
          <div className="user-avatar">
            {user.username.charAt(0).toUpperCase()}
          </div>
          <div className="user-details">
            <span className="user-name">{user.username}</span>
            <span className="user-role">{user.role}</span>
          </div>
        </div>
      )}
      
      <nav>
        <ul>
          {/* Add 'active' class based on currentView prop */}
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
            className={currentView === 'loginsecurity' ? 'active' : ''}
            onClick={() => handleNavClick('loginsecurity')}
          >
            🔐 Login Security
          </li>
          <li
            className={currentView === 'ipquarantine' ? 'active' : ''}
            onClick={() => handleNavClick('ipquarantine')}
          >
            🛡️ IP Quarantine
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
          
          {/* Admin-only: User Management */}
          {user?.role === 'admin' && (
            <li
              className={currentView === 'users' ? 'active' : ''}
              onClick={() => handleNavClick('users')}
            >
              👥 User Management
            </li>
          )}
        </ul>
      </nav>
      
      {/* Logout Button */}
      <button className="logout-btn" onClick={handleLogout}>
        🚪 Logout
      </button>
      
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
        
        .user-info {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 15px;
          margin: 10px 15px;
          background: rgba(0, 188, 212, 0.1);
          border-radius: 10px;
          border: 1px solid rgba(0, 188, 212, 0.2);
        }
        
        .user-avatar {
          width: 40px;
          height: 40px;
          background: linear-gradient(135deg, #00bcd4, #0097a7);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: bold;
          font-size: 1.2rem;
          color: white;
        }
        
        .user-details {
          display: flex;
          flex-direction: column;
        }
        
        .user-name {
          color: #fff;
          font-weight: 600;
          font-size: 0.95rem;
        }
        
        .user-role {
          color: #00bcd4;
          font-size: 0.75rem;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        
        .logout-btn {
          display: block;
          width: calc(100% - 30px);
          margin: 15px;
          padding: 12px;
          background: rgba(255, 68, 68, 0.1);
          border: 1px solid rgba(255, 68, 68, 0.3);
          border-radius: 8px;
          color: #ff4444;
          font-size: 0.9rem;
          cursor: pointer;
          transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
          background: rgba(255, 68, 68, 0.2);
          border-color: #ff4444;
        }
      `}</style>
    </aside>
  );
}

export default SidePanel;