// frontend/src/App.jsx
import React, { useState } from 'react';
import './App.css'; // Import specific styles for the App layout
import SidePanel from './components/SidePanel';
import MainScreen from './components/MainScreen';
import LoginPage from './components/LoginPage';
import { AuthProvider, useAuth } from './context/AuthContext';

// Main dashboard component (shown when authenticated)
function Dashboard() {
  // State to track the currently selected view
  const [currentView, setCurrentView] = useState('monitor'); // Default view
  const { user, logout } = useAuth();

  return (
    <div className="App">
      <SidePanel 
        onViewChange={setCurrentView} 
        currentView={currentView}
        user={user}
        onLogout={logout}
      />
      <MainScreen activeView={currentView} />
    </div>
  );
}

// App content - decides whether to show login or dashboard
function AppContent() {
  const { isAuthenticated, loading } = useAuth();

  // Show loading state while checking auth
  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-content">
          <div className="loading-logo">🛡️</div>
          <div className="loading-spinner"></div>
          <p>Initializing IDS...</p>
        </div>
        <style>{`
          .loading-screen {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 50%, #16213e 100%);
          }
          .loading-content {
            text-align: center;
            color: #fff;
          }
          .loading-logo {
            font-size: 4rem;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
          }
          .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(0, 188, 212, 0.2);
            border-top-color: #00bcd4;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
          @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.05); }
          }
        `}</style>
      </div>
    );
  }

  // Show login if not authenticated
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  // Show dashboard if authenticated
  return <Dashboard />;
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;