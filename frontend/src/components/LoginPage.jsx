// frontend/src/components/LoginPage.jsx
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(username, password);
    
    if (!result.success) {
      setError(result.error || 'Login failed. Please try again.');
    }
    
    setIsLoading(false);
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-header">
          <div className="login-logo">🛡️</div>
          <h1>Intrusion Detection System</h1>
          <p className="login-subtitle">ML-Powered Network Security</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          {error && (
            <div className="login-error">
              <span>⚠️</span> {error}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
              required
              disabled={isLoading}
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
              required
              disabled={isLoading}
              autoComplete="current-password"
            />
          </div>

          <button 
            type="submit" 
            className="login-button"
            disabled={isLoading || !username || !password}
          >
            {isLoading ? (
              <>
                <span className="spinner"></span>
                Authenticating...
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="login-footer">
          <div className="login-info">
            <p>🔐 Secure Authentication Required</p>
            <p className="default-creds">
              Default: <code>admin</code> / <code>admin123</code>
            </p>
          </div>
          <div className="login-features">
            <span>📊 Real-Time Monitoring</span>
            <span>🔍 ML Threat Detection</span>
            <span>🛡️ IP Quarantine</span>
          </div>
        </div>
      </div>

      <style>{`
        .login-page {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: linear-gradient(135deg, #0a0a1a 0%, #1a1a2e 50%, #16213e 100%);
          padding: 20px;
        }

        .login-container {
          background: rgba(30, 30, 46, 0.95);
          border-radius: 20px;
          padding: 40px;
          width: 100%;
          max-width: 420px;
          box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5),
                      0 0 100px rgba(0, 188, 212, 0.1);
          border: 1px solid rgba(0, 188, 212, 0.2);
        }

        .login-header {
          text-align: center;
          margin-bottom: 30px;
        }

        .login-logo {
          font-size: 4rem;
          margin-bottom: 15px;
          filter: drop-shadow(0 0 20px rgba(0, 188, 212, 0.5));
        }

        .login-header h1 {
          color: #fff;
          font-size: 1.5rem;
          margin: 0;
          font-weight: 600;
        }

        .login-subtitle {
          color: #00bcd4;
          font-size: 0.9rem;
          margin-top: 5px;
        }

        .login-form {
          display: flex;
          flex-direction: column;
          gap: 20px;
        }

        .login-error {
          background: rgba(255, 68, 68, 0.1);
          border: 1px solid #ff4444;
          border-radius: 10px;
          padding: 12px 15px;
          color: #ff4444;
          font-size: 0.9rem;
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .form-group label {
          color: #aaa;
          font-size: 0.9rem;
          font-weight: 500;
        }

        .form-group input {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 10px;
          padding: 14px 16px;
          font-size: 1rem;
          color: #fff;
          transition: all 0.3s ease;
        }

        .form-group input:focus {
          outline: none;
          border-color: #00bcd4;
          background: rgba(0, 188, 212, 0.05);
          box-shadow: 0 0 20px rgba(0, 188, 212, 0.2);
        }

        .form-group input::placeholder {
          color: #555;
        }

        .form-group input:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .login-button {
          background: linear-gradient(135deg, #00bcd4, #0097a7);
          border: none;
          border-radius: 10px;
          padding: 14px 20px;
          font-size: 1rem;
          font-weight: 600;
          color: #fff;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 10px;
          margin-top: 10px;
        }

        .login-button:hover:not(:disabled) {
          transform: translateY(-2px);
          box-shadow: 0 10px 30px rgba(0, 188, 212, 0.4);
        }

        .login-button:disabled {
          opacity: 0.6;
          cursor: not-allowed;
          transform: none;
        }

        .spinner {
          width: 20px;
          height: 20px;
          border: 2px solid rgba(255, 255, 255, 0.3);
          border-top-color: #fff;
          border-radius: 50%;
          animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .login-footer {
          margin-top: 30px;
          text-align: center;
        }

        .login-info {
          color: #666;
          font-size: 0.85rem;
          margin-bottom: 20px;
        }

        .login-info p {
          margin: 5px 0;
        }

        .default-creds {
          color: #888;
        }

        .default-creds code {
          background: rgba(0, 188, 212, 0.1);
          color: #00bcd4;
          padding: 2px 8px;
          border-radius: 4px;
          font-family: 'Fira Code', monospace;
        }

        .login-features {
          display: flex;
          justify-content: center;
          gap: 15px;
          flex-wrap: wrap;
          padding-top: 15px;
          border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .login-features span {
          color: #555;
          font-size: 0.8rem;
        }

        @media (max-width: 480px) {
          .login-container {
            padding: 30px 20px;
          }

          .login-logo {
            font-size: 3rem;
          }

          .login-header h1 {
            font-size: 1.3rem;
          }

          .login-features {
            flex-direction: column;
            gap: 8px;
          }
        }
      `}</style>
    </div>
  );
}

export default LoginPage;
