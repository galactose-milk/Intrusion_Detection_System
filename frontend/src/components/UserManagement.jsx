// frontend/src/components/UserManagement.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'viewer' });
  const [creating, setCreating] = useState(false);
  
  const { getAuthHeader, user: currentUser } = useAuth();

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/users`, {
        headers: getAuthHeader()
      });
      
      if (!response.ok) throw new Error('Failed to fetch users');
      
      const data = await response.json();
      setUsers(data.users || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setCreating(true);
    setError(null);

    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeader()
        },
        body: JSON.stringify(newUser)
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to create user');
      }

      setNewUser({ username: '', password: '', role: 'viewer' });
      setShowCreateForm(false);
      fetchUsers();
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`Are you sure you want to delete user "${username}"?`)) return;

    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/users/${username}`, {
        method: 'DELETE',
        headers: getAuthHeader()
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || 'Failed to delete user');
      }

      fetchUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (username, isActive) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/users/${username}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeader()
        },
        body: JSON.stringify({ is_active: !isActive })
      });

      if (!response.ok) throw new Error('Failed to update user');
      fetchUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) {
    return <div className="loading">Loading users...</div>;
  }

  return (
    <div className="user-management">
      <div className="header-row">
        <h3>👥 User Management</h3>
        <button 
          className="btn-primary"
          onClick={() => setShowCreateForm(!showCreateForm)}
        >
          {showCreateForm ? '✕ Cancel' : '+ Add User'}
        </button>
      </div>

      {error && (
        <div className="error-message">
          ⚠️ {error}
          <button onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {showCreateForm && (
        <form className="create-form" onSubmit={handleCreateUser}>
          <h4>Create New User</h4>
          <div className="form-row">
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                placeholder="Enter username"
                required
                minLength={3}
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                placeholder="Enter password"
                required
                minLength={6}
              />
            </div>
            <div className="form-group">
              <label>Role</label>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
              >
                <option value="viewer">Viewer (Read-only)</option>
                <option value="operator">Operator</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <button type="submit" className="btn-create" disabled={creating}>
            {creating ? 'Creating...' : 'Create User'}
          </button>
        </form>
      )}

      <div className="users-table">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} className={!user.is_active ? 'inactive' : ''}>
                <td>
                  <div className="user-cell">
                    <span className="user-avatar">
                      {user.username.charAt(0).toUpperCase()}
                    </span>
                    {user.username}
                    {user.username === currentUser?.username && (
                      <span className="you-badge">You</span>
                    )}
                  </div>
                </td>
                <td>
                  <span className={`role-badge role-${user.role}`}>
                    {user.role}
                  </span>
                </td>
                <td>
                  <span className={`status-badge ${user.is_active ? 'active' : 'inactive'}`}>
                    {user.is_active ? '✅ Active' : '❌ Inactive'}
                  </span>
                </td>
                <td>{new Date(user.created_at).toLocaleDateString()}</td>
                <td>
                  {user.last_login 
                    ? new Date(user.last_login).toLocaleString() 
                    : 'Never'
                  }
                </td>
                <td>
                  <div className="action-buttons">
                    {user.username !== currentUser?.username && (
                      <>
                        <button
                          className="btn-action"
                          onClick={() => handleToggleActive(user.username, user.is_active)}
                          title={user.is_active ? 'Deactivate' : 'Activate'}
                        >
                          {user.is_active ? '🔒' : '🔓'}
                        </button>
                        <button
                          className="btn-action btn-delete"
                          onClick={() => handleDeleteUser(user.username)}
                          title="Delete user"
                        >
                          🗑️
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="role-info">
        <h4>Role Permissions</h4>
        <div className="role-grid">
          <div className="role-card">
            <span className="role-badge role-viewer">viewer</span>
            <p>Read-only access to dashboards and reports</p>
          </div>
          <div className="role-card">
            <span className="role-badge role-operator">operator</span>
            <p>Can view and respond to threats, manage quarantine</p>
          </div>
          <div className="role-card">
            <span className="role-badge role-admin">admin</span>
            <p>Full access including user management</p>
          </div>
        </div>
      </div>

      <style>{`
        .user-management {
          padding: 20px;
        }

        .header-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 20px;
        }

        .btn-primary {
          background: linear-gradient(135deg, #00bcd4, #0097a7);
          border: none;
          padding: 10px 20px;
          border-radius: 8px;
          color: white;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .btn-primary:hover {
          transform: translateY(-2px);
          box-shadow: 0 5px 20px rgba(0, 188, 212, 0.4);
        }

        .error-message {
          background: rgba(255, 68, 68, 0.1);
          border: 1px solid #ff4444;
          border-radius: 8px;
          padding: 12px 15px;
          color: #ff4444;
          margin-bottom: 20px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .error-message button {
          background: none;
          border: none;
          color: #ff4444;
          cursor: pointer;
          font-size: 1.2rem;
        }

        .create-form {
          background: #1e1e2e;
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 20px;
          border: 1px solid rgba(0, 188, 212, 0.3);
        }

        .create-form h4 {
          margin-bottom: 15px;
          color: #00bcd4;
        }

        .form-row {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px;
          margin-bottom: 15px;
        }

        .form-group {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }

        .form-group label {
          color: #aaa;
          font-size: 0.85rem;
        }

        .form-group input,
        .form-group select {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 6px;
          padding: 10px;
          color: #fff;
          font-size: 0.95rem;
        }

        .form-group input:focus,
        .form-group select:focus {
          outline: none;
          border-color: #00bcd4;
        }

        .btn-create {
          background: #00c853;
          border: none;
          padding: 10px 25px;
          border-radius: 6px;
          color: white;
          font-weight: 600;
          cursor: pointer;
        }

        .btn-create:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .users-table {
          background: #1e1e2e;
          border-radius: 12px;
          overflow: hidden;
          margin-bottom: 30px;
        }

        table {
          width: 100%;
          border-collapse: collapse;
        }

        th, td {
          padding: 15px;
          text-align: left;
          border-bottom: 1px solid #333;
        }

        th {
          background: rgba(0, 188, 212, 0.1);
          color: #00bcd4;
          font-weight: 600;
          font-size: 0.85rem;
          text-transform: uppercase;
        }

        tr.inactive {
          opacity: 0.6;
        }

        .user-cell {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .user-avatar {
          width: 32px;
          height: 32px;
          background: linear-gradient(135deg, #00bcd4, #0097a7);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          font-weight: bold;
          font-size: 0.85rem;
          color: white;
        }

        .you-badge {
          background: #00bcd4;
          color: #000;
          padding: 2px 8px;
          border-radius: 10px;
          font-size: 0.7rem;
          font-weight: bold;
          margin-left: 5px;
        }

        .role-badge {
          padding: 4px 10px;
          border-radius: 12px;
          font-size: 0.8rem;
          font-weight: 600;
          text-transform: uppercase;
        }

        .role-admin {
          background: rgba(255, 68, 68, 0.2);
          color: #ff4444;
        }

        .role-operator {
          background: rgba(255, 165, 0, 0.2);
          color: #ffa500;
        }

        .role-viewer {
          background: rgba(0, 188, 212, 0.2);
          color: #00bcd4;
        }

        .status-badge {
          font-size: 0.85rem;
        }

        .status-badge.active {
          color: #00c853;
        }

        .status-badge.inactive {
          color: #ff4444;
        }

        .action-buttons {
          display: flex;
          gap: 8px;
        }

        .btn-action {
          background: rgba(255, 255, 255, 0.05);
          border: 1px solid rgba(255, 255, 255, 0.1);
          padding: 6px 10px;
          border-radius: 6px;
          cursor: pointer;
          font-size: 1rem;
          transition: all 0.3s ease;
        }

        .btn-action:hover {
          background: rgba(255, 255, 255, 0.1);
        }

        .btn-delete:hover {
          background: rgba(255, 68, 68, 0.2);
          border-color: #ff4444;
        }

        .role-info {
          background: #1e1e2e;
          border-radius: 12px;
          padding: 20px;
        }

        .role-info h4 {
          color: #00bcd4;
          margin-bottom: 15px;
        }

        .role-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 15px;
        }

        .role-card {
          background: rgba(255, 255, 255, 0.02);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 8px;
          padding: 15px;
        }

        .role-card p {
          color: #888;
          font-size: 0.85rem;
          margin-top: 10px;
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

export default UserManagement;
