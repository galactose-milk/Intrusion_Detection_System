// frontend/src/context/AuthContext.jsx
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

// Create the context
const AuthContext = createContext(null);

// Storage keys
const TOKEN_KEY = 'ids_token';
const USER_KEY = 'ids_user';

// Auth Provider component
export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Load stored auth state on mount
  useEffect(() => {
    const storedToken = localStorage.getItem(TOKEN_KEY);
    const storedUser = localStorage.getItem(USER_KEY);
    
    if (storedToken && storedUser) {
      setToken(storedToken);
      setUser(JSON.parse(storedUser));
      
      // Verify token is still valid
      verifyToken(storedToken).then(valid => {
        if (!valid) {
          logout();
        }
        setLoading(false);
      });
    } else {
      setLoading(false);
    }
  }, []);

  // Verify token with backend
  const verifyToken = async (tokenToVerify) => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/verify`, {
        headers: {
          'Authorization': `Bearer ${tokenToVerify}`
        }
      });
      return response.ok;
    } catch {
      return false;
    }
  };

  // Login function
  const login = useCallback(async (username, password) => {
    setError(null);
    setLoading(true);
    
    try {
      const response = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Login failed');
      }

      const data = await response.json();
      
      // Store auth data
      setToken(data.access_token);
      setUser(data.user);
      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      
      return { success: true };
    } catch (err) {
      setError(err.message);
      return { success: false, error: err.message };
    } finally {
      setLoading(false);
    }
  }, []);

  // Logout function
  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }, []);

  // Get auth header for API requests
  const getAuthHeader = useCallback(() => {
    if (!token) return {};
    return { 'Authorization': `Bearer ${token}` };
  }, [token]);

  // Fetch with auth
  const authFetch = useCallback(async (url, options = {}) => {
    const headers = {
      ...options.headers,
      ...getAuthHeader()
    };
    
    const response = await fetch(url, { ...options, headers });
    
    // If unauthorized, logout
    if (response.status === 401) {
      logout();
      throw new Error('Session expired. Please login again.');
    }
    
    return response;
  }, [getAuthHeader, logout]);

  // Check if user has specific role
  const hasRole = useCallback((requiredRoles) => {
    if (!user) return false;
    if (Array.isArray(requiredRoles)) {
      return requiredRoles.includes(user.role);
    }
    return user.role === requiredRoles;
  }, [user]);

  // Context value
  const value = {
    user,
    token,
    loading,
    error,
    isAuthenticated: !!token && !!user,
    login,
    logout,
    getAuthHeader,
    authFetch,
    hasRole
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Custom hook to use auth context
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
