/**
 * API Service Layer for Email Threat Intelligence Platform
 * Integrates with Backend APIs or fallback Mock Data
 */

class ApiService {
  constructor() {
    this.baseUrl = window.API_BASE_URL || 'http://localhost:5000/api';
    this.useMock = true; // Set to false when connecting to live backend server
  }

  // Set real API Mode or Mock Mode
  setMockMode(enable) {
    this.useMock = enable;
    console.log(`[API Service] Mode switched to: ${this.useMock ? 'MOCK DATA' : 'LIVE BACKEND (' + this.baseUrl + ')'}`);
  }

  getAuthToken() {
    return localStorage.getItem('sih_auth_token');
  }

  // Simulated latency for realistic enterprise async feel
  async _delay(ms = 250) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /* ============================================================
     1. AUTHENTICATION MODULE (POST /auth/login, POST /auth/signup)
     ============================================================ */
  async login(email, password) {
    if (this.useMock) {
      await this._delay(400);
      if (!email || !password) {
        throw new Error("Email and password are required.");
      }
      if (password.length < 6) {
        throw new Error("Invalid password credentials.");
      }
      const mockUser = {
        id: "usr_" + Math.random().toString(36).substring(2, 9),
        name: email.split('@')[0].replace('.', ' ').toUpperCase(),
        email: email,
        role: "Lead SOC Analyst",
        avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        token: "jwt_mock_token_sih26106_" + Date.now()
      };
      localStorage.setItem('sih_auth_token', mockUser.token);
      localStorage.setItem('sih_user', JSON.stringify(mockUser));
      return { success: true, user: mockUser };
    }

    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.message || 'Login failed');
    }
    return response.json();
  }

  async signup(userData) {
    if (this.useMock) {
      await this._delay(500);
      if (!userData.email || !userData.password || !userData.name) {
        throw new Error("Please fill in all required fields.");
      }
      if (userData.password !== userData.confirmPassword) {
        throw new Error("Passwords do not match.");
      }
      const newUser = {
        id: "usr_" + Math.random().toString(36).substring(2, 9),
        name: userData.name,
        email: userData.email,
        role: userData.role || "SOC Analyst",
        avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
        token: "jwt_mock_token_sih26106_" + Date.now()
      };
      localStorage.setItem('sih_auth_token', newUser.token);
      localStorage.setItem('sih_user', JSON.stringify(newUser));
      return { success: true, user: newUser };
    }

    const response = await fetch(`${this.baseUrl}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.message || 'Registration failed');
    }
    return response.json();
  }

  async logout() {
    localStorage.removeItem('sih_auth_token');
    localStorage.removeItem('sih_user');
    return { success: true };
  }

  /* ============================================================
     2. DASHBOARD MODULE (GET /dashboard/stats, trends, threats)
     ============================================================ */
  async getDashboardStats() {
    if (this.useMock) {
      await this._delay(200);
      return { success: true, data: window.MOCK_DATA.stats };
    }
    const response = await fetch(`${this.baseUrl}/dashboard/stats`, {
      headers: { 'Authorization': `Bearer ${this.getAuthToken()}` }
    });
    return response.json();
  }

  async getDashboardTrends(timeframe = '7d') {
    if (this.useMock) {
      await this._delay(200);
      let trendData;
      if (timeframe === '30d') trendData = window.MOCK_DATA.trends.last30Days;
      else if (timeframe === '6m') trendData = window.MOCK_DATA.trends.last6Months;
      else trendData = window.MOCK_DATA.trends.last7Days;

      return { success: true, timeframe, data: trendData };
    }
    const response = await fetch(`${this.baseUrl}/dashboard/trends?timeframe=${timeframe}`, {
      headers: { 'Authorization': `Bearer ${this.getAuthToken()}` }
    });
    return response.json();
  }

  async getRecentThreats() {
    if (this.useMock) {
      await this._delay(250);
      return { success: true, data: window.MOCK_DATA.recentThreats };
    }
    const response = await fetch(`${this.baseUrl}/dashboard/recent-threats`, {
      headers: { 'Authorization': `Bearer ${this.getAuthToken()}` }
    });
    return response.json();
  }

  /* ============================================================
     3. ANALYTICS MODULE (GET /analytics)
     ============================================================ */
  async getAnalyticsData() {
    if (this.useMock) {
      await this._delay(250);
      return { success: true, data: window.MOCK_DATA.analytics };
    }
    const response = await fetch(`${this.baseUrl}/analytics`, {
      headers: { 'Authorization': `Bearer ${this.getAuthToken()}` }
    });
    return response.json();
  }

  /* ============================================================
     4. LIVE THREAT FEED (GET /threat-feed)
     ============================================================ */
  async getThreatFeed() {
    if (this.useMock) {
      await this._delay(150);
      return { success: true, data: window.MOCK_DATA.threatFeed };
    }
    const response = await fetch(`${this.baseUrl}/threat-feed`, {
      headers: { 'Authorization': `Bearer ${this.getAuthToken()}` }
    });
    return response.json();
  }
}

// Global API instance
const api = new ApiService();
if (typeof window !== 'undefined') {
  window.api = api;
}
