# Email Threat Intelligence Platform (SIH26106)
## Frontend Developer A Module: SOC Dashboard, Analytics, Auth & Reusable UI Components

An enterprise-grade, responsive Cybersecurity Web Dashboard for real-time AI-powered email threat intelligence and phishing mitigation.

---

## 🚀 Live Preview & Getting Started

### Option 1: Direct Browser Launch
Simply open `index.html`, `login.html`, or `analytics.html` in any modern web browser (Chrome, Edge, Firefox, Safari).

### Option 2: Local HTTP Server (Recommended)
Using Python:
```bash
cd email-threat-platform
python -m http.server 3000
```
Then navigate to: `http://localhost:3000`

Using Node.js (`serve` or `npx http-server`):
```bash
npx serve .
```

---

## 📁 Clean Folder Structure

```
email-threat-platform/
├── index.html              # Main Security Operations Center (SOC) Dashboard
├── analytics.html          # In-depth Threat Analytics, Attack Radar & Vulnerability Map
├── login.html              # SOC Operator Authentication & 2FA / SSO Screen
├── signup.html             # SOC Analyst Registration Portal
├── css/
│   └── styles.css          # Custom cyber dark-mode theme, glassmorphism, radar animations
├── js/
│   ├── api.js              # API-ready service layer (Mock & Live Backend switchable)
│   ├── mock-data.js        # Rich cybersecurity telemetry & realistic threat data
│   ├── auth.js             # Session state, 2FA token management, auth guard
│   ├── components.js       # Reusable Navbar, Sidebar, Threat Modals & Toast alerts
│   ├── dashboard.js        # Dashboard controller: stats cards, time-series charts, threat table
│   └── analytics.js        # Analytics controller: radar vectors, department targeting, CSV/JSON export
└── README.md               # Project documentation and architectural guide
```

---

## 🛡️ Key Features Built for Frontend Developer A

### 1. Reusable Enterprise UI Architecture
- **Cybersecurity Dark Mode SOC Theme**: Tailored color tokens (`#0B0F19` deep slate, `#06B6D4` Cyan, `#EF4444` Crimson high-risk indicators, `#10B981` Emerald verified safe).
- **Reusable Component Engine (`js/components.js`)**: Dynamic Navbar, collapsible Sidebar, interactive Threat Investigation Modal, and Cyber Toast notifications.
- **Glassmorphism & High-Tech UI**: Glowing status pulses, radar animations, responsive layout across mobile, tablet, and ultra-wide screens.

### 2. Main SOC Dashboard (`index.html`)
- **Key Statistics Cards**:
  - Total Emails Scanned (14,820)
  - Safe Emails (11,240 - 75.8%)
  - Spam Emails (2,150 - 14.5%)
  - Phishing Attacks (1,090 - 7.4%)
  - Malware Payloads (340 - 2.3%)
- **Threat Trends Chart**: Interactive multi-line chart supporting **Last 7 Days**, **Last 30 Days**, and **Last 6 Months** timeframes.
- **Threat Distribution Donut**: Visual breakdown by threat classification.
- **Recent Threats Interactive Table**: Real-time quarantine table with click-to-investigate modals displaying explainable AI indicators (SPF, DKIM, DMARC, typosquatting domains, suspicious URLs).
- **AI Defense Engine Status**: Real-time confidence and parser health metrics.

### 3. Threat Intelligence Analytics (`analytics.html`)
- **Department Vulnerability Map**: Horizontal bar chart comparing attack frequency across Finance, HR, Executive, IT, and Legal.
- **Threat Vectors Radar Chart**: Visual breakdown of attack methodologies (Credential Phishing, Macros, BEC, Ransomware).
- **Hourly Scan Velocity vs Interception Trend**: Inbound traffic load correlation.
- **Email Protocol Verification Metrics**: Real-time SPF, DKIM, and DMARC failure rates.
- **Telemetry Export**: 1-click **Export to CSV** and **Export to JSON**.

### 4. Authentication Module (`login.html` & `signup.html`)
- Secure login and registration with validation, password policy checks, and simulated enterprise SSO (Microsoft 365, Okta).

### 5. API-Ready Architecture (`js/api.js`)
Endpoints predefined according to team integration requirements:
- `POST /auth/login`
- `POST /auth/signup`
- `POST /auth/logout`
- `GET /dashboard/stats`
- `GET /dashboard/trends`
- `GET /dashboard/recent-threats`
- `GET /analytics`
- `GET /threat-feed`

Switching from mock mode to a real backend:
```javascript
// In js/api.js or browser console:
window.api.setMockMode(false); // Connects to http://localhost:5000/api
```

---

## 👥 Team Integration Notes
- **Frontend Developer B**: Reusable components (`Layout.renderNavbar()`, `Layout.renderSidebar()`, `Toast.show()`, `ThreatModal.open()`) can be referenced directly on the Analyze Email, Upload Email, Threat Report, and History pages.
- **Backend & AI Developer**: The data contracts in `js/mock-data.js` and `js/api.js` match the expected outputs from the Node.js Express server and Python FastAPI AI engine.
