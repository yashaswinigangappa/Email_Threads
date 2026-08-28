# SIH26106 - Email Threat Intelligence Platform Backend

> **Production Node.js + Express REST API Backend for AI-powered Email Threat Intelligence & SOC Defense**

---

## Overview

The **Email Threat Intelligence Platform (ETIP)** backend is a modular, scalable security microservice built with Node.js and Express. It ingests `.eml` email files and raw content, extracts detailed RFC 822 metadata, analyzes sender reputation (SPF/DKIM/DMARC), inspects embedded URLs, screens weaponized attachments, connects to AI classification models, computes multi-vector composite threat scores, generates IOC reports & downloadable PDF files, and serves analytics/history feeds.

---

## Key Features

- **JWT Authentication & API Key Management**: Secure signup, login, session validation, profile updating, password changing, and developer API key access.
- **Dual-Mode AI Connector**: Seamlessly communicates with Python FastAPI model endpoint (`POST /predict`), with an intelligent built-in heuristic/NLP fallback engine when the Python service is offline.
- **Email Ingestion & Parser**: Parses `.eml` files and raw text buffers to extract headers, sender/recipient addresses, authentication flags (SPF/DKIM/DMARC), embedded URLs, IP routing hops, and attachments with cryptographic hashes (SHA-256 & MD5).
- **Multi-Vector Risk Score Engine**: Computes 0-100 composite threat scores and classifications (`Safe`, `Spam`, `Phishing`, `Malware`) with explainable AI reasons.
- **PDF Report Generation**: Generates enterprise-ready cybersecurity threat reports via `pdfkit` complete with executive summary, IOC tables, and mitigation steps.
- **Threat Intelligence & Feed**: Real-time threat feeds including newly detected phishing domains, recent cyber attacks, and threat news.
- **Dashboard & Analytics**: Daily and monthly threat trends, statistics cards, and domain targeting aggregations.
- **API Documentation**: Interactive Swagger UI at `/api-docs` and full OpenAPI 3.0 YAML specification.

---

## Project Structure

```
email-threat-platform-backend/
├── docs/
│   ├── API_CONTRACT.md              # Detailed API contract specification
│   └── openapi.yaml                 # OpenAPI 3.0 / Swagger schema specification
├── src/
│   ├── app.js                       # Express application configuration & middlewares
│   ├── server.js                    # Server startup & MongoDB connection
│   ├── config/                      # Environment variables, DB & Swagger setup
│   ├── models/                      # Mongoose models (User, Email, Report, Threat, Attachment, Analytics)
│   ├── middlewares/                 # Auth (JWT & API Key), Error, Upload, Validation, Rate Limiter, Logger
│   ├── modules/                     # Feature modules (Auth, Dashboard, Email, AI, Sender, URL, Attachment, Report, History, ThreatFeed, Analytics, Settings)
│   ├── services/                    # EmailParser, SenderAnalysis, UrlAnalysis, AttachmentAnalysis, AiPrediction, RiskScore, PdfGenerator, ThreatFeed
│   ├── utils/                       # ApiResponse, ApiError, AsyncCatch, Logger
│   └── seeds/                       # Database seed script
├── tests/                           # Jest & Supertest automated test suites
├── package.json
└── .env.example
```

---

## Getting Started

### 1. Prerequisites
- **Node.js**: v18+ (tested on Node v24)
- **MongoDB**: Local instance (`mongodb://127.0.0.1:27017`) or MongoDB Atlas URI

### 2. Installation
```bash
cd email-threat-platform-backend
npm install
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and adjust settings if required:
```bash
cp .env.example .env
```

### 4. Seed Database (Optional for Demo)
Pre-populate demo analysts, scanned threat emails, reports, feeds, and analytics:
```bash
npm run seed
```

**Pre-seeded Credentials:**
- **Analyst**: `analyst@cybersec.org` / `Password123!` (API Key: `etip_live_demo_key_998877665544`)
- **Admin**: `admin@cybersec.org` / `AdminPassword123!` (API Key: `etip_live_admin_key_112233445566`)

### 5. Running the Backend
- **Development Mode (Nodemon)**:
  ```bash
  npm run dev
  ```
- **Production Mode**:
  ```bash
  npm start
  ```

Server will start on `http://localhost:5000`.

### 6. Interactive API Documentation
Navigate to `http://localhost:5000/api-docs` in your browser for the Swagger UI documentation.

---

## Running Automated Tests

Run the full test suite (Auth, Email Parsing, AI heuristics, URL inspection, and PDF reporting):
```bash
npm test
```

---

## API Summary

| Module | Method | Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **Auth** | `POST` | `/api/auth/signup` | Register new user account |
| **Auth** | `POST` | `/api/auth/login` | Login and get JWT token |
| **Auth** | `GET` | `/api/auth/me` | Get logged-in user profile |
| **Dashboard** | `GET` | `/api/dashboard/stats` | Overview statistics cards |
| **Dashboard** | `GET` | `/api/dashboard/trends` | Threat trends (7d, 30d, 6m) |
| **Dashboard** | `GET` | `/api/dashboard/recent-threats` | Recent threats table |
| **Email** | `POST` | `/api/email/upload` | Ingest `.eml` file or raw text |
| **Email** | `POST` | `/api/email/analyze` | Run full threat analysis pipeline |
| **AI** | `POST` | `/api/ai/predict` | AI threat classification & explainability |
| **Sender** | `GET` | `/api/sender-analysis/:email` | SPF/DKIM/DMARC & reputation check |
| **URL** | `POST` | `/api/url/analyze` | URL threat & shortener inspection |
| **Attachment** | `POST` | `/api/attachment/analyze` | Attachment dangerous file type scan |
| **Report** | `GET` | `/api/report/:id` | Get detailed report with IOCs |
| **Report** | `GET` | `/api/report/download/:id` | Stream/download PDF threat report |
| **History** | `GET` | `/api/history` | Paginated scan history with search/filter |
| **Threat Feed** | `GET` | `/api/threat-feed` | Live phishing domains & threat intelligence |
| **Analytics** | `GET` | `/api/analytics` | Target domains and trend analytics |
| **Settings** | `GET` | `/api/settings` | Retrieve user preferences & API Key |
| **Settings** | `PUT` | `/api/settings` | Update user settings |
| **Settings** | `POST` | `/api/settings/regenerate-api-key` | Generate new API key |
