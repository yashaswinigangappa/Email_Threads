# SIH26106 - Email Threat Intelligence Platform
## Backend API Contract Specification

This document defines the complete REST API contract between the Backend (`Member 4`), Frontend (`Member 2 & 3`), and AI Engine (`Member 5`).

- **Base URL**: `http://localhost:5000/api`
- **Swagger Documentation UI**: `http://localhost:5000/api-docs`
- **Authentication**: Bearer Token (`Authorization: Bearer <JWT_TOKEN>`) or Header API Key (`x-api-key: <API_KEY>`)
- **Default Response Envelope**:
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Operation description",
  "data": { ... }
}
```
- **Error Response Envelope**:
```json
{
  "success": false,
  "statusCode": 400,
  "message": "Detailed error message",
  "errors": [ ... ]
}
```

---

## 1. Authentication Module (`/api/auth`)

### 1.1 User Signup
- **Endpoint**: `POST /api/auth/signup`
- **Access**: Public
- **Request Body**:
```json
{
  "name": "Jane Doe",
  "email": "jane@cybersec.org",
  "password": "Password123!"
}
```
- **Response `201 Created`**:
```json
{
  "success": true,
  "statusCode": 201,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "673cf987a...",
      "name": "Jane Doe",
      "email": "jane@cybersec.org",
      "role": "analyst",
      "apiKey": "etip_live_ab71...",
      "createdAt": "2026-08-27T12:00:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsIn..."
  }
}
```

### 1.2 User Login
- **Endpoint**: `POST /api/auth/login`
- **Access**: Public
- **Request Body**:
```json
{
  "email": "jane@cybersec.org",
  "password": "Password123!"
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "673cf987a...",
      "name": "Jane Doe",
      "email": "jane@cybersec.org",
      "role": "analyst",
      "apiKey": "etip_live_ab71..."
    },
    "token": "eyJhbGciOiJIUzI1NiIsIn..."
  }
}
```

### 1.3 User Logout
- **Endpoint**: `POST /api/auth/logout`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "statusCode": 200,
  "message": "Logged out successfully"
}
```

### 1.4 Get Current User Profile
- **Endpoint**: `GET /api/auth/me`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "statusCode": 200,
  "data": {
    "id": "673cf987a...",
    "name": "Jane Doe",
    "email": "jane@cybersec.org",
    "role": "analyst",
    "avatar": "",
    "apiKey": "etip_live_ab71...",
    "settings": {
      "theme": "dark",
      "notifications": true,
      "autoQuarantine": false
    }
  }
}
```

### 1.5 Update Profile
- **Endpoint**: `PUT /api/auth/profile`
- **Access**: Authenticated
- **Request Body**:
```json
{
  "name": "Jane Analyst",
  "avatar": "https://example.com/avatar.png"
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": { ... }
}
```

### 1.6 Change Password
- **Endpoint**: `PUT /api/auth/change-password`
- **Access**: Authenticated
- **Request Body**:
```json
{
  "currentPassword": "Password123!",
  "newPassword": "NewSecurePassword456!"
}
```

---

## 2. Dashboard Module (`/api/dashboard`)

### 2.1 Overview Statistics Cards
- **Endpoint**: `GET /api/dashboard/stats`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "totalEmailsScanned": 1280,
    "safeEmails": 890,
    "spamEmails": 185,
    "phishingEmails": 165,
    "malwareEmails": 40,
    "avgRiskScore": 24.6,
    "scansToday": 37
  }
}
```

### 2.2 Threat Trends
- **Endpoint**: `GET /api/dashboard/trends?range=7d` (supports `7d`, `30d`, `6m`)
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "range": "7d",
    "timeline": [
      { "date": "2026-08-21", "safe": 40, "spam": 8, "phishing": 5, "malware": 1, "total": 54 },
      { "date": "2026-08-22", "safe": 52, "spam": 11, "phishing": 7, "malware": 2, "total": 72 }
    ],
    "distribution": {
      "safe": 890,
      "spam": 185,
      "phishing": 165,
      "malware": 40
    }
  }
}
```

### 2.3 Recent Threats Table
- **Endpoint**: `GET /api/dashboard/recent-threats?limit=10`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": [
    {
      "id": "673cfe109...",
      "subject": "Urgent: Verify your PayPal account within 24 hours",
      "sender": "security-alert@paypal-update-center.com",
      "riskScore": 92,
      "verdict": "phishing",
      "date": "2026-08-27T10:14:00.000Z",
      "reportId": "673cfe109..."
    }
  ]
}
```

---

## 3. Email Upload & Analysis Module (`/api/email`)

### 3.1 Upload Email File or Paste Raw Content
- **Endpoint**: `POST /api/email/upload`
- **Access**: Authenticated
- **Content-Type**: `multipart/form-data` OR `application/json`
- **Form Data**:
  - `email_file`: `.eml` file binary
- **JSON Alternative**:
  - `{ "rawEmail": "From: ... \nSubject: ... \n\nBody content...", "subject": "...", "body": "..." }`
- **Response `200 OK`**:
```json
{
  "success": true,
  "message": "Email parsed successfully",
  "data": {
    "emailId": "673cfe109...",
    "preview": {
      "subject": "Urgent: Verify your PayPal account",
      "sender": "service@paypal-security.com",
      "receiver": "victim@example.com",
      "date": "2026-08-27T08:30:00.000Z",
      "bodySnippet": "Dear customer, your account has been suspended...",
      "bodyHtml": "<p>Dear customer...</p>",
      "extractedData": {
        "linksCount": 3,
        "attachmentsCount": 1,
        "urls": ["http://paypal-security.com/login", "http://bit.ly/3x8f1"],
        "attachments": [
          { "filename": "Invoice_882.pdf.exe", "size": 45120, "mimeType": "application/x-msdownload", "riskLevel": "high" }
        ],
        "headers": {
          "spf": "fail",
          "dkim": "fail",
          "dmarc": "fail",
          "returnPath": "bounce@spammer-domain.xyz",
          "messageId": "<202608271014.1234@unknown>"
        },
        "extractedIPs": ["198.51.100.23", "203.0.113.15"]
      }
    }
  }
}
```

### 3.2 Full Email Analysis Pipeline
- **Endpoint**: `POST /api/email/analyze`
- **Access**: Authenticated
- **Request Body**:
```json
{
  "emailId": "673cfe109..."
}
```
*(Or upload `.eml` file directly to `POST /api/email/analyze` as multipart to parse & analyze in a single call)*
- **Response `200 OK`**:
```json
{
  "success": true,
  "message": "Analysis completed successfully",
  "data": {
    "reportId": "673d001ab...",
    "emailId": "673cfe109...",
    "verdict": "phishing",
    "riskScore": 91,
    "confidence": 95,
    "summary": "High-risk phishing attack detected utilizing spoofed PayPal credentials, failed SPF/DKIM authentication, and malicious short URLs.",
    "aiAnalysis": {
      "class": "phishing",
      "confidence": 95,
      "risk_score": 91,
      "reasons": [
        "SPF authentication failed",
        "Urgent deceptive language detected",
        "Suspicious disguised URL found",
        "Dangerous executable attachment detected"
      ]
    },
    "senderAnalysis": {
      "sender": "service@paypal-security.com",
      "domain": "paypal-security.com",
      "reputation": "Suspicious",
      "domainAge": "2 Days",
      "spfStatus": "Fail",
      "dkimStatus": "Fail",
      "dmarcStatus": "Fail",
      "dnsValid": true,
      "mxValid": true
    },
    "urlAnalysis": [
      {
        "url": "http://bit.ly/3x8f1",
        "status": "Suspicious",
        "threatLevel": "High",
        "isShortener": true,
        "isIpUrl": false,
        "blacklistMatch": true
      }
    ],
    "attachmentAnalysis": [
      {
        "filename": "Invoice_882.pdf.exe",
        "type": "Executable Binary (.exe)",
        "size": 45120,
        "threatLevel": "Critical",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ],
    "indicatorsOfCompromise": {
      "maliciousDomains": ["paypal-security.com"],
      "maliciousIPs": ["198.51.100.23"],
      "maliciousURLs": ["http://bit.ly/3x8f1"],
      "suspiciousAttachments": ["Invoice_882.pdf.exe"]
    },
    "recommendations": [
      "Do NOT click any links inside this email",
      "Do NOT open or download the attachment 'Invoice_882.pdf.exe'",
      "Block sender domain 'paypal-security.com' across mail gateway",
      "Report email to internal SOC and Delete immediately"
    ]
  }
}
```

### 3.3 Get Email by ID
- **Endpoint**: `GET /api/email/:id`
- **Access**: Authenticated

---

## 4. AI Threat Detection Module (`/api/ai`)

### 4.1 AI Prediction Endpoint
- **Endpoint**: `POST /api/ai/predict`
- **Access**: Authenticated / API Key
- **Request Body**:
```json
{
  "subject": "Urgent: Verify your PayPal account",
  "body": "Dear user, your account will be closed in 24 hours. Click here to confirm identity: http://fake-domain.com",
  "sender": "support@paypal-sec.com",
  "headers": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail"
  },
  "urls": ["http://fake-domain.com/login"],
  "attachments": ["document.exe"]
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "class": "phishing",
    "confidence": 95,
    "risk_score": 91,
    "reasons": [
      "SPF failed",
      "Urgent language detected",
      "Suspicious URL"
    ]
  }
}
```

### 4.2 Multi-Vector Risk Score Calculator
- **Endpoint**: `POST /api/ai/risk-score`
- **Request Body**:
```json
{
  "aiPrediction": { "class": "phishing", "confidence": 95 },
  "senderSignals": { "spfStatus": "Fail", "domainAgeDays": 2 },
  "urls": [{ "isBlacklisted": true, "isShortener": true }],
  "attachments": [{ "isExecutable": true }]
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "riskScore": 92,
    "threatLevel": "Critical",
    "verdict": "phishing"
  }
}
```

---

## 5. Sender Analysis Module (`/api/sender-analysis`)

- **Endpoint**: `GET /api/sender-analysis/:email`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "email": "sender@paypal-security.com",
    "domain": "paypal-security.com",
    "domainAge": "2 Days",
    "reputation": "Poor / Dangerous",
    "spfStatus": "Fail",
    "dkimStatus": "Fail",
    "dmarcStatus": "Fail",
    "dnsRecords": {
      "hasMX": true,
      "hasSPF": false,
      "hasDMARC": false
    },
    "isDisposable": false,
    "riskScore": 85
  }
}
```

---

## 6. URL Analysis Module (`/api/url`)

- **Endpoint**: `POST /api/url/analyze`
- **Request Body**:
```json
{
  "urls": [
    "http://bit.ly/3xyz",
    "http://192.168.1.100/malware.scr",
    "https://google.com"
  ]
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "url": "http://bit.ly/3xyz",
        "status": "Suspicious",
        "threatLevel": "High",
        "isShortener": true,
        "isIpUrl": false,
        "suspiciousTld": false,
        "blacklistMatch": true
      },
      {
        "url": "http://192.168.1.100/malware.scr",
        "status": "Malicious",
        "threatLevel": "Critical",
        "isShortener": false,
        "isIpUrl": true,
        "suspiciousTld": false,
        "blacklistMatch": true
      },
      {
        "url": "https://google.com",
        "status": "Safe",
        "threatLevel": "Low",
        "isShortener": false,
        "isIpUrl": false,
        "suspiciousTld": false,
        "blacklistMatch": false
      }
    ],
    "totalUrls": 3,
    "maliciousCount": 2
  }
}
```

---

## 7. Attachment Analysis Module (`/api/attachment`)

- **Endpoint**: `POST /api/attachment/analyze`
- **Request Body**:
```json
{
  "attachments": [
    { "filename": "statement.pdf.exe", "size": 45000, "mimeType": "application/x-msdownload" },
    { "filename": "contract.docx", "size": 120000, "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }
  ]
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "filename": "statement.pdf.exe",
        "extension": ".exe",
        "hasDoubleExtension": true,
        "isDangerousType": true,
        "threatLevel": "Critical",
        "reasons": ["Executable file type (.exe)", "Double extension obfuscation (.pdf.exe)"]
      },
      {
        "filename": "contract.docx",
        "extension": ".docx",
        "hasDoubleExtension": false,
        "isDangerousType": false,
        "threatLevel": "Low",
        "reasons": []
      }
    ],
    "threatsFound": 1
  }
}
```

---

## 8. Threat Report Module (`/api/report`)

### 8.1 Get Detailed Report by ID
- **Endpoint**: `GET /api/report/:id`
- **Access**: Authenticated
- **Response `200 OK`**: Returns full report JSON with risk score, IOCs, AI explanation, recommendations.

### 8.2 Download PDF Report
- **Endpoint**: `GET /api/report/download/:id`
- **Access**: Authenticated
- **Response**: `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="Threat_Report_<ID>.pdf"`

---

## 9. Email History Module (`/api/history`)

### 9.1 Get Scan History with Search and Filtering
- **Endpoint**: `GET /api/history?page=1&limit=10&search=paypal&verdict=phishing&sortBy=createdAt&sortOrder=desc`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "history": [
      {
        "id": "673cfe...",
        "emailId": "673cfe109...",
        "subject": "Urgent: Verify your PayPal account",
        "sender": "service@paypal-security.com",
        "riskScore": 91,
        "verdict": "phishing",
        "threatCount": 3,
        "createdAt": "2026-08-27T10:14:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "totalRecords": 1,
      "totalPages": 1
    }
  }
}
```

### 9.2 Delete Specific History Entry
- **Endpoint**: `DELETE /api/history/:id`
- **Access**: Authenticated

### 9.3 Clear All Scan History
- **Endpoint**: `DELETE /api/history`
- **Access**: Authenticated

---

## 10. Threat Feed Module (`/api/threat-feed`)

- **Endpoint**: `GET /api/threat-feed?type=all&limit=20`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "newPhishingDomains": [
      { "domain": "paypal-secure-verify.net", "confidence": 98, "detectedAt": "2026-08-27T09:00:00.000Z" },
      { "domain": "microsoft365-login-auth.xyz", "confidence": 95, "detectedAt": "2026-08-27T08:45:00.000Z" }
    ],
    "recentAttacks": [
      { "attackType": "Spear Phishing", "target": "Finance Sector", "signature": "CEO Fraud Invoice Scheme", "severity": "High" }
    ],
    "threatNews": [
      { "title": "New zero-day exploit abusing PDF attachment preview handlers", "source": "CyberSec Global", "publishedAt": "2026-08-27" }
    ]
  }
}
```

---

## 11. Analytics Module (`/api/analytics`)

- **Endpoint**: `GET /api/analytics`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "dailyThreatTrend": [
      { "date": "2026-08-21", "count": 14 },
      { "date": "2026-08-22", "count": 20 }
    ],
    "monthlyThreatTrend": [
      { "month": "2026-06", "count": 320 },
      { "month": "2026-07", "count": 450 },
      { "month": "2026-08", "count": 510 }
    ],
    "mostTargetedDomains": [
      { "domain": "corporate-finance.com", "attacksCount": 87 },
      { "domain": "hr-department.org", "attacksCount": 54 }
    ],
    "threatTypeDistribution": {
      "phishing": 45,
      "spam": 30,
      "malware": 15,
      "safe": 10
    }
  }
}
```

---

## 12. Settings Module (`/api/settings`)

### 12.1 Get Settings
- **Endpoint**: `GET /api/settings`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "theme": "dark",
    "notifications": true,
    "apiKey": "etip_live_ab71...",
    "scanPreferences": {
      "deepUrlInspection": true,
      "checkAttachmentSandboxing": true,
      "alertThresholdRiskScore": 75
    }
  }
}
```

### 12.2 Update Settings
- **Endpoint**: `PUT /api/settings`
- **Request Body**:
```json
{
  "theme": "dark",
  "notifications": false,
  "scanPreferences": {
    "deepUrlInspection": true,
    "alertThresholdRiskScore": 80
  }
}
```

### 12.3 Regenerate API Key
- **Endpoint**: `POST /api/settings/regenerate-api-key`
- **Access**: Authenticated
- **Response `200 OK`**:
```json
{
  "success": true,
  "data": {
    "apiKey": "etip_live_new_93fa..."
  }
}
```
