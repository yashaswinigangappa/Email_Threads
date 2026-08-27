/**
 * Mock Data Repository for Email Threat Intelligence Platform
 * Grounded in SIH26106 Requirements
 */

const MOCK_DATA = {
  // Statistics Overview
  stats: {
    totalScanned: 14820,
    totalScannedGrowth: "+12.4%",
    safeEmails: 11240,
    safePercentage: 75.8,
    spamEmails: 2150,
    spamPercentage: 14.5,
    phishingEmails: 1090,
    phishingPercentage: 7.4,
    malwareEmails: 340,
    malwarePercentage: 2.3,
    criticalThreatsBlocked: 1430,
    averageRiskScore: 32.4,
    aiModelAccuracy: 98.6,
    avgProcessingTimeMs: 142
  },

  // Threat Trends over Time
  trends: {
    last7Days: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      phishing: [45, 62, 58, 81, 95, 40, 38],
      malware: [12, 19, 15, 28, 34, 10, 8],
      spam: [120, 145, 132, 180, 210, 95, 88],
      safe: [620, 710, 680, 850, 920, 410, 390]
    },
    last30Days: {
      labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
      phishing: [240, 310, 280, 360],
      malware: [75, 92, 85, 110],
      spam: [490, 580, 520, 640],
      safe: [2600, 2950, 2750, 3200]
    },
    last6Months: {
      labels: ['Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug'],
      phishing: [780, 920, 850, 1040, 1180, 1090],
      malware: [210, 260, 240, 310, 380, 340],
      spam: [1600, 1850, 1720, 2100, 2350, 2150],
      safe: [8900, 9800, 9400, 10800, 11900, 11240]
    }
  },

  // Threat Distribution
  distribution: {
    labels: ['Safe', 'Spam', 'Phishing', 'Malware'],
    data: [11240, 2150, 1090, 340],
    colors: ['#10B981', '#F59E0B', '#EF4444', '#8B5CF6']
  },

  // Recent Threats Table
  recentThreats: [
    {
      id: "THR-9021",
      subject: "Urgent: Verify Your Microsoft 365 Tenant Credentials",
      sender: "security-update@micros0ft-portal-auth.com",
      receiver: "finance-exec@acme-corp.com",
      riskScore: 94,
      verdict: "Phishing",
      category: "Credential Harvesting",
      date: "2026-08-27 13:28:14",
      confidence: 97.4,
      explainableAi: {
        reasons: [
          "Typosquatting domain detected (micros0ft instead of microsoft)",
          "SPF check failed (IP not authorized in SPF record)",
          "DKIM signature missing or invalid",
          "Urgent psychological framing detected in body text",
          "Hidden URL redirect to credential phishing landing page"
        ],
        spfStatus: "FAIL",
        dkimStatus: "FAIL",
        dmarcStatus: "FAIL",
        domainAge: "3 Days",
        extractedUrls: [
          { url: "https://auth-micros0ft-login.ru/token", threat: "High", blacklisted: true }
        ],
        attachments: []
      }
    },
    {
      id: "THR-9020",
      subject: "Invoice #INV-2026-9812 attached for immediate settlement",
      sender: "billing@swift-transact-global.net",
      receiver: "accounts@acme-corp.com",
      riskScore: 91,
      verdict: "Malware",
      category: "Trojan / Dropper",
      date: "2026-08-27 12:45:02",
      confidence: 95.8,
      explainableAi: {
        reasons: [
          "Malicious executable script disguised as PDF (invoice.pdf.vbs)",
          "High entropy attachment with known malware signature matches",
          "DMARC policy rejection",
          "Suspicious external download trigger in header macro"
        ],
        spfStatus: "SOFTFAIL",
        dkimStatus: "FAIL",
        dmarcStatus: "FAIL",
        domainAge: "11 Days",
        extractedUrls: [
          { url: "http://185.220.101.4/payload.bin", threat: "High", blacklisted: true }
        ],
        attachments: [
          { filename: "invoice_aug_2026.pdf.vbs", type: ".vbs", size: "284 KB", threatLevel: "Critical" }
        ]
      }
    },
    {
      id: "THR-9019",
      subject: "Exclusive 80% discount on Enterprise SEO Ranking Software",
      sender: "marketing-blast@bulk-promo-leads.xyz",
      receiver: "team@acme-corp.com",
      riskScore: 68,
      verdict: "Spam",
      category: "Unsolicited Bulk Email",
      date: "2026-08-27 11:15:30",
      confidence: 91.2,
      explainableAi: {
        reasons: [
          "Bulk mail heuristics triggered",
          "Generic greeting with excessive promotional keywords",
          "Domain listed on Spamhaus ZEN blacklist"
        ],
        spfStatus: "PASS",
        dkimStatus: "PASS",
        dmarcStatus: "PASS",
        domainAge: "45 Days",
        extractedUrls: [
          { url: "https://click.bulk-promo-leads.xyz/trk", threat: "Medium", blacklisted: false }
        ],
        attachments: []
      }
    },
    {
      id: "THR-9018",
      subject: "Payroll Direct Deposit Account Confirmation",
      sender: "hr-payroll@hr-workday-verify.com",
      receiver: "developer1@acme-corp.com",
      riskScore: 89,
      verdict: "Phishing",
      category: "BEC / Social Engineering",
      date: "2026-08-27 10:02:18",
      confidence: 96.1,
      explainableAi: {
        reasons: [
          "Display name spoofing impersonating HR director",
          "Lookalike domain registration (hr-workday-verify.com)",
          "Urgent call-to-action requesting bank account information",
          "SPF alignment failed"
        ],
        spfStatus: "FAIL",
        dkimStatus: "NEUTRAL",
        dmarcStatus: "FAIL",
        domainAge: "1 Day",
        extractedUrls: [
          { url: "http://workday-login-form.co/direct-deposit", threat: "High", blacklisted: true }
        ],
        attachments: []
      }
    },
    {
      id: "THR-9017",
      subject: "Quarterly Engineering Roadmap and Sprint Objectives",
      sender: "vp-tech@acme-corp.com",
      receiver: "engineering@acme-corp.com",
      riskScore: 4,
      verdict: "Safe",
      category: "Internal Communication",
      date: "2026-08-27 09:30:00",
      confidence: 99.8,
      explainableAi: {
        reasons: [
          "Valid internal domain SPF, DKIM, and DMARC alignment",
          "Known sender reputation score 100/100",
          "Zero suspicious links or payload macros"
        ],
        spfStatus: "PASS",
        dkimStatus: "PASS",
        dmarcStatus: "PASS",
        domainAge: "2,190 Days (6 Years)",
        extractedUrls: [
          { url: "https://github.com/acme-corp/roadmap", threat: "Safe", blacklisted: false }
        ],
        attachments: [
          { filename: "q3_roadmap.pdf", type: ".pdf", size: "1.2 MB", threatLevel: "Safe" }
        ]
      }
    },
    {
      id: "THR-9016",
      subject: "Security Alert: New sign-in detected on unauthorized Android device",
      sender: "google-alert@account-security-review.net",
      receiver: "sysadmin@acme-corp.com",
      riskScore: 92,
      verdict: "Phishing",
      category: "Brand Impersonation",
      date: "2026-08-27 08:14:45",
      confidence: 98.2,
      explainableAi: {
        reasons: [
          "Google Security brand asset impersonation",
          "Fake DNS records and forged Envelope From",
          "Reverse proxy phishing kit detected on target URL"
        ],
        spfStatus: "FAIL",
        dkimStatus: "FAIL",
        dmarcStatus: "FAIL",
        domainAge: "4 Days",
        extractedUrls: [
          { url: "https://account-security-review.net/checkpoint", threat: "High", blacklisted: true }
        ],
        attachments: []
      }
    }
  ],

  // Live Threat Feed Stream
  threatFeed: [
    { type: "Phishing", domain: "paypal-resolution-center-case9.com", risk: 96, time: "Just now", target: "Finance Dept" },
    { type: "Malware", domain: "cdn-delivery-office365.cc", risk: 98, time: "2 min ago", target: "Legal Dept" },
    { type: "Spoofing", domain: "chase-secure-verify.org", risk: 89, time: "5 min ago", target: "Executive Office" },
    { type: "Spam", domain: "global-webinar-leads.club", risk: 62, time: "11 min ago", target: "Marketing" },
    { type: "Phishing", domain: "fedex-tracking-package-status.info", risk: 94, time: "18 min ago", target: "Operations" }
  ],

  // Analytics Deep Dives
  analytics: {
    targetedDepartments: {
      labels: ['Finance & Accounting', 'Human Resources', 'Executive / C-Suite', 'IT & DevOps', 'Legal & Compliance', 'Sales & Marketing'],
      phishingAttempts: [420, 290, 185, 160, 110, 85],
      malwareAttempts: [130, 85, 45, 95, 25, 15]
    },
    threatVectors: {
      labels: ['Credential Phishing', 'Malicious Macros', 'BEC / Wire Fraud', 'Ransomware Droppers', 'Bulk Spam', 'Typosquat Impersonation'],
      data: [38, 22, 16, 12, 8, 4]
    },
    authProtocolHealth: {
      spfFailureRate: 84.5,
      dkimFailureRate: 79.2,
      dmarcFailureRate: 91.0
    },
    topAttackingDomains: [
      { domain: "micros0ft-portal-auth.com", attacks: 142, category: "Phishing", risk: 96 },
      { domain: "swift-transact-global.net", attacks: 98, category: "Malware", risk: 94 },
      { domain: "hr-workday-verify.com", attacks: 87, category: "Phishing", risk: 91 },
      { domain: "account-security-review.net", attacks: 76, category: "Phishing", risk: 93 },
      { domain: "dhl-express-dispatch.top", attacks: 64, category: "Malware", risk: 97 }
    ]
  },

  // Security Notifications for the dropdown
  notifications: [
    { id: 1, title: "High-Severity Threat Quarantined", desc: "Micros0ft credential harvesting email blocked for 12 recipients.", time: "10m ago", read: false, type: "danger" },
    { id: 2, title: "AI Model Auto-Tuned", desc: "Phishing classifier weights updated. Accuracy improved to 98.6%.", time: "1h ago", read: false, type: "success" },
    { id: 3, title: "Suspicious Spike Detected", desc: "35% surge in phishing targeting Finance department in last 4 hours.", time: "3h ago", read: true, type: "warning" },
    { id: 4, title: "SPF Policy Anomaly", desc: "5 inbound spoofed emails from lookalike domain rejected.", time: "5h ago", read: true, type: "info" }
  ]
};

// Export to window for global browser access
if (typeof window !== 'undefined') {
  window.MOCK_DATA = MOCK_DATA;
}
