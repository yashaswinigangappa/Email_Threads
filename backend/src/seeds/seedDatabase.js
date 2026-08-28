const mongoose = require('mongoose');
const User = require('../models/User');
const Email = require('../models/Email');
const Report = require('../models/Report');
const Threat = require('../models/Threat');
const Attachment = require('../models/Attachment');
const Analytics = require('../models/Analytics');
const config = require('../config/environment');
const logger = require('../utils/logger');

const seedDatabase = async () => {
  try {
    logger.info(`Connecting to MongoDB at: ${config.mongodb.uri}`);
    await mongoose.connect(config.mongodb.uri);
    logger.info('Connected to MongoDB for database seeding.');

    // 1. Clear existing collections
    logger.info('Clearing old collections...');
    await Promise.all([
      User.deleteMany({}),
      Email.deleteMany({}),
      Report.deleteMany({}),
      Threat.deleteMany({}),
      Attachment.deleteMany({}),
      Analytics.deleteMany({})
    ]);

    // 2. Create Demo Users
    logger.info('Creating demo users...');
    const demoUser = await User.create({
      name: 'CyberSec Analyst',
      email: 'analyst@cybersec.org',
      password: 'Password123!',
      role: 'analyst',
      apiKey: 'etip_live_demo_key_998877665544',
      avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=250&q=80',
      settings: {
        theme: 'dark',
        notifications: true,
        autoQuarantine: true,
        scanPreferences: {
          deepUrlInspection: true,
          checkAttachmentSandboxing: true,
          alertThresholdRiskScore: 75
        }
      }
    });

    const adminUser = await User.create({
      name: 'SOC Administrator',
      email: 'admin@cybersec.org',
      password: 'AdminPassword123!',
      role: 'admin',
      apiKey: 'etip_live_admin_key_112233445566',
      settings: {
        theme: 'dark',
        notifications: true
      }
    });

    // 3. Create Threat Intelligence Indicators
    logger.info('Seeding Threat Intelligence indicators...');
    await Threat.insertMany([
      {
        indicator: 'paypal-security-auth.net',
        indicatorType: 'domain',
        threatType: 'phishing',
        severity: 'Critical',
        riskScore: 98,
        confidence: 99,
        description: 'Brand spoofing credential harvesting portal imitating PayPal login',
        tags: ['phishing', 'brand_impersonation', 'credential_harvesting']
      },
      {
        indicator: 'microsoft365-verify-login.xyz',
        indicatorType: 'domain',
        threatType: 'phishing',
        severity: 'Critical',
        riskScore: 95,
        confidence: 96,
        description: 'Phishing domain harvesting Microsoft 365 OAuth tokens',
        tags: ['phishing', 'm365', 'token_theft']
      },
      {
        indicator: '198.51.100.23',
        indicatorType: 'ip',
        threatType: 'c2',
        severity: 'Critical',
        riskScore: 94,
        confidence: 95,
        description: 'Command and Control server hosting AsyncRAT payload downloaders',
        tags: ['c2', 'rat', 'botnet']
      },
      {
        indicator: 'http://bit.ly/3x8f1-urgent-login',
        indicatorType: 'url',
        threatType: 'phishing',
        severity: 'High',
        riskScore: 90,
        confidence: 92,
        description: 'Shortened URL redirecting to credential harvester portal',
        tags: ['shortener', 'redirect']
      },
      {
        indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        indicatorType: 'hash_sha256',
        threatType: 'malware',
        severity: 'Critical',
        riskScore: 100,
        confidence: 100,
        description: 'Trojan.Win32.Agent malicious dropper executable',
        tags: ['malware', 'trojan', 'dropper']
      }
    ]);

    // 4. Create Sample Scanned Emails & Reports

    // Email 1: Critical Phishing
    const email1 = await Email.create({
      userId: demoUser._id,
      subject: 'Urgent: Verify your PayPal account within 24 hours',
      sender: {
        name: 'PayPal Security Alert',
        email: 'service@paypal-security-alert.com',
        raw: 'PayPal Security Alert <service@paypal-security-alert.com>'
      },
      receiver: {
        name: 'Jane Analyst',
        email: 'analyst@cybersec.org',
        raw: 'Jane Analyst <analyst@cybersec.org>'
      },
      date: new Date(Date.now() - 1000 * 60 * 45),
      bodyText: 'Dear Customer, your account has been temporarily restricted due to unauthorized login attempts. Click here to verify your identity immediately: http://bit.ly/3x8f1-urgent-login or your account will be suspended in 24 hours.',
      bodyHtml: '<p>Dear Customer,</p><p>Your account has been temporarily restricted. <a href="http://bit.ly/3x8f1-urgent-login">Verify Identity</a></p>',
      authResults: {
        spf: 'fail',
        dkim: 'fail',
        dmarc: 'fail',
        receivedSpf: 'fail (domain paypal-security-alert.com does not designate sender IP)'
      },
      extractedUrls: [
        { url: 'http://bit.ly/3x8f1-urgent-login', domain: 'bit.ly', protocol: 'http' }
      ],
      extractedIPs: ['198.51.100.23'],
      status: 'analyzed'
    });

    await Report.create({
      emailId: email1._id,
      userId: demoUser._id,
      verdict: 'phishing',
      threatLevel: 'Critical',
      riskScore: 92,
      confidence: 96,
      summary: 'High-risk phishing attack detected utilizing brand impersonation (PayPal), failed SPF/DKIM authentication, and malicious short URLs.',
      aiAnalysis: {
        prediction: 'phishing',
        confidence: 96,
        risk_score: 92,
        reasons: [
          'SPF and DKIM email authentication checks failed (Sender Spoofing)',
          'Urgent and coercive language detected in subject and body',
          'Suspicious URL shortener obfuscating true destination'
        ],
        modelSource: 'heuristic_nlp_engine'
      },
      senderAnalysis: {
        senderEmail: 'service@paypal-security-alert.com',
        senderDomain: 'paypal-security-alert.com',
        reputation: 'Poor / Dangerous',
        domainAge: '2 Days',
        domainAgeDays: 2,
        spfStatus: 'FAIL',
        dkimStatus: 'FAIL',
        dmarcStatus: 'FAIL',
        dnsValid: true,
        mxValid: true,
        isDisposable: false,
        riskScore: 90
      },
      urlAnalysis: [
        {
          url: 'http://bit.ly/3x8f1-urgent-login',
          domain: 'bit.ly',
          status: 'Malicious',
          threatLevel: 'Critical',
          isShortener: true,
          isIpUrl: false,
          suspiciousTld: false,
          blacklistMatch: true,
          riskScore: 90,
          categories: ['URL Shortener Obfuscation', 'Blacklisted Threat Signature (phishing)']
        }
      ],
      attachmentAnalysis: [],
      indicatorsOfCompromise: {
        maliciousDomains: ['paypal-security-alert.com', 'bit.ly'],
        maliciousIPs: ['198.51.100.23'],
        maliciousURLs: ['http://bit.ly/3x8f1-urgent-login'],
        suspiciousAttachments: []
      },
      recommendations: [
        'Do NOT click or navigate to any hyperlinks contained in this email',
        "Block and blacklist sender domain 'paypal-security-alert.com' on mail gateway",
        "Report this email to your organization's Security Operations Center (SOC)",
        'Delete and quarantine this message immediately'
      ],
      createdAt: new Date(Date.now() - 1000 * 60 * 45)
    });

    // Email 2: Critical Malware
    const email2 = await Email.create({
      userId: demoUser._id,
      subject: 'Invoice Remittance Advice #INV-88921.pdf',
      sender: {
        name: 'Finance Accounts Dept',
        email: 'billing@finance-corp-transfers.xyz',
        raw: 'Finance Accounts Dept <billing@finance-corp-transfers.xyz>'
      },
      receiver: {
        name: 'Jane Analyst',
        email: 'analyst@cybersec.org',
        raw: 'Jane Analyst <analyst@cybersec.org>'
      },
      date: new Date(Date.now() - 1000 * 60 * 120),
      bodyText: 'Please review the attached invoice remittance document for pending account settlement.',
      authResults: { spf: 'fail', dkim: 'none', dmarc: 'none' },
      attachments: [
        {
          filename: 'Invoice_88921.pdf.exe',
          contentType: 'application/x-msdownload',
          size: 52400,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        }
      ],
      extractedIPs: ['203.0.113.88'],
      status: 'analyzed'
    });

    await Report.create({
      emailId: email2._id,
      userId: demoUser._id,
      verdict: 'malware',
      threatLevel: 'Critical',
      riskScore: 98,
      confidence: 99,
      summary: 'Critical malware payload detected with double extension obfuscation (.pdf.exe) and known Trojan hash signature.',
      aiAnalysis: {
        prediction: 'malware',
        confidence: 99,
        risk_score: 98,
        reasons: [
          'Double extension obfuscation (.pdf.exe) concealing executable binary',
          'Dangerous Windows executable file format (.exe)',
          'Matched active Trojan.Win32.Agent IOC signature in threat database'
        ],
        modelSource: 'heuristic_nlp_engine'
      },
      senderAnalysis: {
        senderEmail: 'billing@finance-corp-transfers.xyz',
        senderDomain: 'finance-corp-transfers.xyz',
        reputation: 'Suspicious',
        domainAge: '14 Days',
        domainAgeDays: 14,
        spfStatus: 'FAIL',
        dkimStatus: 'NONE',
        dmarcStatus: 'NONE',
        riskScore: 75
      },
      attachmentAnalysis: [
        {
          filename: 'Invoice_88921.pdf.exe',
          size: 52400,
          contentType: 'application/x-msdownload',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          threatLevel: 'Critical',
          isDangerousType: true,
          hasDoubleExtension: true,
          riskScore: 100,
          reasons: [
            'Double extension obfuscation (.pdf.exe)',
            'High-risk executable file type (.exe)',
            'Known malware hash signature matched'
          ]
        }
      ],
      indicatorsOfCompromise: {
        maliciousDomains: ['finance-corp-transfers.xyz'],
        maliciousIPs: ['203.0.113.88'],
        maliciousURLs: [],
        suspiciousAttachments: ['Invoice_88921.pdf.exe']
      },
      recommendations: [
        'Do NOT open or download the suspicious email attachment(s)',
        "Block and blacklist sender domain 'finance-corp-transfers.xyz' on mail gateway",
        "Report this email to your organization's Security Operations Center (SOC)",
        'Delete and quarantine this message immediately'
      ],
      createdAt: new Date(Date.now() - 1000 * 60 * 120)
    });

    // Email 3: Safe Email
    const email3 = await Email.create({
      userId: demoUser._id,
      subject: 'Weekly Cybersecurity SOC Incident Summary',
      sender: {
        name: 'Google Security Bulletin',
        email: 'security-noreply@google.com',
        raw: 'Google Security Bulletin <security-noreply@google.com>'
      },
      receiver: {
        name: 'Jane Analyst',
        email: 'analyst@cybersec.org',
        raw: 'Jane Analyst <analyst@cybersec.org>'
      },
      date: new Date(Date.now() - 1000 * 60 * 300),
      bodyText: 'Here is your weekly digest of security intelligence updates from Google Security. No incidents detected on your monitored projects.',
      authResults: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
      extractedUrls: [{ url: 'https://security.google.com', domain: 'security.google.com', protocol: 'https' }],
      status: 'analyzed'
    });

    await Report.create({
      emailId: email3._id,
      userId: demoUser._id,
      verdict: 'safe',
      threatLevel: 'Low',
      riskScore: 6,
      confidence: 98,
      summary: 'Legitimate email verified. Passes SPF, DKIM, and DMARC cryptographic checks with clean destination URLs.',
      aiAnalysis: {
        prediction: 'safe',
        confidence: 98,
        risk_score: 6,
        reasons: ['No malicious indicators or spoofing signatures identified'],
        modelSource: 'heuristic_nlp_engine'
      },
      senderAnalysis: {
        senderEmail: 'security-noreply@google.com',
        senderDomain: 'google.com',
        reputation: 'Good',
        domainAge: '3+ Years',
        domainAgeDays: 1200,
        spfStatus: 'PASS',
        dkimStatus: 'PASS',
        dmarcStatus: 'PASS',
        riskScore: 5
      },
      urlAnalysis: [
        {
          url: 'https://security.google.com',
          domain: 'security.google.com',
          status: 'Safe',
          threatLevel: 'Low',
          isShortener: false,
          isIpUrl: false,
          suspiciousTld: false,
          blacklistMatch: false,
          riskScore: 0,
          categories: []
        }
      ],
      attachmentAnalysis: [],
      indicatorsOfCompromise: {
        maliciousDomains: [],
        maliciousIPs: [],
        maliciousURLs: [],
        suspiciousAttachments: []
      },
      recommendations: ['Email appears legitimate. Practice standard cyber hygiene'],
      createdAt: new Date(Date.now() - 1000 * 60 * 300)
    });

    // 5. Seed Daily Analytics Rollups
    logger.info('Seeding Analytics metrics...');
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    await Analytics.create({
      date: today,
      totalScans: 128,
      safeCount: 74,
      spamCount: 26,
      phishingCount: 22,
      malwareCount: 6,
      topAttackedDomains: [
        { domain: 'paypal-security-alert.com', count: 84 },
        { domain: 'finance-corp-transfers.xyz', count: 62 },
        { domain: 'microsoft365-verify.xyz', count: 45 }
      ],
      topThreatTypes: [
        { type: 'phishing', count: 22 },
        { type: 'spam', count: 26 },
        { type: 'malware', count: 6 },
        { type: 'safe', count: 74 }
      ]
    });

    logger.info('===========================================================');
    logger.info('  DATABASE SEEDING COMPLETED SUCCESSFULLY!');
    logger.info('===========================================================');
    logger.info('  Demo User Credentials:');
    logger.info('  Email:    analyst@cybersec.org');
    logger.info('  Password: Password123!');
    logger.info('  API Key:  etip_live_demo_key_998877665544');
    logger.info('-----------------------------------------------------------');
    logger.info('  Admin User Credentials:');
    logger.info('  Email:    admin@cybersec.org');
    logger.info('  Password: AdminPassword123!');
    logger.info('  API Key:  etip_live_admin_key_112233445566');
    logger.info('===========================================================');

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    logger.error(`Database seeding failed: ${error.message}\n${error.stack}`);
    process.exit(1);
  }
};

seedDatabase();
