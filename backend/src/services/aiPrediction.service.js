const axios = require('axios');
const config = require('../config/environment');
const logger = require('../utils/logger');

// Phishing urgency keywords & social engineering patterns
const URGENT_KEYWORDS = [
  'urgent', 'immediately', 'verify your account', 'account suspended',
  'action required', 'unauthorized access', '24 hours', 'security alert',
  'click here to confirm', 'password expired', 'login immediately', 'wire transfer',
  'billing failure', 'confirm identity', 'invoice attached', 'gift card', 'tax refund'
];

const SPAM_KEYWORDS = [
  'winner', 'lottery', 'free offer', 'claim now', 'casino', 'discount',
  'exclusive deal', 'make money fast', 'viagra', 'weight loss', 'unsubscribe'
];

class AiPredictionService {
  /**
   * Predict email classification using FastAPI microservice or built-in heuristic engine
   * @param {Object} emailData - { subject, body, sender, headers, urls, attachments }
   */
  static async predict(emailData) {
    const {
      subject = '',
      body = '',
      sender = '',
      headers = {},
      urls = [],
      attachments = []
    } = emailData;

    // 1. Attempt to call external AI FastAPI service
    try {
      const response = await axios.post(
        `${config.aiService.url}/predict`,
        {
          subject,
          body,
          sender: typeof sender === 'string' ? sender : sender.email || sender.raw || '',
          headers,
          urls: urls.map((u) => (typeof u === 'string' ? u : u.url)),
          attachments: attachments.map((a) => (typeof a === 'string' ? a : a.filename))
        },
        {
          timeout: config.aiService.timeoutMs
        }
      );

      if (response.data && response.data.class) {
        logger.info(`AI FastAPI Service prediction succeeded: ${response.data.class}`);
        return {
          class: response.data.class.toLowerCase(),
          confidence: response.data.confidence || 90,
          risk_score: response.data.risk_score || response.data.riskScore || 85,
          reasons: response.data.reason || response.data.reasons || ['Model classification triggered'],
          source: 'fastapi'
        };
      }
    } catch (apiError) {
      logger.warn(`AI FastAPI Service unreachable (${apiError.message}). Using intelligent heuristic fallback engine.`);
    }

    // 2. Built-in Intelligent NLP / Heuristic Engine Fallback
    return this.heuristicPredict({ subject, body, sender, headers, urls, attachments });
  }

  /**
   * Rule-based / NLP Heuristic prediction fallback
   */
  static heuristicPredict({ subject = '', body = '', sender = '', headers = {}, urls = [], attachments = [] }) {
    const fullText = `${subject} ${body}`.toLowerCase();
    const reasons = [];
    let phishingScore = 0;
    let spamScore = 0;
    let malwareScore = 0;

    // Check Urgent & Phishing triggers
    let urgentMatches = 0;
    for (const phrase of URGENT_KEYWORDS) {
      if (fullText.includes(phrase)) {
        urgentMatches++;
        phishingScore += 20;
      }
    }
    if (urgentMatches > 0) {
      reasons.push('Urgent and coercive language detected');
    }

    // Check Spam triggers
    let spamMatches = 0;
    for (const phrase of SPAM_KEYWORDS) {
      if (fullText.includes(phrase)) {
        spamMatches++;
        spamScore += 18;
      }
    }
    if (spamMatches > 0) {
      reasons.push('Unsolicited commercial / spam keywords detected');
    }

    // Check Sender authentication headers (SPF, DKIM, DMARC)
    const authResults = headers['authentication-results'] || '';
    const receivedSpf = headers['received-spf'] || '';
    const authText = `${authResults} ${receivedSpf}`.toLowerCase();

    if (authText.includes('spf=fail') || authText.includes('spf fail') || headers.spf === 'fail') {
      phishingScore += 35;
      reasons.push('SPF email authentication failure (Sender Spoofing)');
    }
    if (authText.includes('dkim=fail') || headers.dkim === 'fail') {
      phishingScore += 25;
      reasons.push('DKIM cryptographic signature verification failed');
    }
    if (authText.includes('dmarc=fail') || headers.dmarc === 'fail') {
      phishingScore += 25;
      reasons.push('DMARC domain alignment policy failed');
    }

    // Check URLs
    const urlCount = urls.length;
    let suspiciousUrlCount = 0;
    for (const u of urls) {
      const urlStr = typeof u === 'string' ? u.toLowerCase() : (u.url || '').toLowerCase();
      if (
        urlStr.includes('bit.ly') ||
        urlStr.includes('tinyurl') ||
        urlStr.includes('paypal-security') ||
        urlStr.includes('.xyz') ||
        urlStr.includes('.top') ||
        urlStr.includes('verify') ||
        urlStr.includes('login')
      ) {
        suspiciousUrlCount++;
        phishingScore += 25;
      }
    }
    if (suspiciousUrlCount > 0) {
      reasons.push(`Suspicious / obfuscated URL detected (${suspiciousUrlCount} found)`);
    }

    // Check Attachments
    for (const att of attachments) {
      const filename = (typeof att === 'string' ? att : att.filename || '').toLowerCase();
      if (
        filename.endsWith('.exe') ||
        filename.endsWith('.scr') ||
        filename.endsWith('.vbs') ||
        filename.endsWith('.bat') ||
        filename.includes('.pdf.exe')
      ) {
        malwareScore += 70;
        reasons.push(`Dangerous executable payload attachment detected: ${filename}`);
      } else if (filename.endsWith('.zip') || filename.endsWith('.rar')) {
        malwareScore += 20;
        reasons.push(`Compressed archive attachment detected: ${filename}`);
      }
    }

    // Determine Final Classification Class
    let predictedClass = 'safe';
    let confidence = 88;
    let riskScore = 15;

    if (malwareScore >= 50) {
      predictedClass = 'malware';
      riskScore = Math.min(99, 70 + malwareScore / 3);
      confidence = 94;
    } else if (phishingScore >= 35) {
      predictedClass = 'phishing';
      riskScore = Math.min(96, 50 + phishingScore / 2);
      confidence = Math.min(98, 80 + urgentMatches * 4);
    } else if (spamScore >= 30) {
      predictedClass = 'spam';
      riskScore = Math.min(75, 30 + spamScore / 2);
      confidence = 90;
    } else {
      predictedClass = 'safe';
      riskScore = 8;
      confidence = 96;
      reasons.push('No malicious indicators or spoofing signatures identified');
    }

    return {
      class: predictedClass,
      confidence: Math.round(confidence),
      risk_score: Math.round(riskScore),
      reasons,
      source: 'heuristic_nlp_engine'
    };
  }
}

module.exports = AiPredictionService;
