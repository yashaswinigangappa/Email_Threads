const dns = require('dns').promises;
const logger = require('../utils/logger');

// Known disposable email provider domains
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
  'sharklasers.com', 'throwawaymail.com', 'getairmail.com', 'yopmail.com',
  'dispostable.com', 'trashmail.com'
]);

// Well-known trusted brands often spoofed
const POPULAR_BRANDS = [
  'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix',
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'dhl', 'fedex', 'ups'
];

/**
 * Fast DNS resolve with timeout
 */
const resolveMxWithTimeout = (domain, timeoutMs = 400) => {
  return Promise.race([
    dns.resolveMx(domain),
    new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), timeoutMs))
  ]);
};

class SenderAnalysisService {
  /**
   * Analyze sender email address and authentication flags
   * @param {string} emailAddress - Sender's email address
   * @param {Object} authResults - Extracted SPF/DKIM/DMARC results
   */
  static async analyzeSender(emailAddress, authResults = {}) {
    if (!emailAddress || typeof emailAddress !== 'string') {
      return {
        senderEmail: '',
        senderDomain: '',
        reputation: 'Unknown',
        domainAge: 'Unknown',
        domainAgeDays: 0,
        spfStatus: 'None',
        dkimStatus: 'None',
        dmarcStatus: 'None',
        dnsValid: false,
        mxValid: false,
        isDisposable: false,
        riskScore: 20
      };
    }

    const domain = emailAddress.split('@')[1]?.toLowerCase() || '';
    const isDisposable = DISPOSABLE_DOMAINS.has(domain);

    let spfStatus = (authResults.spf || 'none').toUpperCase();
    let dkimStatus = (authResults.dkim || 'none').toUpperCase();
    let dmarcStatus = (authResults.dmarc || 'none').toUpperCase();

    let dnsValid = false;
    let mxValid = false;

    // Check MX records with fast timeout
    if (domain) {
      try {
        const mxRecords = await resolveMxWithTimeout(domain, 300);
        if (mxRecords && mxRecords.length > 0) {
          mxValid = true;
          dnsValid = true;
        }
      } catch (err) {
        dnsValid = false;
        mxValid = false;
      }
    }

    // Check brand spoofing / typosquatting (e.g. paypal-security.com, support-microsoft-verify.com)
    let isBrandImpersonation = false;
    let impersonatedBrand = '';

    for (const brand of POPULAR_BRANDS) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.net`)) {
        isBrandImpersonation = true;
        impersonatedBrand = brand;
        break;
      }
    }

    // Calculate Domain Age simulation / heuristics
    let domainAge = '3+ Years';
    let domainAgeDays = 1200;

    if (isBrandImpersonation || domain.includes('temp') || domain.includes('sec-verify')) {
      domainAge = '2 Days';
      domainAgeDays = 2;
    } else if (isDisposable) {
      domainAge = '1 Month';
      domainAgeDays = 30;
    } else if (domain.endsWith('.xyz') || domain.endsWith('.top') || domain.endsWith('.buzz')) {
      domainAge = '14 Days';
      domainAgeDays = 14;
    }

    // Calculate Sender Risk Score (0-100)
    let riskScore = 10;
    if (spfStatus === 'FAIL') riskScore += 35;
    if (dkimStatus === 'FAIL') riskScore += 25;
    if (dmarcStatus === 'FAIL') riskScore += 20;
    if (isBrandImpersonation) riskScore += 40;
    if (isDisposable) riskScore += 30;
    if (!mxValid && domain) riskScore += 25;
    if (domainAgeDays < 7) riskScore += 25;

    riskScore = Math.min(100, riskScore);

    // Determine reputation tag
    let reputation = 'Good';
    if (riskScore >= 75) reputation = 'Poor / Dangerous';
    else if (riskScore >= 40) reputation = 'Suspicious';
    else if (riskScore >= 20) reputation = 'Moderate';

    return {
      senderEmail: emailAddress,
      senderDomain: domain,
      reputation,
      domainAge,
      domainAgeDays,
      spfStatus: spfStatus || 'None',
      dkimStatus: dkimStatus || 'None',
      dmarcStatus: dmarcStatus || 'None',
      dnsValid,
      mxValid,
      isDisposable,
      isBrandImpersonation,
      impersonatedBrand,
      riskScore
    };
  }
}

module.exports = SenderAnalysisService;
