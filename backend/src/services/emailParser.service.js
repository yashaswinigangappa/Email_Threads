const { simpleParser } = require('mailparser');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const logger = require('../utils/logger');

class EmailParserService {
  /**
   * Parse email from either a file path or raw string content
   * @param {string|Buffer} input - File path or raw email buffer/string
   * @param {boolean} isFilePath - True if input is file path
   */
  static async parseEmail(input, isFilePath = true) {
    try {
      let source;
      let rawEmlPath = '';

      if (isFilePath) {
        source = fs.readFileSync(input);
        rawEmlPath = input;
      } else {
        source = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf-8');
      }

      const parsed = await simpleParser(source);

      // Extract basic header information
      const subject = parsed.subject || '(No Subject)';
      const sender = {
        name: parsed.from?.value?.[0]?.name || '',
        email: parsed.from?.value?.[0]?.address || '',
        raw: parsed.from?.text || ''
      };
      const receiver = {
        name: parsed.to?.value?.[0]?.name || '',
        email: parsed.to?.value?.[0]?.address || '',
        raw: parsed.to?.text || ''
      };

      const date = parsed.date || new Date();
      const messageId = parsed.messageId || '';
      const bodyText = parsed.text || '';
      const bodyHtml = parsed.html || '';

      // Extract all headers into a clean map
      const headers = {};
      if (parsed.headers) {
        for (const [key, value] of parsed.headers) {
          headers[key] = typeof value === 'object' && value.value ? value.value : value;
        }
      }

      // Authentication results parsing (SPF, DKIM, DMARC)
      const authResults = this.extractAuthResults(headers);

      // Extract URLs from body text, html, and headers
      const extractedUrls = this.extractUrls(bodyText, bodyHtml);

      // Extract IP addresses from headers and body
      const extractedIPs = this.extractIPs(headers, bodyText);

      // Extract and hash attachments
      const attachments = this.processAttachments(parsed.attachments);

      return {
        subject,
        sender,
        receiver,
        date,
        messageId,
        bodyText,
        bodyHtml,
        headers,
        authResults,
        extractedUrls,
        extractedIPs,
        attachments,
        rawEmlPath
      };
    } catch (error) {
      logger.error(`Email parsing failed: ${error.message}`);
      throw new Error(`Failed to parse email: ${error.message}`);
    }
  }

  /**
   * Extract SPF, DKIM, DMARC status from email headers
   */
  static extractAuthResults(headers) {
    const authHeader = (headers['authentication-results'] || '').toLowerCase();
    const receivedSpf = (headers['received-spf'] || '').toLowerCase();
    const dkimSignature = headers['dkim-signature'] ? 'present' : 'none';

    let spf = 'none';
    if (receivedSpf.includes('pass') || authHeader.includes('spf=pass')) spf = 'pass';
    else if (receivedSpf.includes('fail') || authHeader.includes('spf=fail')) spf = 'fail';
    else if (receivedSpf.includes('softfail') || authHeader.includes('spf=softfail')) spf = 'softfail';
    else if (receivedSpf.includes('neutral') || authHeader.includes('spf=neutral')) spf = 'neutral';

    let dkim = 'none';
    if (authHeader.includes('dkim=pass')) dkim = 'pass';
    else if (authHeader.includes('dkim=fail')) dkim = 'fail';
    else if (dkimSignature === 'present') dkim = 'unverified';

    let dmarc = 'none';
    if (authHeader.includes('dmarc=pass')) dmarc = 'pass';
    else if (authHeader.includes('dmarc=fail')) dmarc = 'fail';

    return {
      spf,
      dkim,
      dmarc,
      receivedSpf: headers['received-spf'] || '',
      arc: authHeader.includes('arc=pass') ? 'pass' : 'none'
    };
  }

  /**
   * Extract all URLs from body and HTML
   */
  static extractUrls(bodyText = '', bodyHtml = '') {
    const urlRegex = /(https?:\/\/[^\s<>"'\)]+)/gi;
    const combinedContent = `${bodyText} ${bodyHtml}`;
    const matches = combinedContent.match(urlRegex) || [];

    const urlSet = new Set();
    const results = [];

    for (const rawUrl of matches) {
      const cleanUrl = rawUrl.replace(/[.,;:]+$/, '');
      if (!urlSet.has(cleanUrl)) {
        urlSet.add(cleanUrl);
        try {
          const parsed = new URL(cleanUrl);
          results.push({
            url: cleanUrl,
            domain: parsed.hostname,
            protocol: parsed.protocol.replace(':', '')
          });
        } catch (e) {
          results.push({
            url: cleanUrl,
            domain: cleanUrl.split('/')[2] || cleanUrl,
            protocol: 'unknown'
          });
        }
      }
    }

    return results;
  }

  /**
   * Extract IPs from Received headers and content
   */
  static extractIPs(headers = {}, bodyText = '') {
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ips = new Set();

    // Check Received headers
    const received = headers['received'];
    const receivedHeaders = Array.isArray(received) ? received.join(' ') : (received || '');
    const receivedMatches = receivedHeaders.match(ipRegex) || [];
    receivedMatches.forEach((ip) => {
      // Exclude localhost/private router IPs if desired or keep all
      if (!ip.startsWith('127.')) ips.add(ip);
    });

    // Check body text
    const bodyMatches = bodyText.match(ipRegex) || [];
    bodyMatches.forEach((ip) => {
      if (!ip.startsWith('127.')) ips.add(ip);
    });

    return Array.from(ips);
  }

  /**
   * Process email attachments and generate hashes
   */
  static processAttachments(attachments = []) {
    if (!attachments || !Array.isArray(attachments)) return [];

    return attachments.map((att) => {
      const content = att.content || Buffer.from('');
      const sha256 = crypto.createHash('sha256').update(content).digest('hex');
      const md5 = crypto.createHash('md5').update(content).digest('hex');

      return {
        filename: att.filename || 'unnamed_attachment',
        contentType: att.contentType || 'application/octet-stream',
        size: att.size || content.length,
        sha256,
        md5,
        storedPath: ''
      };
    });
  }
}

module.exports = EmailParserService;
