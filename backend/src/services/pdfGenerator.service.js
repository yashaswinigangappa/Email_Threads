const PDFDocument = require('pdfkit');

class PdfGeneratorService {
  /**
   * Generates a cyber threat intelligence PDF report stream
   * @param {Object} report - Report data object
   * @param {Object} email - Email data object
   * @returns {PDFDocument} - Streamable PDF document instance
   */
  static generateReportPdf(report, email = {}) {
    const doc = new PDFDocument({
      size: 'A4',
      margin: 40,
      info: {
        Title: `ETIP Threat Report - ${report._id || report.id}`,
        Author: 'Email Threat Intelligence Platform',
        Subject: 'Cybersecurity Threat Analysis Report'
      }
    });

    // Theme colors
    const colors = {
      primary: '#0f172a',
      accent: '#2563eb',
      dark: '#1e293b',
      gray: '#64748b',
      lightGray: '#f1f5f9',
      white: '#ffffff',
      safe: '#16a34a',
      spam: '#eab308',
      phishing: '#f97316',
      malware: '#dc2626'
    };

    const verdictColor =
      report.verdict === 'malware' ? colors.malware :
      report.verdict === 'phishing' ? colors.phishing :
      report.verdict === 'spam' ? colors.spam : colors.safe;

    // Header Background
    doc.rect(0, 0, doc.page.width, 90).fill(colors.primary);

    // Title
    doc.fillColor(colors.white)
      .fontSize(18)
      .font('Helvetica-Bold')
      .text('EMAIL THREAT INTELLIGENCE PLATFORM', 40, 25);

    doc.fontSize(10)
      .font('Helvetica')
      .fillColor('#94a3b8')
      .text(`INCIDENT & THREAT ANALYSIS REPORT | SIH26106`, 40, 48);

    doc.fontSize(8)
      .text(`Generated: ${new Date().toUTCString()} | Report ID: ${report._id || report.id || 'N/A'}`, 40, 65);

    // Threat Verdict & Score Banner
    const bannerTop = 105;
    doc.roundedRect(40, bannerTop, doc.page.width - 80, 85, 6).fill(colors.lightGray);

    // Verdict Badge
    doc.roundedRect(55, bannerTop + 15, 140, 55, 4).fill(verdictColor);
    doc.fillColor(colors.white)
      .fontSize(10)
      .font('Helvetica-Bold')
      .text('THREAT VERDICT', 65, bannerTop + 24, { width: 120, align: 'center' });

    doc.fontSize(16)
      .text((report.verdict || 'UNKNOWN').toUpperCase(), 65, bannerTop + 42, { width: 120, align: 'center' });

    // Risk Score Box
    doc.fillColor(colors.dark)
      .fontSize(11)
      .font('Helvetica-Bold')
      .text('RISK SCORE', 215, bannerTop + 22);

    doc.fontSize(24)
      .fillColor(verdictColor)
      .text(`${report.riskScore || 0}/100`, 215, bannerTop + 38);

    // Confidence Box
    doc.fillColor(colors.dark)
      .fontSize(11)
      .font('Helvetica-Bold')
      .text('CONFIDENCE', 330, bannerTop + 22);

    doc.fontSize(24)
      .fillColor(colors.accent)
      .text(`${report.confidence || 90}%`, 330, bannerTop + 38);

    // Threat Level
    doc.fillColor(colors.dark)
      .fontSize(11)
      .font('Helvetica-Bold')
      .text('SEVERITY', 440, bannerTop + 22);

    doc.fontSize(20)
      .fillColor(verdictColor)
      .text(`${report.threatLevel || 'Low'}`, 440, bannerTop + 40);

    // Executive Summary
    let currentY = bannerTop + 100;
    doc.fillColor(colors.primary)
      .fontSize(12)
      .font('Helvetica-Bold')
      .text('EXECUTIVE SUMMARY', 40, currentY);

    currentY += 16;
    doc.fillColor(colors.dark)
      .fontSize(9)
      .font('Helvetica')
      .text(report.summary || 'Threat analysis conducted across headers, sender reputation, embedded URLs, and attachments.', 40, currentY, {
        width: doc.page.width - 80,
        lineGap: 3
      });

    // Email Metadata Section
    currentY += 40;
    doc.fillColor(colors.primary)
      .fontSize(12)
      .font('Helvetica-Bold')
      .text('EMAIL METADATA & PARSED DETAILS', 40, currentY);

    currentY += 16;
    doc.roundedRect(40, currentY, doc.page.width - 80, 75, 4).stroke(colors.gray);

    const metaY = currentY + 8;
    const senderStr = email.sender?.raw || email.sender?.email || report.senderAnalysis?.senderEmail || 'N/A';
    const receiverStr = email.receiver?.raw || email.receiver?.email || 'N/A';
    const subjectStr = email.subject || 'N/A';

    doc.fontSize(8.5).font('Helvetica-Bold').fillColor(colors.dark).text('Subject: ', 50, metaY);
    doc.font('Helvetica').text(subjectStr, 110, metaY, { width: 400 });

    doc.font('Helvetica-Bold').text('Sender: ', 50, metaY + 16);
    doc.font('Helvetica').text(senderStr, 110, metaY + 16, { width: 400 });

    doc.font('Helvetica-Bold').text('Recipient: ', 50, metaY + 32);
    doc.font('Helvetica').text(receiverStr, 110, metaY + 32, { width: 400 });

    doc.font('Helvetica-Bold').text('Auth Status: ', 50, metaY + 48);
    const spf = report.senderAnalysis?.spfStatus || 'None';
    const dkim = report.senderAnalysis?.dkimStatus || 'None';
    const dmarc = report.senderAnalysis?.dmarcStatus || 'None';
    doc.font('Helvetica').text(`SPF: ${spf} | DKIM: ${dkim} | DMARC: ${dmarc}`, 110, metaY + 48);

    // AI Threat Analysis & Explainability
    currentY += 90;
    doc.fillColor(colors.primary)
      .fontSize(12)
      .font('Helvetica-Bold')
      .text('AI THREAT DETECTION & EXPLAINABILITY REASONS', 40, currentY);

    currentY += 16;
    const aiReasons = report.aiAnalysis?.reasons || [];
    if (aiReasons.length === 0) {
      doc.fontSize(9).font('Helvetica').fillColor(colors.gray).text('• No critical threat triggers detected.', 50, currentY);
      currentY += 14;
    } else {
      aiReasons.forEach((reason) => {
        doc.fontSize(9).font('Helvetica-Bold').fillColor(colors.malware).text('• ', 50, currentY);
        doc.font('Helvetica').fillColor(colors.dark).text(reason, 62, currentY, { width: 480 });
        currentY += 15;
      });
    }

    // Indicators of Compromise (IOC)
    currentY += 15;
    doc.fillColor(colors.primary)
      .fontSize(12)
      .font('Helvetica-Bold')
      .text('INDICATORS OF COMPROMISE (IOCs)', 40, currentY);

    currentY += 16;
    const ioc = report.indicatorsOfCompromise || {};
    const domains = ioc.maliciousDomains || [];
    const urls = ioc.maliciousURLs || [];
    const attachments = ioc.suspiciousAttachments || [];
    const ips = ioc.maliciousIPs || [];

    doc.fontSize(8.5).font('Helvetica-Bold').fillColor(colors.dark).text('Malicious Domains: ', 50, currentY);
    doc.font('Helvetica').fillColor(domains.length ? colors.malware : colors.gray)
      .text(domains.length ? domains.join(', ') : 'None detected', 160, currentY);

    currentY += 14;
    doc.font('Helvetica-Bold').fillColor(colors.dark).text('Malicious URLs: ', 50, currentY);
    doc.font('Helvetica').fillColor(urls.length ? colors.malware : colors.gray)
      .text(urls.length ? urls.slice(0, 3).join(', ') : 'None detected', 160, currentY, { width: 380 });

    currentY += 14;
    doc.font('Helvetica-Bold').fillColor(colors.dark).text('Malicious Attachments: ', 50, currentY);
    doc.font('Helvetica').fillColor(attachments.length ? colors.malware : colors.gray)
      .text(attachments.length ? attachments.join(', ') : 'None detected', 160, currentY);

    currentY += 14;
    doc.font('Helvetica-Bold').fillColor(colors.dark).text('Suspicious IP Nodes: ', 50, currentY);
    doc.font('Helvetica').fillColor(ips.length ? colors.malware : colors.gray)
      .text(ips.length ? ips.join(', ') : 'None detected', 160, currentY);

    // Recommended Mitigation Steps
    currentY += 25;
    doc.fillColor(colors.primary)
      .fontSize(12)
      .font('Helvetica-Bold')
      .text('RECOMMENDED MITIGATION ACTIONS', 40, currentY);

    currentY += 16;
    const recommendations = report.recommendations || [];
    recommendations.forEach((rec, idx) => {
      doc.fontSize(9).font('Helvetica-Bold').fillColor(colors.accent).text(`[Step ${idx + 1}] `, 50, currentY);
      doc.font('Helvetica').fillColor(colors.dark).text(rec, 95, currentY, { width: 450 });
      currentY += 15;
    });

    // Footer
    doc.fontSize(8)
      .font('Helvetica')
      .fillColor(colors.gray)
      .text('Confidential - Generated by AI Email Threat Intelligence Platform (ETIP). For SOC Analyst use only.', 40, doc.page.height - 35, {
        align: 'center',
        width: doc.page.width - 80
      });

    return doc;
  }
}

module.exports = PdfGeneratorService;
