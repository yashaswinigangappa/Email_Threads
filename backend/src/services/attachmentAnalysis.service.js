const path = require('path');
const Threat = require('../models/Threat');

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.iso',
  '.img', '.jar', '.hta', '.cpl', '.wsf', '.msc', '.dll', '.com'
]);

const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'
]);

const MACRO_OFFICE_EXTENSIONS = new Set([
  '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.xlam'
]);

class AttachmentAnalysisService {
  /**
   * Analyze an array of attachments
   * @param {Array<Object>} attachments - List of attachments
   */
  static async analyzeAttachments(attachments = []) {
    if (!attachments || attachments.length === 0) {
      return {
        results: [],
        totalAttachments: 0,
        threatsFound: 0,
        overallAttachmentThreatLevel: 'Low',
        overallAttachmentRiskScore: 0
      };
    }

    const results = [];
    let maxRisk = 0;
    let threatsFound = 0;

    for (const att of attachments) {
      const singleAnalysis = await this.analyzeSingleAttachment(att);
      results.push(singleAnalysis);

      if (singleAnalysis.threatLevel === 'High' || singleAnalysis.threatLevel === 'Critical') {
        threatsFound++;
      }
      if (singleAnalysis.riskScore > maxRisk) {
        maxRisk = singleAnalysis.riskScore;
      }
    }

    let overallThreatLevel = 'Low';
    if (threatsFound > 0 || maxRisk >= 80) overallThreatLevel = 'Critical';
    else if (maxRisk >= 50) overallThreatLevel = 'High';
    else if (maxRisk >= 25) overallThreatLevel = 'Medium';

    return {
      results,
      totalAttachments: results.length,
      threatsFound,
      overallAttachmentThreatLevel: overallThreatLevel,
      overallAttachmentRiskScore: maxRisk
    };
  }

  /**
   * Analyze a single attachment
   * @param {Object} att - Attachment details { filename, size, mimeType, sha256 }
   */
  static async analyzeSingleAttachment(att) {
    const filename = att.filename || 'unnamed_attachment';
    const size = att.size || 0;
    const contentType = att.contentType || att.mimeType || 'application/octet-stream';
    const sha256 = att.sha256 || '';

    const reasons = [];
    let riskScore = 0;
    let isDangerousType = false;
    let hasDoubleExtension = false;

    const ext = path.extname(filename).toLowerCase();
    const nameWithoutExt = path.basename(filename, ext);
    const secondaryExt = path.extname(nameWithoutExt).toLowerCase();

    // 1. Double extension check (e.g. invoice.pdf.exe)
    if (secondaryExt && secondaryExt.length >= 3) {
      hasDoubleExtension = true;
      reasons.push(`Double extension obfuscation (${secondaryExt}${ext})`);
      riskScore += 50;
    }

    // 2. Dangerous executable/script extension check
    if (DANGEROUS_EXTENSIONS.has(ext)) {
      isDangerousType = true;
      reasons.push(`High-risk executable file type (${ext})`);
      riskScore += 60;
    } else if (MACRO_OFFICE_EXTENSIONS.has(ext)) {
      isDangerousType = true;
      reasons.push(`Macro-enabled Office document (${ext})`);
      riskScore += 45;
    } else if (ARCHIVE_EXTENSIONS.has(ext)) {
      reasons.push(`Compressed archive container (${ext}) - may conceal payload`);
      riskScore += 25;
    }

    // 3. MIME type spoofing detection
    if (ext === '.pdf' && contentType.includes('application/x-msdownload')) {
      isDangerousType = true;
      reasons.push('MIME type spoofing: Executable payload masked as PDF document');
      riskScore += 70;
    }

    // 4. Check SHA-256 against known malware IOC signatures
    if (sha256) {
      try {
        const threatRecord = await Threat.findOne({ indicator: sha256, isActive: true });
        if (threatRecord) {
          reasons.push(`Known malware hash signature matched (${threatRecord.description || 'Malware payload'})`);
          riskScore = 100;
        }
      } catch (e) {
        // Fallback gracefully
      }
    }

    riskScore = Math.min(100, riskScore);

    let threatLevel = 'Low';
    if (riskScore >= 75) threatLevel = 'Critical';
    else if (riskScore >= 45) threatLevel = 'High';
    else if (riskScore >= 20) threatLevel = 'Medium';

    return {
      filename,
      size,
      contentType,
      sha256,
      threatLevel,
      isDangerousType,
      hasDoubleExtension,
      riskScore,
      reasons
    };
  }
}

module.exports = AttachmentAnalysisService;
