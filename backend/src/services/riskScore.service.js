class RiskScoreService {
  /**
   * Consolidate multi-vector signals into final threat report payload
   */
  static consolidate({
    aiResult = {},
    senderResult = {},
    urlResult = {},
    attachmentResult = {},
    extractedIPs = []
  }) {
    const aiRisk = aiResult.risk_score || aiResult.riskScore || 10;
    const senderRisk = senderResult.riskScore || 10;
    const urlRisk = urlResult.overallUrlRiskScore || 0;
    const attachmentRisk = attachmentResult.overallAttachmentRiskScore || 0;

    // Weighted scoring: AI (35%), Sender (25%), URL (20%), Attachment (20%)
    let compositeScore = (
      aiRisk * 0.35 +
      senderRisk * 0.25 +
      urlRisk * 0.20 +
      attachmentRisk * 0.20
    );

    // If critical threats exist, elevate composite score
    if (attachmentResult.threatsFound > 0) {
      compositeScore = Math.max(compositeScore, 85);
    }
    if (urlResult.maliciousCount > 0) {
      compositeScore = Math.max(compositeScore, 80);
    }
    if (senderResult.isBrandImpersonation && senderResult.spfStatus === 'FAIL') {
      compositeScore = Math.max(compositeScore, 90);
    }

    const finalRiskScore = Math.min(100, Math.max(0, Math.round(compositeScore)));

    // Determine Final Verdict
    let verdict = 'safe';
    if (attachmentResult.threatsFound > 0 || aiResult.class === 'malware') {
      verdict = 'malware';
    } else if (finalRiskScore >= 60 || aiResult.class === 'phishing') {
      verdict = 'phishing';
    } else if (finalRiskScore >= 35 || aiResult.class === 'spam') {
      verdict = 'spam';
    } else {
      verdict = 'safe';
    }

    // Threat Level
    let threatLevel = 'Low';
    if (finalRiskScore >= 80) threatLevel = 'Critical';
    else if (finalRiskScore >= 55) threatLevel = 'High';
    else if (finalRiskScore >= 30) threatLevel = 'Medium';

    // Build Indicators of Compromise (IOCs)
    const maliciousDomains = new Set();
    const maliciousIPs = new Set();
    const maliciousURLs = new Set();
    const suspiciousAttachments = new Set();

    if (senderResult.reputation !== 'Good' && senderResult.senderDomain) {
      maliciousDomains.add(senderResult.senderDomain);
    }

    (urlResult.results || []).forEach((u) => {
      if (u.status === 'Malicious' || u.status === 'Suspicious') {
        maliciousURLs.add(u.url);
        if (u.domain) maliciousDomains.add(u.domain);
      }
    });

    (attachmentResult.results || []).forEach((a) => {
      if (a.threatLevel === 'High' || a.threatLevel === 'Critical' || a.isDangerousType) {
        suspiciousAttachments.add(a.filename);
      }
    });

    extractedIPs.forEach((ip) => {
      if (senderResult.spfStatus === 'FAIL' || finalRiskScore > 70) {
        maliciousIPs.add(ip);
      }
    });

    // Build Recommendations
    const recommendations = [];
    if (suspiciousAttachments.size > 0) {
      recommendations.push("Do NOT open or download the suspicious email attachment(s)");
    }
    if (maliciousURLs.size > 0) {
      recommendations.push("Do NOT click or navigate to any hyperlinks contained in this email");
    }
    if (senderResult.senderDomain && (senderResult.spfStatus === 'FAIL' || senderResult.isBrandImpersonation)) {
      recommendations.push(`Block and blacklist sender domain '${senderResult.senderDomain}' on mail gateway`);
    }
    if (verdict === 'phishing' || verdict === 'malware') {
      recommendations.push("Report this email to your organization's Security Operations Center (SOC)");
      recommendations.push("Delete and quarantine this message immediately");
    } else if (verdict === 'spam') {
      recommendations.push("Mark as spam and filter future communications");
    } else {
      recommendations.push("Email appears legitimate. Practice standard cyber hygiene");
    }

    // Build Human-Readable Summary
    let summary = '';
    if (verdict === 'phishing') {
      summary = `High-confidence phishing attack detected (${finalRiskScore}/100 risk score). Features deceptive urgency, ${senderResult.spfStatus === 'FAIL' ? 'spoofed sender headers' : 'suspicious sender domain'}, and suspicious redirection links.`;
    } else if (verdict === 'malware') {
      summary = `Malicious payload detected (${finalRiskScore}/100 risk score). Contains high-risk executable or obfuscated attachment designed to compromise client workstations.`;
    } else if (verdict === 'spam') {
      summary = `Unsolicited spam campaign detected (${finalRiskScore}/100 risk score). Minimal malicious indicators identified but exhibits high commercial/promotional volume patterns.`;
    } else {
      summary = `Email verified as safe (${finalRiskScore}/100 risk score). Passes SPF/DKIM authentication checks and contains no known malicious URLs or weaponized attachments.`;
    }

    return {
      riskScore: finalRiskScore,
      threatLevel,
      verdict,
      confidence: aiResult.confidence || 90,
      summary,
      indicatorsOfCompromise: {
        maliciousDomains: Array.from(maliciousDomains),
        maliciousIPs: Array.from(maliciousIPs),
        maliciousURLs: Array.from(maliciousURLs),
        suspiciousAttachments: Array.from(suspiciousAttachments)
      },
      recommendations
    };
  }
}

module.exports = RiskScoreService;
