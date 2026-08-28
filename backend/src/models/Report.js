const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    emailId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Email',
      required: true,
      index: true
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: false,
      index: true
    },
    verdict: {
      type: String,
      enum: ['safe', 'spam', 'phishing', 'malware'],
      required: true,
      index: true
    },
    threatLevel: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical'],
      default: 'Low'
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      required: true,
      index: true
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    summary: {
      type: String,
      default: ''
    },
    aiAnalysis: {
      prediction: { type: String },
      confidence: { type: Number },
      risk_score: { type: Number },
      reasons: [{ type: String }],
      modelSource: { type: String, default: 'fastapi_or_heuristic' }
    },
    senderAnalysis: {
      senderEmail: { type: String },
      senderDomain: { type: String },
      reputation: { type: String },
      domainAge: { type: String },
      domainAgeDays: { type: Number },
      spfStatus: { type: String },
      dkimStatus: { type: String },
      dmarcStatus: { type: String },
      dnsValid: { type: Boolean, default: false },
      mxValid: { type: Boolean, default: false },
      isDisposable: { type: Boolean, default: false },
      riskScore: { type: Number, default: 0 }
    },
    urlAnalysis: [
      {
        url: { type: String },
        domain: { type: String },
        status: { type: String, enum: ['Safe', 'Suspicious', 'Malicious'] },
        threatLevel: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'] },
        isShortener: { type: Boolean, default: false },
        isIpUrl: { type: Boolean, default: false },
        suspiciousTld: { type: Boolean, default: false },
        blacklistMatch: { type: Boolean, default: false },
        riskScore: { type: Number, default: 0 },
        categories: [{ type: String }]
      }
    ],
    attachmentAnalysis: [
      {
        filename: { type: String },
        size: { type: Number },
        contentType: { type: String },
        sha256: { type: String },
        threatLevel: { type: String, enum: ['Low', 'Medium', 'High', 'Critical'] },
        isDangerousType: { type: Boolean, default: false },
        hasDoubleExtension: { type: Boolean, default: false },
        riskScore: { type: Number, default: 0 },
        reasons: [{ type: String }]
      }
    ],
    indicatorsOfCompromise: {
      maliciousDomains: [{ type: String }],
      maliciousIPs: [{ type: String }],
      maliciousURLs: [{ type: String }],
      suspiciousAttachments: [{ type: String }]
    },
    recommendations: [{ type: String }]
  },
  {
    timestamps: true
  }
);

reportSchema.index({ createdAt: -1 });
reportSchema.index({ verdict: 1, createdAt: -1 });

module.exports = mongoose.model('Report', reportSchema);
