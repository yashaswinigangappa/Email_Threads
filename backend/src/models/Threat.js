const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema(
  {
    indicator: {
      type: String,
      required: true,
      trim: true,
      index: true
    },
    indicatorType: {
      type: String,
      enum: ['domain', 'ip', 'url', 'hash_sha256', 'sender_email'],
      required: true
    },
    threatType: {
      type: String,
      enum: ['phishing', 'malware', 'spam', 'spoofing', 'ransomware', 'c2'],
      required: true
    },
    severity: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical'],
      default: 'Medium'
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 50
    },
    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 80
    },
    description: {
      type: String,
      default: ''
    },
    source: {
      type: String,
      default: 'ETIP Global Feed'
    },
    firstSeen: {
      type: Date,
      default: Date.now
    },
    lastSeen: {
      type: Date,
      default: Date.now
    },
    isActive: {
      type: Boolean,
      default: true
    },
    tags: [{ type: String }]
  },
  {
    timestamps: true
  }
);

threatSchema.index({ indicator: 1, indicatorType: 1 }, { unique: true });

module.exports = mongoose.model('Threat', threatSchema);
