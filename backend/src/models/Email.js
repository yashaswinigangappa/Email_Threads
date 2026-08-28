const mongoose = require('mongoose');

const emailSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: false
    },
    subject: {
      type: String,
      default: '(No Subject)',
      trim: true
    },
    sender: {
      name: { type: String, default: '' },
      email: { type: String, default: '', lowercase: true, trim: true },
      raw: { type: String, default: '' }
    },
    receiver: {
      name: { type: String, default: '' },
      email: { type: String, default: '', lowercase: true, trim: true },
      raw: { type: String, default: '' }
    },
    cc: [{ type: String }],
    bcc: [{ type: String }],
    date: {
      type: Date,
      default: Date.now
    },
    messageId: {
      type: String,
      default: ''
    },
    bodyText: {
      type: String,
      default: ''
    },
    bodyHtml: {
      type: String,
      default: ''
    },
    headers: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: {}
    },
    extractedUrls: [
      {
        url: { type: String },
        domain: { type: String },
        protocol: { type: String }
      }
    ],
    extractedIPs: [{ type: String }],
    attachments: [
      {
        filename: { type: String },
        contentType: { type: String },
        size: { type: Number },
        sha256: { type: String },
        md5: { type: String },
        storedPath: { type: String }
      }
    ],
    authResults: {
      spf: { type: String, default: 'none' }, // pass, fail, softfail, neutral, none
      dkim: { type: String, default: 'none' },
      dmarc: { type: String, default: 'none' },
      receivedSpf: { type: String, default: '' },
      arc: { type: String, default: 'none' }
    },
    rawEmlPath: {
      type: String,
      default: ''
    },
    status: {
      type: String,
      enum: ['uploaded', 'analyzed', 'archived', 'failed'],
      default: 'uploaded'
    }
  },
  {
    timestamps: true
  }
);

emailSchema.index({ userId: 1, createdAt: -1 });
emailSchema.index({ 'sender.email': 1 });
emailSchema.index({ subject: 'text', bodyText: 'text' });

module.exports = mongoose.model('Email', emailSchema);
