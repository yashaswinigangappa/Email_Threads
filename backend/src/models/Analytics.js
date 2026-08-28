const mongoose = require('mongoose');

const analyticsSchema = new mongoose.Schema(
  {
    date: {
      type: Date,
      required: true,
      unique: true,
      index: true
    },
    totalScans: { type: Number, default: 0 },
    safeCount: { type: Number, default: 0 },
    spamCount: { type: Number, default: 0 },
    phishingCount: { type: Number, default: 0 },
    malwareCount: { type: Number, default: 0 },
    topAttackedDomains: [
      {
        domain: { type: String },
        count: { type: Number, default: 0 }
      }
    ],
    topThreatTypes: [
      {
        type: { type: String },
        count: { type: Number, default: 0 }
      }
    ]
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Analytics', analyticsSchema);
