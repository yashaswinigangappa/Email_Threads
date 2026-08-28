const mongoose = require('mongoose');

const attachmentSchema = new mongoose.Schema(
  {
    emailId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Email',
      required: true,
      index: true
    },
    filename: {
      type: String,
      required: true
    },
    originalName: {
      type: String
    },
    extension: {
      type: String
    },
    mimeType: {
      type: String
    },
    size: {
      type: Number
    },
    sha256: {
      type: String,
      index: true
    },
    md5: {
      type: String
    },
    isDangerous: {
      type: Boolean,
      default: false
    },
    threatLevel: {
      type: String,
      enum: ['Low', 'Medium', 'High', 'Critical'],
      default: 'Low'
    },
    detectionReasons: [{ type: String }],
    storedPath: {
      type: String
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model('Attachment', attachmentSchema);
