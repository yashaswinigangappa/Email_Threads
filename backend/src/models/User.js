const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Please provide a name'],
      trim: true,
      maxlength: [50, 'Name cannot exceed 50 characters']
    },
    email: {
      type: String,
      required: [true, 'Please provide an email address'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
        'Please provide a valid email'
      ]
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: [6, 'Password must be at least 6 characters'],
      select: false
    },
    avatar: {
      type: String,
      default: ''
    },
    role: {
      type: String,
      enum: ['admin', 'analyst', 'user'],
      default: 'analyst'
    },
    apiKey: {
      type: String,
      unique: true,
      sparse: true
    },
    settings: {
      theme: {
        type: String,
        enum: ['light', 'dark', 'system'],
        default: 'dark'
      },
      notifications: {
        type: Boolean,
        default: true
      },
      autoQuarantine: {
        type: Boolean,
        default: false
      },
      scanPreferences: {
        deepUrlInspection: { type: Boolean, default: true },
        checkAttachmentSandboxing: { type: Boolean, default: true },
        alertThresholdRiskScore: { type: Number, default: 75 }
      }
    }
  },
  {
    timestamps: true
  }
);

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Generate default API key if absent
userSchema.pre('save', function (next) {
  if (!this.apiKey) {
    this.apiKey = `etip_live_${crypto.randomBytes(16).toString('hex')}`;
  }
  next();
});

// Compare password method
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Generate fresh API Key
userSchema.methods.generateApiKey = function () {
  this.apiKey = `etip_live_${crypto.randomBytes(16).toString('hex')}`;
  return this.apiKey;
};

module.exports = mongoose.model('User', userSchema);
