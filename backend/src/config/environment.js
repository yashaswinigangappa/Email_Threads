const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10) || 5000,
  clientUrl: process.env.CLIENT_URL || 'http://localhost:3000',
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/email_threat_intelligence',
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'super_secret_jwt_key_sih26106_email_threat_platform_2026',
    expiresIn: process.env.JWT_EXPIRES_IN || '7d',
  },
  aiService: {
    url: process.env.AI_SERVICE_URL || 'http://localhost:8000',
    timeoutMs: parseInt(process.env.AI_SERVICE_TIMEOUT_MS, 10) || 5000,
  },
  upload: {
    maxSize: parseInt(process.env.MAX_FILE_SIZE, 10) || 26214400, // 25MB
    directory: process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads'),
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 100,
  }
};

module.exports = config;
