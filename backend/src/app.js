const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const config = require('./config/environment');
const morganMiddleware = require('./middlewares/logger.middleware');
const { generalLimiter } = require('./middlewares/rateLimiter.middleware');
const { errorHandler, notFoundHandler } = require('./middlewares/error.middleware');
const setupSwagger = require('./config/swagger');

// Import Module Routers
const authRoutes = require('./modules/auth/auth.routes');
const dashboardRoutes = require('./modules/dashboard/dashboard.routes');
const emailRoutes = require('./modules/email/email.routes');
const aiRoutes = require('./modules/ai/ai.routes');
const senderRoutes = require('./modules/sender/sender.routes');
const urlRoutes = require('./modules/url/url.routes');
const attachmentRoutes = require('./modules/attachment/attachment.routes');
const reportRoutes = require('./modules/report/report.routes');
const historyRoutes = require('./modules/history/history.routes');
const threatFeedRoutes = require('./modules/threatFeed/threatFeed.routes');
const analyticsRoutes = require('./modules/analytics/analytics.routes');
const settingsRoutes = require('./modules/settings/settings.routes');

// Import controllers for direct alias routes
const emailController = require('./modules/email/email.controller');
const reportController = require('./modules/report/report.controller');
const historyController = require('./modules/history/history.controller');
const aiController = require('./modules/ai/ai.controller');
const authController = require('./modules/auth/auth.controller');
const upload = require('./middlewares/upload.middleware');
const { optionalAuth, protect } = require('./middlewares/auth.middleware');

const app = express();

// Security Middlewares
app.use(helmet({
  crossOriginResourcePolicy: false
}));

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));

// Body Parsers
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));

// Logging & Rate Limiting
app.use(morganMiddleware);
app.use('/api/', generalLimiter);

// Serve Swagger Documentation
setupSwagger(app);

// Health Check API
app.get(['/', '/health', '/api/health'], (req, res) => {
  res.status(200).json({
    status: 'online',
    platform: 'SIH26106 Email Threat Intelligence Platform Backend',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    documentation: '/api-docs'
  });
});

// Primary API Routes under /api prefix
app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/email', emailRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/sender-analysis', senderRoutes);
app.use('/api/url', urlRoutes);
app.use('/api/attachment', attachmentRoutes);
app.use('/api/report', reportRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/threat-feed', threatFeedRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/settings', settingsRoutes);

// Compatibility Alias Routes (Matching Member 4 Team Task Blueprint page 3 & 4)
app.post('/login', authController.login);
app.post('/signup', authController.signup);
app.post('/upload-email', optionalAuth, upload.single('email_file'), emailController.uploadEmail);
app.post('/analyze', optionalAuth, upload.single('email_file'), emailController.analyzeEmail);
app.get('/report/:id', optionalAuth, reportController.getReportById);
app.get('/report/download/:id', optionalAuth, reportController.downloadPdf);
app.get('/history', optionalAuth, historyController.getHistory);
app.delete('/history/:id', optionalAuth, historyController.deleteHistoryItem);
app.delete('/history', optionalAuth, historyController.clearHistory);
app.get('/sender-analysis/:email', optionalAuth, senderRoutes);
app.get('/threat-feed', optionalAuth, threatFeedRoutes);
app.get('/analytics', optionalAuth, analyticsRoutes);

// 404 & Global Error Handling
app.use(notFoundHandler);
app.use(errorHandler);

module.exports = app;
