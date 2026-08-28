const express = require('express');
const router = express.Router();
const attachmentController = require('./attachment.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.post('/analyze', optionalAuth, attachmentController.analyzeAttachments);

module.exports = router;
