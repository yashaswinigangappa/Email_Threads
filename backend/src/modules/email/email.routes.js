const express = require('express');
const router = express.Router();
const emailController = require('./email.controller');
const upload = require('../../middlewares/upload.middleware');
const { optionalAuth } = require('../../middlewares/auth.middleware');

// Ingest/upload email (.eml file field 'email_file' or 'file', or JSON body)
router.post('/upload', optionalAuth, upload.single('email_file'), emailController.uploadEmail);

// Full threat analysis endpoint
router.post('/analyze', optionalAuth, upload.single('email_file'), emailController.analyzeEmail);

// Get email details by ID
router.get('/:id', optionalAuth, emailController.getEmailById);

module.exports = router;
