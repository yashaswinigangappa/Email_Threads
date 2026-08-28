const express = require('express');
const router = express.Router();
const urlController = require('./url.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.post('/analyze', optionalAuth, urlController.analyzeUrls);

module.exports = router;
