const express = require('express');
const router = express.Router();
const threatFeedController = require('./threatFeed.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/', optionalAuth, threatFeedController.getThreatFeed);

module.exports = router;
