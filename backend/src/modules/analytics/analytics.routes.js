const express = require('express');
const router = express.Router();
const analyticsController = require('./analytics.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/', optionalAuth, analyticsController.getAnalytics);

module.exports = router;
