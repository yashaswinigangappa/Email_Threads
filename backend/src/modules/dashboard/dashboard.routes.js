const express = require('express');
const router = express.Router();
const dashboardController = require('./dashboard.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/stats', optionalAuth, dashboardController.getStats);
router.get('/trends', optionalAuth, dashboardController.getTrends);
router.get('/recent-threats', optionalAuth, dashboardController.getRecentThreats);

module.exports = router;
