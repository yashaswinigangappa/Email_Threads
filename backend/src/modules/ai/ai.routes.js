const express = require('express');
const router = express.Router();
const aiController = require('./ai.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.post('/predict', optionalAuth, aiController.predict);
router.post('/risk-score', optionalAuth, aiController.calculateRiskScore);

module.exports = router;
