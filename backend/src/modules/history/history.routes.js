const express = require('express');
const router = express.Router();
const historyController = require('./history.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/', optionalAuth, historyController.getHistory);
router.delete('/', optionalAuth, historyController.clearHistory);
router.delete('/:id', optionalAuth, historyController.deleteHistoryItem);

module.exports = router;
