const express = require('express');
const router = express.Router();
const settingsController = require('./settings.controller');
const { protect } = require('../../middlewares/auth.middleware');

router.get('/', protect, settingsController.getSettings);
router.put('/', protect, settingsController.updateSettings);
router.post('/regenerate-api-key', protect, settingsController.regenerateApiKey);

module.exports = router;
