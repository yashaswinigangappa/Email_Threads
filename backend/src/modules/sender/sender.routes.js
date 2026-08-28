const express = require('express');
const router = express.Router();
const senderController = require('./sender.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/:email', optionalAuth, senderController.analyzeSender);

module.exports = router;
