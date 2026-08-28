const express = require('express');
const router = express.Router();
const reportController = require('./report.controller');
const { optionalAuth } = require('../../middlewares/auth.middleware');

router.get('/:id', optionalAuth, reportController.getReportById);
router.get('/download/:id', optionalAuth, reportController.downloadPdf);

module.exports = router;
