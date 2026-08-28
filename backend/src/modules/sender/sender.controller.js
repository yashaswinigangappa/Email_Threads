const SenderAnalysisService = require('../../services/senderAnalysis.service');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Analyze sender email address, reputation, and domain authentication
 * @route   GET /api/sender-analysis/:email
 * @access  Public / Optional
 */
const analyzeSender = asyncCatch(async (req, res, next) => {
  const emailAddress = req.params.email;
  if (!emailAddress) {
    return next(ApiError.badRequest('Please provide an email address in the URL parameter'));
  }

  const analysis = await SenderAnalysisService.analyzeSender(emailAddress, {
    spf: req.query.spf || 'none',
    dkim: req.query.dkim || 'none',
    dmarc: req.query.dmarc || 'none'
  });

  return ApiResponse.success(res, analysis, 'Sender reputation analysis completed');
});

module.exports = {
  analyzeSender
};
