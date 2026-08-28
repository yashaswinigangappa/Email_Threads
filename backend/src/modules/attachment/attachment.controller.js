const AttachmentAnalysisService = require('../../services/attachmentAnalysis.service');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Analyze list of email attachments
 * @route   POST /api/attachment/analyze
 * @access  Public / Optional
 */
const analyzeAttachments = asyncCatch(async (req, res, next) => {
  let attachments = req.body.attachments || req.body.attachment;
  if (!attachments) {
    return next(ApiError.badRequest('Please provide an array of attachments in the request body'));
  }

  if (!Array.isArray(attachments)) {
    attachments = [attachments];
  }

  const result = await AttachmentAnalysisService.analyzeAttachments(attachments);
  return ApiResponse.success(res, result, 'Attachment threat analysis completed');
});

module.exports = {
  analyzeAttachments
};
