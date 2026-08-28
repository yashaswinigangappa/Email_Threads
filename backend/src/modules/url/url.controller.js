const UrlAnalysisService = require('../../services/urlAnalysis.service');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Analyze list of URLs for security threats
 * @route   POST /api/url/analyze
 * @access  Public / Optional
 */
const analyzeUrls = asyncCatch(async (req, res, next) => {
  let urls = req.body.urls || req.body.url;
  if (!urls) {
    return next(ApiError.badRequest('Please provide an array of URLs or a URL string in the request body'));
  }

  if (typeof urls === 'string') {
    urls = [urls];
  }

  const result = await UrlAnalysisService.analyzeUrls(urls);
  return ApiResponse.success(res, result, 'URL security analysis completed');
});

module.exports = {
  analyzeUrls
};
