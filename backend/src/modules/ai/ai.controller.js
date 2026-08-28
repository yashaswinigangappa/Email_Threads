const AiPredictionService = require('../../services/aiPrediction.service');
const RiskScoreService = require('../../services/riskScore.service');
const ApiResponse = require('../../utils/apiResponse');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Predict email threat classification using AI model / heuristic engine
 * @route   POST /api/ai/predict
 * @access  Public / API Key
 */
const predict = asyncCatch(async (req, res) => {
  const {
    subject = '',
    body = '',
    sender = '',
    headers = {},
    urls = [],
    attachments = []
  } = req.body;

  const result = await AiPredictionService.predict({
    subject,
    body,
    sender,
    headers,
    urls,
    attachments
  });

  return ApiResponse.success(res, result, 'AI prediction completed');
});

/**
 * @desc    Calculate consolidated risk score
 * @route   POST /api/ai/risk-score
 * @access  Public / API Key
 */
const calculateRiskScore = asyncCatch(async (req, res) => {
  const {
    aiPrediction = {},
    senderSignals = {},
    urls = [],
    attachments = [],
    extractedIPs = []
  } = req.body;

  const consolidated = RiskScoreService.consolidate({
    aiResult: aiPrediction,
    senderResult: senderSignals,
    urlResult: { results: urls, maliciousCount: urls.filter((u) => u.isBlacklisted || u.status === 'Malicious').length, overallUrlRiskScore: 0 },
    attachmentResult: { results: attachments, threatsFound: attachments.filter((a) => a.isExecutable || a.isDangerous).length, overallAttachmentRiskScore: 0 },
    extractedIPs
  });

  return ApiResponse.success(res, consolidated, 'Risk score calculated successfully');
});

module.exports = {
  predict,
  calculateRiskScore
};
