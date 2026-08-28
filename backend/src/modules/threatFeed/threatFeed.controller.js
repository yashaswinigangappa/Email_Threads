const ThreatFeedService = require('../../services/threatFeed.service');
const ApiResponse = require('../../utils/apiResponse');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Get live threat intelligence feeds
 * @route   GET /api/threat-feed
 * @access  Public / Optional
 */
const getThreatFeed = asyncCatch(async (req, res) => {
  const feed = await ThreatFeedService.getThreatFeed();
  return ApiResponse.success(res, feed, 'Live threat feed retrieved');
});

module.exports = {
  getThreatFeed
};
