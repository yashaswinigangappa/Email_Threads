const Report = require('../../models/Report');
const Email = require('../../models/Email');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Get paginated email scan history with search and filter
 * @route   GET /api/history
 * @access  Private / Optional
 */
const getHistory = asyncCatch(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 10;
  const skip = (page - 1) * limit;

  const { search, verdict, startDate, endDate, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;

  const query = {};
  if (req.user) {
    query.userId = req.user._id;
  }

  // Verdict filter
  if (verdict && verdict !== 'all') {
    query.verdict = verdict.toLowerCase();
  }

  // Date range filter
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) query.createdAt.$gte = new Date(startDate);
    if (endDate) query.createdAt.$lte = new Date(endDate);
  }

  // Search by sender or subject
  let emailIds;
  if (search) {
    const matchingEmails = await Email.find({
      $or: [
        { subject: { $regex: search, $options: 'i' } },
        { 'sender.email': { $regex: search, $options: 'i' } },
        { 'sender.raw': { $regex: search, $options: 'i' } }
      ]
    }).select('_id');

    emailIds = matchingEmails.map((e) => e._id);
    query.$or = [
      { emailId: { $in: emailIds } },
      { 'senderAnalysis.senderEmail': { $regex: search, $options: 'i' } },
      { summary: { $regex: search, $options: 'i' } }
    ];
  }

  const sortDirection = sortOrder === 'asc' ? 1 : -1;

  const [reports, totalRecords] = await Promise.all([
    Report.find(query)
      .sort({ [sortBy]: sortDirection })
      .skip(skip)
      .limit(limit)
      .populate('emailId', 'subject sender receiver date')
      .lean(),
    Report.countDocuments(query)
  ]);

  const history = reports.map((rep) => ({
    id: rep._id,
    reportId: rep._id,
    emailId: rep.emailId?._id || rep.emailId,
    subject: rep.emailId?.subject || 'N/A',
    sender: rep.senderAnalysis?.senderEmail || rep.emailId?.sender?.email || 'N/A',
    receiver: rep.emailId?.receiver?.email || 'N/A',
    verdict: rep.verdict,
    threatLevel: rep.threatLevel,
    riskScore: rep.riskScore,
    confidence: rep.confidence,
    threatCount:
      (rep.indicatorsOfCompromise?.maliciousDomains?.length || 0) +
      (rep.indicatorsOfCompromise?.maliciousURLs?.length || 0) +
      (rep.indicatorsOfCompromise?.suspiciousAttachments?.length || 0),
    createdAt: rep.createdAt
  }));

  const totalPages = Math.ceil(totalRecords / limit) || 1;

  return ApiResponse.success(res, {
    history,
    pagination: {
      page,
      limit,
      totalRecords,
      totalPages,
      hasNextPage: page < totalPages,
      hasPrevPage: page > 1
    }
  }, 'History retrieved successfully');
});

/**
 * @desc    Delete a specific history record
 * @route   DELETE /api/history/:id
 * @access  Private / Optional
 */
const deleteHistoryItem = asyncCatch(async (req, res, next) => {
  const filter = { _id: req.params.id };
  if (req.user) filter.userId = req.user._id;

  const report = await Report.findOneAndDelete(filter);
  if (!report) {
    return next(ApiError.notFound('History record not found'));
  }

  // Delete associated email
  if (report.emailId) {
    await Email.findByIdAndDelete(report.emailId);
  }

  return ApiResponse.success(res, null, 'History record deleted successfully');
});

/**
 * @desc    Clear all scan history for the user
 * @route   DELETE /api/history
 * @access  Private / Optional
 */
const clearHistory = asyncCatch(async (req, res) => {
  const filter = req.user ? { userId: req.user._id } : {};
  const reports = await Report.find(filter).select('emailId');
  const emailIds = reports.map((r) => r.emailId).filter(Boolean);

  await Promise.all([
    Report.deleteMany(filter),
    Email.deleteMany({ _id: { $in: emailIds } })
  ]);

  return ApiResponse.success(res, null, 'Scan history cleared successfully');
});

module.exports = {
  getHistory,
  deleteHistoryItem,
  clearHistory
};
