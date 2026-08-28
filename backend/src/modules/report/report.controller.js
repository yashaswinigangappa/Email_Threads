const Report = require('../../models/Report');
const Email = require('../../models/Email');
const PdfGeneratorService = require('../../services/pdfGenerator.service');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Get detailed threat report by ID
 * @route   GET /api/report/:id
 * @access  Private / Optional
 */
const getReportById = asyncCatch(async (req, res, next) => {
  const report = await Report.findById(req.params.id).populate('emailId');
  if (!report) {
    return next(ApiError.notFound('Threat report not found'));
  }

  return ApiResponse.success(res, report, 'Threat report retrieved successfully');
});

/**
 * @desc    Download PDF threat report
 * @route   GET /api/report/download/:id
 * @access  Private / Optional
 */
const downloadPdf = asyncCatch(async (req, res, next) => {
  const report = await Report.findById(req.params.id).populate('emailId');
  if (!report) {
    return next(ApiError.notFound('Threat report not found for PDF export'));
  }

  const email = report.emailId || {};

  // Set response headers for PDF download
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="Threat_Report_${report._id}.pdf"`
  );

  const pdfStream = PdfGeneratorService.generateReportPdf(report, email);
  pdfStream.pipe(res);
  pdfStream.end();
});

module.exports = {
  getReportById,
  downloadPdf
};
