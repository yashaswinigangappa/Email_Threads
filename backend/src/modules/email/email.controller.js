const Email = require('../../models/Email');
const Report = require('../../models/Report');
const Attachment = require('../../models/Attachment');
const EmailParserService = require('../../services/emailParser.service');
const SenderAnalysisService = require('../../services/senderAnalysis.service');
const UrlAnalysisService = require('../../services/urlAnalysis.service');
const AttachmentAnalysisService = require('../../services/attachmentAnalysis.service');
const AiPredictionService = require('../../services/aiPrediction.service');
const RiskScoreService = require('../../services/riskScore.service');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Upload and parse email (.eml file or raw text)
 * @route   POST /api/email/upload
 * @access  Private / Optional
 */
const uploadEmail = asyncCatch(async (req, res, next) => {
  let parsedResult;

  if (req.file) {
    // 1. File uploaded (.eml or text)
    parsedResult = await EmailParserService.parseEmail(req.file.path, true);
  } else if (req.body.rawEmail) {
    // 2. Raw email text pasted
    parsedResult = await EmailParserService.parseEmail(req.body.rawEmail, false);
  } else if (req.body.subject || req.body.body) {
    // 3. Structured JSON payload passed
    const rawSubject = req.body.subject || '(No Subject)';
    const rawBody = req.body.body || '';
    const rawSender = req.body.sender || 'unknown@domain.com';
    const fakeRaw = `From: ${rawSender}\nSubject: ${rawSubject}\n\n${rawBody}`;
    parsedResult = await EmailParserService.parseEmail(fakeRaw, false);
  } else {
    return next(ApiError.badRequest('Please upload an .eml file or provide email text content'));
  }

  // Create Email document in database
  const emailDoc = await Email.create({
    userId: req.user ? req.user._id : null,
    subject: parsedResult.subject,
    sender: parsedResult.sender,
    receiver: parsedResult.receiver,
    date: parsedResult.date,
    messageId: parsedResult.messageId,
    bodyText: parsedResult.bodyText,
    bodyHtml: parsedResult.bodyHtml,
    headers: parsedResult.headers,
    authResults: parsedResult.authResults,
    extractedUrls: parsedResult.extractedUrls,
    extractedIPs: parsedResult.extractedIPs,
    attachments: parsedResult.attachments,
    rawEmlPath: parsedResult.rawEmlPath,
    status: 'uploaded'
  });

  // Save extracted attachments into Attachment collection
  if (parsedResult.attachments && parsedResult.attachments.length > 0) {
    const attachmentRecords = parsedResult.attachments.map((att) => ({
      emailId: emailDoc._id,
      filename: att.filename,
      mimeType: att.contentType,
      size: att.size,
      sha256: att.sha256,
      md5: att.md5
    }));
    await Attachment.insertMany(attachmentRecords);
  }

  // Return preview response
  return ApiResponse.success(res, {
    emailId: emailDoc._id,
    preview: {
      subject: emailDoc.subject,
      sender: emailDoc.sender,
      receiver: emailDoc.receiver,
      date: emailDoc.date,
      bodySnippet: (emailDoc.bodyText || '').slice(0, 300),
      bodyHtml: emailDoc.bodyHtml,
      extractedData: {
        linksCount: emailDoc.extractedUrls.length,
        attachmentsCount: emailDoc.attachments.length,
        urls: emailDoc.extractedUrls.map((u) => u.url),
        attachments: emailDoc.attachments.map((a) => ({
          filename: a.filename,
          size: a.size,
          contentType: a.contentType
        })),
        headers: {
          spf: emailDoc.authResults.spf,
          dkim: emailDoc.authResults.dkim,
          dmarc: emailDoc.authResults.dmarc,
          receivedSpf: emailDoc.authResults.receivedSpf,
          messageId: emailDoc.messageId
        },
        extractedIPs: emailDoc.extractedIPs
      }
    }
  }, 'Email uploaded and parsed successfully');
});

/**
 * @desc    Run full multi-vector threat analysis pipeline
 * @route   POST /api/email/analyze
 * @access  Private / Optional
 */
const analyzeEmail = asyncCatch(async (req, res, next) => {
  let emailDoc;

  // Check if file is directly uploaded to /analyze
  if (req.file || req.body.rawEmail) {
    const parsedResult = await EmailParserService.parseEmail(
      req.file ? req.file.path : req.body.rawEmail,
      Boolean(req.file)
    );

    emailDoc = await Email.create({
      userId: req.user ? req.user._id : null,
      subject: parsedResult.subject,
      sender: parsedResult.sender,
      receiver: parsedResult.receiver,
      date: parsedResult.date,
      messageId: parsedResult.messageId,
      bodyText: parsedResult.bodyText,
      bodyHtml: parsedResult.bodyHtml,
      headers: parsedResult.headers,
      authResults: parsedResult.authResults,
      extractedUrls: parsedResult.extractedUrls,
      extractedIPs: parsedResult.extractedIPs,
      attachments: parsedResult.attachments,
      rawEmlPath: parsedResult.rawEmlPath,
      status: 'uploaded'
    });
  } else if (req.body.emailId) {
    emailDoc = await Email.findById(req.body.emailId);
    if (!emailDoc) {
      return next(ApiError.notFound('Email record not found with the provided emailId'));
    }
  } else {
    // If no emailId provided and no file, try finding latest uploaded email
    emailDoc = await Email.findOne(req.user ? { userId: req.user._id } : {}).sort({ createdAt: -1 });
    if (!emailDoc) {
      return next(ApiError.badRequest('Please upload an email or provide a valid emailId for analysis'));
    }
  }

  // 1. Run Sender Analysis
  const senderEmail = emailDoc.sender?.email || emailDoc.sender?.raw || '';
  const senderAnalysis = await SenderAnalysisService.analyzeSender(senderEmail, emailDoc.authResults);

  // 2. Run URL Threat Analysis
  const urlAnalysisResult = await UrlAnalysisService.analyzeUrls(emailDoc.extractedUrls);

  // 3. Run Attachment Analysis
  const attachmentAnalysisResult = await AttachmentAnalysisService.analyzeAttachments(emailDoc.attachments);

  // 4. Run AI Threat Prediction (FastAPI with Heuristic fallback)
  const aiPrediction = await AiPredictionService.predict({
    subject: emailDoc.subject,
    body: emailDoc.bodyText,
    sender: emailDoc.sender,
    headers: emailDoc.headers,
    urls: emailDoc.extractedUrls,
    attachments: emailDoc.attachments
  });

  // 5. Consolidate Multi-Vector Signals into Risk Score & Verdict
  const consolidated = RiskScoreService.consolidate({
    aiResult: aiPrediction,
    senderResult: senderAnalysis,
    urlResult: urlAnalysisResult,
    attachmentResult: attachmentAnalysisResult,
    extractedIPs: emailDoc.extractedIPs
  });

  // 6. Create Report Record
  const reportDoc = await Report.create({
    emailId: emailDoc._id,
    userId: req.user ? req.user._id : emailDoc.userId,
    verdict: consolidated.verdict,
    threatLevel: consolidated.threatLevel,
    riskScore: consolidated.riskScore,
    confidence: consolidated.confidence,
    summary: consolidated.summary,
    aiAnalysis: {
      prediction: aiPrediction.class,
      confidence: aiPrediction.confidence,
      risk_score: aiPrediction.risk_score,
      reasons: aiPrediction.reasons,
      modelSource: aiPrediction.source
    },
    senderAnalysis,
    urlAnalysis: urlAnalysisResult.results,
    attachmentAnalysis: attachmentAnalysisResult.results,
    indicatorsOfCompromise: consolidated.indicatorsOfCompromise,
    recommendations: consolidated.recommendations
  });

  // Update Email status
  emailDoc.status = 'analyzed';
  await emailDoc.save();

  // Return full analysis payload matching API blueprint
  return ApiResponse.success(res, {
    reportId: reportDoc._id,
    emailId: emailDoc._id,
    verdict: reportDoc.verdict,
    threatLevel: reportDoc.threatLevel,
    riskScore: reportDoc.riskScore,
    confidence: reportDoc.confidence,
    summary: reportDoc.summary,
    aiAnalysis: reportDoc.aiAnalysis,
    senderAnalysis: reportDoc.senderAnalysis,
    urlAnalysis: reportDoc.urlAnalysis,
    attachmentAnalysis: reportDoc.attachmentAnalysis,
    indicatorsOfCompromise: reportDoc.indicatorsOfCompromise,
    recommendations: reportDoc.recommendations,
    createdAt: reportDoc.createdAt
  }, 'Email threat analysis completed successfully');
});

/**
 * @desc    Get parsed email details by ID
 * @route   GET /api/email/:id
 * @access  Private / Optional
 */
const getEmailById = asyncCatch(async (req, res, next) => {
  const email = await Email.findById(req.params.id);
  if (!email) {
    return next(ApiError.notFound('Email record not found'));
  }

  return ApiResponse.success(res, email, 'Email details retrieved');
});

module.exports = {
  uploadEmail,
  analyzeEmail,
  getEmailById
};
