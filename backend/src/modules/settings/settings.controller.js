const User = require('../../models/User');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * @desc    Get user settings
 * @route   GET /api/settings
 * @access  Private
 */
const getSettings = asyncCatch(async (req, res) => {
  const user = await User.findById(req.user._id);

  return ApiResponse.success(res, {
    theme: user.settings?.theme || 'dark',
    notifications: user.settings?.notifications ?? true,
    autoQuarantine: user.settings?.autoQuarantine ?? false,
    scanPreferences: user.settings?.scanPreferences || {
      deepUrlInspection: true,
      checkAttachmentSandboxing: true,
      alertThresholdRiskScore: 75
    },
    apiKey: user.apiKey
  }, 'Settings retrieved');
});

/**
 * @desc    Update user settings
 * @route   PUT /api/settings
 * @access  Private
 */
const updateSettings = asyncCatch(async (req, res) => {
  const user = await User.findById(req.user._id);
  const { theme, notifications, autoQuarantine, scanPreferences } = req.body;

  if (!user.settings) user.settings = {};

  if (theme) user.settings.theme = theme;
  if (notifications !== undefined) user.settings.notifications = notifications;
  if (autoQuarantine !== undefined) user.settings.autoQuarantine = autoQuarantine;
  if (scanPreferences) {
    user.settings.scanPreferences = {
      ...user.settings.scanPreferences,
      ...scanPreferences
    };
  }

  await user.save();

  return ApiResponse.success(res, {
    theme: user.settings.theme,
    notifications: user.settings.notifications,
    autoQuarantine: user.settings.autoQuarantine,
    scanPreferences: user.settings.scanPreferences,
    apiKey: user.apiKey
  }, 'Settings updated successfully');
});

/**
 * @desc    Regenerate API key for developer access
 * @route   POST /api/settings/regenerate-api-key
 * @access  Private
 */
const regenerateApiKey = asyncCatch(async (req, res) => {
  const user = await User.findById(req.user._id);
  const newApiKey = user.generateApiKey();
  await user.save();

  return ApiResponse.success(res, {
    apiKey: newApiKey
  }, 'New API key generated successfully');
});

module.exports = {
  getSettings,
  updateSettings,
  regenerateApiKey
};
