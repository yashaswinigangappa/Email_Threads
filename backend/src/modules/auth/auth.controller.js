const jwt = require('jsonwebtoken');
const User = require('../../models/User');
const config = require('../../config/environment');
const ApiResponse = require('../../utils/apiResponse');
const ApiError = require('../../utils/apiError');
const asyncCatch = require('../../utils/asyncCatch');

/**
 * Generate JWT token for user
 */
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    config.jwt.secret,
    { expiresIn: config.jwt.expiresIn }
  );
};

/**
 * @desc    Register a new user
 * @route   POST /api/auth/signup
 * @access  Public
 */
const signup = asyncCatch(async (req, res, next) => {
  const { name, email, password } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return next(ApiError.conflict('An account with this email address already exists'));
  }

  const user = await User.create({
    name,
    email,
    password
  });

  const token = generateToken(user);

  return ApiResponse.created(res, {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      apiKey: user.apiKey,
      createdAt: user.createdAt
    },
    token
  }, 'User registered successfully');
});

/**
 * @desc    Login user & get token
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = asyncCatch(async (req, res, next) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select('+password');
  if (!user) {
    return next(ApiError.unauthorized('Invalid email or password'));
  }

  const isMatch = await user.matchPassword(password);
  if (!isMatch) {
    return next(ApiError.unauthorized('Invalid email or password'));
  }

  const token = generateToken(user);

  return ApiResponse.success(res, {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      apiKey: user.apiKey,
      avatar: user.avatar,
      settings: user.settings
    },
    token
  }, 'Login successful');
});

/**
 * @desc    Logout user / destroy session
 * @route   POST /api/auth/logout
 * @access  Private
 */
const logout = asyncCatch(async (req, res) => {
  return ApiResponse.success(res, null, 'Logged out successfully');
});

/**
 * @desc    Get current logged in user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getMe = asyncCatch(async (req, res) => {
  const user = await User.findById(req.user._id);
  return ApiResponse.success(res, {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    avatar: user.avatar,
    apiKey: user.apiKey,
    settings: user.settings,
    createdAt: user.createdAt
  }, 'User profile retrieved');
});

/**
 * @desc    Update user profile
 * @route   PUT /api/auth/profile
 * @access  Private
 */
const updateProfile = asyncCatch(async (req, res) => {
  const { name, avatar } = req.body;
  const user = await User.findById(req.user._id);

  if (name) user.name = name;
  if (avatar !== undefined) user.avatar = avatar;

  await user.save();

  return ApiResponse.success(res, {
    id: user._id,
    name: user.name,
    email: user.email,
    avatar: user.avatar,
    role: user.role
  }, 'Profile updated successfully');
});

/**
 * @desc    Change user password
 * @route   PUT /api/auth/change-password
 * @access  Private
 */
const changePassword = asyncCatch(async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  const user = await User.findById(req.user._id).select('+password');
  const isMatch = await user.matchPassword(currentPassword);

  if (!isMatch) {
    return next(ApiError.badRequest('Current password provided is incorrect'));
  }

  user.password = newPassword;
  await user.save();

  return ApiResponse.success(res, null, 'Password changed successfully');
});

module.exports = {
  signup,
  login,
  logout,
  getMe,
  updateProfile,
  changePassword
};
