const jwt = require('jsonwebtoken');
const config = require('../config/environment');
const User = require('../models/User');
const ApiError = require('../utils/apiError');
const asyncCatch = require('../utils/asyncCatch');

/**
 * Protect routes - checks JWT Bearer token or x-api-key header
 */
const protect = asyncCatch(async (req, res, next) => {
  let token;

  // 1. Check Bearer Token in Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // 2. Check x-api-key header
  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const user = await User.findOne({ apiKey });
    if (user) {
      req.user = user;
      return next();
    }
    return next(ApiError.unauthorized('Invalid API Key provided'));
  }

  if (!token) {
    return next(ApiError.unauthorized('Authentication token or API key required'));
  }

  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    const user = await User.findById(decoded.id);

    if (!user) {
      return next(ApiError.unauthorized('User associated with this token no longer exists'));
    }

    req.user = user;
    next();
  } catch (error) {
    return next(ApiError.unauthorized('Invalid or expired authentication token'));
  }
});

/**
 * Optional authentication - attaches user if token exists, but doesn't block unauthenticated requests
 */
const optionalAuth = asyncCatch(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  const apiKey = req.headers['x-api-key'];
  if (apiKey) {
    const user = await User.findOne({ apiKey });
    if (user) req.user = user;
    return next();
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret);
      const user = await User.findById(decoded.id);
      if (user) req.user = user;
    } catch (e) {
      // Ignore error for optional auth
    }
  }

  next();
});

/**
 * Restrict to specific roles
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return next(ApiError.forbidden('You do not have permission to perform this action'));
    }
    next();
  };
};

module.exports = { protect, optionalAuth, authorize };
