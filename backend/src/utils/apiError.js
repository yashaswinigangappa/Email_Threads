/**
 * Custom ApiError for operational & HTTP errors
 */
class ApiError extends Error {
  constructor(message, statusCode = 500, errors = null, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.errors = errors;
    this.isOperational = isOperational;
    this.success = false;

    Error.captureStackTrace(this, this.constructor);
  }

  static badRequest(msg = 'Bad Request', errors = null) {
    return new ApiError(msg, 400, errors);
  }

  static unauthorized(msg = 'Unauthorized access') {
    return new ApiError(msg, 401);
  }

  static forbidden(msg = 'Forbidden: Insufficient permissions') {
    return new ApiError(msg, 403);
  }

  static notFound(msg = 'Requested resource not found') {
    return new ApiError(msg, 404);
  }

  static conflict(msg = 'Resource already exists') {
    return new ApiError(msg, 409);
  }

  static internal(msg = 'Internal server error') {
    return new ApiError(msg, 500);
  }
}

module.exports = ApiError;
