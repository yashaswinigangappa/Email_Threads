const ApiError = require('../utils/apiError');

/**
 * Validates request schema using Joi
 * @param {Object} schema - Joi schema object with optional body, query, params keys
 */
const validate = (schema) => (req, res, next) => {
  const validationKeys = ['body', 'query', 'params'];

  for (const key of validationKeys) {
    if (schema[key]) {
      const { error, value } = schema[key].validate(req[key], {
        abortEarly: false,
        stripUnknown: true
      });

      if (error) {
        const errorDetails = error.details.map((detail) => ({
          field: detail.path.join('.'),
          message: detail.message.replace(/['"]/g, '')
        }));
        return next(ApiError.badRequest('Validation failed', errorDetails));
      }

      req[key] = value;
    }
  }

  next();
};

module.exports = validate;
