const Joi = require('joi');

const analyzeEmailSchema = {
  body: Joi.object({
    emailId: Joi.string().hex().length(24).optional()
  })
};

module.exports = {
  analyzeEmailSchema
};
