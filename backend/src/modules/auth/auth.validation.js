const Joi = require('joi');

const signupSchema = {
  body: Joi.object({
    name: Joi.string().trim().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(100).required()
  })
};

const loginSchema = {
  body: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  })
};

const updateProfileSchema = {
  body: Joi.object({
    name: Joi.string().trim().min(2).max(50),
    avatar: Joi.string().uri().allow('')
  })
};

const changePasswordSchema = {
  body: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string().min(6).max(100).required()
  })
};

module.exports = {
  signupSchema,
  loginSchema,
  updateProfileSchema,
  changePasswordSchema
};
