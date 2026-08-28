const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const path = require('path');
const logger = require('../utils/logger');

let swaggerDocument;
try {
  const swaggerPath = path.resolve(__dirname, '../../docs/openapi.yaml');
  swaggerDocument = YAML.load(swaggerPath);
} catch (err) {
  logger.warn(`Could not load Swagger openapi.yaml: ${err.message}`);
  swaggerDocument = { openapi: '3.0.0', info: { title: 'API Docs', version: '1.0' } };
}

const setupSwagger = (app) => {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCss: '.swagger-ui .topbar { background-color: #0f172a; }',
    customSiteTitle: 'Email Threat Intelligence Platform - API Docs'
  }));
  logger.info('Swagger documentation available at /api-docs');
};

module.exports = setupSwagger;
