const morgan = require('morgan');
const logger = require('../utils/logger');

// Stream for morgan to route through winston
const stream = {
  write: (message) => logger.info(message.trim())
};

// Morgan request logging middleware
const morganMiddleware = morgan(
  ':remote-addr - :method :url :status :res[content-length] - :response-time ms',
  { stream }
);

module.exports = morganMiddleware;
