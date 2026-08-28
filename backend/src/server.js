const app = require('./app');
const config = require('./config/environment');
const { connectDB } = require('./config/db');
const logger = require('./utils/logger');

const startServer = async () => {
  // Connect to Database
  await connectDB();

  const server = app.listen(config.port, () => {
    logger.info(`=======================================================`);
    logger.info(`  SIH26106 - Email Threat Intelligence Platform Backend`);
    logger.info(`  Environment: ${config.env}`);
    logger.info(`  Server running on port: ${config.port}`);
    logger.info(`  API Base URL: http://localhost:${config.port}/api`);
    logger.info(`  API Docs: http://localhost:${config.port}/api-docs`);
    logger.info(`=======================================================`);
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (err) => {
    logger.error(`Unhandled Rejection: ${err.message}`);
  });

  // Handle uncaught exceptions
  process.on('uncaughtException', (err) => {
    logger.error(`Uncaught Exception: ${err.message}`);
  });

  // Graceful shutdown
  const shutdown = () => {
    logger.info('Shutting down server gracefully...');
    server.close(() => {
      logger.info('Process terminated');
      process.exit(0);
    });
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
};

startServer();
