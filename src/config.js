require('dotenv').config();

function loadConfig(customConfig = {}) {
  // Default configuration
  const defaultConfig = {
    SMTP_PORT: process.env.SMTP_PORT || 2525,
    HTTP_ENDPOINT: process.env.HTTP_ENDPOINT || 'http://localhost:3000/api/email',
    AUTH_REQUIRED: process.env.AUTH_REQUIRED === 'true' || false,
    USERS: JSON.parse(process.env.USERS || '{}'),
    TLS: process.env.TLS === 'true' || false,
    TLS_KEY: process.env.TLS_KEY || './certs/key.pem',
    TLS_CERT: process.env.TLS_CERT || './certs/cert.pem',
    MAX_MESSAGE_SIZE: parseInt(process.env.MAX_MESSAGE_SIZE || 25 * 1024 * 1024), // 25MB
    WEBHOOK_TIMEOUT: parseInt(process.env.WEBHOOK_TIMEOUT || 30000), // 30 seconds
    RETRY_COUNT: parseInt(process.env.RETRY_COUNT || 3),
    RETRY_DELAY: parseInt(process.env.RETRY_DELAY || 5000), // 5 seconds
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  };

  // Merge with custom config
  return { ...defaultConfig, ...customConfig };
}

module.exports = { loadConfig };

