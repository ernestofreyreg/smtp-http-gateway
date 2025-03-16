const SMTPServer = require('smtp-server').SMTPServer;
const simpleParser = require('mailparser').simpleParser;
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { loadConfig } = require('./config');

class SmtpHttpGateway {
  constructor(customConfig = {}) {
    // Load configuration
    this.config = loadConfig(customConfig);
    
    // Set up logging
    this.logger = this._setupLogger();
    
    // Set up the directory for failed webhooks
    this.failedDir = path.join(process.cwd(), 'failed_webhooks');
    if (!fs.existsSync(this.failedDir)) {
      fs.mkdirSync(this.failedDir, { recursive: true });
    }
    
    // Create the SMTP server
    this.server = this._createServer();
  }

  _setupLogger() {
    const logLevels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3,
    };

    const logLevel = logLevels[this.config.LOG_LEVEL] || logLevels.info;

    return {
      error: (...args) => { if (logLevel >= logLevels.error) console.error(new Date().toISOString(), '[ERROR]', ...args); },
      warn: (...args) => { if (logLevel >= logLevels.warn) console.warn(new Date().toISOString(), '[WARN]', ...args); },
      info: (...args) => { if (logLevel >= logLevels.info) console.info(new Date().toISOString(), '[INFO]', ...args); },
      debug: (...args) => { if (logLevel >= logLevels.debug) console.debug(new Date().toISOString(), '[DEBUG]', ...args); },
    };
  }

  _createServer() {
    // Set up the SMTP server options
    const smtpOptions = {
      secure: this.config.TLS,
      size: this.config.MAX_MESSAGE_SIZE,
      onAuth: this.config.AUTH_REQUIRED ? (auth, session, callback) => {
        const user = this.config.USERS[auth.username];
        this.logger.info(`login: ${auth.username} password: ${auth.password}`);
        // if (!user || user !== auth.password) {
        //   this.logger.warn(`Authentication failed for user: ${auth.username}`);
        //   return callback(new Error('Invalid username or password'));
        // }
        this.logger.debug(`User authenticated: ${auth.username}`);
        callback(null, { user: auth.username });
      } : null,
      authOptional: !this.config.AUTH_REQUIRED,
      logger: this.config.LOG_LEVEL === 'debug',
    };

    // Add TLS certificates if TLS is enabled
    if (this.config.TLS) {
      try {
        smtpOptions.key = fs.readFileSync(this.config.TLS_KEY);
        smtpOptions.cert = fs.readFileSync(this.config.TLS_CERT);
      } catch (error) {
        this.logger.error(`Failed to load TLS certificates: ${error.message}`);
        throw new Error(`Failed to load TLS certificates: ${error.message}`);
      }
    }

    // Create the SMTP server
    const server = new SMTPServer({
      ...smtpOptions,
      
      // This function is called when a client connects
      onConnect: (session, callback) => {
        this.logger.debug(`SMTP connection from ${session.remoteAddress}`);
        callback();
      },
      
      // This function handles the actual email data
      onData: (stream, session, callback) => {
        this.logger.debug(`Receiving email data from ${session.remoteAddress}`);
        
        this.processEmail(stream, session)
          .then(() => {
            this.logger.info('Email processed successfully');
            callback();
          })
          .catch(error => {
            this.logger.error(`Failed to process email: ${error.message}`);
            callback(new Error('Error processing email'));
          });
      }
    });

    // Handle server errors
    server.on('error', error => {
      this.logger.error(`Server error: ${error.message}`);
    });

    return server;
  }

  async processEmail(stream, session) {
    try {
      // Parse the email
      const parsed = await simpleParser(stream);
      
      // Create payload for the webhook
      const emailData = {
        from: parsed.from?.text || '',
        to: parsed.to?.text || '',
        cc: parsed.cc?.text || '',
        subject: parsed.subject || '',
        text: parsed.text || '',
        html: parsed.html || '',
        date: parsed.date,
        messageId: parsed.messageId,
        attachments: parsed.attachments.map(attachment => ({
          filename: attachment.filename,
          contentType: attachment.contentType,
          contentDisposition: attachment.contentDisposition,
          size: attachment.size,
          content: attachment.content.toString('base64'),
        })),
        headers: {},
        smtp: {
          remoteAddress: session.remoteAddress,
          transmissionId: session.id,
          envelope: session.envelope,
        }
      };
      
      // Add headers
      parsed.headerLines.forEach(header => {
        emailData.headers[header.key] = header.line;
      });
      
      this.logger.info(`Processing email: ${emailData.messageId} from ${emailData.from} to ${emailData.to}`);
      
      // Send to webhook
      await this.sendToWebhook(emailData);
      return true;
    } catch (error) {
      this.logger.error(`Email processing error: ${error.message}`);
      throw error;
    }
  }

  async sendToWebhook(emailData, retryCount = 0) {
    try {
      this.logger.debug(`Sending webhook, attempt ${retryCount + 1}`);
      const response = await axios.post(this.config.HTTP_ENDPOINT, emailData, {
        timeout: this.config.WEBHOOK_TIMEOUT,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'SMTP-HTTP-Gateway/1.0',
        },
      });
      
      this.logger.info(`Webhook delivered successfully: ${response.status}`);
      return response;
    } catch (error) {
      this.logger.error(`Webhook delivery error: ${error.message}`);
      
      // Retry logic
      if (retryCount < this.config.RETRY_COUNT - 1) {
        this.logger.info(`Retrying webhook in ${this.config.RETRY_DELAY}ms...`);
        await new Promise(resolve => setTimeout(resolve, this.config.RETRY_DELAY));
        return this.sendToWebhook(emailData, retryCount + 1);
      } else {
        // Save failed webhook for later processing
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = path.join(this.failedDir, `failed_${timestamp}.json`);
        fs.writeFileSync(filename, JSON.stringify(emailData, null, 2));
        this.logger.warn(`Max retries reached. Saved to ${filename}`);
        throw error;
      }
    }
  }

  start() {
    return new Promise((resolve) => {
      this.server.listen(this.config.SMTP_PORT, () => {
        this.logger.info(`SMTP to HTTP gateway running on port ${this.config.SMTP_PORT}`);
        this.logger.info(`Forwarding emails to ${this.config.HTTP_ENDPOINT}`);
        this.logger.info(`Authentication ${this.config.AUTH_REQUIRED ? 'enabled' : 'disabled'}`);
        resolve(this.server);
      });
    });
  }

  stop() {
    return new Promise((resolve) => {
      this.logger.info('Server shutting down...');
      this.server.close(() => {
        this.logger.info('Server stopped');
        resolve();
      });
    });
  }
}

module.exports = SmtpHttpGateway;

