const SMTPServer = require('smtp-server').SMTPServer;
const simpleParser = require('mailparser').simpleParser;
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { loadConfig } = require('./config');
const { parseSimpleYaml } = require('./helpers');
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
      hostname: 'smtp.emailssary.com',
      size: this.config.MAX_MESSAGE_SIZE,
      onAuth: this.config.AUTH_REQUIRED ? (auth, session, callback) => {        
        session.auth = {
          username: auth.username,
          password: auth.password
        };
        this.logger.debug(`User authenticated: ${auth.username}`);
        callback(null, { user: auth.username });
      } : null,
      authOptional: !this.config.AUTH_REQUIRED,
      logger: this.config.LOG_LEVEL === 'debug',
      // TLS configuration
      secure: false, // Start with non-secure, allow STARTTLS upgrade
      allowInsecureAuth: true, // Allow authentication on non-secure connections
      hideSTARTTLS: false, // Enable STARTTLS command
      // Enhanced TLS options
      tls: {
        rejectUnauthorized: false, // Accept self-signed certificates
        minVersion: 'TLSv1.2', // Minimum TLS version
        ciphers: 'HIGH:MEDIUM:!aNULL:!eNULL:!NULL:!DH:!EDH:!AESGCM:!DSS:!SHA1:!SHA256:!SHA384:!CAMELLIA', // Strong ciphers
        honorCipherOrder: true, // Use server's cipher preferences
        handshakeTimeout: 10000, // 10 seconds timeout for handshake
        requestCert: false, // Don't require client certificate
        sessionTimeout: 600, // 10 minutes session timeout
      }
    };

    // Add TLS certificates if TLS is enabled
    if (this.config.TLS) {
      try {
        const key = fs.readFileSync(this.config.TLS_KEY);
        const cert = fs.readFileSync(this.config.TLS_CERT);
        
        smtpOptions.key = key;
        smtpOptions.cert = cert;
        
        // Verify certificate files are valid
        require('tls').createSecureContext({
          key: key,
          cert: cert
        });
        
        this.logger.info('TLS certificates loaded and validated successfully');
      } catch (error) {
        this.logger.error(`Failed to load or validate TLS certificates: ${error.message}`);
        throw new Error(`Failed to load or validate TLS certificates: ${error.message}`);
      }
    }

    // Create the SMTP server
    const server = new SMTPServer({
      ...smtpOptions,
      
      // This function is called when a client connects
      onConnect: (session, callback) => {
        this.logger.info(`New SMTP connection from ${session.remoteAddress}`, {
          sessionId: session.id,
          secure: session.secure,
          tlsOptions: session.tlsOptions || 'none'
        });
        callback();
      },
      
      // Handle STARTTLS upgrade
      onSecure: (socket, session, callback) => {
        this.logger.info(`TLS connection upgraded for ${session.remoteAddress}`, {
          sessionId: session.id,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
        });
        callback();
      },

      // Handle client disconnections
      onClose: (session) => {
        this.logger.info(`SMTP connection closed for ${session.remoteAddress}`, {
          sessionId: session.id,
          secure: session.secure
        });
      },

      // Log SMTP commands for debugging
      onCommand: (cmd, args, session, callback) => {
        this.logger.debug(`SMTP command received: ${cmd}`, {
          sessionId: session.id,
          args: args,
          secure: session.secure,
          authenticated: session.auth ? 'yes' : 'no'
        });
        callback();
      },
      
      // This function handles the actual email data
      onData: (stream, session, callback) => {
        this.logger.info(`Receiving email data from ${session.remoteAddress}`, {
          sessionId: session.id,
          secure: session.secure,
          authenticated: session.auth ? 'yes' : 'no',
          user: session.auth ? session.auth.username : 'anonymous'
        });
        
        this.processEmail(stream, session)
          .then(() => {
            this.logger.info('Email processed successfully', {
              sessionId: session.id,
              secure: session.secure
            });
            callback();
          })
          .catch(error => {
            this.logger.error(`Failed to process email: ${error.message}`, {
              sessionId: session.id,
              error: error.stack
            });
            callback(new Error('Error processing email'));
          });
      }
    });

    // Handle server errors with detailed logging
    server.on('error', error => {
      this.logger.error('SMTP Server error:', {
        error: error.message,
        stack: error.stack,
        code: error.code,
        phase: error.phase,
        responseCode: error.responseCode
      });
    });

    // Additional server event listeners for debugging
    server.on('tlsError', (error, socket) => {
      this.logger.error('TLS Error:', {
        error: error.message,
        stack: error.stack,
        code: error.code,
        remoteAddress: socket?.remoteAddress
      });
    });

    return server;
  }

  async processEmail(stream, session) {
    try {
      const parsed = await simpleParser(stream);
      const sdk = new EmailssarySDK(session.auth.password);

      const htmlParsed = parseSimpleYaml(parsed.html || '');
      if (!htmlParsed.type) {
        this.logger.error('No email type found in the HTML');
        throw new Error('No email type found in the HTML');
      }
      const { type, ...data } = htmlParsed;
      const recipient = parsed.to?.text || '';
      try {
        await sdk.sendEmail({
          recipient: recipient,
          email_type: type,
          data: data
        });
        this.logger.info(`Email sent successfully - ${parsed.messageId} - ${recipient}`);
      } catch (error) {
        this.logger.error(`Error sending email: ${error.message}`);
        return false;
      }
      
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

