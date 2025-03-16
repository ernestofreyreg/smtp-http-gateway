#!/usr/bin/env node
// bin/cli.js
const SmtpHttpGateway = require('../src/index');

// Handle process termination
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

let gateway;

async function shutdown() {
  if (gateway) {
    await gateway.stop();
  }
  process.exit(0);
}

// Start the gateway
async function start() {
  gateway = new SmtpHttpGateway();
  
  try {
    await gateway.start();
  } catch (error) {
    console.error('Failed to start SMTP to HTTP gateway:', error);
    process.exit(1);
  }
}

start();
