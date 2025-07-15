/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Advanced Logging Utility
 * 
 * @author IRFAN AHMMED
 * @description Production-grade logging with multiple transports,
 * security event tracking, and structured logging
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Custom log levels for cybersecurity events
const customLevels = {
  levels: {
    fatal: 0,
    error: 1,
    security: 2,
    warn: 3,
    audit: 4,
    info: 5,
    debug: 6,
    trace: 7
  },
  colors: {
    fatal: 'red bold',
    error: 'red',
    security: 'magenta bold',
    warn: 'yellow',
    audit: 'blue bold',
    info: 'green',
    debug: 'cyan',
    trace: 'gray'
  }
};

// Custom format for structured logging
const customFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    let logEntry = {
      timestamp,
      level: level.toUpperCase(),
      message,
      ...(stack && { stack }),
      ...meta
    };

    // Add security context for security-related logs
    if (level === 'security' || level === 'audit') {
      logEntry.component = 'SECURITY';
      logEntry.category = meta.category || 'GENERAL';
    }

    return JSON.stringify(logEntry);
  })
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({
    format: 'HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}] ${message} ${stack || ''} ${metaStr}`;
  })
);

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');
require('fs').mkdirSync(logsDir, { recursive: true });

// Configure transports
const transports = [
  // Console transport for development
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: process.env.NODE_ENV === 'production' ? customFormat : consoleFormat,
    handleExceptions: true,
    handleRejections: true
  })
];

// File transports for production
if (process.env.LOG_FILE_ENABLED === 'true' || process.env.NODE_ENV === 'production') {
  // General application logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'app-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: process.env.LOG_MAX_FILES || '14d',
      maxSize: process.env.LOG_MAX_SIZE || '100m',
      format: customFormat,
      level: 'info'
    })
  );

  // Error logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: process.env.LOG_MAX_FILES || '30d',
      maxSize: process.env.LOG_MAX_SIZE || '100m',
      format: customFormat,
      level: 'error'
    })
  );

  // Security audit logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'security-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: '90d', // Keep security logs longer
      maxSize: process.env.LOG_MAX_SIZE || '100m',
      format: customFormat,
      level: 'security'
    })
  );

  // Audit trail logs
  transports.push(
    new DailyRotateFile({
      filename: path.join(logsDir, 'audit-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: '365d', // Keep audit logs for compliance
      maxSize: process.env.LOG_MAX_SIZE || '100m',
      format: customFormat,
      level: 'audit'
    })
  );
}

// Create the logger instance
const logger = winston.createLogger({
  levels: customLevels.levels,
  level: process.env.LOG_LEVEL || 'info',
  format: customFormat,
  transports,
  exitOnError: false
});

// Add colors to winston
winston.addColors(customLevels.colors);

// Enhanced logging methods with context
class CybersecLogger {
  constructor(winstonLogger) {
    this.winston = winstonLogger;
  }

  // Standard logging methods
  fatal(message, meta = {}) {
    this.winston.log('fatal', message, { ...meta, severity: 'CRITICAL' });
  }

  error(message, meta = {}) {
    this.winston.log('error', message, meta);
  }

  warn(message, meta = {}) {
    this.winston.log('warn', message, meta);
  }

  info(message, meta = {}) {
    this.winston.log('info', message, meta);
  }

  debug(message, meta = {}) {
    this.winston.log('debug', message, meta);
  }

  trace(message, meta = {}) {
    this.winston.log('trace', message, meta);
  }

  // Security-specific logging methods
  security(message, meta = {}) {
    this.winston.log('security', message, {
      ...meta,
      category: meta.category || 'SECURITY_EVENT',
      timestamp: new Date().toISOString()
    });
  }

  audit(message, meta = {}) {
    this.winston.log('audit', message, {
      ...meta,
      category: meta.category || 'AUDIT_TRAIL',
      timestamp: new Date().toISOString()
    });
  }

  // Specialized cybersecurity logging methods
  authAttempt(username, success, ip, userAgent, meta = {}) {
    this.security(`Authentication attempt: ${success ? 'SUCCESS' : 'FAILED'}`, {
      category: 'AUTHENTICATION',
      username,
      success,
      ip,
      userAgent,
      ...meta
    });
  }

  scanEvent(scanType, target, userId, status, meta = {}) {
    this.security(`Scan ${status}: ${scanType}`, {
      category: 'VULNERABILITY_SCAN',
      scanType,
      target,
      userId,
      status,
      ...meta
    });
  }

  bruteForceAttempt(target, protocol, userId, status, meta = {}) {
    this.security(`Brute force simulation: ${status}`, {
      category: 'BRUTE_FORCE_SIM',
      target,
      protocol,
      userId,
      status,
      ...meta
    });
  }

  phishingEvent(campaignId, userId, action, meta = {}) {
    this.security(`Phishing simulation: ${action}`, {
      category: 'PHISHING_SIM',
      campaignId,
      userId,
      action,
      ...meta
    });
  }

  riskAssessment(targetId, riskScore, aiPrediction, meta = {}) {
    this.audit('Risk assessment completed', {
      category: 'RISK_ASSESSMENT',
      targetId,
      riskScore,
      aiPrediction,
      ...meta
    });
  }

  billingEvent(userId, action, amount, meta = {}) {
    this.audit(`Billing event: ${action}`, {
      category: 'BILLING',
      userId,
      action,
      amount,
      ...meta
    });
  }

  apiAccess(endpoint, method, userId, ip, statusCode, responseTime, meta = {}) {
    this.audit('API access', {
      category: 'API_ACCESS',
      endpoint,
      method,
      userId,
      ip,
      statusCode,
      responseTime,
      ...meta
    });
  }

  systemEvent(component, event, status, meta = {}) {
    this.info(`System event: ${component} - ${event}`, {
      category: 'SYSTEM',
      component,
      event,
      status,
      ...meta
    });
  }

  // Performance logging
  performanceMetric(operation, duration, meta = {}) {
    this.debug(`Performance: ${operation}`, {
      category: 'PERFORMANCE',
      operation,
      duration,
      ...meta
    });
  }

  // Structured error logging
  errorWithContext(error, context = {}) {
    this.error(error.message, {
      stack: error.stack,
      name: error.name,
      code: error.code,
      ...context
    });
  }

  // Create child logger with persistent context
  child(persistentMeta = {}) {
    return {
      ...this,
      info: (message, meta = {}) => this.info(message, { ...persistentMeta, ...meta }),
      error: (message, meta = {}) => this.error(message, { ...persistentMeta, ...meta }),
      warn: (message, meta = {}) => this.warn(message, { ...persistentMeta, ...meta }),
      debug: (message, meta = {}) => this.debug(message, { ...persistentMeta, ...meta }),
      security: (message, meta = {}) => this.security(message, { ...persistentMeta, ...meta }),
      audit: (message, meta = {}) => this.audit(message, { ...persistentMeta, ...meta })
    };
  }
}

// Create enhanced logger instance
const cybersecLogger = new CybersecLogger(logger);

// Handle logging errors
logger.on('error', (error) => {
  console.error('Logger error:', error);
});

// Log system startup
cybersecLogger.systemEvent('LOGGER', 'INITIALIZED', 'SUCCESS', {
  logLevel: process.env.LOG_LEVEL || 'info',
  environment: process.env.NODE_ENV || 'development',
  fileLogging: process.env.LOG_FILE_ENABLED === 'true' || process.env.NODE_ENV === 'production'
});

module.exports = cybersecLogger;