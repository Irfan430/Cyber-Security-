/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Global Error Handler Middleware
 * 
 * @author IRFAN AHMMED
 * @description Production-grade error handling with security logging,
 * sanitization, and appropriate response formatting
 */

const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

/**
 * Custom application error class
 */
class AppError extends Error {
  constructor(message, statusCode, code = null, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = isOperational;
    this.code = code;
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Sanitize error message for production
 */
const sanitizeErrorMessage = (error, isProduction) => {
  if (!isProduction) {
    return error.message;
  }

  // Don't expose sensitive information in production
  const safeMappings = {
    'ValidationError': 'Invalid input data provided',
    'CastError': 'Invalid data format',
    'JsonWebTokenError': 'Authentication failed',
    'TokenExpiredError': 'Session expired',
    'MongoServerError': 'Database operation failed',
    'MulterError': 'File upload error'
  };

  return safeMappings[error.name] || 'An internal server error occurred';
};

/**
 * Handle MongoDB validation errors
 */
const handleValidationError = (error) => {
  const errors = Object.values(error.errors).map(err => ({
    field: err.path,
    message: err.message,
    value: err.value
  }));

  return new AppError('Invalid input data', 400, 'VALIDATION_ERROR');
};

/**
 * Handle MongoDB duplicate key errors
 */
const handleDuplicateKeyError = (error) => {
  const field = Object.keys(error.keyValue)[0];
  const value = error.keyValue[field];
  
  return new AppError(
    `Duplicate value for field ${field}: ${value}`,
    400,
    'DUPLICATE_KEY_ERROR'
  );
};

/**
 * Handle MongoDB cast errors
 */
const handleCastError = (error) => {
  return new AppError(
    `Invalid ${error.path}: ${error.value}`,
    400,
    'INVALID_ID_ERROR'
  );
};

/**
 * Handle JWT errors
 */
const handleJWTError = () => {
  return new AppError('Invalid authentication token', 401, 'INVALID_TOKEN');
};

const handleJWTExpiredError = () => {
  return new AppError('Authentication token has expired', 401, 'TOKEN_EXPIRED');
};

/**
 * Handle Multer errors
 */
const handleMulterError = (error) => {
  const errorMessages = {
    'LIMIT_FILE_SIZE': 'File too large',
    'LIMIT_FILE_COUNT': 'Too many files',
    'LIMIT_UNEXPECTED_FILE': 'Unexpected file field',
    'MISSING_FIELD_NAME': 'Missing field name'
  };

  return new AppError(
    errorMessages[error.code] || 'File upload error',
    400,
    'FILE_UPLOAD_ERROR'
  );
};

/**
 * Security-related error detection
 */
const detectSecurityThreats = (error, req) => {
  const threats = [];

  // SQL Injection attempt detection
  if (error.message && /('|(\\\')|(%27)|(\\%27)|(\\\'))/i.test(error.message)) {
    threats.push('SQL_INJECTION_ATTEMPT');
  }

  // XSS attempt detection
  if (error.message && /<script[^>]*>.*?<\/script>/gi.test(error.message)) {
    threats.push('XSS_ATTEMPT');
  }

  // Path traversal detection
  if (error.message && /(\.\.\/|\.\.\\)/i.test(error.message)) {
    threats.push('PATH_TRAVERSAL_ATTEMPT');
  }

  // Command injection detection
  if (error.message && /(\;|\||\&|\$\(|\`)/i.test(error.message)) {
    threats.push('COMMAND_INJECTION_ATTEMPT');
  }

  // Log security threats
  if (threats.length > 0) {
    logger.security('Security threat detected in error', {
      category: 'THREAT_DETECTION',
      threats,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      method: req.method,
      userId: req.user?.id,
      errorMessage: error.message
    });
  }

  return threats;
};

/**
 * Rate limiting detection for error-based attacks
 */
const trackErrorRates = (() => {
  const errorCounts = new Map();
  const WINDOW_SIZE = 5 * 60 * 1000; // 5 minutes
  const ERROR_THRESHOLD = 50; // errors per window

  return (req) => {
    const key = req.ip;
    const now = Date.now();
    
    if (!errorCounts.has(key)) {
      errorCounts.set(key, []);
    }

    const timestamps = errorCounts.get(key);
    
    // Remove old timestamps
    const validTimestamps = timestamps.filter(time => now - time < WINDOW_SIZE);
    validTimestamps.push(now);
    
    errorCounts.set(key, validTimestamps);

    // Check if threshold exceeded
    if (validTimestamps.length > ERROR_THRESHOLD) {
      logger.security('High error rate detected - possible attack', {
        category: 'ERROR_RATE_ANOMALY',
        ip: req.ip,
        errorCount: validTimestamps.length,
        timeWindow: WINDOW_SIZE,
        userAgent: req.get('User-Agent')
      });
      
      return true;
    }

    return false;
  };
})();

/**
 * Development error response
 */
const sendErrorDev = (err, req, res) => {
  const errorId = uuidv4();
  
  logger.error('Development error', {
    errorId,
    name: err.name,
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });

  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      id: errorId,
      status: err.status,
      message: err.message,
      code: err.code,
      stack: err.stack,
      timestamp: err.timestamp || new Date().toISOString()
    },
    request: {
      url: req.originalUrl,
      method: req.method,
      headers: req.headers,
      body: req.body
    }
  });
};

/**
 * Production error response
 */
const sendErrorProd = (err, req, res) => {
  const errorId = uuidv4();
  
  // Log full error details for debugging
  logger.error('Production error', {
    errorId,
    name: err.name,
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    isOperational: err.isOperational
  });

  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      error: {
        id: errorId,
        status: err.status,
        message: err.message,
        code: err.code,
        timestamp: err.timestamp || new Date().toISOString()
      }
    });
  } else {
    // Programming or other unknown error: don't leak error details
    logger.fatal('Non-operational error', {
      errorId,
      name: err.name,
      message: err.message,
      stack: err.stack
    });

    res.status(500).json({
      success: false,
      error: {
        id: errorId,
        status: 'error',
        message: 'Something went wrong on our end',
        timestamp: new Date().toISOString()
      }
    });
  }
};

/**
 * Main error handling middleware
 */
const globalErrorHandler = (err, req, res, next) => {
  // Set default values
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  // Detect security threats
  detectSecurityThreats(err, req);

  // Track error rates for abuse detection
  trackErrorRates(req);

  // Handle different error types
  let error = { ...err };
  error.message = err.message;

  // MongoDB validation error
  if (err.name === 'ValidationError') {
    error = handleValidationError(err);
  }

  // MongoDB duplicate key error
  if (err.code === 11000) {
    error = handleDuplicateKeyError(err);
  }

  // MongoDB cast error
  if (err.name === 'CastError') {
    error = handleCastError(err);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    error = handleJWTError();
  }

  if (err.name === 'TokenExpiredError') {
    error = handleJWTExpiredError();
  }

  // Multer errors
  if (err.name === 'MulterError') {
    error = handleMulterError(err);
  }

  // Send appropriate response based on environment
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(error, req, res);
  } else {
    sendErrorProd(error, req, res);
  }
};

/**
 * Async error wrapper
 */
const catchAsync = (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res, next) => {
  const err = new AppError(`Can't find ${req.originalUrl} on this server!`, 404, 'NOT_FOUND');
  next(err);
};

module.exports = {
  AppError,
  globalErrorHandler,
  catchAsync,
  notFoundHandler
};