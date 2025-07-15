/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Security Middleware
 * 
 * @author IRFAN AHMMED
 * @description Advanced security middleware with threat detection,
 * input sanitization, attack prevention, and security logging
 */

const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const validator = require('validator');
const { AppError } = require('./errorHandler');
const logger = require('../utils/logger');

/**
 * Comprehensive input sanitization
 */
const sanitizeInput = (req, res, next) => {
  const sanitizeObject = (obj) => {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }

    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === 'string') {
          // XSS protection
          obj[key] = xss(obj[key], {
            whiteList: {}, // No HTML tags allowed
            stripIgnoreTag: true,
            stripIgnoreTagBody: ['script']
          });

          // Additional sanitization for common injection patterns
          obj[key] = obj[key]
            .replace(/[<>]/g, '') // Remove < and >
            .replace(/javascript:/gi, '') // Remove javascript: protocol
            .replace(/on\w+\s*=/gi, '') // Remove event handlers
            .replace(/data:/gi, '') // Remove data: protocol
            .trim();

        } else if (typeof obj[key] === 'object') {
          sanitizeObject(obj[key]);
        }
      }
    }
  };

  // Sanitize request body
  if (req.body) {
    sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query) {
    sanitizeObject(req.query);
  }

  // Sanitize URL parameters
  if (req.params) {
    sanitizeObject(req.params);
  }

  next();
};

/**
 * SQL Injection detection and prevention
 */
const detectSQLInjection = (req, res, next) => {
  const sqlPatterns = [
    /('|(\\\')|(%27)|(\\%27)|(\\\'))/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\\\')|(\')|((\%3B)|(;)))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /((\%27)|(\'))union/i,
    /exec(\s|\+)+(s|x)p\w+/i,
    /UNION[^a-zA-Z]/i,
    /SELECT[^a-zA-Z]/i,
    /INSERT[^a-zA-Z]/i,
    /UPDATE[^a-zA-Z]/i,
    /DELETE[^a-zA-Z]/i,
    /DROP[^a-zA-Z]/i,
    /CREATE[^a-zA-Z]/i,
    /ALTER[^a-zA-Z]/i
  ];

  const checkForSQLInjection = (obj, path = '') => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        for (const pattern of sqlPatterns) {
          if (pattern.test(obj[key])) {
            logger.security('SQL Injection attempt detected', {
              category: 'SQL_INJECTION',
              field: `${path}${key}`,
              value: obj[key],
              pattern: pattern.source,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              endpoint: req.originalUrl,
              method: req.method
            });
            
            return next(new AppError('Invalid input detected', 400, 'INVALID_INPUT'));
          }
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        checkForSQLInjection(obj[key], `${path}${key}.`);
      }
    }
  };

  // Check all input sources
  if (req.body) checkForSQLInjection(req.body, 'body.');
  if (req.query) checkForSQLInjection(req.query, 'query.');
  if (req.params) checkForSQLInjection(req.params, 'params.');

  next();
};

/**
 * NoSQL Injection detection and prevention
 */
const detectNoSQLInjection = (req, res, next) => {
  const checkForNoSQLInjection = (obj, path = '') => {
    for (const key in obj) {
      // Check for MongoDB operators
      if (key.startsWith('$')) {
        logger.security('NoSQL Injection attempt detected', {
          category: 'NOSQL_INJECTION',
          field: `${path}${key}`,
          value: obj[key],
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.originalUrl,
          method: req.method
        });
        
        return next(new AppError('Invalid input detected', 400, 'INVALID_INPUT'));
      }

      if (typeof obj[key] === 'object' && obj[key] !== null) {
        checkForNoSQLInjection(obj[key], `${path}${key}.`);
      }
    }
  };

  // Check all input sources
  if (req.body) checkForNoSQLInjection(req.body, 'body.');
  if (req.query) checkForNoSQLInjection(req.query, 'query.');
  if (req.params) checkForNoSQLInjection(req.params, 'params.');

  next();
};

/**
 * Command Injection detection
 */
const detectCommandInjection = (req, res, next) => {
  const commandPatterns = [
    /(\;|\||\&|\$\(|\`)/i,
    /(system|exec|eval|shell_exec|passthru|cmd)/i,
    /(rm\s|del\s|format\s|mkfs)/i,
    /(\/bin\/|\/usr\/bin\/|cmd\.exe|powershell)/i,
    /(wget|curl|nc|netcat|telnet)/i
  ];

  const checkForCommandInjection = (obj, path = '') => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        for (const pattern of commandPatterns) {
          if (pattern.test(obj[key])) {
            logger.security('Command Injection attempt detected', {
              category: 'COMMAND_INJECTION',
              field: `${path}${key}`,
              value: obj[key],
              pattern: pattern.source,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              endpoint: req.originalUrl,
              method: req.method
            });
            
            return next(new AppError('Invalid input detected', 400, 'INVALID_INPUT'));
          }
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        checkForCommandInjection(obj[key], `${path}${key}.`);
      }
    }
  };

  // Check all input sources
  if (req.body) checkForCommandInjection(req.body, 'body.');
  if (req.query) checkForCommandInjection(req.query, 'query.');
  if (req.params) checkForCommandInjection(req.params, 'params.');

  next();
};

/**
 * Path Traversal detection
 */
const detectPathTraversal = (req, res, next) => {
  const pathTraversalPatterns = [
    /(\.\.\/|\.\.\\)/i,
    /(%2e%2e%2f|%2e%2e%5c)/i,
    /(\.\.%2f|\.\.%5c)/i,
    /(%252e%252e%252f|%252e%252e%255c)/i
  ];

  const checkForPathTraversal = (obj, path = '') => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        for (const pattern of pathTraversalPatterns) {
          if (pattern.test(obj[key])) {
            logger.security('Path Traversal attempt detected', {
              category: 'PATH_TRAVERSAL',
              field: `${path}${key}`,
              value: obj[key],
              pattern: pattern.source,
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              endpoint: req.originalUrl,
              method: req.method
            });
            
            return next(new AppError('Invalid input detected', 400, 'INVALID_INPUT'));
          }
        }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        checkForPathTraversal(obj[key], `${path}${key}.`);
      }
    }
  };

  // Check all input sources
  if (req.body) checkForPathTraversal(req.body, 'body.');
  if (req.query) checkForPathTraversal(req.query, 'query.');
  if (req.params) checkForPathTraversal(req.params, 'params.');

  next();
};

/**
 * Detect suspicious user agents
 */
const detectSuspiciousUserAgent = (req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  
  const suspiciousPatterns = [
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /masscan/i,
    /zap/i,
    /burp/i,
    /nuclei/i,
    /gobuster/i,
    /dirb/i,
    /dirbuster/i,
    /python-requests/i,
    /curl\/[0-9]/i,
    /wget/i
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(userAgent)) {
      logger.security('Suspicious User-Agent detected', {
        category: 'SUSPICIOUS_USER_AGENT',
        userAgent: userAgent,
        ip: req.ip,
        endpoint: req.originalUrl,
        method: req.method
      });
      
      // Don't block but log for monitoring
      break;
    }
  }

  next();
};

/**
 * Detect bot and crawler activity
 */
const detectBots = (req, res, next) => {
  const userAgent = req.get('User-Agent') || '';
  
  const botPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i,
    /googlebot/i,
    /bingbot/i,
    /slurp/i,
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i
  ];

  for (const pattern of botPatterns) {
    if (pattern.test(userAgent)) {
      req.isBot = true;
      
      logger.debug('Bot detected', {
        category: 'BOT_DETECTION',
        userAgent: userAgent,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      break;
    }
  }

  next();
};

/**
 * Content Security Policy violations handler
 */
const handleCSPViolation = (req, res, next) => {
  if (req.path === '/csp-violation-report' && req.method === 'POST') {
    logger.security('CSP Violation reported', {
      category: 'CSP_VIOLATION',
      violation: req.body,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    res.status(204).end();
    return;
  }
  
  next();
};

/**
 * Request size limiting
 */
const limitRequestSize = (req, res, next) => {
  const maxSize = 10 * 1024 * 1024; // 10MB
  const contentLength = parseInt(req.get('Content-Length') || '0');
  
  if (contentLength > maxSize) {
    logger.security('Request size limit exceeded', {
      category: 'SIZE_LIMIT_EXCEEDED',
      contentLength: contentLength,
      maxSize: maxSize,
      ip: req.ip,
      endpoint: req.originalUrl
    });
    
    return next(new AppError('Request entity too large', 413, 'REQUEST_TOO_LARGE'));
  }
  
  next();
};

/**
 * Honeypot detection
 */
const detectHoneypot = (req, res, next) => {
  // Check for common vulnerability scanner paths
  const honeypotPaths = [
    '/admin',
    '/wp-admin',
    '/phpmyadmin',
    '/mysql',
    '/.env',
    '/config.php',
    '/wp-config.php',
    '/.git',
    '/backup',
    '/test',
    '/debug'
  ];

  if (honeypotPaths.some(path => req.path.includes(path))) {
    logger.security('Honeypot triggered', {
      category: 'HONEYPOT',
      path: req.path,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      method: req.method
    });
    
    // Return 404 to hide the fact that this is a honeypot
    return next(new AppError('Not found', 404, 'NOT_FOUND'));
  }
  
  next();
};

/**
 * Main security middleware
 */
const securityMiddleware = [
  // Limit request size
  limitRequestSize,
  
  // MongoDB injection protection
  mongoSanitize(),
  
  // Parameter pollution protection
  hpp({
    whitelist: ['sort', 'fields', 'limit', 'page'] // Allow certain parameters to be duplicated
  }),
  
  // Custom security checks
  detectSuspiciousUserAgent,
  detectBots,
  handleCSPViolation,
  detectHoneypot,
  sanitizeInput,
  detectSQLInjection,
  detectNoSQLInjection,
  detectCommandInjection,
  detectPathTraversal
];

module.exports = securityMiddleware;