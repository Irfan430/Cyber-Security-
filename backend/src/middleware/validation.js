/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Validation Middleware
 * 
 * @author IRFAN AHMMED
 * @description Comprehensive input validation using Joi schemas
 * with cybersecurity-specific validation rules
 */

const Joi = require('joi');
const { AppError } = require('./errorHandler');
const logger = require('../utils/logger');

/**
 * Custom validation rules for cybersecurity context
 */
const customJoi = Joi.extend({
  type: 'cybersec',
  base: Joi.string(),
  messages: {
    'cybersec.ip': 'Must be a valid IP address',
    'cybersec.domain': 'Must be a valid domain name',
    'cybersec.port': 'Must be a valid port number (1-65535)',
    'cybersec.cidr': 'Must be a valid CIDR notation',
    'cybersec.protocol': 'Must be a valid network protocol'
  },
  rules: {
    ip: {
      validate(value, helpers) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(value)) {
          return helpers.error('cybersec.ip');
        }
        return value;
      }
    },
    domain: {
      validate(value, helpers) {
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!domainRegex.test(value)) {
          return helpers.error('cybersec.domain');
        }
        return value;
      }
    },
    port: {
      validate(value, helpers) {
        const port = parseInt(value);
        if (isNaN(port) || port < 1 || port > 65535) {
          return helpers.error('cybersec.port');
        }
        return port;
      }
    },
    cidr: {
      validate(value, helpers) {
        const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
        if (!cidrRegex.test(value)) {
          return helpers.error('cybersec.cidr');
        }
        return value;
      }
    },
    protocol: {
      validate(value, helpers) {
        const validProtocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'ftp', 'ssh', 'telnet', 'smtp', 'pop3', 'imap'];
        if (!validProtocols.includes(value.toLowerCase())) {
          return helpers.error('cybersec.protocol');
        }
        return value.toLowerCase();
      }
    }
  }
});

/**
 * Common validation schemas
 */
const schemas = {
  // User validation schemas
  userRegistration: Joi.object({
    firstName: Joi.string().min(2).max(50).trim().required(),
    lastName: Joi.string().min(2).max(50).trim().required(),
    email: Joi.string().email().lowercase().required(),
    password: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required()
      .messages({
        'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
      }),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required(),
    organization: Joi.string().min(2).max(100).trim().optional(),
    role: Joi.string().valid('admin', 'manager', 'viewer').default('viewer'),
    termsAccepted: Joi.boolean().valid(true).required()
  }),

  userLogin: Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
    rememberMe: Joi.boolean().default(false)
  }),

  userUpdate: Joi.object({
    firstName: Joi.string().min(2).max(50).trim(),
    lastName: Joi.string().min(2).max(50).trim(),
    organization: Joi.string().min(2).max(100).trim(),
    avatar: Joi.string().uri(),
    preferences: Joi.object({
      theme: Joi.string().valid('light', 'dark').default('light'),
      notifications: Joi.object({
        email: Joi.boolean().default(true),
        push: Joi.boolean().default(true),
        slack: Joi.boolean().default(false),
        telegram: Joi.boolean().default(false)
      })
    })
  }),

  passwordChange: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: Joi.string()
      .min(8)
      .max(128)
      .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .required(),
    confirmPassword: Joi.string().valid(Joi.ref('newPassword')).required()
  }),

  // Target validation schemas
  targetCreation: Joi.object({
    name: Joi.string().min(2).max(100).trim().required(),
    description: Joi.string().max(500).trim().optional(),
    type: Joi.string().valid('domain', 'ip', 'range', 'url').required(),
    value: Joi.alternatives().conditional('type', [
      { is: 'domain', then: customJoi.cybersec().domain().required() },
      { is: 'ip', then: customJoi.cybersec().ip().required() },
      { is: 'range', then: customJoi.cybersec().cidr().required() },
      { is: 'url', then: Joi.string().uri().required() }
    ]),
    tags: Joi.array().items(Joi.string().min(1).max(20)).max(10).default([]),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium'),
    active: Joi.boolean().default(true)
  }),

  targetUpdate: Joi.object({
    name: Joi.string().min(2).max(100).trim(),
    description: Joi.string().max(500).trim(),
    tags: Joi.array().items(Joi.string().min(1).max(20)).max(10),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical'),
    active: Joi.boolean()
  }),

  // Scan validation schemas
  scanCreation: Joi.object({
    targetId: Joi.string().hex().length(24).required(),
    scanType: Joi.string().valid('nmap', 'nikto', 'custom').required(),
    configuration: Joi.object({
      ports: Joi.string().pattern(/^[\d,-]+$/).optional(),
      aggressive: Joi.boolean().default(false),
      stealth: Joi.boolean().default(true),
      timeout: Joi.number().min(30).max(3600).default(300),
      maxHosts: Joi.number().min(1).max(100).default(10)
    }).default({}),
    scheduled: Joi.boolean().default(false),
    scheduleTime: Joi.date().greater('now').when('scheduled', {
      is: true,
      then: Joi.required()
    })
  }),

  // Brute force simulation schemas
  bruteForceCreation: Joi.object({
    targetId: Joi.string().hex().length(24).required(),
    protocol: customJoi.cybersec().protocol().required(),
    port: customJoi.cybersec().port().optional(),
    usernames: Joi.array().items(Joi.string().min(1).max(50)).min(1).max(100).required(),
    passwords: Joi.array().items(Joi.string().min(1).max(50)).min(1).max(100),
    wordlistType: Joi.string().valid('common', 'extended', 'custom').default('common'),
    maxAttempts: Joi.number().min(1).max(1000).default(100),
    delay: Joi.number().min(100).max(10000).default(1000),
    threads: Joi.number().min(1).max(10).default(3),
    useProxyRotation: Joi.boolean().default(true),
    useUserAgentRotation: Joi.boolean().default(true)
  }),

  // Risk assessment schemas
  riskAssessment: Joi.object({
    targetId: Joi.string().hex().length(24).required(),
    scanResults: Joi.array().items(Joi.string().hex().length(24)).min(1).required(),
    customFactors: Joi.object({
      businessCriticality: Joi.number().min(1).max(10).default(5),
      dataClassification: Joi.string().valid('public', 'internal', 'confidential', 'restricted').default('internal'),
      exposureLevel: Joi.string().valid('internal', 'external', 'public').default('internal')
    }).default({})
  }),

  // Report generation schemas
  reportGeneration: Joi.object({
    targetIds: Joi.array().items(Joi.string().hex().length(24)).min(1).required(),
    reportType: Joi.string().valid('summary', 'detailed', 'executive', 'technical').default('summary'),
    format: Joi.string().valid('pdf', 'html', 'json').default('pdf'),
    includeRecommendations: Joi.boolean().default(true),
    includeCharts: Joi.boolean().default(true),
    customSections: Joi.array().items(Joi.string()).optional()
  }),

  // Phishing simulation schemas
  phishingCampaign: Joi.object({
    name: Joi.string().min(2).max(100).trim().required(),
    description: Joi.string().max(500).trim().optional(),
    templateId: Joi.string().hex().length(24).required(),
    targets: Joi.array().items(
      Joi.object({
        email: Joi.string().email().required(),
        firstName: Joi.string().min(1).max(50).trim().required(),
        lastName: Joi.string().min(1).max(50).trim().required(),
        department: Joi.string().max(50).trim().optional(),
        consentGiven: Joi.boolean().valid(true).required()
      })
    ).min(1).max(1000).required(),
    sendingSchedule: Joi.object({
      startDate: Joi.date().greater('now').required(),
      endDate: Joi.date().greater(Joi.ref('startDate')).optional(),
      frequency: Joi.string().valid('immediate', 'hourly', 'daily', 'weekly').default('immediate')
    }).required(),
    trackingEnabled: Joi.boolean().default(true)
  }),

  // Billing schemas
  subscriptionCreation: Joi.object({
    planId: Joi.string().valid('basic', 'professional', 'enterprise').required(),
    paymentMethod: Joi.string().valid('stripe', 'paypal').required(),
    billingCycle: Joi.string().valid('monthly', 'yearly').default('monthly'),
    couponCode: Joi.string().max(50).optional()
  }),

  // DevOps API schemas
  devopsSecurityCheck: Joi.object({
    repositoryUrl: Joi.string().uri().required(),
    branch: Joi.string().min(1).max(100).default('main'),
    scanTypes: Joi.array().items(
      Joi.string().valid('sast', 'dast', 'dependency', 'secrets', 'iac')
    ).min(1).required(),
    severity: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium'),
    failOnIssues: Joi.boolean().default(false)
  }),

  // Query parameters validation
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(10),
    sort: Joi.string().pattern(/^-?[a-zA-Z_][a-zA-Z0-9_]*$/).default('-createdAt'),
    fields: Joi.string().pattern(/^[a-zA-Z_][a-zA-Z0-9_,]*$/).optional()
  }),

  // Common filters
  dateRange: Joi.object({
    startDate: Joi.date().required(),
    endDate: Joi.date().greater(Joi.ref('startDate')).required()
  }),

  // ID parameter validation
  mongoId: Joi.string().hex().length(24).required()
};

/**
 * Generic validation middleware factory
 */
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const data = source === 'body' ? req.body : 
                  source === 'query' ? req.query : 
                  source === 'params' ? req.params : req[source];

    const { error, value } = schema.validate(data, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      logger.debug('Validation failed', {
        source,
        errors,
        data,
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.user?.id
      });

      return next(new AppError('Validation failed', 400, 'VALIDATION_ERROR', true, { errors }));
    }

    // Replace the source data with validated and sanitized data
    req[source] = value;
    next();
  };
};

/**
 * File upload validation
 */
const validateFileUpload = (allowedTypes = [], maxSize = 5 * 1024 * 1024) => {
  return (req, res, next) => {
    if (!req.file && !req.files) {
      return next();
    }

    const files = req.files || [req.file];
    
    for (const file of files) {
      // Check file type
      if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
        logger.security('Invalid file type uploaded', {
          category: 'FILE_UPLOAD',
          fileName: file.originalname,
          mimeType: file.mimetype,
          allowedTypes,
          userId: req.user?.id,
          ip: req.ip
        });
        
        return next(new AppError(`File type ${file.mimetype} is not allowed`, 400, 'INVALID_FILE_TYPE'));
      }

      // Check file size
      if (file.size > maxSize) {
        logger.security('File size limit exceeded', {
          category: 'FILE_UPLOAD',
          fileName: file.originalname,
          fileSize: file.size,
          maxSize,
          userId: req.user?.id,
          ip: req.ip
        });
        
        return next(new AppError(`File size ${file.size} exceeds limit of ${maxSize}`, 400, 'FILE_TOO_LARGE'));
      }

      // Check for malicious file names
      const maliciousPatterns = [
        /\.\.\//, // Path traversal
        /\.php$|\.asp$|\.jsp$|\.js$/, // Executable files
        /[<>:"|?*]/, // Invalid characters
        /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i // Windows reserved names
      ];

      for (const pattern of maliciousPatterns) {
        if (pattern.test(file.originalname)) {
          logger.security('Malicious file name detected', {
            category: 'FILE_UPLOAD',
            fileName: file.originalname,
            pattern: pattern.source,
            userId: req.user?.id,
            ip: req.ip
          });
          
          return next(new AppError('Invalid file name', 400, 'INVALID_FILE_NAME'));
        }
      }
    }

    next();
  };
};

/**
 * Rate limiting validation
 */
const validateRateLimit = (windowMs = 15 * 60 * 1000, max = 100) => {
  const requests = new Map();

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();

    if (!requests.has(key)) {
      requests.set(key, []);
    }

    const userRequests = requests.get(key);
    const recentRequests = userRequests.filter(time => now - time < windowMs);

    if (recentRequests.length >= max) {
      logger.security('Rate limit exceeded', {
        category: 'RATE_LIMITING',
        ip: req.ip,
        requests: recentRequests.length,
        max,
        windowMs,
        endpoint: req.originalUrl
      });

      return next(new AppError('Too many requests', 429, 'RATE_LIMIT_EXCEEDED'));
    }

    recentRequests.push(now);
    requests.set(key, recentRequests);
    next();
  };
};

module.exports = {
  validate,
  schemas,
  validateFileUpload,
  validateRateLimit,
  customJoi
};