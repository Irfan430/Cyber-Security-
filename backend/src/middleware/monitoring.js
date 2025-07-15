/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Monitoring Middleware
 * 
 * @author IRFAN AHMMED
 * @description Advanced monitoring with performance tracking,
 * metrics collection, health monitoring, and alerting
 */

const logger = require('../utils/logger');
const os = require('os');
const process = require('process');
const { v4: uuidv4 } = require('uuid');

/**
 * Performance metrics collector
 */
class MetricsCollector {
  constructor() {
    this.metrics = {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        byEndpoint: new Map(),
        byStatusCode: new Map(),
        byUserAgent: new Map(),
        responseTime: {
          min: Infinity,
          max: 0,
          sum: 0,
          count: 0,
          avg: 0
        }
      },
      security: {
        authAttempts: 0,
        authFailures: 0,
        blockedRequests: 0,
        suspiciousActivity: 0,
        rateLimitHits: 0
      },
      system: {
        cpuUsage: 0,
        memoryUsage: 0,
        diskUsage: 0,
        uptime: 0,
        loadAverage: [0, 0, 0]
      },
      database: {
        connections: 0,
        queries: 0,
        errors: 0,
        avgResponseTime: 0
      },
      business: {
        activeUsers: 0,
        scansRunning: 0,
        reportsGenerated: 0,
        alerts: 0
      }
    };
    
    // Update system metrics every 30 seconds
    setInterval(() => {
      this.updateSystemMetrics();
    }, 30000);
  }

  updateSystemMetrics() {
    this.metrics.system.cpuUsage = os.loadavg()[0];
    this.metrics.system.memoryUsage = (process.memoryUsage().rss / 1024 / 1024).toFixed(2);
    this.metrics.system.uptime = process.uptime();
    this.metrics.system.loadAverage = os.loadavg();
  }

  recordRequest(req, res, responseTime) {
    this.metrics.requests.total++;
    
    if (res.statusCode >= 200 && res.statusCode < 400) {
      this.metrics.requests.successful++;
    } else {
      this.metrics.requests.failed++;
    }

    // Track by endpoint
    const endpoint = req.route ? req.route.path : req.path;
    const endpointCount = this.metrics.requests.byEndpoint.get(endpoint) || 0;
    this.metrics.requests.byEndpoint.set(endpoint, endpointCount + 1);

    // Track by status code
    const statusCount = this.metrics.requests.byStatusCode.get(res.statusCode) || 0;
    this.metrics.requests.byStatusCode.set(res.statusCode, statusCount + 1);

    // Track by user agent
    const userAgent = req.get('User-Agent') || 'Unknown';
    const uaCount = this.metrics.requests.byUserAgent.get(userAgent) || 0;
    this.metrics.requests.byUserAgent.set(userAgent, uaCount + 1);

    // Update response time metrics
    this.metrics.requests.responseTime.min = Math.min(this.metrics.requests.responseTime.min, responseTime);
    this.metrics.requests.responseTime.max = Math.max(this.metrics.requests.responseTime.max, responseTime);
    this.metrics.requests.responseTime.sum += responseTime;
    this.metrics.requests.responseTime.count++;
    this.metrics.requests.responseTime.avg = this.metrics.requests.responseTime.sum / this.metrics.requests.responseTime.count;
  }

  recordSecurityEvent(type) {
    switch (type) {
      case 'auth_attempt':
        this.metrics.security.authAttempts++;
        break;
      case 'auth_failure':
        this.metrics.security.authFailures++;
        break;
      case 'blocked_request':
        this.metrics.security.blockedRequests++;
        break;
      case 'suspicious_activity':
        this.metrics.security.suspiciousActivity++;
        break;
      case 'rate_limit':
        this.metrics.security.rateLimitHits++;
        break;
    }
  }

  getMetrics() {
    this.updateSystemMetrics();
    return {
      ...this.metrics,
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    };
  }

  reset() {
    this.metrics = {
      requests: {
        total: 0,
        successful: 0,
        failed: 0,
        byEndpoint: new Map(),
        byStatusCode: new Map(),
        byUserAgent: new Map(),
        responseTime: {
          min: Infinity,
          max: 0,
          sum: 0,
          count: 0,
          avg: 0
        }
      },
      security: {
        authAttempts: 0,
        authFailures: 0,
        blockedRequests: 0,
        suspiciousActivity: 0,
        rateLimitHits: 0
      }
    };
  }
}

// Global metrics collector instance
const metricsCollector = new MetricsCollector();

/**
 * Request tracking and performance monitoring
 */
const requestTracker = (req, res, next) => {
  const startTime = process.hrtime.bigint();
  const requestId = uuidv4();
  
  // Add request ID to request object
  req.requestId = requestId;
  
  // Add request ID to response headers
  res.setHeader('X-Request-ID', requestId);
  
  // Track request start
  logger.debug('Request started', {
    requestId,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id
  });

  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(...args) {
    const endTime = process.hrtime.bigint();
    const responseTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds
    
    // Record metrics
    metricsCollector.recordRequest(req, res, responseTime);
    
    // Log request completion
    const logLevel = res.statusCode >= 400 ? 'warn' : 'debug';
    logger[logLevel]('Request completed', {
      requestId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      responseTime: `${responseTime.toFixed(2)}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      contentLength: res.get('Content-Length')
    });

    // Performance alerts
    if (responseTime > 5000) { // 5 seconds
      logger.warn('Slow response detected', {
        requestId,
        responseTime: `${responseTime.toFixed(2)}ms`,
        endpoint: req.originalUrl,
        method: req.method,
        userId: req.user?.id
      });
    }

    originalEnd.apply(this, args);
  };

  next();
};

/**
 * Health check monitoring
 */
const healthMonitor = () => {
  const healthChecks = {
    database: false,
    redis: false,
    mlService: false,
    diskSpace: false,
    memory: false
  };

  return {
    async checkHealth() {
      const health = {
        status: 'healthy',
        checks: {},
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: process.env.npm_package_version || '1.0.0'
      };

      try {
        // Check MongoDB connection
        const mongoose = require('mongoose');
        health.checks.database = {
          status: mongoose.connection.readyState === 1 ? 'healthy' : 'unhealthy',
          responseTime: await this.checkDatabaseResponseTime()
        };

        // Check Redis connection
        health.checks.redis = {
          status: await this.checkRedisConnection() ? 'healthy' : 'unhealthy'
        };

        // Check ML Service
        health.checks.mlService = {
          status: await this.checkMLService() ? 'healthy' : 'unhealthy'
        };

        // Check system resources
        health.checks.memory = {
          status: this.checkMemoryUsage() ? 'healthy' : 'unhealthy',
          usage: `${(process.memoryUsage().rss / 1024 / 1024).toFixed(2)}MB`
        };

        health.checks.diskSpace = {
          status: await this.checkDiskSpace() ? 'healthy' : 'unhealthy'
        };

        // Determine overall health status
        const unhealthyChecks = Object.values(health.checks).filter(check => check.status === 'unhealthy');
        if (unhealthyChecks.length > 0) {
          health.status = 'unhealthy';
        }

      } catch (error) {
        logger.error('Health check failed', { error: error.message });
        health.status = 'unhealthy';
        health.error = error.message;
      }

      return health;
    },

    async checkDatabaseResponseTime() {
      const start = Date.now();
      try {
        const mongoose = require('mongoose');
        await mongoose.connection.db.admin().ping();
        return Date.now() - start;
      } catch (error) {
        return -1;
      }
    },

    async checkRedisConnection() {
      try {
        const { createClient } = require('redis');
        const client = createClient({ url: process.env.REDIS_URL });
        await client.connect();
        await client.ping();
        await client.quit();
        return true;
      } catch (error) {
        return false;
      }
    },

    async checkMLService() {
      try {
        const axios = require('axios');
        const response = await axios.get(`${process.env.ML_SERVICE_URL}/health`, {
          timeout: 5000
        });
        return response.status === 200;
      } catch (error) {
        return false;
      }
    },

    checkMemoryUsage() {
      const memUsage = process.memoryUsage();
      const totalMem = os.totalmem();
      const usagePercent = (memUsage.rss / totalMem) * 100;
      return usagePercent < 80; // Alert if memory usage > 80%
    },

    async checkDiskSpace() {
      try {
        const fs = require('fs').promises;
        const stats = await fs.statfs(process.cwd());
        const freePercent = (stats.free / stats.size) * 100;
        return freePercent > 10; // Alert if less than 10% free space
      } catch (error) {
        return true; // Assume healthy if can't check
      }
    }
  };
};

const healthMonitorInstance = healthMonitor();

/**
 * Error monitoring and alerting
 */
const errorMonitor = (err, req, res, next) => {
  // Record security event if it's a security-related error
  if (err.code && ['INVALID_TOKEN', 'AUTHENTICATION_FAILED', 'RATE_LIMIT_EXCEEDED'].includes(err.code)) {
    metricsCollector.recordSecurityEvent('suspicious_activity');
  }

  // Critical error alerting
  if (err.statusCode >= 500) {
    logger.error('Critical error detected', {
      error: err.message,
      stack: err.stack,
      requestId: req.requestId,
      userId: req.user?.id,
      ip: req.ip,
      endpoint: req.originalUrl,
      method: req.method
    });

    // TODO: Send alert to external monitoring services
    // sendAlert('critical_error', { error: err, request: req });
  }

  next(err);
};

/**
 * Performance metrics endpoint middleware
 */
const metricsEndpoint = (req, res) => {
  const metrics = metricsCollector.getMetrics();
  
  // Convert Maps to Objects for JSON serialization
  metrics.requests.byEndpoint = Object.fromEntries(metrics.requests.byEndpoint);
  metrics.requests.byStatusCode = Object.fromEntries(metrics.requests.byStatusCode);
  metrics.requests.byUserAgent = Object.fromEntries(metrics.requests.byUserAgent);

  res.json(metrics);
};

/**
 * Health check endpoint middleware
 */
const healthEndpoint = async (req, res) => {
  const health = await healthMonitorInstance.checkHealth();
  const statusCode = health.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(health);
};

/**
 * Anomaly detection
 */
const anomalyDetector = (() => {
  let previousMetrics = null;
  
  return () => {
    const currentMetrics = metricsCollector.getMetrics();
    
    if (previousMetrics) {
      // Check for sudden spikes in failed requests
      const failureRate = currentMetrics.requests.failed / (currentMetrics.requests.total || 1);
      const prevFailureRate = previousMetrics.requests.failed / (previousMetrics.requests.total || 1);
      
      if (failureRate > 0.1 && failureRate > prevFailureRate * 2) {
        logger.warn('Anomaly detected: High failure rate', {
          currentFailureRate: failureRate,
          previousFailureRate: prevFailureRate,
          category: 'ANOMALY_DETECTION'
        });
      }

      // Check for response time anomalies
      if (currentMetrics.requests.responseTime.avg > 2000) { // 2 seconds
        logger.warn('Anomaly detected: High response time', {
          avgResponseTime: currentMetrics.requests.responseTime.avg,
          category: 'ANOMALY_DETECTION'
        });
      }

      // Check for security anomalies
      if (currentMetrics.security.suspiciousActivity > previousMetrics.security.suspiciousActivity + 10) {
        logger.security('Anomaly detected: Spike in suspicious activity', {
          currentSuspiciousActivity: currentMetrics.security.suspiciousActivity,
          previousSuspiciousActivity: previousMetrics.security.suspiciousActivity,
          category: 'SECURITY_ANOMALY'
        });
      }
    }
    
    previousMetrics = { ...currentMetrics };
  };
})();

// Run anomaly detection every 5 minutes
setInterval(anomalyDetector, 5 * 60 * 1000);

/**
 * Main monitoring middleware
 */
const monitoringMiddleware = [
  requestTracker,
  errorMonitor
];

module.exports = {
  monitoringMiddleware,
  metricsCollector,
  healthMonitorInstance,
  metricsEndpoint,
  healthEndpoint,
  requestTracker,
  errorMonitor
};