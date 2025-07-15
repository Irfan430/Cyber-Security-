/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Authentication & Authorization Middleware
 * 
 * @author IRFAN AHMMED
 * @description Production-grade authentication with JWT, role-based access control,
 * session management, and comprehensive security logging
 */

const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/User');
const { AppError } = require('./errorHandler');
const logger = require('../utils/logger');
const { createClient } = require('redis');

// Redis client for session management
let redisClient;
(async () => {
  redisClient = createClient({ url: process.env.REDIS_URL });
  await redisClient.connect();
})();

/**
 * Generate JWT tokens
 */
const signToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    issuer: 'cybersec-platform',
    audience: 'cybersec-users'
  });
};

const signRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'cybersec-platform',
    audience: 'cybersec-users'
  });
};

/**
 * Create and send JWT tokens
 */
const createSendToken = async (user, statusCode, req, res, message = 'Success') => {
  const payload = {
    id: user._id,
    email: user.email,
    role: user.role
  };

  const token = signToken(payload);
  const refreshToken = signRefreshToken(payload);

  // Store refresh token in Redis with expiration
  const refreshTokenKey = `refresh:${user._id}`;
  await redisClient.setEx(refreshTokenKey, 7 * 24 * 60 * 60, refreshToken); // 7 days

  // Update user's last login
  user.lastLogin = new Date();
  user.lastLoginIP = req.ip;
  await user.save({ validateBeforeSave: false });

  // Log successful authentication
  logger.authAttempt(user.email, true, req.ip, req.get('User-Agent'), {
    userId: user._id,
    role: user.role
  });

  // Cookie options
  const cookieOptions = {
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  };

  res.cookie('jwt', token, cookieOptions);
  res.cookie('refreshToken', refreshToken, {
    ...cookieOptions,
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
  });

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    success: true,
    message,
    data: {
      user,
      token,
      refreshToken
    }
  });
};

/**
 * Verify JWT token
 */
const verifyToken = async (token, secret) => {
  try {
    const decoded = await promisify(jwt.verify)(token, secret);
    return decoded;
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Token has expired', 401, 'TOKEN_EXPIRED');
    } else if (error.name === 'JsonWebTokenError') {
      throw new AppError('Invalid token', 401, 'INVALID_TOKEN');
    }
    throw error;
  }
};

/**
 * Main authentication middleware
 */
const authenticate = async (req, res, next) => {
  try {
    // 1) Getting token and check if it exists
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      logger.security('Authentication attempt without token', {
        category: 'AUTHENTICATION',
        ip: req.ip,
        endpoint: req.originalUrl,
        userAgent: req.get('User-Agent')
      });
      
      return next(new AppError('You are not logged in! Please log in to get access.', 401, 'NO_TOKEN'));
    }

    // 2) Verify token
    const decoded = await verifyToken(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id).select('+active');
    if (!currentUser) {
      logger.security('Token used for non-existent user', {
        category: 'AUTHENTICATION',
        userId: decoded.id,
        ip: req.ip,
        token: token.substring(0, 20) + '...'
      });
      
      return next(new AppError('The user belonging to this token no longer exists.', 401, 'USER_NOT_FOUND'));
    }

    // 4) Check if user account is active
    if (!currentUser.active) {
      logger.security('Token used for inactive user', {
        category: 'AUTHENTICATION',
        userId: currentUser._id,
        email: currentUser.email,
        ip: req.ip
      });
      
      return next(new AppError('Your account has been deactivated. Please contact support.', 401, 'ACCOUNT_DEACTIVATED'));
    }

    // 5) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
      logger.security('Token used after password change', {
        category: 'AUTHENTICATION',
        userId: currentUser._id,
        email: currentUser.email,
        ip: req.ip,
        tokenIssuedAt: new Date(decoded.iat * 1000)
      });
      
      return next(new AppError('User recently changed password! Please log in again.', 401, 'PASSWORD_CHANGED'));
    }

    // 6) Check for session validity in Redis
    const sessionKey = `session:${currentUser._id}`;
    const sessionData = await redisClient.get(sessionKey);
    
    if (!sessionData) {
      logger.security('Invalid session - not found in Redis', {
        category: 'AUTHENTICATION',
        userId: currentUser._id,
        email: currentUser.email,
        ip: req.ip
      });
      
      return next(new AppError('Session expired. Please log in again.', 401, 'SESSION_EXPIRED'));
    }

    // 7) Update session expiry
    await redisClient.expire(sessionKey, 15 * 60); // 15 minutes

    // 8) Grant access to protected route
    req.user = currentUser;
    res.locals.user = currentUser;
    
    // Log successful authentication
    logger.debug('User authenticated successfully', {
      userId: currentUser._id,
      email: currentUser.email,
      role: currentUser.role,
      ip: req.ip,
      endpoint: req.originalUrl
    });

    next();
  } catch (error) {
    // Log authentication failure
    logger.security('Authentication failed', {
      category: 'AUTHENTICATION',
      error: error.message,
      ip: req.ip,
      endpoint: req.originalUrl,
      userAgent: req.get('User-Agent')
    });
    
    return next(error);
  }
};

/**
 * Role-based authorization middleware
 */
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.security('Unauthorized access attempt', {
        category: 'AUTHORIZATION',
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
        endpoint: req.originalUrl,
        ip: req.ip
      });
      
      return next(new AppError('You do not have permission to perform this action', 403, 'INSUFFICIENT_PERMISSIONS'));
    }
    next();
  };
};

/**
 * API Key authentication for DevOps endpoints
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return next(new AppError('API key is required', 401, 'NO_API_KEY'));
    }

    // In production, you would validate against a database of API keys
    const validApiKeys = [
      process.env.DEVOPS_API_KEY,
      process.env.CI_CD_API_KEY
    ].filter(Boolean);

    if (!validApiKeys.includes(apiKey)) {
      logger.security('Invalid API key used', {
        category: 'API_AUTHENTICATION',
        apiKey: apiKey.substring(0, 8) + '...',
        ip: req.ip,
        endpoint: req.originalUrl,
        userAgent: req.get('User-Agent')
      });
      
      return next(new AppError('Invalid API key', 401, 'INVALID_API_KEY'));
    }

    // Log successful API key authentication
    logger.audit('API key authentication successful', {
      category: 'API_ACCESS',
      ip: req.ip,
      endpoint: req.originalUrl,
      userAgent: req.get('User-Agent')
    });

    next();
  } catch (error) {
    return next(error);
  }
};

/**
 * Refresh token middleware
 */
const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return next(new AppError('Refresh token is required', 400, 'NO_REFRESH_TOKEN'));
    }

    // Verify refresh token
    const decoded = await verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET);

    // Check if refresh token exists in Redis
    const refreshTokenKey = `refresh:${decoded.id}`;
    const storedRefreshToken = await redisClient.get(refreshTokenKey);

    if (!storedRefreshToken || storedRefreshToken !== refreshToken) {
      logger.security('Invalid refresh token used', {
        category: 'AUTHENTICATION',
        userId: decoded.id,
        ip: req.ip
      });
      
      return next(new AppError('Invalid refresh token', 401, 'INVALID_REFRESH_TOKEN'));
    }

    // Get user
    const user = await User.findById(decoded.id);
    if (!user || !user.active) {
      return next(new AppError('User not found or inactive', 401, 'USER_NOT_FOUND'));
    }

    // Generate new tokens
    await createSendToken(user, 200, req, res, 'Token refreshed successfully');
    
  } catch (error) {
    return next(error);
  }
};

/**
 * Logout middleware
 */
const logout = async (req, res, next) => {
  try {
    const userId = req.user._id;

    // Remove refresh token from Redis
    const refreshTokenKey = `refresh:${userId}`;
    await redisClient.del(refreshTokenKey);

    // Remove session from Redis
    const sessionKey = `session:${userId}`;
    await redisClient.del(sessionKey);

    // Clear cookies
    res.cookie('jwt', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    res.cookie('refreshToken', 'loggedout', {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true
    });

    // Log logout event
    logger.audit('User logged out', {
      category: 'AUTHENTICATION',
      userId: req.user._id,
      email: req.user.email,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    return next(error);
  }
};

/**
 * Check if user is logged in (for rendered pages)
 */
const isLoggedIn = async (req, res, next) => {
  if (req.cookies.jwt) {
    try {
      const decoded = await verifyToken(req.cookies.jwt, process.env.JWT_SECRET);
      const currentUser = await User.findById(decoded.id);
      
      if (currentUser && currentUser.active) {
        res.locals.user = currentUser;
      }
    } catch (err) {
      // Silently fail for this middleware
    }
  }
  next();
};

/**
 * Rate limiting for authentication endpoints
 */
const authRateLimit = (() => {
  const attempts = new Map();
  const MAX_ATTEMPTS = 5;
  const WINDOW_SIZE = 15 * 60 * 1000; // 15 minutes

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();

    if (!attempts.has(key)) {
      attempts.set(key, []);
    }

    const userAttempts = attempts.get(key);
    const recentAttempts = userAttempts.filter(time => now - time < WINDOW_SIZE);

    if (recentAttempts.length >= MAX_ATTEMPTS) {
      logger.security('Authentication rate limit exceeded', {
        category: 'RATE_LIMITING',
        ip: req.ip,
        attempts: recentAttempts.length,
        userAgent: req.get('User-Agent')
      });

      return next(new AppError('Too many authentication attempts. Please try again later.', 429, 'RATE_LIMIT_EXCEEDED'));
    }

    recentAttempts.push(now);
    attempts.set(key, recentAttempts);
    next();
  };
})();

module.exports = {
  authenticate,
  authorize,
  authenticateApiKey,
  refreshToken,
  logout,
  isLoggedIn,
  authRateLimit,
  createSendToken,
  signToken,
  signRefreshToken
};