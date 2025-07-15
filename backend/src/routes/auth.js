/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Authentication Routes
 * 
 * @author IRFAN AHMMED
 * @description Comprehensive authentication endpoints with security features,
 * rate limiting, and audit logging
 */

const express = require('express');
const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');

// Models and services
const User = require('../models/User');
const { AppError, catchAsync } = require('../middleware/errorHandler');
const { 
  createSendToken, 
  authenticate, 
  authRateLimit,
  refreshToken: refreshTokenMiddleware
} = require('../middleware/auth');
const { validate, schemas } = require('../middleware/validation');
const notificationService = require('../services/notificationService');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication and account management
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - email
 *               - password
 *               - confirmPassword
 *               - termsAccepted
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 example: SecurePass123!
 *               confirmPassword:
 *                 type: string
 *                 example: SecurePass123!
 *               organization:
 *                 type: string
 *                 example: Acme Corp
 *               termsAccepted:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Invalid input data
 *       409:
 *         description: User already exists
 */
router.post('/register', 
  authRateLimit,
  validate(schemas.userRegistration),
  catchAsync(async (req, res, next) => {
    const { firstName, lastName, email, password, organization, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      logger.security('Registration attempt with existing email', {
        category: 'REGISTRATION',
        email,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return next(new AppError('User already exists with this email', 409, 'USER_EXISTS'));
    }

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password,
      organization,
      role: role || 'viewer', // Default role
      audit: {
        createdBy: null // Self-registration
      }
    });

    // Generate email verification token
    const verificationToken = newUser.createEmailVerificationToken();
    await newUser.save({ validateBeforeSave: false });

    // Log registration event
    logger.audit('User registered', {
      category: 'USER_REGISTRATION',
      userId: newUser._id,
      email: newUser.email,
      organization: newUser.organization,
      role: newUser.role,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send verification email
    try {
      await notificationService.sendEmail({
        to: newUser.email,
        subject: 'Welcome to Cybersecurity Platform - Verify Your Email',
        html: generateVerificationEmail(newUser.firstName, verificationToken)
      });

      logger.info('Verification email sent', {
        userId: newUser._id,
        email: newUser.email
      });
    } catch (error) {
      logger.error('Failed to send verification email', {
        error: error.message,
        userId: newUser._id,
        email: newUser.email
      });
    }

    // Send welcome notification to admins
    notificationService.sendSecurityAlert({
      title: 'New User Registration',
      message: `New user registered: ${newUser.fullName} (${newUser.email})`,
      severity: 'low',
      channels: ['slack'],
      details: {
        email: newUser.email,
        organization: newUser.organization,
        role: newUser.role
      }
    });

    // Create and send token (user will need to verify email to activate account)
    createSendToken(newUser, 201, req, res, 'Registration successful! Please check your email to verify your account.');
  })
);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: User login
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *               password:
 *                 type: string
 *                 example: SecurePass123!
 *               rememberMe:
 *                 type: boolean
 *                 example: false
 *     responses:
 *       200:
 *         description: Login successful
 *       401:
 *         description: Invalid credentials
 *       423:
 *         description: Account locked
 */
router.post('/login',
  authRateLimit,
  validate(schemas.userLogin),
  catchAsync(async (req, res, next) => {
    const { email, password, rememberMe } = req.body;

    // Authenticate user with account locking
    const authResult = await User.getAuthenticated(email, password);
    
    if (!authResult.success) {
      // Log failed login attempt
      logger.authAttempt(email, false, req.ip, req.get('User-Agent'), {
        reason: authResult.reason
      });

      // Log to user's login history if user exists
      if (authResult.user) {
        await authResult.user.logLoginAttempt(
          req.ip, 
          req.get('User-Agent'), 
          false, 
          authResult.reason
        );
      }

      let errorMessage = 'Invalid email or password';
      let statusCode = 401;
      
      if (authResult.reason === 'Account locked') {
        errorMessage = 'Account temporarily locked due to too many failed login attempts';
        statusCode = 423;
      }

      return next(new AppError(errorMessage, statusCode, 'AUTHENTICATION_FAILED'));
    }

    const user = authResult.user;

    // Check if account is active
    if (!user.active) {
      logger.security('Login attempt on inactive account', {
        category: 'AUTHENTICATION',
        userId: user._id,
        email: user.email,
        ip: req.ip
      });
      
      return next(new AppError('Account is deactivated. Please contact support.', 401, 'ACCOUNT_INACTIVE'));
    }

    // Log successful login attempt to user's history
    await user.logLoginAttempt(req.ip, req.get('User-Agent'), true);

    // Check for suspicious login (different IP, location, etc.)
    const suspiciousLogin = await checkSuspiciousLogin(user, req);
    if (suspiciousLogin) {
      // Send security alert
      notificationService.sendSecurityAlert({
        title: 'Suspicious Login Detected',
        message: `Login from new location detected for user ${user.email}`,
        severity: 'medium',
        userId: user._id,
        channels: ['realtime', 'email'],
        details: {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          previousIP: user.lastLoginIP
        }
      });
    }

    // Create and send token
    createSendToken(user, 200, req, res, 'Login successful');
  })
);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: User logout
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post('/logout', authenticate, catchAsync(async (req, res, next) => {
  // Logout is handled by the authenticate middleware
  // The actual logout logic is in the auth middleware
  next();
}));

/**
 * @swagger
 * /api/auth/refresh-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *       401:
 *         description: Invalid refresh token
 */
router.post('/refresh-token', refreshTokenMiddleware);

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *     responses:
 *       200:
 *         description: Password reset email sent
 *       404:
 *         description: User not found
 */
router.post('/forgot-password',
  authRateLimit,
  catchAsync(async (req, res, next) => {
    const { email } = req.body;

    // Get user based on POSTed email
    const user = await User.findOne({ email });
    if (!user) {
      // Don't reveal if user exists for security
      return res.status(200).json({
        success: true,
        message: 'If a user with that email exists, a password reset link has been sent.'
      });
    }

    // Generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // Log password reset request
    logger.security('Password reset requested', {
      category: 'PASSWORD_RESET',
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    try {
      // Send password reset email
      await notificationService.sendEmail({
        to: user.email,
        subject: 'Cybersecurity Platform - Password Reset Request',
        html: generatePasswordResetEmail(user.firstName, resetToken)
      });

      logger.info('Password reset email sent', {
        userId: user._id,
        email: user.email
      });

      res.status(200).json({
        success: true,
        message: 'Password reset email sent'
      });
    } catch (error) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      logger.error('Failed to send password reset email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });

      return next(new AppError('There was an error sending the email. Try again later.', 500, 'EMAIL_SEND_ERROR'));
    }
  })
);

/**
 * @swagger
 * /api/auth/reset-password/{token}:
 *   patch:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Password reset token
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *               - confirmPassword
 *             properties:
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 example: NewSecurePass123!
 *               confirmPassword:
 *                 type: string
 *                 example: NewSecurePass123!
 *     responses:
 *       200:
 *         description: Password reset successful
 *       400:
 *         description: Invalid or expired token
 */
router.patch('/reset-password/:token',
  authRateLimit,
  catchAsync(async (req, res, next) => {
    // Get user based on the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    // If token has not expired, and there is a user, set the new password
    if (!user) {
      logger.security('Invalid password reset token used', {
        category: 'PASSWORD_RESET',
        token: req.params.token.substring(0, 10) + '...',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return next(new AppError('Token is invalid or has expired', 400, 'INVALID_TOKEN'));
    }

    // Validate new password
    const { password, confirmPassword } = req.body;
    if (!password || !confirmPassword) {
      return next(new AppError('Please provide password and confirmPassword', 400, 'MISSING_FIELDS'));
    }

    if (password !== confirmPassword) {
      return next(new AppError('Passwords do not match', 400, 'PASSWORD_MISMATCH'));
    }

    // Set the new password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Log successful password reset
    logger.security('Password reset completed', {
      category: 'PASSWORD_RESET',
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send confirmation email
    try {
      await notificationService.sendEmail({
        to: user.email,
        subject: 'Cybersecurity Platform - Password Reset Confirmation',
        html: generatePasswordResetConfirmationEmail(user.firstName)
      });
    } catch (error) {
      logger.error('Failed to send password reset confirmation email', {
        error: error.message,
        userId: user._id
      });
    }

    // Send security alert
    notificationService.sendSecurityAlert({
      title: 'Password Reset Completed',
      message: `Password reset completed for user ${user.email}`,
      severity: 'medium',
      userId: user._id,
      channels: ['realtime', 'email'],
      details: {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      }
    });

    // Log the user in with the new password
    createSendToken(user, 200, req, res, 'Password reset successful');
  })
);

/**
 * @swagger
 * /api/auth/verify-email/{token}:
 *   get:
 *     summary: Verify email address
 *     tags: [Authentication]
 *     parameters:
 *       - in: path
 *         name: token
 *         required: true
 *         schema:
 *           type: string
 *         description: Email verification token
 *     responses:
 *       200:
 *         description: Email verified successfully
 *       400:
 *         description: Invalid or expired token
 */
router.get('/verify-email/:token',
  catchAsync(async (req, res, next) => {
    // Get user based on the token
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      emailVerificationToken: hashedToken,
      emailVerificationExpires: { $gt: Date.now() }
    });

    if (!user) {
      logger.security('Invalid email verification token used', {
        category: 'EMAIL_VERIFICATION',
        token: req.params.token.substring(0, 10) + '...',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return next(new AppError('Token is invalid or has expired', 400, 'INVALID_TOKEN'));
    }

    // Verify the email
    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save({ validateBeforeSave: false });

    // Log email verification
    logger.audit('Email verified', {
      category: 'EMAIL_VERIFICATION',
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    res.status(200).json({
      success: true,
      message: 'Email verified successfully'
    });
  })
);

/**
 * @swagger
 * /api/auth/change-password:
 *   patch:
 *     summary: Change user password
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *               - confirmPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 example: CurrentPass123!
 *               newPassword:
 *                 type: string
 *                 example: NewSecurePass123!
 *               confirmPassword:
 *                 type: string
 *                 example: NewSecurePass123!
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       401:
 *         description: Invalid current password
 */
router.patch('/change-password',
  authenticate,
  validate(schemas.passwordChange),
  catchAsync(async (req, res, next) => {
    // Get user from database with password
    const user = await User.findById(req.user.id).select('+password');

    // Check if POSTed current password is correct
    if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
      logger.security('Invalid current password during password change', {
        category: 'PASSWORD_CHANGE',
        userId: user._id,
        email: user.email,
        ip: req.ip
      });
      
      return next(new AppError('Your current password is incorrect', 401, 'INVALID_PASSWORD'));
    }

    // If so, update password
    user.password = req.body.newPassword;
    await user.save();

    // Log password change
    logger.security('Password changed', {
      category: 'PASSWORD_CHANGE',
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Send notification email
    try {
      await notificationService.sendEmail({
        to: user.email,
        subject: 'Cybersecurity Platform - Password Changed',
        html: generatePasswordChangeNotificationEmail(user.firstName)
      });
    } catch (error) {
      logger.error('Failed to send password change notification', {
        error: error.message,
        userId: user._id
      });
    }

    // Send security alert
    notificationService.sendSecurityAlert({
      title: 'Password Changed',
      message: `Password changed for user ${user.email}`,
      severity: 'medium',
      userId: user._id,
      channels: ['realtime'],
      details: {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      }
    });

    // Log user in with new password
    createSendToken(user, 200, req, res, 'Password changed successfully');
  })
);

/**
 * @swagger
 * /api/auth/me:
 *   get:
 *     summary: Get current user profile
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 */
router.get('/me',
  authenticate,
  catchAsync(async (req, res, next) => {
    res.status(200).json({
      success: true,
      data: {
        user: req.user
      }
    });
  })
);

/**
 * Helper function to check for suspicious login
 */
async function checkSuspiciousLogin(user, req) {
  // Check if login is from a different IP
  if (user.lastLoginIP && user.lastLoginIP !== req.ip) {
    return true;
  }

  // Check login history for patterns
  const recentLogins = user.audit.loginHistory.slice(-5);
  const uniqueIPs = new Set(recentLogins.map(login => login.ip));
  
  // If more than 3 different IPs in recent logins
  if (uniqueIPs.size > 3) {
    return true;
  }

  return false;
}

/**
 * Generate verification email HTML
 */
function generateVerificationEmail(firstName, token) {
  const verificationUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/verify-email/${token}`;
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #2196F3; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .button { background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 20px 0; }
            .footer { text-align: center; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to Cybersecurity Platform!</h1>
            </div>
            <div class="content">
                <h2>Hello ${firstName},</h2>
                <p>Thank you for registering with our Cybersecurity Risk Simulation Platform. To complete your registration, please verify your email address by clicking the button below:</p>
                
                <a href="${verificationUrl}" class="button">Verify Email Address</a>
                
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p>${verificationUrl}</p>
                
                <p>This verification link will expire in 24 hours.</p>
                
                <p>If you didn't create an account with us, please ignore this email.</p>
                
                <p>Best regards,<br>The Cybersecurity Platform Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

/**
 * Generate password reset email HTML
 */
function generatePasswordResetEmail(firstName, token) {
  const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password/${token}`;
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #f44336; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
            .button { background-color: #f44336; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 20px 0; }
            .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Request</h1>
            </div>
            <div class="content">
                <h2>Hello ${firstName},</h2>
                <p>We received a request to reset your password for your Cybersecurity Platform account.</p>
                
                <a href="${resetUrl}" class="button">Reset Password</a>
                
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p>${resetUrl}</p>
                
                <div class="warning">
                    <strong>Important:</strong>
                    <ul>
                        <li>This link will expire in 10 minutes</li>
                        <li>If you didn't request this reset, please ignore this email</li>
                        <li>Your password will remain unchanged until you create a new one</li>
                    </ul>
                </div>
                
                <p>Best regards,<br>The Cybersecurity Platform Team</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

/**
 * Generate password reset confirmation email HTML
 */
function generatePasswordResetConfirmationEmail(firstName) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Successful</h1>
            </div>
            <div class="content">
                <h2>Hello ${firstName},</h2>
                <p>Your password has been successfully reset for your Cybersecurity Platform account.</p>
                <p>If you did not perform this action, please contact our support team immediately.</p>
                <p>Best regards,<br>The Cybersecurity Platform Team</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

/**
 * Generate password change notification email HTML
 */
function generatePasswordChangeNotificationEmail(firstName) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #ff9800; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Changed</h1>
            </div>
            <div class="content">
                <h2>Hello ${firstName},</h2>
                <p>Your password has been successfully changed for your Cybersecurity Platform account.</p>
                <p>If you did not perform this action, please contact our support team immediately.</p>
                <p>Best regards,<br>The Cybersecurity Platform Team</p>
            </div>
        </div>
    </body>
    </html>
  `;
}

module.exports = router;