/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * User Model
 * 
 * @author IRFAN AHMMED
 * @description Comprehensive user model with security features,
 * role-based access control, and audit trail
 */

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const validator = require('validator');

/**
 * User Schema Definition
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - firstName
 *         - lastName
 *         - email
 *         - password
 *         - role
 *       properties:
 *         firstName:
 *           type: string
 *           description: User's first name
 *         lastName:
 *           type: string
 *           description: User's last name
 *         email:
 *           type: string
 *           format: email
 *           description: User's email address
 *         role:
 *           type: string
 *           enum: [admin, manager, viewer]
 *           description: User's role in the system
 *         organization:
 *           type: string
 *           description: User's organization
 *         avatar:
 *           type: string
 *           format: uri
 *           description: User's avatar URL
 *         active:
 *           type: boolean
 *           description: Whether the user account is active
 *         emailVerified:
 *           type: boolean
 *           description: Whether the user's email is verified
 *         twoFactorEnabled:
 *           type: boolean
 *           description: Whether 2FA is enabled
 *         lastLogin:
 *           type: string
 *           format: date-time
 *           description: Last login timestamp
 *         preferences:
 *           type: object
 *           description: User preferences and settings
 */
const userSchema = new mongoose.Schema({
  // Basic Information
  firstName: {
    type: String,
    required: [true, 'First name is required'],
    trim: true,
    minlength: [2, 'First name must be at least 2 characters'],
    maxlength: [50, 'First name cannot exceed 50 characters'],
    validate: {
      validator: function(v) {
        return /^[a-zA-Z\s]+$/.test(v);
      },
      message: 'First name can only contain letters and spaces'
    }
  },
  
  lastName: {
    type: String,
    required: [true, 'Last name is required'],
    trim: true,
    minlength: [2, 'Last name must be at least 2 characters'],
    maxlength: [50, 'Last name cannot exceed 50 characters'],
    validate: {
      validator: function(v) {
        return /^[a-zA-Z\s]+$/.test(v);
      },
      message: 'Last name can only contain letters and spaces'
    }
  },

  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide a valid email address'],
    index: true
  },

  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false, // Don't include password in queries by default
    validate: {
      validator: function(password) {
        // Check for at least one uppercase, one lowercase, one number, and one special character
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(password);
      },
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }
  },

  passwordChangedAt: {
    type: Date,
    default: Date.now
  },

  passwordResetToken: {
    type: String,
    select: false
  },

  passwordResetExpires: {
    type: Date,
    select: false
  },

  // Role and Permissions
  role: {
    type: String,
    enum: {
      values: ['admin', 'manager', 'viewer'],
      message: 'Role must be either admin, manager, or viewer'
    },
    default: 'viewer',
    required: true,
    index: true
  },

  permissions: [{
    type: String,
    enum: [
      'scan:create', 'scan:read', 'scan:update', 'scan:delete',
      'target:create', 'target:read', 'target:update', 'target:delete',
      'report:create', 'report:read', 'report:update', 'report:delete',
      'user:create', 'user:read', 'user:update', 'user:delete',
      'billing:read', 'billing:manage',
      'phishing:create', 'phishing:read', 'phishing:manage',
      'admin:access', 'system:manage'
    ]
  }],

  // Organization and Profile
  organization: {
    type: String,
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },

  jobTitle: {
    type: String,
    trim: true,
    maxlength: [100, 'Job title cannot exceed 100 characters']
  },

  department: {
    type: String,
    trim: true,
    maxlength: [50, 'Department cannot exceed 50 characters']
  },

  avatar: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || validator.isURL(v);
      },
      message: 'Avatar must be a valid URL'
    }
  },

  // Account Status
  active: {
    type: Boolean,
    default: true,
    select: false
  },

  emailVerified: {
    type: Boolean,
    default: false
  },

  emailVerificationToken: {
    type: String,
    select: false
  },

  emailVerificationExpires: {
    type: Date,
    select: false
  },

  // Two-Factor Authentication
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },

  twoFactorSecret: {
    type: String,
    select: false
  },

  twoFactorBackupCodes: [{
    type: String,
    select: false
  }],

  // Login and Session Management
  lastLogin: {
    type: Date
  },

  lastLoginIP: {
    type: String,
    validate: {
      validator: function(v) {
        return !v || validator.isIP(v);
      },
      message: 'Invalid IP address format'
    }
  },

  loginAttempts: {
    type: Number,
    default: 0
  },

  lockUntil: {
    type: Date
  },

  // User Preferences
  preferences: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    },
    
    language: {
      type: String,
      enum: ['en', 'es', 'fr', 'de', 'zh'],
      default: 'en'
    },
    
    timezone: {
      type: String,
      default: 'UTC'
    },
    
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      },
      slack: {
        type: Boolean,
        default: false
      },
      telegram: {
        type: Boolean,
        default: false
      },
      criticalOnly: {
        type: Boolean,
        default: false
      }
    },
    
    dashboard: {
      layout: {
        type: String,
        enum: ['default', 'compact', 'detailed'],
        default: 'default'
      },
      widgets: [{
        type: String,
        enum: ['recent_scans', 'risk_overview', 'alerts', 'targets', 'reports']
      }]
    }
  },

  // Subscription and Billing
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'professional', 'enterprise'],
      default: 'free'
    },
    
    status: {
      type: String,
      enum: ['active', 'inactive', 'trial', 'expired', 'cancelled'],
      default: 'trial'
    },
    
    expiresAt: {
      type: Date
    },
    
    stripeCustomerId: {
      type: String,
      select: false
    },
    
    paypalCustomerId: {
      type: String,
      select: false
    }
  },

  // API Access
  apiKeys: [{
    name: {
      type: String,
      required: true
    },
    key: {
      type: String,
      required: true,
      select: false
    },
    permissions: [{
      type: String
    }],
    lastUsed: {
      type: Date
    },
    expiresAt: {
      type: Date
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],

  // Security and Compliance
  securitySettings: {
    ipWhitelist: [{
      type: String,
      validate: {
        validator: function(v) {
          return validator.isIP(v) || /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v);
        },
        message: 'Invalid IP address or CIDR notation'
      }
    }],
    
    sessionTimeout: {
      type: Number,
      default: 3600, // 1 hour in seconds
      min: 300, // 5 minutes minimum
      max: 86400 // 24 hours maximum
    },
    
    requirePasswordChange: {
      type: Boolean,
      default: false
    },
    
    passwordChangeFrequency: {
      type: Number, // days
      default: 90
    }
  },

  // Audit Trail
  audit: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    
    lastModifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    
    loginHistory: [{
      timestamp: {
        type: Date,
        default: Date.now
      },
      ip: String,
      userAgent: String,
      location: {
        country: String,
        city: String,
        region: String
      },
      success: {
        type: Boolean,
        default: true
      },
      failureReason: String
    }],
    
    passwordHistory: [{
      hashedPassword: {
        type: String,
        select: false
      },
      changedAt: {
        type: Date,
        default: Date.now
      }
    }]
  }

}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ role: 1 });
userSchema.index({ 'subscription.plan': 1 });
userSchema.index({ active: 1 });
userSchema.index({ createdAt: -1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for subscription active status
userSchema.virtual('isSubscriptionActive').get(function() {
  return this.subscription.status === 'active' && 
         (!this.subscription.expiresAt || this.subscription.expiresAt > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  this.password = await bcrypt.hash(this.password, saltRounds);

  // Set password changed timestamp
  this.passwordChangedAt = Date.now() - 1000; // Subtract 1 second to ensure JWT is created after password change

  next();
});

// Pre-save middleware to set permissions based on role
userSchema.pre('save', function(next) {
  if (!this.isModified('role')) return next();

  const rolePermissions = {
    admin: [
      'scan:create', 'scan:read', 'scan:update', 'scan:delete',
      'target:create', 'target:read', 'target:update', 'target:delete',
      'report:create', 'report:read', 'report:update', 'report:delete',
      'user:create', 'user:read', 'user:update', 'user:delete',
      'billing:read', 'billing:manage',
      'phishing:create', 'phishing:read', 'phishing:manage',
      'admin:access', 'system:manage'
    ],
    manager: [
      'scan:create', 'scan:read', 'scan:update', 'scan:delete',
      'target:create', 'target:read', 'target:update', 'target:delete',
      'report:create', 'report:read', 'report:update', 'report:delete',
      'user:read', 'billing:read',
      'phishing:create', 'phishing:read', 'phishing:manage'
    ],
    viewer: [
      'scan:read', 'target:read', 'report:read', 'user:read', 'billing:read'
    ]
  };

  this.permissions = rolePermissions[this.role] || rolePermissions.viewer;
  next();
});

// Instance method to check password
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Instance method to check if password changed after JWT was issued
userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Instance method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  
  return resetToken;
};

// Instance method to create email verification token
userSchema.methods.createEmailVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
  
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  
  return verificationToken;
};

// Instance method to check permission
userSchema.methods.hasPermission = function(permission) {
  return this.permissions && this.permissions.includes(permission);
};

// Instance method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Instance method to log login attempt
userSchema.methods.logLoginAttempt = function(ip, userAgent, success = true, failureReason = null) {
  const loginEntry = {
    timestamp: new Date(),
    ip,
    userAgent,
    success,
    ...(failureReason && { failureReason })
  };
  
  this.audit.loginHistory.push(loginEntry);
  
  // Keep only last 50 login attempts
  if (this.audit.loginHistory.length > 50) {
    this.audit.loginHistory = this.audit.loginHistory.slice(-50);
  }
  
  return this.save({ validateBeforeSave: false });
};

// Static method to find active users
userSchema.statics.findActive = function() {
  return this.find({ active: true });
};

// Static method to find by role
userSchema.statics.findByRole = function(role) {
  return this.find({ role, active: true });
};

// Static method for authentication with account locking
userSchema.statics.getAuthenticated = async function(email, password) {
  const user = await this.findOne({ email }).select('+password +loginAttempts +lockUntil');
  
  if (!user) {
    return { success: false, reason: 'User not found' };
  }
  
  // Check if account is locked
  if (user.isLocked) {
    return { success: false, reason: 'Account locked', user };
  }
  
  // Check password
  const isMatch = await user.correctPassword(password, user.password);
  
  if (isMatch) {
    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }
    return { success: true, user };
  }
  
  // Increment login attempts on failed login
  await user.incLoginAttempts();
  return { success: false, reason: 'Invalid password', user };
};

const User = mongoose.model('User', userSchema);

module.exports = User;