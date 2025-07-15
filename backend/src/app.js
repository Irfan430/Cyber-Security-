/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Main Backend Application Server
 * 
 * @author IRFAN AHMMED
 * @description Production-grade Express.js server with comprehensive security,
 * monitoring, and cybersecurity features
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const http = require('http');
const socketIo = require('socket.io');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Internal imports
const logger = require('./utils/logger');
const errorHandler = require('./middleware/errorHandler');
const authMiddleware = require('./middleware/auth');
const validationMiddleware = require('./middleware/validation');
const securityMiddleware = require('./middleware/security');
const monitoringMiddleware = require('./middleware/monitoring');

// Route imports
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const riskRoutes = require('./routes/risk');
const reportRoutes = require('./routes/reports');
const billingRoutes = require('./routes/billing');
const alertRoutes = require('./routes/alerts');
const trainingRoutes = require('./routes/training');
const devopsRoutes = require('./routes/devops');

// Service imports
const socketService = require('./services/socketService');
const jobScheduler = require('./services/jobScheduler');
const notificationService = require('./services/notificationService');

// Constants
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cybersec_platform';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

class CybersecurityPlatform {
  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.io = socketIo(this.server, {
      cors: {
        origin: process.env.CORS_ORIGIN || "http://localhost:3000",
        methods: ["GET", "POST"],
        credentials: true
      }
    });
    this.redisClient = null;
  }

  /**
   * Initialize database connections
   */
  async initializeDatabase() {
    try {
      // MongoDB connection with advanced options
      await mongoose.connect(MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
        bufferCommands: false,
        bufferMaxEntries: 0
      });

      logger.info('✅ MongoDB connected successfully');

      // Redis connection
      this.redisClient = createClient({
        url: REDIS_URL,
        retry_strategy: (options) => {
          if (options.error && options.error.code === 'ECONNREFUSED') {
            logger.error('Redis connection refused');
            return new Error('Redis connection refused');
          }
          if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Retry time exhausted');
          }
          if (options.attempt > 10) {
            return undefined;
          }
          return Math.min(options.attempt * 100, 3000);
        }
      });

      await this.redisClient.connect();
      logger.info('✅ Redis connected successfully');

    } catch (error) {
      logger.error('❌ Database connection failed:', error);
      process.exit(1);
    }
  }

  /**
   * Configure security middleware
   */
  configureSecurityMiddleware() {
    // Helmet for security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "https:"],
          scriptSrc: ["'self'"],
          connectSrc: ["'self'", "ws:", "wss:"]
        }
      },
      crossOriginEmbedderPolicy: false
    }));

    // CORS configuration
    const corsOptions = {
      origin: (origin, callback) => {
        const allowedOrigins = [
          process.env.CORS_ORIGIN || 'http://localhost:3000',
          'http://localhost:3000',
          'https://your-domain.com'
        ];
        
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Not allowed by CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
    };
    
    this.app.use(cors(corsOptions));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
      max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
      message: 'Too many requests from this IP, please try again later.',
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/health';
      }
    });
    
    this.app.use('/api', limiter);

    // Custom security middleware
    this.app.use(securityMiddleware);
  }

  /**
   * Configure application middleware
   */
  configureMiddleware() {
    // Compression
    this.app.use(compression());

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Logging
    if (NODE_ENV === 'production') {
      this.app.use(morgan('combined', { stream: { write: message => logger.info(message.trim()) } }));
    } else {
      this.app.use(morgan('dev'));
    }

    // Session configuration
    this.app.use(session({
      store: new RedisStore({ client: this.redisClient }),
      secret: process.env.SESSION_SECRET || 'cybersec-session-secret',
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        secure: NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      }
    }));

    // Monitoring middleware
    this.app.use(monitoringMiddleware);

    // Global validation middleware
    this.app.use(validationMiddleware);
  }

  /**
   * Configure API documentation
   */
  configureApiDocs() {
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'AI-Powered Cybersecurity Platform API',
          version: '1.0.0',
          description: 'Comprehensive cybersecurity risk simulation and assessment platform',
          contact: {
            name: 'IRFAN AHMMED',
            email: 'support@cybersec-platform.com'
          }
        },
        servers: [
          {
            url: process.env.NODE_ENV === 'production' 
              ? 'https://your-domain.com/api' 
              : 'http://localhost:5000/api',
            description: NODE_ENV === 'production' ? 'Production server' : 'Development server'
          }
        ],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT'
            }
          }
        }
      },
      apis: ['./src/routes/*.js', './src/models/*.js']
    };

    const specs = swaggerJsdoc(swaggerOptions);
    this.app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(specs, {
      explorer: true,
      customCss: '.swagger-ui .topbar { display: none }'
    }));
  }

  /**
   * Configure routes
   */
  configureRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: NODE_ENV,
        version: process.env.npm_package_version || '1.0.0'
      });
    });

    // API routes
    this.app.use('/api/auth', authRoutes);
    this.app.use('/api/users', authMiddleware, userRoutes);
    this.app.use('/api/targets', authMiddleware, targetRoutes);
    this.app.use('/api/scans', authMiddleware, scanRoutes);
    this.app.use('/api/risk', authMiddleware, riskRoutes);
    this.app.use('/api/reports', authMiddleware, reportRoutes);
    this.app.use('/api/billing', authMiddleware, billingRoutes);
    this.app.use('/api/alerts', authMiddleware, alertRoutes);
    this.app.use('/api/training', authMiddleware, trainingRoutes);
    this.app.use('/api/devops', devopsRoutes); // DevOps API might use API key auth

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        message: 'API endpoint not found',
        path: req.originalUrl
      });
    });

    // Global error handler
    this.app.use(errorHandler);
  }

  /**
   * Initialize Socket.IO
   */
  initializeSocketIO() {
    socketService.initialize(this.io);
    logger.info('✅ Socket.IO initialized');
  }

  /**
   * Initialize background services
   */
  async initializeServices() {
    try {
      // Initialize job scheduler
      await jobScheduler.initialize(this.redisClient);
      
      // Initialize notification service
      await notificationService.initialize();
      
      logger.info('✅ Background services initialized');
    } catch (error) {
      logger.error('❌ Service initialization failed:', error);
      throw error;
    }
  }

  /**
   * Graceful shutdown handler
   */
  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      logger.info(`📛 Received ${signal}. Starting graceful shutdown...`);
      
      this.server.close(async () => {
        logger.info('🔴 HTTP server closed');
        
        try {
          await mongoose.connection.close();
          logger.info('🔴 MongoDB connection closed');
          
          await this.redisClient.quit();
          logger.info('🔴 Redis connection closed');
          
          process.exit(0);
        } catch (error) {
          logger.error('❌ Error during shutdown:', error);
          process.exit(1);
        }
      });
      
      // Force shutdown after 30 seconds
      setTimeout(() => {
        logger.error('⚠️ Forced shutdown after timeout');
        process.exit(1);
      }, 30000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('💥 Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown('unhandledRejection');
    });
  }

  /**
   * Start the application
   */
  async start() {
    try {
      logger.info('🚀 Starting AI-Powered Cybersecurity Platform...');
      
      // Initialize database connections
      await this.initializeDatabase();
      
      // Configure middleware
      this.configureSecurityMiddleware();
      this.configureMiddleware();
      
      // Configure API documentation
      this.configureApiDocs();
      
      // Configure routes
      this.configureRoutes();
      
      // Initialize Socket.IO
      this.initializeSocketIO();
      
      // Initialize background services
      await this.initializeServices();
      
      // Setup graceful shutdown
      this.setupGracefulShutdown();
      
      // Start server
      this.server.listen(PORT, () => {
        logger.info(`🎯 Server running on port ${PORT} in ${NODE_ENV} mode`);
        logger.info(`📚 API Documentation: http://localhost:${PORT}/api/docs`);
        logger.info(`💚 Health Check: http://localhost:${PORT}/health`);
      });
      
    } catch (error) {
      logger.error('💥 Failed to start application:', error);
      process.exit(1);
    }
  }
}

// Create and start the application
const platform = new CybersecurityPlatform();
platform.start();

module.exports = platform;