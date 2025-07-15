/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Job Scheduler Service
 * 
 * @author IRFAN AHMMED
 * @description Background job processing for scans, reports, and automated tasks
 */

const Bull = require('bull');
const cron = require('node-cron');
const logger = require('../utils/logger');
const socketService = require('./socketService');

class JobScheduler {
  constructor() {
    this.queues = {};
    this.workers = {};
    this.cronJobs = new Map();
    this.redisClient = null;
  }

  /**
   * Initialize job scheduler with Redis connection
   */
  async initialize(redisClient) {
    this.redisClient = redisClient;
    
    // Initialize job queues
    this.initializeQueues();
    
    // Set up queue processors
    this.setupQueueProcessors();
    
    // Start cron jobs
    this.startCronJobs();
    
    logger.info('Job scheduler initialized successfully');
  }

  /**
   * Initialize different job queues
   */
  initializeQueues() {
    const redisConfig = {
      redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD || undefined
      }
    };

    // Vulnerability scanning queue
    this.queues.scans = new Bull('vulnerability-scans', redisConfig);
    
    // Brute force simulation queue
    this.queues.bruteForce = new Bull('brute-force-sims', redisConfig);
    
    // Report generation queue
    this.queues.reports = new Bull('report-generation', redisConfig);
    
    // Email and notification queue
    this.queues.notifications = new Bull('notifications', redisConfig);
    
    // ML risk assessment queue
    this.queues.riskAssessment = new Bull('risk-assessment', redisConfig);
    
    // Phishing simulation queue
    this.queues.phishing = new Bull('phishing-simulation', redisConfig);
    
    // System maintenance queue
    this.queues.maintenance = new Bull('system-maintenance', redisConfig);

    // Set up queue event handlers
    Object.values(this.queues).forEach(queue => {
      this.setupQueueEventHandlers(queue);
    });

    logger.info('Job queues initialized', {
      queues: Object.keys(this.queues)
    });
  }

  /**
   * Set up event handlers for job queues
   */
  setupQueueEventHandlers(queue) {
    queue.on('completed', (job, result) => {
      logger.debug('Job completed', {
        queueName: queue.name,
        jobId: job.id,
        jobType: job.name,
        processingTime: Date.now() - job.processedOn,
        result: typeof result === 'object' ? JSON.stringify(result) : result
      });
    });

    queue.on('failed', (job, err) => {
      logger.error('Job failed', {
        queueName: queue.name,
        jobId: job.id,
        jobType: job.name,
        error: err.message,
        stack: err.stack,
        attempts: job.attemptsMade,
        data: job.data
      });
    });

    queue.on('stalled', (job) => {
      logger.warn('Job stalled', {
        queueName: queue.name,
        jobId: job.id,
        jobType: job.name,
        data: job.data
      });
    });

    queue.on('progress', (job, progress) => {
      // Send real-time progress updates via socket
      if (job.data.userId && job.data.scanId) {
        socketService.sendScanUpdate(job.data.scanId, {
          progress,
          status: 'running',
          message: `${job.name} progress: ${progress}%`
        });
      }
    });
  }

  /**
   * Set up queue processors
   */
  setupQueueProcessors() {
    // Vulnerability scan processor
    this.queues.scans.process('nmap-scan', 3, require('./processors/nmapProcessor'));
    this.queues.scans.process('nikto-scan', 2, require('./processors/niktoProcessor'));
    this.queues.scans.process('custom-scan', 1, require('./processors/customScanProcessor'));

    // Brute force simulation processor
    this.queues.bruteForce.process('ssh-brute', 2, require('./processors/sshBruteProcessor'));
    this.queues.bruteForce.process('ftp-brute', 2, require('./processors/ftpBruteProcessor'));
    this.queues.bruteForce.process('http-brute', 3, require('./processors/httpBruteProcessor'));

    // Report generation processor
    this.queues.reports.process('pdf-report', 2, require('./processors/pdfReportProcessor'));
    this.queues.reports.process('csv-report', 1, require('./processors/csvReportProcessor'));

    // Notification processor
    this.queues.notifications.process('email', 5, require('./processors/emailProcessor'));
    this.queues.notifications.process('slack', 3, require('./processors/slackProcessor'));
    this.queues.notifications.process('telegram', 3, require('./processors/telegramProcessor'));

    // ML risk assessment processor
    this.queues.riskAssessment.process('risk-analysis', 2, require('./processors/riskAssessmentProcessor'));

    // Phishing simulation processor
    this.queues.phishing.process('send-phishing-email', 1, require('./processors/phishingProcessor'));

    // System maintenance processor
    this.queues.maintenance.process('cleanup-logs', 1, require('./processors/logCleanupProcessor'));
    this.queues.maintenance.process('backup-database', 1, require('./processors/backupProcessor'));

    logger.info('Queue processors initialized');
  }

  /**
   * Start scheduled cron jobs
   */
  startCronJobs() {
    // Daily system health check (every day at 2 AM)
    this.addCronJob('daily-health-check', '0 2 * * *', () => {
      this.scheduleSystemHealthCheck();
    });

    // Weekly vulnerability database update (every Sunday at 3 AM)
    this.addCronJob('weekly-vuln-update', '0 3 * * 0', () => {
      this.scheduleVulnerabilityDatabaseUpdate();
    });

    // Daily log cleanup (every day at 4 AM)
    this.addCronJob('daily-log-cleanup', '0 4 * * *', () => {
      this.scheduleLogCleanup();
    });

    // Weekly database backup (every Sunday at 1 AM)
    this.addCronJob('weekly-backup', '0 1 * * 0', () => {
      this.scheduleDatabaseBackup();
    });

    // Hourly queue cleanup
    this.addCronJob('hourly-queue-cleanup', '0 * * * *', () => {
      this.cleanupCompletedJobs();
    });

    // Daily subscription check (every day at 6 AM)
    this.addCronJob('daily-subscription-check', '0 6 * * *', () => {
      this.scheduleSubscriptionCheck();
    });

    logger.info('Cron jobs started', {
      jobs: Array.from(this.cronJobs.keys())
    });
  }

  /**
   * Add a cron job
   */
  addCronJob(name, schedule, task) {
    const job = cron.schedule(schedule, task, {
      scheduled: false,
      timezone: 'UTC'
    });
    
    this.cronJobs.set(name, job);
    job.start();
    
    logger.info('Cron job added', { name, schedule });
  }

  /**
   * Schedule vulnerability scan
   */
  async scheduleVulnerabilityScan(scanData) {
    const jobOptions = {
      delay: scanData.delay || 0,
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      },
      removeOnComplete: 10,
      removeOnFail: 5
    };

    let job;
    
    switch (scanData.type) {
      case 'nmap':
        job = await this.queues.scans.add('nmap-scan', scanData, jobOptions);
        break;
      case 'nikto':
        job = await this.queues.scans.add('nikto-scan', scanData, jobOptions);
        break;
      default:
        job = await this.queues.scans.add('custom-scan', scanData, jobOptions);
    }

    logger.info('Vulnerability scan scheduled', {
      jobId: job.id,
      scanType: scanData.type,
      targetId: scanData.targetId,
      userId: scanData.userId
    });

    return job;
  }

  /**
   * Schedule brute force simulation
   */
  async scheduleBruteForceSimulation(bruteData) {
    const jobOptions = {
      attempts: 2,
      backoff: {
        type: 'fixed',
        delay: 5000
      },
      removeOnComplete: 5,
      removeOnFail: 3
    };

    let job;
    
    switch (bruteData.protocol) {
      case 'ssh':
        job = await this.queues.bruteForce.add('ssh-brute', bruteData, jobOptions);
        break;
      case 'ftp':
        job = await this.queues.bruteForce.add('ftp-brute', bruteData, jobOptions);
        break;
      case 'http':
        job = await this.queues.bruteForce.add('http-brute', bruteData, jobOptions);
        break;
      default:
        throw new Error(`Unsupported protocol: ${bruteData.protocol}`);
    }

    logger.security('Brute force simulation scheduled', {
      category: 'BRUTE_FORCE_SIM',
      jobId: job.id,
      protocol: bruteData.protocol,
      targetId: bruteData.targetId,
      userId: bruteData.userId
    });

    return job;
  }

  /**
   * Schedule report generation
   */
  async scheduleReportGeneration(reportData) {
    const jobOptions = {
      attempts: 2,
      removeOnComplete: 5,
      removeOnFail: 3
    };

    const job = await this.queues.reports.add('pdf-report', reportData, jobOptions);

    logger.info('Report generation scheduled', {
      jobId: job.id,
      reportType: reportData.type,
      userId: reportData.userId
    });

    return job;
  }

  /**
   * Schedule notification
   */
  async scheduleNotification(notificationData) {
    const jobOptions = {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 1000
      },
      removeOnComplete: 20,
      removeOnFail: 10
    };

    let job;
    
    switch (notificationData.type) {
      case 'email':
        job = await this.queues.notifications.add('email', notificationData, jobOptions);
        break;
      case 'slack':
        job = await this.queues.notifications.add('slack', notificationData, jobOptions);
        break;
      case 'telegram':
        job = await this.queues.notifications.add('telegram', notificationData, jobOptions);
        break;
      default:
        throw new Error(`Unsupported notification type: ${notificationData.type}`);
    }

    logger.debug('Notification scheduled', {
      jobId: job.id,
      type: notificationData.type,
      recipient: notificationData.recipient
    });

    return job;
  }

  /**
   * Schedule risk assessment
   */
  async scheduleRiskAssessment(assessmentData) {
    const jobOptions = {
      attempts: 2,
      removeOnComplete: 10,
      removeOnFail: 5
    };

    const job = await this.queues.riskAssessment.add('risk-analysis', assessmentData, jobOptions);

    logger.info('Risk assessment scheduled', {
      jobId: job.id,
      targetId: assessmentData.targetId,
      userId: assessmentData.userId
    });

    return job;
  }

  /**
   * Schedule phishing simulation
   */
  async schedulePhishingSimulation(phishingData) {
    const jobOptions = {
      attempts: 2,
      delay: phishingData.delay || 0,
      removeOnComplete: 10,
      removeOnFail: 5
    };

    const job = await this.queues.phishing.add('send-phishing-email', phishingData, jobOptions);

    logger.security('Phishing simulation scheduled', {
      category: 'PHISHING_SIM',
      jobId: job.id,
      campaignId: phishingData.campaignId,
      targetCount: phishingData.targets?.length || 0
    });

    return job;
  }

  /**
   * Schedule system health check
   */
  scheduleSystemHealthCheck() {
    this.queues.maintenance.add('system-health-check', {
      timestamp: new Date(),
      type: 'automated'
    });
  }

  /**
   * Schedule vulnerability database update
   */
  scheduleVulnerabilityDatabaseUpdate() {
    this.queues.maintenance.add('vuln-db-update', {
      timestamp: new Date(),
      type: 'automated'
    });
  }

  /**
   * Schedule log cleanup
   */
  scheduleLogCleanup() {
    this.queues.maintenance.add('cleanup-logs', {
      timestamp: new Date(),
      retentionDays: 30
    });
  }

  /**
   * Schedule database backup
   */
  scheduleDatabaseBackup() {
    this.queues.maintenance.add('backup-database', {
      timestamp: new Date(),
      type: 'automated'
    });
  }

  /**
   * Schedule subscription check
   */
  scheduleSubscriptionCheck() {
    this.queues.maintenance.add('subscription-check', {
      timestamp: new Date()
    });
  }

  /**
   * Clean up completed jobs
   */
  async cleanupCompletedJobs() {
    const promises = Object.values(this.queues).map(async (queue) => {
      await queue.clean(24 * 60 * 60 * 1000, 'completed'); // Remove completed jobs older than 24 hours
      await queue.clean(7 * 24 * 60 * 60 * 1000, 'failed'); // Remove failed jobs older than 7 days
    });

    await Promise.all(promises);
    
    logger.debug('Completed jobs cleanup finished');
  }

  /**
   * Get queue statistics
   */
  async getQueueStats() {
    const stats = {};
    
    for (const [name, queue] of Object.entries(this.queues)) {
      const [waiting, active, completed, failed, delayed] = await Promise.all([
        queue.getWaiting(),
        queue.getActive(),
        queue.getCompleted(),
        queue.getFailed(),
        queue.getDelayed()
      ]);

      stats[name] = {
        waiting: waiting.length,
        active: active.length,
        completed: completed.length,
        failed: failed.length,
        delayed: delayed.length
      };
    }

    return stats;
  }

  /**
   * Cancel a job
   */
  async cancelJob(queueName, jobId) {
    const queue = this.queues[queueName];
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }

    const job = await queue.getJob(jobId);
    if (!job) {
      throw new Error(`Job ${jobId} not found`);
    }

    await job.remove();
    
    logger.info('Job cancelled', {
      queueName,
      jobId,
      jobType: job.name
    });

    return true;
  }

  /**
   * Pause a queue
   */
  async pauseQueue(queueName) {
    const queue = this.queues[queueName];
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }

    await queue.pause();
    logger.info('Queue paused', { queueName });
  }

  /**
   * Resume a queue
   */
  async resumeQueue(queueName) {
    const queue = this.queues[queueName];
    if (!queue) {
      throw new Error(`Queue ${queueName} not found`);
    }

    await queue.resume();
    logger.info('Queue resumed', { queueName });
  }

  /**
   * Stop cron job
   */
  stopCronJob(name) {
    const job = this.cronJobs.get(name);
    if (job) {
      job.stop();
      logger.info('Cron job stopped', { name });
      return true;
    }
    return false;
  }

  /**
   * Start cron job
   */
  startCronJob(name) {
    const job = this.cronJobs.get(name);
    if (job) {
      job.start();
      logger.info('Cron job started', { name });
      return true;
    }
    return false;
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    logger.info('Shutting down job scheduler...');

    // Stop all cron jobs
    for (const [name, job] of this.cronJobs) {
      job.stop();
      logger.debug('Cron job stopped', { name });
    }

    // Close all queues
    const closePromises = Object.entries(this.queues).map(async ([name, queue]) => {
      await queue.close();
      logger.debug('Queue closed', { name });
    });

    await Promise.all(closePromises);
    
    logger.info('Job scheduler shutdown completed');
  }
}

// Create singleton instance
const jobScheduler = new JobScheduler();

module.exports = jobScheduler;