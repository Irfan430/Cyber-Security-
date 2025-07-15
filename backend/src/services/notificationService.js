/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Notification Service
 * 
 * @author IRFAN AHMMED
 * @description Multi-channel notification service supporting email,
 * Slack, Telegram, and real-time notifications
 */

const nodemailer = require('nodemailer');
const axios = require('axios');
const logger = require('../utils/logger');
const socketService = require('./socketService');

class NotificationService {
  constructor() {
    this.emailTransporter = null;
    this.slackWebhookUrl = process.env.SLACK_WEBHOOK_URL;
    this.telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;
    this.telegramChatId = process.env.TELEGRAM_CHAT_ID;
    this.isInitialized = false;
  }

  /**
   * Initialize notification service
   */
  async initialize() {
    try {
      // Initialize email transporter
      await this.initializeEmailTransporter();
      
      // Test external service connections
      await this.testConnections();
      
      this.isInitialized = true;
      logger.info('Notification service initialized successfully');
    } catch (error) {
      logger.error('Failed to initialize notification service', { error: error.message });
      throw error;
    }
  }

  /**
   * Initialize email transporter
   */
  async initializeEmailTransporter() {
    const emailConfig = {
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      tls: {
        rejectUnauthorized: false
      }
    };

    this.emailTransporter = nodemailer.createTransporter(emailConfig);

    // Verify SMTP connection
    try {
      await this.emailTransporter.verify();
      logger.info('SMTP connection verified');
    } catch (error) {
      logger.warn('SMTP verification failed', { error: error.message });
    }
  }

  /**
   * Test external service connections
   */
  async testConnections() {
    const testResults = {
      slack: false,
      telegram: false
    };

    // Test Slack webhook
    if (this.slackWebhookUrl) {
      try {
        await axios.post(this.slackWebhookUrl, {
          text: 'Cybersecurity Platform - Connection Test',
          username: 'CyberSec Bot',
          icon_emoji: ':shield:'
        });
        testResults.slack = true;
        logger.info('Slack webhook connection verified');
      } catch (error) {
        logger.warn('Slack webhook test failed', { error: error.message });
      }
    }

    // Test Telegram bot
    if (this.telegramBotToken) {
      try {
        const response = await axios.get(`https://api.telegram.org/bot${this.telegramBotToken}/getMe`);
        if (response.data.ok) {
          testResults.telegram = true;
          logger.info('Telegram bot connection verified');
        }
      } catch (error) {
        logger.warn('Telegram bot test failed', { error: error.message });
      }
    }

    return testResults;
  }

  /**
   * Send email notification
   */
  async sendEmail(emailData) {
    try {
      const { to, subject, text, html, attachments } = emailData;

      const mailOptions = {
        from: `"Cybersecurity Platform" <${process.env.SMTP_USER}>`,
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        text,
        html: html || text,
        attachments
      };

      const result = await this.emailTransporter.sendMail(mailOptions);
      
      logger.info('Email sent successfully', {
        to: mailOptions.to,
        subject,
        messageId: result.messageId
      });

      return { success: true, messageId: result.messageId };
    } catch (error) {
      logger.error('Failed to send email', {
        error: error.message,
        to: emailData.to,
        subject: emailData.subject
      });
      throw error;
    }
  }

  /**
   * Send Slack notification
   */
  async sendSlackNotification(slackData) {
    if (!this.slackWebhookUrl) {
      throw new Error('Slack webhook URL not configured');
    }

    try {
      const payload = {
        username: 'CyberSec Bot',
        icon_emoji: ':shield:',
        ...slackData
      };

      const response = await axios.post(this.slackWebhookUrl, payload);
      
      logger.info('Slack notification sent successfully', {
        channel: slackData.channel,
        text: slackData.text?.substring(0, 100)
      });

      return { success: true, response: response.data };
    } catch (error) {
      logger.error('Failed to send Slack notification', {
        error: error.message,
        payload: slackData
      });
      throw error;
    }
  }

  /**
   * Send Telegram notification
   */
  async sendTelegramNotification(telegramData) {
    if (!this.telegramBotToken) {
      throw new Error('Telegram bot token not configured');
    }

    try {
      const { chatId = this.telegramChatId, text, parseMode = 'HTML' } = telegramData;

      const response = await axios.post(
        `https://api.telegram.org/bot${this.telegramBotToken}/sendMessage`,
        {
          chat_id: chatId,
          text,
          parse_mode: parseMode
        }
      );

      logger.info('Telegram notification sent successfully', {
        chatId,
        text: text.substring(0, 100)
      });

      return { success: true, messageId: response.data.result.message_id };
    } catch (error) {
      logger.error('Failed to send Telegram notification', {
        error: error.message,
        chatId: telegramData.chatId,
        text: telegramData.text?.substring(0, 100)
      });
      throw error;
    }
  }

  /**
   * Send real-time notification via Socket.IO
   */
  sendRealtimeNotification(userId, notification) {
    try {
      const success = socketService.sendNotification(userId, notification);
      
      if (success) {
        logger.debug('Real-time notification sent', {
          userId,
          type: notification.type,
          title: notification.title
        });
      }

      return success;
    } catch (error) {
      logger.error('Failed to send real-time notification', {
        error: error.message,
        userId,
        notification
      });
      return false;
    }
  }

  /**
   * Send security alert to multiple channels
   */
  async sendSecurityAlert(alertData) {
    const { 
      title, 
      message, 
      severity, 
      userId, 
      channels = ['realtime', 'email', 'slack'],
      details = {}
    } = alertData;

    const results = {};

    // Format alert message
    const formattedMessage = this.formatSecurityAlert(title, message, severity, details);

    // Send real-time notification
    if (channels.includes('realtime') && userId) {
      results.realtime = this.sendRealtimeNotification(userId, {
        type: 'security_alert',
        title,
        message,
        severity,
        timestamp: new Date(),
        details
      });
    }

    // Send email notification
    if (channels.includes('email')) {
      try {
        const emailRecipients = await this.getAlertRecipients('email', severity);
        if (emailRecipients.length > 0) {
          results.email = await this.sendEmail({
            to: emailRecipients,
            subject: `🚨 Security Alert: ${title}`,
            html: this.generateSecurityAlertEmail(title, message, severity, details)
          });
        }
      } catch (error) {
        results.email = { success: false, error: error.message };
      }
    }

    // Send Slack notification
    if (channels.includes('slack')) {
      try {
        results.slack = await this.sendSlackNotification({
          text: `🚨 *Security Alert*`,
          attachments: [{
            color: this.getSeverityColor(severity),
            title,
            text: message,
            fields: [
              {
                title: 'Severity',
                value: severity.toUpperCase(),
                short: true
              },
              {
                title: 'Timestamp',
                value: new Date().toISOString(),
                short: true
              }
            ],
            footer: 'Cybersecurity Platform',
            ts: Math.floor(Date.now() / 1000)
          }]
        });
      } catch (error) {
        results.slack = { success: false, error: error.message };
      }
    }

    // Send Telegram notification
    if (channels.includes('telegram')) {
      try {
        results.telegram = await this.sendTelegramNotification({
          text: formattedMessage
        });
      } catch (error) {
        results.telegram = { success: false, error: error.message };
      }
    }

    logger.security('Security alert sent', {
      category: 'SECURITY_ALERT',
      title,
      severity,
      channels,
      results
    });

    return results;
  }

  /**
   * Send scan completion notification
   */
  async sendScanNotification(scanData) {
    const { scanId, userId, type, status, findings, target } = scanData;

    const notification = {
      type: 'scan_completion',
      title: `Scan Completed: ${type}`,
      message: `Scan of ${target} completed with status: ${status}`,
      scanId,
      findings: findings?.length || 0,
      timestamp: new Date()
    };

    // Send real-time notification
    this.sendRealtimeNotification(userId, notification);

    // Send email if scan has critical findings
    if (findings && findings.some(f => f.severity === 'critical')) {
      try {
        await this.sendEmail({
          to: await this.getUserEmail(userId),
          subject: `🔍 Critical Findings in ${type} Scan`,
          html: this.generateScanNotificationEmail(scanData)
        });
      } catch (error) {
        logger.error('Failed to send scan notification email', { error: error.message });
      }
    }

    logger.info('Scan notification sent', {
      scanId,
      userId,
      type,
      status,
      findingsCount: findings?.length || 0
    });
  }

  /**
   * Send phishing simulation results
   */
  async sendPhishingResults(phishingData) {
    const { campaignId, userId, results, targets } = phishingData;

    const clickRate = (results.clicks / targets.length * 100).toFixed(1);
    
    const notification = {
      type: 'phishing_results',
      title: 'Phishing Simulation Complete',
      message: `Campaign completed with ${clickRate}% click rate`,
      campaignId,
      results,
      timestamp: new Date()
    };

    // Send real-time notification
    this.sendRealtimeNotification(userId, notification);

    // Send detailed email report
    try {
      await this.sendEmail({
        to: await this.getUserEmail(userId),
        subject: `📧 Phishing Simulation Results - ${clickRate}% Click Rate`,
        html: this.generatePhishingResultsEmail(phishingData)
      });
    } catch (error) {
      logger.error('Failed to send phishing results email', { error: error.message });
    }

    logger.security('Phishing simulation results sent', {
      category: 'PHISHING_SIM',
      campaignId,
      userId,
      clickRate
    });
  }

  /**
   * Format security alert message
   */
  formatSecurityAlert(title, message, severity, details) {
    const severityEmoji = {
      low: '🟡',
      medium: '🟠', 
      high: '🔴',
      critical: '🚨'
    };

    let formatted = `${severityEmoji[severity] || '⚠️'} *SECURITY ALERT*\n\n`;
    formatted += `*Title:* ${title}\n`;
    formatted += `*Severity:* ${severity.toUpperCase()}\n`;
    formatted += `*Message:* ${message}\n`;
    formatted += `*Time:* ${new Date().toISOString()}\n`;

    if (details && Object.keys(details).length > 0) {
      formatted += '\n*Details:*\n';
      for (const [key, value] of Object.entries(details)) {
        formatted += `• ${key}: ${value}\n`;
      }
    }

    return formatted;
  }

  /**
   * Get severity color for Slack attachments
   */
  getSeverityColor(severity) {
    const colors = {
      low: '#36a64f',
      medium: '#ff9500', 
      high: '#ff4444',
      critical: '#8B0000'
    };
    return colors[severity] || '#808080';
  }

  /**
   * Get alert recipients based on severity
   */
  async getAlertRecipients(channel, severity) {
    // This would typically query the database for users who should receive alerts
    // For now, return admin emails based on environment
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').filter(Boolean);
    
    if (severity === 'critical' || severity === 'high') {
      return adminEmails;
    }
    
    return adminEmails.slice(0, 1); // Only first admin for lower severity
  }

  /**
   * Get user email by ID
   */
  async getUserEmail(userId) {
    // This would query the database for user email
    // For now, return a placeholder
    const User = require('../models/User');
    const user = await User.findById(userId);
    return user ? user.email : null;
  }

  /**
   * Generate security alert email HTML
   */
  generateSecurityAlertEmail(title, message, severity, details) {
    const severityColor = this.getSeverityColor(severity);
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .alert-container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: ${severityColor}; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .details { background-color: white; padding: 15px; margin-top: 15px; border-radius: 5px; }
            .footer { text-align: center; padding: 10px; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="alert-container">
            <div class="header">
                <h1>🚨 Security Alert</h1>
                <h2>${title}</h2>
            </div>
            <div class="content">
                <p><strong>Severity:</strong> ${severity.toUpperCase()}</p>
                <p><strong>Message:</strong> ${message}</p>
                <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
                
                ${Object.keys(details).length > 0 ? `
                <div class="details">
                    <h3>Details:</h3>
                    ${Object.entries(details).map(([key, value]) => 
                      `<p><strong>${key}:</strong> ${value}</p>`
                    ).join('')}
                </div>
                ` : ''}
            </div>
            <div class="footer">
                Cybersecurity Risk Simulation Platform
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate scan notification email HTML
   */
  generateScanNotificationEmail(scanData) {
    const { scanId, type, status, findings, target } = scanData;
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .scan-container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #2196F3; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .findings { background-color: white; padding: 15px; margin-top: 15px; border-radius: 5px; }
            .critical { color: #f44336; }
            .high { color: #ff9800; }
            .medium { color: #ffeb3b; }
            .low { color: #4caf50; }
        </style>
    </head>
    <body>
        <div class="scan-container">
            <div class="header">
                <h1>🔍 Scan Completed</h1>
                <h2>${type} Scan</h2>
            </div>
            <div class="content">
                <p><strong>Target:</strong> ${target}</p>
                <p><strong>Status:</strong> ${status}</p>
                <p><strong>Scan ID:</strong> ${scanId}</p>
                <p><strong>Completed:</strong> ${new Date().toISOString()}</p>
                
                <div class="findings">
                    <h3>Findings Summary:</h3>
                    <p>Total findings: ${findings?.length || 0}</p>
                    ${findings && findings.length > 0 ? findings.map(finding => 
                      `<p class="${finding.severity}">• ${finding.title} (${finding.severity})</p>`
                    ).join('') : '<p>No vulnerabilities found.</p>'}
                </div>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Generate phishing results email HTML
   */
  generatePhishingResultsEmail(phishingData) {
    const { campaignId, results, targets } = phishingData;
    const clickRate = (results.clicks / targets.length * 100).toFixed(1);
    
    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .phishing-container { font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }
            .header { background-color: #ff5722; color: white; padding: 20px; text-align: center; }
            .content { padding: 20px; background-color: #f9f9f9; }
            .stats { background-color: white; padding: 15px; margin-top: 15px; border-radius: 5px; }
            .stat-item { display: flex; justify-content: space-between; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="phishing-container">
            <div class="header">
                <h1>📧 Phishing Simulation Results</h1>
            </div>
            <div class="content">
                <p><strong>Campaign ID:</strong> ${campaignId}</p>
                <p><strong>Completed:</strong> ${new Date().toISOString()}</p>
                
                <div class="stats">
                    <h3>Results Summary:</h3>
                    <div class="stat-item">
                        <span>Emails Sent:</span>
                        <span>${targets.length}</span>
                    </div>
                    <div class="stat-item">
                        <span>Emails Opened:</span>
                        <span>${results.opens || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span>Links Clicked:</span>
                        <span>${results.clicks || 0}</span>
                    </div>
                    <div class="stat-item">
                        <span>Click Rate:</span>
                        <span>${clickRate}%</span>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  /**
   * Test notification channels
   */
  async testNotifications() {
    const results = {};

    try {
      results.email = await this.sendEmail({
        to: process.env.ADMIN_EMAILS?.split(',')[0],
        subject: 'Test Email - Cybersecurity Platform',
        text: 'This is a test email from the cybersecurity platform notification service.'
      });
    } catch (error) {
      results.email = { success: false, error: error.message };
    }

    try {
      results.slack = await this.sendSlackNotification({
        text: 'Test notification from Cybersecurity Platform',
        channel: '#security-alerts'
      });
    } catch (error) {
      results.slack = { success: false, error: error.message };
    }

    try {
      results.telegram = await this.sendTelegramNotification({
        text: 'Test notification from Cybersecurity Platform'
      });
    } catch (error) {
      results.telegram = { success: false, error: error.message };
    }

    return results;
  }
}

// Create singleton instance
const notificationService = new NotificationService();

module.exports = notificationService;