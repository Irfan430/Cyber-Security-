/**
 * 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
 * Socket.IO Service
 * 
 * @author IRFAN AHMMED
 * @description Real-time communication service for live updates,
 * notifications, and scan progress tracking
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

class SocketService {
  constructor() {
    this.io = null;
    this.connectedUsers = new Map(); // userId -> socketId mapping
    this.userSockets = new Map(); // socketId -> user data mapping
  }

  /**
   * Initialize Socket.IO with authentication and event handlers
   */
  initialize(io) {
    this.io = io;

    // Authentication middleware for socket connections
    io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];
        
        if (!token) {
          return next(new Error('Authentication error: No token provided'));
        }

        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from database
        const user = await User.findById(decoded.id).select('+active');
        if (!user || !user.active) {
          return next(new Error('Authentication error: User not found or inactive'));
        }

        socket.userId = user._id.toString();
        socket.user = user;
        next();
      } catch (error) {
        logger.security('Socket authentication failed', {
          category: 'SOCKET_AUTH',
          error: error.message,
          socketId: socket.id,
          ip: socket.handshake.address
        });
        next(new Error('Authentication error'));
      }
    });

    // Connection event handlers
    io.on('connection', (socket) => {
      this.handleConnection(socket);
    });

    logger.info('Socket.IO service initialized');
  }

  /**
   * Handle new socket connection
   */
  handleConnection(socket) {
    const userId = socket.userId;
    const user = socket.user;

    // Store user connection
    this.connectedUsers.set(userId, socket.id);
    this.userSockets.set(socket.id, {
      userId,
      user,
      connectedAt: new Date(),
      lastActivity: new Date()
    });

    logger.debug('User connected via socket', {
      userId,
      socketId: socket.id,
      email: user.email,
      ip: socket.handshake.address
    });

    // Join user to their personal room
    socket.join(`user:${userId}`);
    
    // Join user to their organization room if they have one
    if (user.organization) {
      socket.join(`org:${user.organization}`);
    }

    // Join user to role-based rooms
    socket.join(`role:${user.role}`);

    // Send welcome message
    socket.emit('connected', {
      message: 'Successfully connected to cybersecurity platform',
      timestamp: new Date(),
      connectedUsers: this.getConnectedUsersCount()
    });

    // Broadcast user connection to admins
    this.broadcastToRole('admin', 'user_connected', {
      userId,
      email: user.email,
      timestamp: new Date()
    });

    // Set up event handlers
    this.setupEventHandlers(socket);

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      this.handleDisconnection(socket, reason);
    });

    // Update last activity on any event
    socket.onAny(() => {
      const userData = this.userSockets.get(socket.id);
      if (userData) {
        userData.lastActivity = new Date();
      }
    });
  }

  /**
   * Set up event handlers for different socket events
   */
  setupEventHandlers(socket) {
    const userId = socket.userId;

    // Scan-related events
    socket.on('scan:subscribe', (scanId) => {
      socket.join(`scan:${scanId}`);
      logger.debug('User subscribed to scan updates', { userId, scanId });
    });

    socket.on('scan:unsubscribe', (scanId) => {
      socket.leave(`scan:${scanId}`);
      logger.debug('User unsubscribed from scan updates', { userId, scanId });
    });

    // Target monitoring
    socket.on('target:subscribe', (targetId) => {
      socket.join(`target:${targetId}`);
      logger.debug('User subscribed to target updates', { userId, targetId });
    });

    socket.on('target:unsubscribe', (targetId) => {
      socket.leave(`target:${targetId}`);
      logger.debug('User unsubscribed from target updates', { userId, targetId });
    });

    // Real-time dashboard updates
    socket.on('dashboard:subscribe', () => {
      socket.join(`dashboard:${userId}`);
      logger.debug('User subscribed to dashboard updates', { userId });
    });

    // Notification management
    socket.on('notification:read', (notificationId) => {
      this.handleNotificationRead(userId, notificationId);
    });

    socket.on('notification:clear_all', () => {
      this.handleClearAllNotifications(userId);
    });

    // Chat/collaboration features
    socket.on('chat:join_room', (roomId) => {
      socket.join(`chat:${roomId}`);
      this.broadcastToRoom(`chat:${roomId}`, 'user_joined_chat', {
        userId,
        email: socket.user.email,
        timestamp: new Date()
      });
    });

    socket.on('chat:leave_room', (roomId) => {
      socket.leave(`chat:${roomId}`);
      this.broadcastToRoom(`chat:${roomId}`, 'user_left_chat', {
        userId,
        email: socket.user.email,
        timestamp: new Date()
      });
    });

    socket.on('chat:message', (data) => {
      const { roomId, message } = data;
      this.broadcastToRoom(`chat:${roomId}`, 'chat_message', {
        userId,
        email: socket.user.email,
        message,
        timestamp: new Date()
      });
    });

    // System monitoring for admins
    if (socket.user.role === 'admin') {
      socket.on('admin:monitor_system', () => {
        socket.join('admin:system_monitor');
        logger.debug('Admin subscribed to system monitoring', { userId });
      });
    }

    // Heartbeat for connection health
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: new Date() });
    });
  }

  /**
   * Handle socket disconnection
   */
  handleDisconnection(socket, reason) {
    const userId = socket.userId;
    const userData = this.userSockets.get(socket.id);

    if (userData) {
      const sessionDuration = new Date() - userData.connectedAt;
      
      logger.debug('User disconnected from socket', {
        userId,
        socketId: socket.id,
        reason,
        sessionDuration: `${Math.round(sessionDuration / 1000)}s`,
        email: userData.user.email
      });

      // Remove user from tracking
      this.connectedUsers.delete(userId);
      this.userSockets.delete(socket.id);

      // Broadcast disconnection to admins
      this.broadcastToRole('admin', 'user_disconnected', {
        userId,
        email: userData.user.email,
        reason,
        sessionDuration,
        timestamp: new Date()
      });
    }
  }

  /**
   * Broadcast message to a specific user
   */
  emitToUser(userId, event, data) {
    const socketId = this.connectedUsers.get(userId);
    if (socketId && this.io) {
      this.io.to(`user:${userId}`).emit(event, data);
      return true;
    }
    return false;
  }

  /**
   * Broadcast message to all users with a specific role
   */
  broadcastToRole(role, event, data) {
    if (this.io) {
      this.io.to(`role:${role}`).emit(event, data);
    }
  }

  /**
   * Broadcast message to a specific room
   */
  broadcastToRoom(room, event, data) {
    if (this.io) {
      this.io.to(room).emit(event, data);
    }
  }

  /**
   * Broadcast message to all connected users
   */
  broadcast(event, data) {
    if (this.io) {
      this.io.emit(event, data);
    }
  }

  /**
   * Send notification to specific user
   */
  sendNotification(userId, notification) {
    const success = this.emitToUser(userId, 'notification', notification);
    
    logger.debug('Notification sent via socket', {
      userId,
      type: notification.type,
      success,
      title: notification.title
    });

    return success;
  }

  /**
   * Send scan progress update
   */
  sendScanUpdate(scanId, update) {
    this.broadcastToRoom(`scan:${scanId}`, 'scan_update', {
      scanId,
      ...update,
      timestamp: new Date()
    });
  }

  /**
   * Send real-time alert
   */
  sendAlert(alert) {
    // Send to all admins
    this.broadcastToRole('admin', 'security_alert', alert);
    
    // Send to specific user if specified
    if (alert.userId) {
      this.emitToUser(alert.userId, 'security_alert', alert);
    }

    logger.security('Real-time alert sent', {
      category: 'ALERT_BROADCAST',
      alertType: alert.type,
      severity: alert.severity,
      recipients: alert.userId ? 'specific_user' : 'all_admins'
    });
  }

  /**
   * Send system metrics to monitoring admins
   */
  sendSystemMetrics(metrics) {
    this.broadcastToRoom('admin:system_monitor', 'system_metrics', metrics);
  }

  /**
   * Handle notification read event
   */
  handleNotificationRead(userId, notificationId) {
    logger.debug('Notification marked as read', { userId, notificationId });
    // Here you would update the notification status in database
    // For now, we'll just acknowledge it
    this.emitToUser(userId, 'notification_read_ack', { notificationId });
  }

  /**
   * Handle clear all notifications event
   */
  handleClearAllNotifications(userId) {
    logger.debug('All notifications cleared', { userId });
    // Here you would clear all notifications for user in database
    this.emitToUser(userId, 'notifications_cleared');
  }

  /**
   * Get count of connected users
   */
  getConnectedUsersCount() {
    return this.connectedUsers.size;
  }

  /**
   * Get list of connected users (admin only)
   */
  getConnectedUsers() {
    const users = [];
    for (const [socketId, userData] of this.userSockets) {
      users.push({
        userId: userData.userId,
        email: userData.user.email,
        role: userData.user.role,
        connectedAt: userData.connectedAt,
        lastActivity: userData.lastActivity
      });
    }
    return users;
  }

  /**
   * Check if user is connected
   */
  isUserConnected(userId) {
    return this.connectedUsers.has(userId);
  }

  /**
   * Disconnect a specific user (admin function)
   */
  disconnectUser(userId, reason = 'Administrative action') {
    const socketId = this.connectedUsers.get(userId);
    if (socketId && this.io) {
      const socket = this.io.sockets.sockets.get(socketId);
      if (socket) {
        socket.emit('force_disconnect', { reason });
        socket.disconnect(true);
        
        logger.security('User forcibly disconnected', {
          category: 'ADMIN_ACTION',
          userId,
          reason,
          socketId
        });
        
        return true;
      }
    }
    return false;
  }

  /**
   * Send maintenance notification
   */
  sendMaintenanceNotification(message, scheduledTime) {
    this.broadcast('maintenance_notification', {
      message,
      scheduledTime,
      timestamp: new Date()
    });
  }
}

// Create singleton instance
const socketService = new SocketService();

module.exports = socketService;