# 🛡️ AI-Powered Cybersecurity Risk Simulation Platform
# Backend Dockerfile
# Author: IRFAN AHMMED

# Use Node.js 18 LTS Alpine image for smaller size and security
FROM node:18-alpine AS base

# Install system dependencies required for security tools
RUN apk add --no-cache \
    curl \
    bash \
    git \
    python3 \
    py3-pip \
    build-base \
    nmap \
    nmap-scripts \
    nikto \
    && rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S cybersec -u 1001

# Copy package files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY backend/ ./backend/
COPY shared/ ./shared/

# Create necessary directories
RUN mkdir -p logs uploads reports && \
    chown -R cybersec:nodejs /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Switch to non-root user
USER cybersec

# Expose port
EXPOSE 5000

# Set environment variables
ENV NODE_ENV=production
ENV PORT=5000

# Start the application
CMD ["node", "backend/src/app.js"]