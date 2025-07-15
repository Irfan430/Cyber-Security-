# 🛡️ AI-Powered Cybersecurity Risk Simulation Platform

**Author:** IRFAN AHMMED

A comprehensive, production-grade cybersecurity risk assessment and simulation platform with AI-powered threat prediction capabilities.

## 🚀 Features

### Core Security Features
- **Vulnerability Scanning**: Custom Nmap and Nikto integration
- **Safe Brute Force Simulation**: FTP, SSH, HTTP forms with threading and proxy rotation
- **AI/ML Risk Prediction**: Advanced threat probability analysis using sklearn/PyTorch
- **Real-time Dashboards**: Risk scores, heatmaps, and monitoring charts
- **PDF Security Reports**: Automated, downloadable security assessments

### Platform Features
- **Multi-tenant Architecture**: User signup, login, target management
- **Role-based Access**: Admin, Manager, Viewer permissions
- **Real-time Alerts**: Telegram & Slack integration for critical findings
- **Training Playground**: Consent-based phishing simulation with tracking
- **SaaS Billing**: Stripe/PayPal integration for subscriptions
- **DevSecOps API**: CI/CD integration for automated security checks

## 🏗️ Architecture

```
├── frontend/          # React.js + Tailwind CSS Dashboard
├── backend/           # Node.js + Express API Server
├── ml-service/        # Python FastAPI AI/ML Service
├── shared/            # Common utilities and scanners
├── scripts/           # Database seeding and migration scripts
└── .github/           # CI/CD workflows
```

## 🛠️ Tech Stack

- **Frontend**: React.js, Tailwind CSS, Recharts
- **Backend**: Node.js, Express.js, Socket.IO
- **ML Service**: Python, FastAPI, scikit-learn, PyTorch
- **Database**: MongoDB with Mongoose ODM
- **Caching/Queue**: Redis
- **Containerization**: Docker & Docker Compose
- **CI/CD**: GitHub Actions
- **Deployment**: Render.com ready, Kubernetes compatible

## 🚦 Quick Start

### Prerequisites
- Node.js 18+
- Python 3.9+
- Docker & Docker Compose
- MongoDB
- Redis

### Environment Setup

1. **Clone and setup environment**:
```bash
cp .env.example .env
# Edit .env with your configurations
```

2. **Using Docker (Recommended)**:
```bash
docker-compose up -d
```

3. **Manual Setup**:
```bash
# Install dependencies
npm install
cd frontend && npm install
cd ../ml-service && pip install -r requirements.txt

# Seed database
npm run seed

# Start services
npm run dev        # Backend
npm run frontend   # Frontend
npm run ml-service # ML Service
```

### 🌐 Access Points
- **Frontend Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:5000/api/docs
- **ML Service**: http://localhost:8000/docs

## 📊 API Documentation

### Authentication
```bash
POST /api/auth/register
POST /api/auth/login
POST /api/auth/logout
```

### Vulnerability Scanning
```bash
GET  /api/scans
POST /api/scans/nmap
POST /api/scans/nikto
GET  /api/scans/:id/results
```

### Risk Assessment
```bash
GET  /api/risk/assessment/:targetId
POST /api/risk/predict
GET  /api/risk/reports/:id/pdf
```

## 🔒 Security Features

- **Input Validation**: Joi/Zod schema validation
- **Authentication**: JWT with refresh tokens
- **Rate Limiting**: API endpoint protection
- **CORS Configuration**: Secure cross-origin requests
- **SQL Injection Prevention**: Parameterized queries
- **XSS Protection**: Content Security Policy headers

## 🧪 Testing

```bash
npm test                 # Backend tests
npm run test:frontend    # Frontend tests
npm run test:ml          # ML service tests
npm run test:integration # Integration tests
```

## 📦 Deployment

### Render.com (One-click)
1. Connect your GitHub repository
2. Use the included `render.yaml` configuration
3. Set environment variables in Render dashboard

### Kubernetes
```bash
kubectl apply -f k8s/
```

### Manual Deployment
```bash
docker build -t cybersec-platform .
docker run -p 5000:5000 cybersec-platform
```

## 🔧 Configuration

### Environment Variables
```env
# Database
MONGODB_URI=mongodb://localhost:27017/cybersec_platform
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-refresh-secret

# External Services
STRIPE_SECRET_KEY=sk_test_...
TELEGRAM_BOT_TOKEN=your-telegram-token
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# ML Service
ML_SERVICE_URL=http://localhost:8000
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in this repository
- Email: support@cybersec-platform.com

## 🔮 Roadmap

- [ ] Advanced ML threat detection models
- [ ] Mobile app for iOS/Android
- [ ] Blockchain-based audit trails
- [ ] Advanced phishing simulation templates
- [ ] Integration with major SIEM platforms
- [ ] Multi-cloud deployment support

---

**⚠️ Disclaimer**: This platform is designed for authorized security testing only. Users must have explicit permission to scan targets and conduct security assessments.