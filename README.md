# Intelligent Intrusion Detection System (IDS)

🛡️ **ML-Powered Network Security Monitoring & Threat Detection**

This project transforms a basic API monitoring system into a sophisticated **Machine Learning-powered Intrusion Detection System** capable of real-time network traffic analysis, behavioral anomaly detection, and automated threat response.

## 🚀 Features

### 🤖 Machine Learning & AI
- **Isolation Forest** anomaly detection for network behavior analysis
- **Real-time ML inference** on network traffic patterns
- **Behavioral analysis** to detect unusual user/system activities
- **Groq API integration** for advanced threat intelligence analysis
- **Automated model training** with synthetic and real network data

### 🌐 Network Monitoring
- **Real-time packet capture** and analysis
- **Connection monitoring** with protocol detection
- **Network statistics** and traffic pattern analysis
- **Port scan detection** and suspicious activity identification
- **System resource monitoring** (CPU, Memory, Disk usage)

### 🔍 Threat Intelligence
- **IP reputation analysis** with threat scoring
- **Port activity analysis** for suspicious behavior detection
- **Multi-layered security alerts** with confidence scoring
- **Threat correlation** and pattern recognition
- **Risk assessment** with severity classification (LOW, MEDIUM, HIGH, CRITICAL)

### 📊 Security Dashboard
- **Real-time threat visualization** with Chart.js
- **Interactive security metrics** and KPI monitoring  
- **Alert management** with filtering and search capabilities
- **Network topology** and connection analysis
- **Threat timeline** and incident tracking

## 🏗️ Architecture

### Backend (FastAPI + Python)
```
backend/
├── app/
│   ├── main.py              # IDS API endpoints & FastAPI application
│   ├── ml_models.py         # ML models for anomaly detection
│   ├── network_monitor.py   # Network traffic monitoring & analysis
│   └── log_analyzer.py      # Log analysis with Groq API
├── requirements.txt         # Python dependencies with ML libraries
└── models/                  # Trained ML model storage
```

**Key Components:**
- **AnomalyDetector**: Isolation Forest model for network anomaly detection
- **ThreatIntelligence**: IP reputation and threat scoring system  
- **NetworkTrafficMonitor**: Real-time network connection monitoring
- **SystemResourceMonitor**: System performance and resource analysis

### Frontend (React + Vite)
```
frontend/
├── src/
│   ├── components/
│   │   ├── SetupView.jsx      # Network monitoring configuration
│   │   ├── VisualizerView.jsx # Threat analysis & visualization  
│   │   └── AlertsView.jsx     # Security alerts & incident management
│   ├── App.jsx                # Main security dashboard application
│   └── App.css                # Security-themed UI styling
└── package.json               # Frontend dependencies with Chart.js
```

## 🔧 Installation & Setup

### Prerequisites
- **Python 3.11+**
- **Node.js 16+**
- **Git**

### 1. Clone & Setup
```bash
git clone https://github.com/JayGadre/Barclays_Hackthon.git
cd Barclays_Hackthon
```

### 2. Backend Setup
```bash
cd backend

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Install ML dependencies
pip install -r requirements.txt

# Start IDS backend
python -m uvicorn app.main:app --reload --port 8000
```

### 3. Frontend Setup  
```bash
cd frontend

# Install dependencies
npm install

# Start security dashboard
npm run dev
```

### 4. Access the System
- **Security Dashboard**: http://localhost:5173
- **API Documentation**: http://localhost:8000/docs
- **Backend Health**: http://localhost:8000

## 🎯 Usage Guide

### 1. Network Configuration
- Navigate to **"Network Setup"**
- Configure network range (e.g., `192.168.1.0/24`)
- Set monitoring type: Full, Packets Only, Connections Only, or Behavioral
- Customize ML alert thresholds

### 2. Threat Analysis
- View **"Threat Analysis"** for real-time security visualization
- Monitor threat severity timeline with interactive charts
- Analyze network events and suspicious activities  
- Review ML confidence scores and threat intelligence

### 3. Security Alerts
- Access **"Security Alerts"** for incident management
- Filter alerts by severity: CRITICAL, HIGH, MEDIUM, LOW
- Search through security events and threat indicators
- Review detailed threat analysis and ML predictions

## 🤖 Machine Learning Models

### Isolation Forest Anomaly Detection
- **Purpose**: Detect unusual network traffic patterns
- **Features**: Packet size, connection duration, protocol types, port activity
- **Training**: Synthetic network data + real traffic patterns
- **Output**: Anomaly score, confidence level, threat classification

### Threat Intelligence Scoring
- **IP Reputation**: Known malicious IP database
- **Port Analysis**: Suspicious port activity detection  
- **Behavioral Patterns**: User and system behavior analysis
- **Risk Assessment**: Multi-factor threat scoring (0-10 scale)

## 📈 Key Metrics & Alerts

### Network Security Metrics
- **Network Events**: Total network connections and packet analysis
- **Suspicious Activities**: ML-flagged anomalous behavior
- **Threat Scores**: Risk assessment based on multiple factors
- **Alert Severity**: Categorized threat levels with automated response

### Performance Monitoring  
- **Real-time Processing**: Sub-second threat detection
- **ML Model Accuracy**: Continuous model performance tracking
- **System Resources**: CPU, memory, and network utilization
- **Threat Response Time**: Average incident detection and alerting speed

## 🔒 Security Features

- **Real-time Network Monitoring**: Continuous traffic analysis  
- **ML-powered Anomaly Detection**: Behavioral pattern recognition
- **Threat Intelligence Integration**: IP reputation and threat databases
- **Automated Alert System**: Instant notifications for security incidents
- **Multi-layered Analysis**: Network, system, and behavioral monitoring
- **Scalable Architecture**: Designed for enterprise deployment

## 🚦 API Endpoints

### Network Setup
- `POST /api/network/setup` - Configure network monitoring
- `GET /api/dashboard/stats` - Security dashboard statistics

### Threat Analysis
- `GET /api/threats/analyze` - Comprehensive threat analysis
- `POST /api/ml/analyze` - ML-powered network data analysis

### System Health
- `GET /` - IDS system status and health check

## 🌟 Advanced Features

### Machine Learning Pipeline
- **Data Preprocessing**: Network traffic feature extraction
- **Model Training**: Automated retraining with new threat patterns  
- **Inference Engine**: Real-time ML predictions on network data
- **Model Persistence**: Trained model storage and versioning

### Threat Intelligence
- **IP Geolocation**: Geographic threat analysis
- **Reputation Databases**: Known malicious IP and domain lists
- **Behavioral Analytics**: User and entity behavior analysis (UEBA)
- **Threat Hunting**: Proactive security threat discovery

## 📊 Visualization & Reporting

- **Interactive Charts**: Real-time threat timeline visualization
- **Security Metrics**: KPI dashboards with threat indicators
- **Alert Management**: Incident response and case management
- **Threat Maps**: Geographic and network topology visualization
- **Compliance Reporting**: Security audit and compliance metrics

## 🔧 Customization & Configuration

### ML Model Tuning
- Adjust anomaly detection thresholds
- Configure threat scoring parameters
- Customize alert sensitivity levels
- Train models with organization-specific data

### Network Monitoring
- Define network segments and monitoring zones  
- Configure protocol analysis and deep packet inspection
- Set up custom alerting rules and response actions
- Integrate with existing SIEM and security tools

---

**🛡️ Transform your network security with intelligent, ML-powered threat detection!**

For questions or support, please open an issue in the GitHub repository.