# Intelligent Intrusion Detection System (IDS)

🛡️ **ML-Powered Network Security Monitoring & Threat Detection**

A sophisticated **Machine Learning-powered Intrusion Detection System** capable of real-time network traffic analysis using **REAL device data**, behavioral anomaly detection, and automated threat response.

## 🚀 Features

### 🤖 Machine Learning & AI
- **NSL-KDD trained models** - Industry-standard intrusion detection dataset
- **41 real network features** - All features populated from actual device traffic
- **Multiple ML algorithms tested** - Decision Tree, Random Forest, XGBoost, LightGBM
- **Real-time ML inference** on live network traffic
- **Behavioral analysis** to detect unusual user/system activities

### 🌐 Network Monitoring
- **Real-time packet capture** with Scapy integration
- **Connection monitoring** using psutil
- **41 NSL-KDD features** extracted from actual network traffic:
  - Duration, bytes, protocol type, service, flag
  - Error rates (serror, rerror, srv_serror, srv_rerror)
  - Host-based features (dst_host_count, srv_count, same_srv_rate)
  - Content features (num_failed_logins, num_shells, num_file_creations)
- **Port scan detection** and suspicious activity identification

### 🔐 Security Features
- **JWT Authentication** with user roles (admin, analyst, viewer)
- **Login Rate Limiting** - Brute force attack protection
- **IP Quarantine System** - Auto-block attacking IPs
- **Login Security Monitoring** - Track failed login attempts per IP

### 📊 Security Dashboard
- **Real-time threat visualization** 
- **Interactive security metrics** and KPI monitoring  
- **Alert management** with filtering and search
- **Login security view** for monitoring brute force attempts
- **IP quarantine management** interface

## 📈 ML Model Performance

Tested on NSL-KDD dataset (22,544 test samples):

| Model | Accuracy | Precision | Recall | F1 Score |
|-------|----------|-----------|--------|----------|
| **Decision Tree** | 81.22% | 93.72% | **71.83%** | **81.33%** |
| AdaBoost | 79.87% | 96.61% | 67.00% | 79.12% |
| XGBoost | 79.56% | 96.71% | 66.34% | 78.70% |
| Random Forest | 77.94% | 96.71% | 63.40% | 76.59% |

**Decision Tree recommended** - Best recall (catches 72% of attacks) and F1 score.

## 🏗️ Architecture

### Backend (FastAPI + Python)
\`\`\`
backend/
├── app/
│   ├── main.py              # FastAPI application & endpoints
│   ├── ml_models.py         # NSL-KDD trained ML models
│   ├── network_monitor.py   # Real network traffic monitoring
│   ├── real_packet_capture.py # Scapy packet capture
│   ├── auth.py              # JWT authentication
│   ├── ip_quarantine.py     # IP blocking system
│   └── attack_detector.py   # Attack pattern detection
├── models/                  # Trained ML models (.pkl)
├── requirements.txt         # Python dependencies
└── compare_models.py        # ML model comparison script
\`\`\`

### Frontend (React + Vite)
\`\`\`
frontend/
├── src/
│   ├── components/
│   │   ├── MainScreen.jsx       # Dashboard layout
│   │   ├── RealTimeMonitor.jsx  # Live network monitoring
│   │   ├── AlertsView.jsx       # Security alerts
│   │   ├── VisualizerView.jsx   # ML visualization
│   │   ├── LoginSecurityView.jsx # Login monitoring
│   │   ├── IPQuarantineView.jsx # IP blocking UI
│   │   └── LoginPage.jsx        # Authentication
│   ├── context/
│   │   └── AuthContext.jsx      # Auth state management
│   └── App.jsx                  # Main application
└── package.json
\`\`\`

### Attacker Machine (Testing)
\`\`\`
AttackerMachine/
├── attacker_panel.html      # Web-based attack launcher
├── attacker_cli.py          # CLI attack tools
├── attack_standalone.py     # Standalone attack scripts
└── NETWORK_ATTACK_GUIDE.md  # Attack testing guide
\`\`\`

## 🔧 Installation & Setup

### Prerequisites
- **Python 3.11+**
- **Node.js 16+**
- **Git**

### 1. Clone Repository
\`\`\`bash
git clone https://github.com/galactose-milk/Intrusion_Detection_System.git
cd Intrusion_Detection_System
\`\`\`

### 2. Backend Setup
\`\`\`bash
cd backend

# Create virtual environment (optional)
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Start backend server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
\`\`\`

### 3. Frontend Setup  
\`\`\`bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
\`\`\`

### 4. Access the System
- **Dashboard**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs
- **Backend Health**: http://localhost:8000

### 5. Default Login Credentials
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |
| viewer | viewer123 | Viewer |

## 🎯 NSL-KDD Features (41 Total)

All features are populated with **REAL network data** from your device:

### Basic Features
| Feature | Source |
|---------|--------|
| duration | Connection start time tracking |
| protocol_type | psutil connection type |
| service | Port-to-service mapping |
| flag | Connection status |
| src_bytes, dst_bytes | Network I/O monitoring |

### Content Features
| Feature | Source |
|---------|--------|
| wrong_fragment | Scapy IP fragmentation analysis |
| urgent | Scapy TCP URG flag detection |
| num_compromised | Payload compromise signatures |
| num_failed_logins | Login rate limiter |
| num_shells | Process monitoring |
| num_file_creations | File system monitoring |

### Traffic Features
| Feature | Source |
|---------|--------|
| count | Connection history window |
| srv_count | Service access tracking |
| serror_rate | SYN error tracking |
| same_srv_rate | Service pattern analysis |

### Host-based Features
| Feature | Source |
|---------|--------|
| dst_host_count | Destination host tracking |
| dst_host_same_src_port_rate | Source port pattern analysis |
| srv_diff_host_rate | Multi-host service tracking |

## 🔒 Security Endpoints

### Authentication
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/register\` - Register new user (admin only)
- \`GET /api/auth/me\` - Current user info

### Detection
- \`GET /api/detection/alerts\` - Security alerts
- \`GET /api/detection/statistics\` - Detection stats
- \`GET /api/realtime/connections\` - Live connections

### IP Quarantine
- \`GET /api/quarantine/blocked\` - Blocked IPs
- \`POST /api/quarantine/block\` - Block an IP
- \`DELETE /api/quarantine/unblock/{ip}\` - Unblock IP

### Login Security
- \`GET /api/auth/login-stats\` - Login attempt statistics
- \`GET /api/auth/locked-ips\` - Locked out IPs

## 🧪 Testing Attacks

Use the Attacker Machine tools to test detection:

\`\`\`bash
cd AttackerMachine

# Web panel
open attacker_panel.html

# CLI attacks
python attacker_cli.py --target http://localhost:8000
\`\`\`

Available attacks:
- Port scanning
- Brute force login
- DDoS simulation
- SQL injection attempts
- API endpoint probing

## 📊 ML Model Comparison

Run the comparison script:
\`\`\`bash
cd backend
python compare_models.py
\`\`\`

This tests 10+ models on NSL-KDD and outputs:
- Accuracy, Precision, Recall, F1 scores
- Training time comparison
- Feature importance analysis

## 📁 Project Structure

\`\`\`
Intrusion_detection_system/
├── backend/           # FastAPI backend
├── frontend/          # React frontend
├── NSL-KDD/           # Training dataset
├── AttackerMachine/   # Attack testing tools
├── ML_MODEL_COMPARISON.md  # Model benchmark results
└── README.md
\`\`\`

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (\`git checkout -b feature/amazing-feature\`)
3. Commit changes (\`git commit -m 'Add amazing feature'\`)
4. Push to branch (\`git push origin feature/amazing-feature\`)
5. Open a Pull Request

## 📝 License

This project is for educational purposes.

---

**🛡️ Real ML-powered intrusion detection with actual network data!**

For questions or support, please open an issue in the GitHub repository.
