# CyberDefense AI Platform

> AI-powered ransomware detection with real blockchain logging, built for a hackathon & portfolio.

**Developer:** Gagandeep Singh ([@Shekhawat12082003](https://github.com/Shekhawat12082003))

---

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Features](#features)
- [Machine Learning Pipeline](#machine-learning-pipeline)
- [Blockchain Integration](#blockchain-integration)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Demo Credentials](#demo-credentials)
- [URLs](#urls)
- [Build History](#build-history)

---

## Overview

CyberDefense AI Platform is a full-stack cybersecurity platform that combines:

- **Dual AI models** (Random Forest + PyTorch DNN) for real-time ransomware detection
- **Real blockchain logging** on Core Testnet2 — every high-severity threat is immutably recorded
- **Auto-quarantine** — files scoring above threshold are isolated, analysts notified instantly
- **Fullscreen SOC war room** — cinematic dashboard for live threat monitoring
- **6-mode ransomware simulator** — for safe, controlled demos

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask, Flask-SocketIO, JWT |
| ML Models | Scikit-learn (Random Forest), PyTorch (DNN), SHAP |
| Database | SQLite |
| Blockchain | Solidity, Hardhat, Web3.py, Core Testnet2 |
| Frontend | React 18, Vite, Tailwind CSS |
| File Monitor | Watchdog |
| Email Alerts | Gmail SMTP |
| Reports | ReportLab (PDF) |

---

## Architecture

```
File dropped in watched/
        │
        ▼
Watchdog detects → file_monitor.py
        │
        ▼
Extract 15 PE features
        │
        ▼
Random Forest  (60% weight) → probability
PyTorch DNN    (40% weight) → probability
        │
        ▼
Combined threat score (0–100)
        │
      Score > 70?
     /           \
   YES             NO
    │               │
    ├─ Auto quarantine file
    ├─ WebSocket alert to SOC dashboard
    ├─ Email alert to analyst inbox
    └─ Log hash to Core Testnet2 blockchain
                    │
              Log as benign in SQLite
                    │
         Analyst can:
           → Verify hash on Blockchain page
           → Download PDF incident report
           → View SHAP explainability
           → Manage via Admin panel
```

---

## Features

### Phase 1 — AI Model Training
- Dataset: **62,485 PE files** (ransomware + benign)
- **15 extracted features:** Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA, ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections, SizeOfStackReserve, DllCharacteristics, ResourceSize, BitcoinAddresses
- Random Forest → **99.62% accuracy**
- PyTorch DNN (4-layer) → **98.30% accuracy**
- Ensemble prediction: `RF × 0.60 + DNN × 0.40`
- SHAP explainability values generated

### Phase 2 — Flask Backend
- Full REST API with JWT authentication (admin / analyst roles)
- SQLite threat history database
- WebSocket real-time alerts via Flask-SocketIO
- PDF incident report generation

### Phase 3 — React Frontend
- Cyberpunk dark theme with neon animations
- Pages: Login, Dashboard, Threats, Analytics, Blockchain, Admin, SOC
- Live stats cards, threat timeline chart, WebSocket live alerts banner

### Phase 4 — Smart Contract
- `ThreatLogger.sol` on Core Testnet2 (Chain ID: 1114)
- Functions: `logThreatSimple()`, `verifyHash()`, `getThreatByHash()`, `getTotalThreats()`
- Web3.py backend integration with local fallback

### Phase 5 — File Monitor + Auto Quarantine
- Watchdog monitors `backend/watched/`
- Supported: `.dll .exe .sys .bat .ps1 .vbs .js .locked .enc .crypto`
- Files scoring > 70 → auto-quarantined to `backend/quarantine/`
- WebSocket notification on detection

### Phase 6 — Ransomware Simulator
6 simulation modes:

| Mode | Description |
|------|-------------|
| 1 | Mixed Attack (HIGH + MEDIUM + LOW) — best for demo |
| 2 | Full Ransomware (all HIGH) |
| 3 | Gradual Escalation (APT simulation) |
| 4 | Benign Files Only |
| 5 | Quick Single File |
| 6 | Clean watched folder |

### Phase 7 — Email Alert System
- Gmail SMTP integration
- HTML dark-themed email template
- Startup email when backend launches
- HIGH threat email includes: score, file name, ML/DL confidence, top indicators, blockchain TX link, integrity hash, recommended actions

### Phase 8 — Admin Panel
4 tabs: Users, Quarantine, System, Settings

| Route | Method | Description |
|-------|--------|-------------|
| `/api/admin/users` | GET / POST | List / add users |
| `/api/admin/users/<username>` | DELETE | Remove user |
| `/api/admin/quarantine` | GET | View quarantined files |
| `/api/admin/quarantine/clear` | DELETE | Clear quarantine |
| `/api/admin/system` | GET | Platform info |
| `/api/admin/threats/clear` | DELETE | Clear threat history |
| `/api/admin/settings` | POST | Update settings |

### Phase 9 — Fullscreen SOC Dashboard
- Matrix rain background animation
- Live clock, threat level banner (LOW / MEDIUM / HIGH / CRITICAL)
- Real-time stats, service status indicators
- Recent detections table with progress bars
- Threat distribution chart
- Live activity feed via WebSocket
- Auto-refreshes every 5 seconds, fullscreen toggle (F11)

---

## Machine Learning Pipeline

```python
# Ensemble prediction
rf_prob   = random_forest.predict_proba(features)[0][1]   # 60% weight
dnn_prob  = pytorch_dnn(features_tensor).item()           # 40% weight
score     = (rf_prob * 0.60 + dnn_prob * 0.40) * 100
```

Models are stored in `backend/models/`:
- `rf_model.pkl` — trained Random Forest
- `dl_model.pth` — PyTorch DNN weights
- `scaler.pkl` — StandardScaler for feature normalization
- `shap_values.json` — pre-computed SHAP explainability data

---

## Blockchain Integration

| Item | Value |
|------|-------|
| Network | Core Testnet2 |
| Chain ID | 1114 |
| RPC | https://rpc.test2.btcs.network |
| Explorer | https://scan.test2.btcs.network |
| Contract | `0x9807Ae60581B38611534d656f6a16AF28B846E17` |
| Deployer Wallet | `0xa0a9579D2F7b201cF2C09C09bE8B6D230b198c13` |

Every HIGH-severity threat logs a SHA-256 hash to the blockchain. Analysts can verify file integrity on the Blockchain page.

---

## Project Structure

```
cyberdefense-platform/
├── backend/
│   ├── app.py                    ← Main Flask server (all routes)
│   ├── .env                      ← Secrets (gitignored)
│   ├── cyberdefense.db           ← SQLite database
│   ├── blockchain_log.json       ← Local blockchain fallback log
│   ├── simulate_ransomware.py    ← 6-mode attack simulator
│   ├── watched/                  ← Auto-scan drop folder
│   ├── quarantine/               ← Auto-quarantine folder
│   ├── models/
│   │   ├── threat_scorer.py      ← RF + DNN prediction engine
│   │   ├── file_monitor.py       ← Watchdog auto-scanner
│   │   ├── rf_model.pkl          ← Random Forest (99.62%)
│   │   ├── dl_model.pth          ← PyTorch DNN (98.30%)
│   │   ├── scaler.pkl            ← StandardScaler
│   │   └── shap_values.json      ← Explainability data
│   ├── utils/
│   │   ├── db.py                 ← SQLite operations
│   │   ├── blockchain_logger.py  ← Web3 + local logging
│   │   ├── email_alerts.py       ← Gmail SMTP alerts
│   │   └── report_generator.py   ← PDF reports
│   └── blockchain/
│       └── ThreatLogger_ABI.json ← Contract ABI
├── frontend/
│   └── src/
│       ├── App.jsx               ← Router + protected routes
│       ├── api.js                ← Axios config
│       ├── index.css             ← Cyberpunk animations
│       └── pages/
│           ├── Login.jsx
│           ├── Dashboard.jsx
│           ├── Threats.jsx
│           ├── Analytics.jsx
│           ├── Blockchain.jsx
│           ├── Admin.jsx
│           └── SOC.jsx           ← Fullscreen war room
├── blockchain/
│   ├── contracts/
│   │   └── ThreatLogger.sol      ← Solidity smart contract
│   ├── scripts/
│   │   └── deploy.js             ← Hardhat deployment
│   ├── hardhat.config.js
│   ├── deployment.json
│   └── ThreatLogger_ABI.json
├── notebooks/
│   └── ransomware_model_training.ipynb
├── .gitignore
└── README.md
```

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- Node.js 18+
- Git

### Backend

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install flask flask-socketio flask-jwt-extended flask-cors \
    scikit-learn torch numpy pandas watchdog web3 \
    python-dotenv reportlab shap pefile
```

Create `backend/.env`:
```env
FLASK_ENV=development
SECRET_KEY=your-secret-key
MONITOR_PATH=C:\path\to\backend\watched
ETH_RPC_URL=https://rpc.test2.btcs.network
CONTRACT_ADDRESS=0x9807Ae60581B38611534d656f6a16AF28B846E17
WALLET_PRIVATE_KEY=your-private-key
CHAIN_ID=1114
EMAIL_SENDER=your@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_RECEIVER=analyst@example.com
EMAIL_ENABLED=true
```

### Frontend

```powershell
cd frontend
npm install
```

### Blockchain (optional re-deploy)

```powershell
cd blockchain
npm install
npx hardhat run scripts/deploy.js --network coreTestnet2
```

---

## Usage

```powershell
# Terminal 1 — Backend
cd backend
venv\Scripts\activate
python app.py

# Terminal 2 — Frontend
cd frontend
npm run dev

# Terminal 3 — Run ransomware simulation (demo)
cd backend
venv\Scripts\activate
python simulate_ransomware.py
```

---

## API Reference

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/login` | POST | — | Obtain JWT token |
| `/api/predict` | POST | JWT | Analyze file features |
| `/api/threats` | GET | JWT | Threat history |
| `/api/stats` | GET | JWT | Platform statistics |
| `/api/shap` | GET | JWT | SHAP explainability data |
| `/api/report` | POST | JWT | Generate PDF report |
| `/api/admin/users` | GET/POST | Admin | Manage users |
| `/api/admin/quarantine` | GET | Admin | View quarantine |
| `/api/admin/quarantine/clear` | DELETE | Admin | Clear quarantine |
| `/api/admin/system` | GET | Admin | System info |
| `/api/admin/threats/clear` | DELETE | Admin | Clear threat log |
| `/api/admin/settings` | POST | Admin | Update settings |

---

## Demo Credentials

| User | Password | Role |
|------|----------|------|
| admin | admin123 | Admin |
| analyst | analyst123 | Analyst |

---

## URLs

| Service | URL |
|---------|-----|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:5000 |
| SOC Dashboard | http://localhost:5173/soc |
| Admin Panel | http://localhost:5173/admin |
| Blockchain Page | http://localhost:5173/blockchain |
| Contract Explorer | https://scan.test2.btcs.network/address/0x9807Ae60581B38611534d656f6a16AF28B846E17 |

---

## Build History

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Dataset & Model Training (RF 99.62% + DNN 98.30%) | ✅ Complete |
| 2 | Flask REST API + JWT + SQLite + WebSocket | ✅ Complete |
| 3 | React Frontend — Cyberpunk Dark Theme | ✅ Complete |
| 4 | Solidity Smart Contract + Core Testnet2 Deployment | ✅ Complete |
| 5 | Watchdog File Monitor + Auto Quarantine | ✅ Complete |
| 6 | 6-Mode Ransomware Simulator | ✅ Complete |
| 7 | Gmail Email Alert System | ✅ Complete |
| 8 | Admin Panel (Users / Quarantine / System / Settings) | ✅ Complete |
| 9 | Fullscreen SOC War Room Dashboard | ✅ Complete |
| 10 | GitHub Push | ✅ Complete |

### Planned Features

| Feature | Priority |
|---------|----------|
| AI Chatbot integration | HIGH |
| Network Traffic Analysis | MEDIUM |

---

## What Makes This Project Stand Out

- **Real blockchain** — not simulated, actual on-chain transactions on Core Testnet2
- **Dual AI ensemble** — Random Forest + PyTorch DNN with weighted voting
- **Live attack simulation** — 6-mode ransomware simulator for controlled demos
- **Auto incident response** — quarantine + email + blockchain logging in seconds
- **SHAP explainability** — every prediction is interpretable
- **Production-ready** — JWT auth, WebSocket, PDF reports, role-based access

---

*Built with ❤️ by Gagandeep Singh — Hackathon / Portfolio Project*
