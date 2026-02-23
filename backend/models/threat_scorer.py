import os
import json
import pickle
import numpy as np
from datetime import datetime

import torch
import torch.nn as nn

# ── Paths ─────────────────────────────────────────────────
MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

FEATURES = ['Machine', 'DebugSize', 'DebugRVA', 'MajorImageVersion',
            'MajorOSVersion', 'ExportRVA', 'ExportSize', 'IatVRA',
            'MajorLinkerVersion', 'MinorLinkerVersion', 'NumberOfSections',
            'SizeOfStackReserve', 'DllCharacteristics', 'ResourceSize',
            'BitcoinAddresses']

# ── Load Scaler ───────────────────────────────────────────
with open(os.path.join(MODELS_DIR, 'scaler.pkl'), 'rb') as f:
    scaler = pickle.load(f)

# ── Load Random Forest ────────────────────────────────────
with open(os.path.join(MODELS_DIR, 'rf_model.pkl'), 'rb') as f:
    rf_model = pickle.load(f)

# ── Load Deep Learning Model ──────────────────────────────
class RansomwareNet(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
    def forward(self, x):
        return self.network(x).squeeze()

dl_model = RansomwareNet(input_dim=len(FEATURES))
dl_model.load_state_dict(torch.load(
    os.path.join(MODELS_DIR, 'dl_model.pth'),
    map_location='cpu'
))
dl_model.eval()

print("✅ All models loaded successfully!")

# ── Load SHAP values ──────────────────────────────────────
shap_path = os.path.join(MODELS_DIR, 'shap_values.json')
with open(shap_path) as f:
    shap_values = json.load(f)


def predict(features: dict) -> dict:
    # Build feature vector in correct order
    x = np.array([[features.get(f, 0) for f in FEATURES]], dtype=np.float32)

    # ── Random Forest prediction ──────────────────────────
    rf_prob    = rf_model.predict_proba(x)[0]
    rf_ransomware_prob = float(rf_prob[0])  # class 0 = ransomware

    # ── Deep Learning prediction ──────────────────────────
    x_scaled = scaler.transform(x)
    x_tensor = torch.FloatTensor(x_scaled)
    with torch.no_grad():
        dl_prob_benign = float(dl_model(x_tensor).item())
    dl_ransomware_prob = 1.0 - dl_prob_benign

    # ── Combine scores (RF weighted higher) ───────────────
    combined = (0.6 * rf_ransomware_prob) + (0.4 * dl_ransomware_prob)
    threat_score = round(combined * 100, 2)

    # ── Risk level ────────────────────────────────────────
    if threat_score > 70:
        risk_level = 'HIGH'
        prediction = 'Ransomware'
    elif threat_score > 30:
        risk_level = 'MEDIUM'
        prediction = 'Suspicious'
    else:
        risk_level = 'LOW'
        prediction = 'Benign'

    # ── Top 3 contributing features ───────────────────────
    top_features = list(shap_values.keys())[:3]

    return {
        'prediction':      prediction,
        'risk_level':      risk_level,
        'threat_score':    threat_score,
        'ml_confidence':   round(rf_ransomware_prob * 100, 2),
        'dl_confidence':   round(dl_ransomware_prob * 100, 2),
        'top_features':    top_features,
        'explanation':     f"Top indicators: {', '.join(top_features)}",
        'timestamp':       datetime.utcnow().isoformat()
    }