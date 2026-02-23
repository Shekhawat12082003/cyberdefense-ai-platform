import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent / '.env')

SENDER   = os.getenv('EMAIL_SENDER', '')
PASSWORD = os.getenv('EMAIL_PASSWORD', '')
RECEIVER = os.getenv('EMAIL_RECEIVER', '')
ENABLED  = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'


def send_high_threat_alert(threat_data: dict) -> bool:
    if not ENABLED:
        print("ℹ️  Email alerts disabled")
        return False
    if not all([SENDER, PASSWORD, RECEIVER]):
        print("⚠️  Email not configured in .env")
        return False

    try:
        score      = threat_data.get('threat_score', 0)
        prediction = threat_data.get('prediction', 'Unknown')
        risk       = threat_data.get('risk_level', 'HIGH')
        timestamp  = threat_data.get('timestamp', datetime.utcnow().isoformat())
        file_name  = threat_data.get('file_name', 'unknown')
        hash_val   = threat_data.get('hash', 'N/A')
        features   = threat_data.get('top_features', [])
        bc         = threat_data.get('blockchain', {})
        ml_conf    = threat_data.get('ml_confidence', 0)
        dl_conf    = threat_data.get('dl_confidence', 0)

        html = f"""
<!DOCTYPE html>
<html>
<head>
<style>
  body {{
    font-family: 'Courier New', monospace;
    background: #000;
    color: #fff;
    margin: 0;
    padding: 20px;
  }}
  .container {{
    max-width: 650px;
    margin: 0 auto;
    background: #0a0a0a;
    border: 1px solid #ff003c;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 0 30px #ff003c55;
  }}
  .header {{
    background: #ff003c;
    padding: 20px 30px;
    text-align: center;
  }}
  .header h1 {{
    margin: 0;
    font-size: 22px;
    color: #000;
    font-weight: bold;
    letter-spacing: 3px;
  }}
  .header p {{
    margin: 5px 0 0;
    color: #000;
    font-size: 12px;
    opacity: 0.8;
  }}
  .score-box {{
    text-align: center;
    padding: 30px;
    background: #111;
    border-bottom: 1px solid #222;
  }}
  .score {{
    font-size: 72px;
    font-weight: bold;
    color: #ff003c;
    line-height: 1;
  }}
  .score-label {{
    color: #666;
    font-size: 11px;
    letter-spacing: 3px;
    margin-top: 5px;
  }}
  .risk-badge {{
    display: inline-block;
    background: #ff003c;
    color: #000;
    padding: 6px 20px;
    border-radius: 4px;
    font-weight: bold;
    font-size: 14px;
    letter-spacing: 2px;
    margin-top: 10px;
  }}
  .section {{
    padding: 20px 30px;
    border-bottom: 1px solid #1a1a1a;
  }}
  .section-title {{
    color: #00d4ff;
    font-size: 11px;
    letter-spacing: 3px;
    margin-bottom: 12px;
    border-bottom: 1px solid #00d4ff33;
    padding-bottom: 6px;
  }}
  .row {{
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid #111;
    font-size: 13px;
  }}
  .row-label {{ color: #666; }}
  .row-value {{ color: #fff; font-weight: bold; }}
  .feature {{
    background: #111;
    border: 1px solid #222;
    padding: 8px 12px;
    border-radius: 4px;
    margin: 4px 0;
    font-size: 12px;
    color: #00d4ff;
  }}
  .hash {{
    background: #111;
    padding: 10px;
    border-radius: 4px;
    font-size: 11px;
    color: #666;
    word-break: break-all;
    border: 1px solid #222;
  }}
  .blockchain {{
    background: #001a2e;
    border: 1px solid #00d4ff33;
    padding: 12px;
    border-radius: 4px;
    font-size: 12px;
  }}
  .blockchain a {{
    color: #00d4ff;
    text-decoration: none;
  }}
  .actions {{
    background: #111;
    padding: 20px 30px;
    text-align: center;
  }}
  .btn {{
    display: inline-block;
    padding: 12px 30px;
    background: #ff003c;
    color: #000;
    font-weight: bold;
    font-size: 12px;
    letter-spacing: 2px;
    border-radius: 4px;
    text-decoration: none;
    margin: 5px;
  }}
  .btn-blue {{ background: #00d4ff; }}
  .footer {{
    padding: 15px 30px;
    text-align: center;
    font-size: 11px;
    color: #333;
    background: #050505;
  }}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <h1>🚨 HIGH THREAT DETECTED</h1>
    <p>CyberDefense AI — Automated Security Alert</p>
  </div>

  <div class="score-box">
    <div class="score">{score}</div>
    <div class="score-label">THREAT SCORE / 100</div>
    <div class="risk-badge">⚠ {risk} RISK — {prediction}</div>
  </div>

  <div class="section">
    <div class="section-title">📋 INCIDENT DETAILS</div>
    <div class="row">
      <span class="row-label">File Name</span>
      <span class="row-value">{file_name}</span>
    </div>
    <div class="row">
      <span class="row-label">Prediction</span>
      <span class="row-value" style="color:#ff003c">{prediction}</span>
    </div>
    <div class="row">
      <span class="row-label">Threat Score</span>
      <span class="row-value" style="color:#ff003c">{score} / 100</span>
    </div>
    <div class="row">
      <span class="row-label">Risk Level</span>
      <span class="row-value">{risk}</span>
    </div>
    <div class="row">
      <span class="row-label">Detected At</span>
      <span class="row-value">{timestamp[:19]} UTC</span>
    </div>
    <div class="row">
      <span class="row-label">ML Confidence</span>
      <span class="row-value">{ml_conf}%</span>
    </div>
    <div class="row">
      <span class="row-label">DL Confidence</span>
      <span class="row-value">{dl_conf}%</span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">🔍 TOP THREAT INDICATORS</div>
    {''.join(f'<div class="feature">▶ {f}</div>' for f in features[:5])}
  </div>

  <div class="section">
    <div class="section-title">⛓ BLOCKCHAIN LOG</div>
    <div class="blockchain">
      <div style="margin-bottom:6px">
        Mode: <strong style="color:#00d4ff">{bc.get('mode', 'N/A')}</strong>
      </div>
      <div style="margin-bottom:6px">
        Block: <strong style="color:#00d4ff">#{bc.get('block', 'N/A')}</strong>
      </div>
      <div style="margin-bottom:6px">
        TX: <strong style="color:#00d4ff">{str(bc.get('tx_hash', 'N/A'))[:30]}...</strong>
      </div>
      {('<a href="' + bc.get('explorer') + '">🔗 View TX on Core Testnet2 Explorer</a>') if bc.get('explorer') else '<span style="color:#666">Local simulation mode</span>'}
    </div>
  </div>

  <div class="section">
    <div class="section-title">🔐 INTEGRITY HASH</div>
    <div class="hash">{hash_val}</div>
  </div>

  <div class="section">
    <div class="section-title">🛡️ IMMEDIATE ACTIONS REQUIRED</div>
    <div class="feature">🔒 1. Isolate affected system from network immediately</div>
    <div class="feature">🔒 2. File has been auto-quarantined by CyberDefense AI</div>
    <div class="feature">📋 3. Run full system scan with updated signatures</div>
    <div class="feature">📋 4. Review system logs for lateral movement indicators</div>
    <div class="feature">🔄 5. Check backup integrity before any restoration</div>
  </div>

  <div class="actions">
    <a href="http://localhost:5173/threats" class="btn">🔍 VIEW THREATS</a>
    <a href="http://localhost:5173/blockchain" class="btn btn-blue">⛓ BLOCKCHAIN LOG</a>
  </div>

  <div class="footer">
    Generated by CyberDefense AI Platform — {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC<br>
    This is an automated security alert. Do not reply to this email.
  </div>

</div>
</body>
</html>
"""

        text = f"""
CYBERDEFENSE AI — HIGH THREAT ALERT
=====================================
File      : {file_name}
Score     : {score} / 100
Prediction: {prediction}
Risk      : {risk}
Timestamp : {timestamp[:19]} UTC
ML Conf   : {ml_conf}%
DL Conf   : {dl_conf}%

TOP INDICATORS:
{chr(10).join(f'  - {f}' for f in features[:5])}

BLOCKCHAIN:
  Mode  : {bc.get('mode', 'N/A')}
  Block : #{bc.get('block', 'N/A')}
  TX    : {bc.get('explorer', 'N/A')}

HASH: {hash_val}

IMMEDIATE ACTIONS:
  1. Isolate affected system
  2. File auto-quarantined
  3. Run full system scan
  4. Review system logs
  5. Check backup integrity

CyberDefense AI Platform
"""

        msg            = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 HIGH THREAT — Score: {score} | {prediction} | CyberDefense AI"
        msg['From']    = f"CyberDefense AI <{SENDER}>"
        msg['To']      = RECEIVER

        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html,  'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER, PASSWORD)
            server.sendmail(SENDER, RECEIVER, msg.as_string())

        print(f"✅ Alert email sent to {RECEIVER}")
        return True

    except Exception as e:
        print(f"⚠️  Email send failed: {e}")
        return False


def send_system_startup_email() -> bool:
    if not ENABLED or not all([SENDER, PASSWORD, RECEIVER]):
        return False
    try:
        msg            = MIMEMultipart('alternative')
        msg['Subject'] = "✅ CyberDefense AI Platform Started"
        msg['From']    = f"CyberDefense AI <{SENDER}>"
        msg['To']      = RECEIVER

        html = f"""
<div style="font-family:monospace;background:#000;color:#fff;padding:20px;max-width:500px;margin:0 auto">
  <div style="background:#00d4ff;padding:20px;border-radius:4px;text-align:center">
    <h2 style="color:#000;margin:0;letter-spacing:3px">🛡️ CYBERDEFENSE AI ONLINE</h2>
  </div>
  <div style="background:#111;padding:20px;margin-top:10px;border-radius:4px;border:1px solid #222">
    <p style="color:#666;font-size:12px">System started at</p>
    <p style="color:#00d4ff;font-size:16px;font-weight:bold">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
    <hr style="border-color:#222;margin:15px 0">
    <p style="color:#00ff88">✅ AI Models loaded (RF + DNN)</p>
    <p style="color:#00ff88">✅ Blockchain connected (Core Testnet2)</p>
    <p style="color:#00ff88">✅ File monitor active</p>
    <p style="color:#00ff88">✅ Email alerts enabled</p>
    <p style="color:#00ff88">✅ WebSocket SOC ready</p>
    <hr style="border-color:#222;margin:15px 0">
    <a href="http://localhost:5173"
       style="background:#00d4ff;color:#000;padding:12px 25px;border-radius:4px;
              text-decoration:none;font-weight:bold;letter-spacing:2px;display:inline-block">
      OPEN DASHBOARD →
    </a>
  </div>
  <p style="color:#333;font-size:11px;text-align:center;margin-top:10px">
    CyberDefense AI — Automated Security Platform
  </p>
</div>
"""
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(SENDER, PASSWORD)
            server.sendmail(SENDER, RECEIVER, msg.as_string())

        print(f"✅ Startup email sent to {RECEIVER}")
        return True

    except Exception as e:
        print(f"⚠️  Startup email failed: {e}")
        return False