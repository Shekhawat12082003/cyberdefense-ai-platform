"""
Webhook alert dispatcher.
Supports Slack, Discord and generic HTTP webhooks.
Set WEBHOOK_URL in .env — auto-detects format from the URL.
"""
import os
import json
import requests
from datetime import datetime


def send_webhook_alert(threat_data: dict):
    url = os.getenv('WEBHOOK_URL', '').strip()
    if not url:
        return

    score      = threat_data.get('threat_score', 0)
    prediction = threat_data.get('prediction', 'Unknown')
    file_name  = threat_data.get('file_name', 'unknown')
    risk       = threat_data.get('risk_level', 'HIGH')
    ts         = threat_data.get('timestamp', datetime.utcnow().isoformat())[:19]
    mitre      = threat_data.get('mitre_tactics', '')
    tx         = (threat_data.get('blockchain') or {}).get('tx_hash', '')
    explorer   = (threat_data.get('blockchain') or {}).get('explorer', '')

    color_hex  = 'FF003C' if score > 70 else 'FF8C00'
    emoji      = '🚨' if score > 70 else '⚠️'

    mitre_line = f'\n🎯 MITRE: {mitre}' if mitre else ''
    chain_line = f'\n⛓ TX: {explorer or tx[:20] + "..." if tx else "local log"}' if tx or explorer else ''

    try:
        # ── Discord ───────────────────────────────────────
        if 'discord' in url:
            payload = {
                'embeds': [{
                    'title':       f'{emoji} HIGH THREAT DETECTED — {file_name}',
                    'description': (
                        f'**Score:** {score}\n'
                        f'**Prediction:** {prediction}\n'
                        f'**Risk:** {risk}\n'
                        f'**Time:** {ts}'
                        f'{mitre_line}'
                        f'{chain_line}'
                    ),
                    'color': int(color_hex, 16),
                    'footer': {'text': 'CyberDefense AI Platform'}
                }]
            }
        # ── Slack ─────────────────────────────────────────
        elif 'slack' in url or 'hooks.slack' in url:
            payload = {
                'text': f'{emoji} *HIGH THREAT DETECTED*',
                'attachments': [{
                    'color':  f'#{color_hex}',
                    'fields': [
                        {'title': 'File',       'value': file_name,       'short': True},
                        {'title': 'Score',      'value': str(score),      'short': True},
                        {'title': 'Prediction', 'value': prediction,      'short': True},
                        {'title': 'Risk',       'value': risk,            'short': True},
                        {'title': 'Time',       'value': ts,              'short': True},
                    ] + ([{'title': 'MITRE', 'value': mitre, 'short': False}] if mitre else []),
                    'footer': 'CyberDefense AI Platform'
                }]
            }
        # ── Generic JSON (Teams, custom) ──────────────────
        else:
            payload = {
                'title':      f'{emoji} HIGH THREAT — {file_name}',
                'score':      score,
                'prediction': prediction,
                'risk':       risk,
                'timestamp':  ts,
                'mitre':      mitre
            }

        res = requests.post(url, json=payload, timeout=8)
        if res.status_code < 300:
            print(f'🔔 Webhook alert sent → {url[:40]}...')
        else:
            print(f'⚠️  Webhook failed: {res.status_code} {res.text[:80]}')

    except Exception as e:
        print(f'⚠️  Webhook error: {e}')
