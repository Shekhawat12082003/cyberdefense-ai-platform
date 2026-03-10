"""
AI Security Analyst Chatbot
Uses OpenAI API if OPENAI_API_KEY is set in .env.
Falls back to a context-aware rule-based engine if no key is configured.
"""
import os
import json


def _build_system_prompt(context: dict) -> str:
    stats   = context.get('stats',   {}) if context else {}
    threats = context.get('threats', []) if context else []

    threat_summary = ''
    if threats:
        lines = []
        for t in threats[:5]:
            lines.append(
                f"  - {t.get('file_name','?')} | {t.get('prediction','?')} | "
                f"score {t.get('threat_score',0):.1f} | {t.get('timestamp','')[:19]}"
            )
        threat_summary = 'Recent detections:\n' + '\n'.join(lines)

    stats_summary = (
        f"Platform stats — total scanned: {stats.get('total_scanned',0)}, "
        f"active threats: {stats.get('active_threats',0)}, "
        f"high risk: {stats.get('high_risk_alerts',0)}, "
        f"system health: {stats.get('system_health',100)}%"
    ) if stats else ''

    return f"""You are an expert AI cybersecurity analyst embedded in the CyberDefense AI Platform.
You help SOC analysts understand ransomware threats, interpret ML predictions, and respond to incidents.

Platform context:
{stats_summary}
{threat_summary}

Platform details:
- Dual AI ensemble: Random Forest (60%) + PyTorch DNN (40%), trained on 62,485 PE files
- Random Forest accuracy: 99.62% | DNN accuracy: 98.30%
- 15 features: Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA,
  ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections,
  SizeOfStackReserve, DllCharacteristics, ResourceSize, BitcoinAddresses
- Threat thresholds: >70 = HIGH/Ransomware, 30-70 = MEDIUM/Suspicious, <30 = LOW/Benign
- Blockchain: Core Testnet2 (Chain ID 1114), contract 0x9807Ae60581B38611534d656f6a16AF28B846E17
- Auto-quarantine on HIGH threat detection
- SHAP values used for explainability

Respond concisely and professionally. Use **bold** for key terms.
Format lists with - bullets. Keep answers focused and actionable."""


def _rule_based_reply(message: str, context: dict) -> str:
    """Context-aware rule-based fallback when no API key is set."""
    msg = message.lower()
    stats   = context.get('stats',   {}) if context else {}
    threats = context.get('threats', []) if context else []

    # Status / summary
    if any(w in msg for w in ['status', 'summary', 'current', 'overview', 'situation']):
        total   = stats.get('total_scanned',   0)
        active  = stats.get('active_threats',  0)
        high    = stats.get('high_risk_alerts', 0)
        health  = stats.get('system_health',   100)
        return (
            f"**Current Threat Status**\n\n"
            f"- Total files scanned: **{total}**\n"
            f"- Active ransomware detections: **{active}**\n"
            f"- High-risk alerts: **{high}**\n"
            f"- System health: **{health}%**\n\n"
            + (f"Most recent detection: **{threats[0]['file_name']}** — "
               f"score {threats[0]['threat_score']:.1f} ({threats[0]['prediction']})"
               if threats else "No detections recorded yet.")
        )

    # Dangerous files
    if any(w in msg for w in ['dangerous', 'worst', 'highest', 'most']):
        if not threats:
            return "No threats recorded yet."
        top = sorted(threats, key=lambda x: x.get('threat_score', 0), reverse=True)[:3]
        lines = [f"- **{t['file_name']}** — score {t['threat_score']:.1f} ({t['prediction']})" for t in top]
        return "**Top Threats by Score**\n\n" + '\n'.join(lines)

    # SHAP
    if 'shap' in msg:
        return (
            "**SHAP (SHapley Additive exPlanations)**\n\n"
            "SHAP values show how much each feature contributed to a prediction.\n\n"
            "Key features for ransomware detection:\n"
            "- **BitcoinAddresses** — presence of BTC addresses in PE headers\n"
            "- **DllCharacteristics** — unusual DLL flags (e.g. no ASLR/DEP)\n"
            "- **NumberOfSections** — packed malware often has very few or many sections\n"
            "- **SizeOfStackReserve** — abnormal stack allocation\n"
            "- **ResourceSize** — malware often embeds payloads in resources\n\n"
            "A positive SHAP value pushes the score towards Ransomware."
        )

    # How the model works
    if any(w in msg for w in ['model', 'how does', 'algorithm', 'ml', 'ai', 'dnn', 'neural', 'forest']):
        return (
            "**How the AI Models Work**\n\n"
            "The platform uses an **ensemble of two models**:\n\n"
            "1. **Random Forest** (60% weight) — 99.62% accuracy\n"
            "   - 100 decision trees voting on 15 PE header features\n"
            "   - Excellent at detecting known ransomware patterns\n\n"
            "2. **PyTorch DNN** (40% weight) — 98.30% accuracy\n"
            "   - 4-layer network: 128 → 64 → 32 → 1\n"
            "   - BatchNorm + Dropout for robustness\n\n"
            "**Final score** = `(RF_prob × 0.60) + (DNN_prob × 0.40) × 100`\n\n"
            "Trained on **62,485 PE files** (ransomware + benign)."
        )

    # Incident response
    if any(w in msg for w in ['respond', 'response', 'incident', 'what should i do', 'action', 'step']):
        return (
            "**Incident Response Steps**\n\n"
            "1. **Isolate** — The file is auto-quarantined. Confirm it's in `backend/quarantine/`\n"
            "2. **Verify** — Check the blockchain hash on the Blockchain page for integrity proof\n"
            "3. **Analyse** — Download the PDF incident report for full details\n"
            "4. **Contain** — Disconnect affected systems from the network\n"
            "5. **Eradicate** — Run full endpoint scan; remove quarantined files after review\n"
            "6. **Recover** — Restore from clean backup; reset compromised credentials\n"
            "7. **Report** — Document the incident using the PDF report for compliance"
        )

    # Blockchain
    if any(w in msg for w in ['blockchain', 'hash', 'chain', 'on-chain', 'verify']):
        return (
            "**Blockchain Integration**\n\n"
            "Every **HIGH** threat is logged immutably to **Core Testnet2** (Chain ID 1114).\n\n"
            "- Contract: `0x9807Ae60581B38611534d656f6a16AF28B846E17`\n"
            "- Function: `logThreatSimple(hash, score, prediction)`\n"
            "- Each log is a real on-chain transaction — tamper-proof\n\n"
            "To verify: go to the **Blockchain page**, paste the SHA-256 hash of a threat,\n"
            "and it will retrieve the on-chain record.\n\n"
            "Explorer: https://scan.test2.btcs.network"
        )

    # Quarantine
    if any(w in msg for w in ['quarantin', 'isolat', 'enc', 'locked']):
        return (
            "**Auto-Quarantine System**\n\n"
            "Files scoring **>70** are automatically:\n"
            "1. Moved to `backend/quarantine/` with a timestamped name\n"
            "2. XOR-encrypted to prevent execution\n"
            "3. Logged in `quarantine_log.json`\n\n"
            "Manage quarantined files from the **Admin panel → Quarantine tab**.\n"
            "You can view all quarantined files or clear them entirely."
        )

    # Default
    return (
        "I can help with:\n\n"
        "- **Threat status** — ask 'summarize current threats'\n"
        "- **Model explanation** — ask 'how does the AI model work'\n"
        "- **SHAP values** — ask 'explain SHAP'\n"
        "- **Incident response** — ask 'what should I do about a ransomware'\n"
        "- **Blockchain** — ask 'how does blockchain logging work'\n"
        "- **Quarantine** — ask 'how does auto-quarantine work'\n\n"
        "💡 Tip: Set `OPENAI_API_KEY` in `.env` to enable full conversational AI."
    )


def chat(message: str, context: dict = None, history: list = None) -> str:
    """
    Main entry point.
    Returns a string reply.
    Uses OpenAI if OPENAI_API_KEY is available, else rule-based fallback.
    """
    api_key = os.getenv('OPENAI_API_KEY', '').strip()

    if not api_key:
        return _rule_based_reply(message, context or {})

    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        messages = [{'role': 'system', 'content': _build_system_prompt(context)}]

        # Add conversation history (last 10 turns)
        for h in (history or [])[-10:]:
            messages.append({'role': h['role'], 'content': h['text']})

        messages.append({'role': 'user', 'content': message})

        response = client.chat.completions.create(
            model='gpt-4o-mini',
            messages=messages,
            max_tokens=600,
            temperature=0.4
        )
        return response.choices[0].message.content

    except ImportError:
        return _rule_based_reply(message, context or {})
    except Exception as e:
        return (
            f"⚠️ OpenAI API error: {str(e)}\n\n"
            + _rule_based_reply(message, context or {})
        )
