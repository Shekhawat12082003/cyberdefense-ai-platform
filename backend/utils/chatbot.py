"""
AI Security Analyst Chatbot
Provider priority (first available key wins):
  1. OpenAI   — OPENAI_API_KEY   (gpt-4o-mini)
  2. Gemini   — GEMINI_API_KEY   (gemini-2.0-flash, generous free tier)
  3. Groq     — GROQ_API_KEY     (llama-3.3-70b-versatile, free tier)
  4. Rule-based fallback (no key required)
"""
import os
import json


def _build_system_prompt(context: dict) -> str:
    stats             = context.get('stats',           {}) if context else {}
    threats           = context.get('threats',         []) if context else []
    failed_logins     = context.get('failed_logins',    0)
    recent_logins     = context.get('recent_logins',   [])
    quarantine_count  = context.get('quarantine_count', 0)
    quarantine_log    = context.get('quarantine_log',  [])
    recent_audit      = context.get('recent_audit',    [])
    users_count       = context.get('users_count',      0)
    users             = context.get('users',           [])
    blockchain_mode   = context.get('blockchain_mode', 'unknown')
    threat_threshold  = context.get('threat_threshold', 70)
    email_enabled     = context.get('email_enabled',   False)
    current_user      = context.get('current_user',    'analyst')
    current_role      = context.get('current_role',    'analyst')

    threat_summary = ''
    if threats:
        lines = []
        for t in threats[:8]:
            lines.append(
                f"  - {t.get('file_name','?')} | {t.get('prediction','?')} | "
                f"score {t.get('threat_score',0):.1f} | risk {t.get('risk_level','?')} | {t.get('timestamp','')[:19]}"
            )
        threat_summary = 'Recent detections (latest first):\n' + '\n'.join(lines)

    quarantine_summary = ''
    if quarantine_log:
        qlines = [f"  - {q.get('original','?')} | score {q.get('score',0):.1f} | {q.get('timestamp','')[:19]}" for q in quarantine_log[:5]]
        quarantine_summary = f'Quarantined files ({quarantine_count} total):\n' + '\n'.join(qlines)

    audit_summary = ''
    if recent_audit:
        alines = [f"  - [{e.get('timestamp','')[:19]}] {e.get('username','?')}: {e.get('action','?')} — {e.get('details','')}" for e in recent_audit[:5]]
        audit_summary = 'Recent audit events:\n' + '\n'.join(alines)

    login_summary = ''
    if recent_logins:
        llines = [f"  - [{e.get('timestamp','')[:19]}] {e.get('username','?')}: {e.get('action','?')} {e.get('details','')}" for e in recent_logins[:5]]
        login_summary = f'Recent login activity (failed attempts total: {failed_logins}):\n' + '\n'.join(llines)

    users_summary = ''
    if users:
        users_summary = f'Platform users ({users_count} total): ' + ', '.join(f"{u['username']} ({u['role']})" for u in users)

    stats_summary = (
        f"Platform stats — total scanned: {stats.get('total_scanned',0)}, "
        f"active threats: {stats.get('active_threats',0)}, "
        f"medium threats: {stats.get('medium_threats',0)}, "
        f"high risk alerts: {stats.get('high_risk_alerts',0)}, "
        f"system health: {stats.get('system_health',100)}%, "
        f"quarantine files: {quarantine_count}, "
        f"failed login attempts: {failed_logins}"
    ) if stats else ''

    return f"""You are an expert AI cybersecurity analyst embedded in the CyberDefense AI Platform.
You are talking to **{current_user}** (role: {current_role}). Answer questions about the live platform state using the context below.
Be specific — quote real numbers, file names, scores, and timestamps from the context when answering.

LIVE PLATFORM CONTEXT:
{stats_summary}
{threat_summary}
{quarantine_summary}
{login_summary}
{audit_summary}
{users_summary}

Platform configuration:
- Threat threshold: {threat_threshold} (scores >{threat_threshold} = HIGH)
- Blockchain mode: {blockchain_mode} | Contract: 0x9807Ae60581B38611534d656f6a16AF28B846E17
- Email alerts: {'enabled' if email_enabled else 'disabled'}
- AI ensemble: Random Forest (60%) + PyTorch DNN (40%), trained on 62,485 PE files
- RF accuracy: 99.62% | DNN accuracy: 98.30%
- 15 PE features: Machine, DebugSize, DebugRVA, MajorImageVersion, MajorOSVersion, ExportRVA,
  ExportSize, IatVRA, MajorLinkerVersion, MinorLinkerVersion, NumberOfSections,
  SizeOfStackReserve, DllCharacteristics, ResourceSize, BitcoinAddresses
- SHAP values used for explainability
- Auto-quarantine triggers on score >{threat_threshold} or ransomware extension

Respond concisely and professionally. Use **bold** for key terms and numbers.
Format lists with - bullets. Always use real data from the context above when available."""


def _rule_based_reply(message: str, context: dict) -> str:
    """Context-aware rule-based fallback when no API key is set."""
    msg = message.lower()
    stats            = context.get('stats',            {}) if context else {}
    threats          = context.get('threats',          []) if context else []
    failed_logins    = context.get('failed_logins',     0)
    recent_logins    = context.get('recent_logins',    [])
    quarantine_count = context.get('quarantine_count',  0)
    quarantine_log   = context.get('quarantine_log',   [])
    recent_audit     = context.get('recent_audit',     [])
    users_count      = context.get('users_count',       0)
    users            = context.get('users',            [])
    blockchain_mode  = context.get('blockchain_mode',  'unknown')
    threat_threshold = context.get('threat_threshold',  70)
    email_enabled    = context.get('email_enabled',    False)

    # ── Status / summary / overview ───────────────────────
    if any(w in msg for w in ['status', 'summary', 'current', 'overview', 'situation', 'dashboard', 'report', 'tell me about', 'how is']):
        total   = stats.get('total_scanned',    0)
        active  = stats.get('active_threats',   0)
        medium  = stats.get('medium_threats',   0)
        high    = stats.get('high_risk_alerts', 0)
        health  = stats.get('system_health',    100)
        latest  = threats[0] if threats else None
        out = (
            f"**Current Platform Status**\n\n"
            f"- Total files scanned: **{total}**\n"
            f"- Ransomware detections: **{active}**\n"
            f"- Medium/Suspicious threats: **{medium}**\n"
            f"- High-risk alerts: **{high}**\n"
            f"- System health: **{health}%**\n"
            f"- Quarantined files: **{quarantine_count}**\n"
            f"- Failed login attempts: **{failed_logins}**\n"
            f"- Registered users: **{users_count}**\n"
            f"- Blockchain mode: **{blockchain_mode}**\n"
            f"- Email alerts: **{'enabled' if email_enabled else 'disabled'}**\n\n"
        )
        if latest:
            out += (f"Most recent detection: **{latest['file_name']}** — "
                    f"score {latest['threat_score']:.1f} ({latest['prediction']}) at {latest.get('timestamp','')[:19]}")
        else:
            out += "No detections recorded yet."
        return out

    # ── Failed logins / security / brute force ────────────
    if any(w in msg for w in ['fail', 'failed', 'attempt', 'login', 'brute', 'unauthori', 'credential', 'password', 'auth']):
        out = f"**Login & Authentication Status**\n\n- Failed login attempts recorded: **{failed_logins}**\n"
        if failed_logins > 5:
            out += f"- ⚠️  **{failed_logins} failed attempts** detected — possible brute-force activity!\n"
        if recent_logins:
            out += "\n**Recent login events:**\n"
            for e in recent_logins[:6]:
                icon = '✅' if e.get('action') == 'LOGIN_SUCCESS' else '❌'
                out += f"- {icon} {e.get('username','?')} — {e.get('action','?')} | {e.get('details','')} | {e.get('timestamp','')[:19]}\n"
        else:
            out += "\nNo login activity recorded yet."
        return out

    # ── System health ─────────────────────────────────────
    if any(w in msg for w in ['health', 'system', 'platform', 'uptime', 'operational', 'running', 'performance']):
        health   = stats.get('system_health', 100)
        total    = stats.get('total_scanned', 0)
        active   = stats.get('active_threats', 0)
        status   = '🟢 Healthy' if health >= 80 else ('🟡 Degraded' if health >= 50 else '🔴 Critical')
        return (
            f"**System Health Report**\n\n"
            f"- Health score: **{health}%** — {status}\n"
            f"- Total files scanned: **{total}**\n"
            f"- Active threats: **{active}**\n"
            f"- Quarantined files: **{quarantine_count}**\n"
            f"- Failed login attempts: **{failed_logins}**\n"
            f"- Blockchain mode: **{blockchain_mode}**\n"
            f"- Threat detection threshold: **{threat_threshold}**\n"
            f"- Email alerts: **{'enabled' if email_enabled else 'disabled'}**"
        )

    # ── Quarantine ────────────────────────────────────────
    if any(w in msg for w in ['quarantin', 'isolat', 'locked', 'enc']):
        out = (
            f"**Quarantine Status**\n\n"
            f"- Files currently quarantined: **{quarantine_count}**\n"
            f"- Location: `backend/quarantine/`\n"
            f"- Trigger: score > {threat_threshold} OR ransomware extension (.locked, .enc, .crypto)\n\n"
        )
        if quarantine_log:
            out += "**Recently quarantined:**\n"
            for q in quarantine_log[:5]:
                out += f"- **{q.get('original', q.get('file','?'))}** — score {q.get('score',0):.1f} ({q.get('prediction','?')}) | {q.get('timestamp','')[:19]}\n"
        else:
            out += "No quarantine records yet. Files are quarantined when the threat score exceeds the threshold."
        return out

    # ── Users ─────────────────────────────────────────────
    if any(w in msg for w in ['user', 'account', 'analyst', 'admin', 'role', 'who']):
        out = f"**Platform Users ({users_count} registered)**\n\n"
        if users:
            for u in users:
                out += f"- **{u['username']}** — role: {u['role']}\n"
        out += f"\nFailed login attempts: **{failed_logins}**"
        return out

    # ── Audit log / activity ──────────────────────────────
    if any(w in msg for w in ['audit', 'log', 'activity', 'event', 'history', 'action', 'recent']):
        out = "**Recent Platform Activity**\n\n"
        if recent_audit:
            for e in recent_audit[:8]:
                out += f"- [{e.get('timestamp','')[:19]}] **{e.get('username','?')}**: {e.get('action','?')} — {e.get('details','')}\n"
        else:
            out += "No audit events recorded yet.\n"
        out += f"\n*Failed login attempts today: **{failed_logins}***"
        return out

    # ── Dangerous files ───────────────────────────────────
    if any(w in msg for w in ['dangerous', 'worst', 'highest', 'most', 'top', 'critical']):
        if not threats:
            return "No threats recorded yet."
        top = sorted(threats, key=lambda x: x.get('threat_score', 0), reverse=True)[:5]
        lines = [
            f"- **{t['file_name']}** — score {t['threat_score']:.1f} | {t['prediction']} | {t.get('risk_level','?')} | {t.get('timestamp','')[:19]}"
            for t in top
        ]
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

    # ── Blockchain ────────────────────────────────────────
    if any(w in msg for w in ['blockchain', 'hash', 'chain', 'on-chain', 'verify', 'tx', 'transaction']):
        return (
            f"**Blockchain Integration**\n\n"
            f"- Mode: **{blockchain_mode}** (Core Testnet2, Chain ID 1114)\n"
            f"- Contract: `0x9807Ae60581B38611534d656f6a16AF28B846E17`\n"
            f"- Every HIGH threat is logged as an immutable on-chain transaction\n"
            f"- Function: `logThreatSimple(hash, score, prediction)`\n\n"
            f"To verify: go to the **Blockchain page**, paste the SHA-256 hash of a threat.\n"
            f"Explorer: https://scan.test2.btcs.network"
        )

    # ── Scanned / threats count ───────────────────────────
    if any(w in msg for w in ['how many', 'count', 'total', 'scanned', 'number', 'stat', 'metric']):
        total  = stats.get('total_scanned',    0)
        active = stats.get('active_threats',   0)
        medium = stats.get('medium_threats',   0)
        high   = stats.get('high_risk_alerts', 0)
        health = stats.get('system_health',    100)
        return (
            f"**Platform Metrics**\n\n"
            f"- Total files scanned: **{total}**\n"
            f"- Ransomware detections: **{active}**\n"
            f"- Medium/Suspicious threats: **{medium}**\n"
            f"- High-risk alerts: **{high}**\n"
            f"- System health: **{health}%**\n"
            f"- Quarantined files: **{quarantine_count}**\n"
            f"- Failed login attempts: **{failed_logins}**\n"
            f"- Registered users: **{users_count}**"
        )

    # ── Default ───────────────────────────────────────────
    return (
        "I can help with:\n\n"
        "- **Platform status** — 'give me a full system status'\n"
        "- **Failed logins** — 'how many failed login attempts'\n"
        "- **System health** — 'what is the system health'\n"
        "- **Quarantine** — 'what files are quarantined'\n"
        "- **Users** — 'list all users'\n"
        "- **Audit log** — 'show recent activity'\n"
        "- **Top threats** — 'what are the most dangerous files'\n"
        "- **Model explanation** — 'how does the AI model work'\n"
        "- **SHAP values** — 'explain SHAP'\n"
        "- **Incident response** — 'what should I do about a ransomware'\n"
        "- **Blockchain** — 'how does blockchain logging work'\n\n"
        "💡 Tip: Set `GEMINI_API_KEY` (free at aistudio.google.com) or `GROQ_API_KEY` "
        "(free at console.groq.com) in `.env` to enable full conversational AI."
    )


def _chat_openai(message: str, context: dict, history: list) -> str:
    from openai import OpenAI
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY', '').strip())
    messages = [{'role': 'system', 'content': _build_system_prompt(context)}]
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


def _chat_gemini(message: str, context: dict, history: list) -> str:
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.getenv('GEMINI_API_KEY', '').strip())

    # Build conversation history
    contents = []
    for h in (history or [])[-10:]:
        role = 'user' if h['role'] == 'user' else 'model'
        contents.append(types.Content(role=role, parts=[types.Part(text=h['text'])]))
    contents.append(types.Content(role='user', parts=[types.Part(text=message)]))

    response = client.models.generate_content(
        model='gemini-2.0-flash',
        contents=contents,
        config=types.GenerateContentConfig(
            system_instruction=_build_system_prompt(context),
            max_output_tokens=600,
            temperature=0.4
        )
    )
    return response.text


def _chat_groq(message: str, context: dict, history: list) -> str:
    from groq import Groq
    client = Groq(api_key=os.getenv('GROQ_API_KEY', '').strip())
    messages = [{'role': 'system', 'content': _build_system_prompt(context)}]
    for h in (history or [])[-10:]:
        messages.append({'role': h['role'], 'content': h['text']})
    messages.append({'role': 'user', 'content': message})
    response = client.chat.completions.create(
        model='llama-3.3-70b-versatile',
        messages=messages,
        max_tokens=600,
        temperature=0.4
    )
    return response.choices[0].message.content


def chat(message: str, context: dict = None, history: list = None) -> str:
    """
    Main entry point.  Tries providers in order: OpenAI → Gemini → Groq → rule-based.
    """
    context = context or {}
    history = history or []

    providers = [
        ('openai',  os.getenv('OPENAI_API_KEY',  '').strip(), _chat_openai),
        ('gemini',  os.getenv('GEMINI_API_KEY',  '').strip(), _chat_gemini),
        ('groq',    os.getenv('GROQ_API_KEY',    '').strip(), _chat_groq),
    ]

    last_error = None
    for name, key, fn in providers:
        if not key:
            continue
        try:
            return fn(message, context, history)
        except ImportError:
            continue          # package not installed — try next
        except Exception as e:
            last_error = (name, e)
            continue          # API error (quota, auth, …) — try next

    # All providers failed or none configured — use rule-based engine
    # Don't surface noisy API errors (quota, auth) to the user; fallback handles it cleanly
    return _rule_based_reply(message, context)

