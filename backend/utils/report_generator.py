import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')

# ── Color Palette ─────────────────────────────────────────
BLACK      = colors.HexColor('#000000')
DARK_GRAY  = colors.HexColor('#111111')
NEON_BLUE  = colors.HexColor('#00d4ff')
NEON_RED   = colors.HexColor('#ff003c')
NEON_GREEN = colors.HexColor('#00ff88')
WHITE      = colors.white
GRAY       = colors.HexColor('#888888')


def get_risk_color(score):
    if score > 70:   return NEON_RED
    if score > 30:   return colors.HexColor('#ffaa00')
    return NEON_GREEN


def generate_report(threat_data: dict) -> str:
    """Generate a PDF incident report and return file path."""
    os.makedirs(REPORTS_DIR, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename  = f"incident_report_{timestamp}.pdf"
    filepath  = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=40, leftMargin=40,
        topMargin=40,   bottomMargin=40
    )

    styles  = getSampleStyleSheet()
    story   = []

    # ── Custom Styles ─────────────────────────────────────
    title_style = ParagraphStyle('Title',
        fontSize=22, textColor=NEON_BLUE,
        alignment=TA_CENTER, fontName='Helvetica-Bold',
        spaceAfter=4)

    subtitle_style = ParagraphStyle('Subtitle',
        fontSize=10, textColor=GRAY,
        alignment=TA_CENTER, spaceAfter=20)

    section_style = ParagraphStyle('Section',
        fontSize=12, textColor=NEON_BLUE,
        fontName='Helvetica-Bold', spaceAfter=8, spaceBefore=16)

    body_style = ParagraphStyle('Body',
        fontSize=9, textColor=colors.HexColor('#cccccc'),
        spaceAfter=4, leading=14)

    # ── Header ────────────────────────────────────────────
    story.append(Paragraph("🛡️ CYBERDEFENSE AI", title_style))
    story.append(Paragraph("INCIDENT REPORT — RANSOMWARE DETECTION SYSTEM", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=NEON_BLUE))
    story.append(Spacer(1, 12))

    # ── Report Metadata ───────────────────────────────────
    score      = threat_data.get('threat_score', 0)
    prediction = threat_data.get('prediction', 'Unknown')
    risk_level = threat_data.get('risk_level', 'UNKNOWN')
    risk_color = get_risk_color(score)

    meta_data = [
        ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['File Analyzed',    threat_data.get('file_name', 'unknown')],
        ['Analyst',          'CyberDefense AI System'],
        ['Report ID',        f"CDR-{timestamp}"],
    ]
    meta_table = Table(meta_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (0, -1), colors.HexColor('#111111')),
        ('TEXTCOLOR',   (0, 0), (0, -1), NEON_BLUE),
        ('TEXTCOLOR',   (1, 0), (1, -1), WHITE),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1),
            [colors.HexColor('#0a0a0a'), colors.HexColor('#111111')]),
        ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#222222')),
        ('PADDING',     (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ── Threat Summary ────────────────────────────────────
    story.append(Paragraph("1. INCIDENT SUMMARY", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#333333')))
    story.append(Spacer(1, 8))

    summary_data = [
        ['THREAT SCORE',   f"{score} / 100"],
        ['RISK LEVEL',     risk_level],
        ['PREDICTION',     prediction],
        ['ML CONFIDENCE',  f"{threat_data.get('ml_confidence', 0)}%"],
        ['DL CONFIDENCE',  f"{threat_data.get('dl_confidence', 0)}%"],
        ['TIMESTAMP',      threat_data.get('timestamp', 'N/A')[:19]],
    ]
    summary_table = Table(summary_data, colWidths=[200, 300])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (0, -1), colors.HexColor('#111111')),
        ('TEXTCOLOR',   (0, 0), (0, -1), GRAY),
        ('TEXTCOLOR',   (1, 0), (1, -1), WHITE),
        ('FONTSIZE',    (0, 0), (-1, -1), 10),
        ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR',   (1, 0), (1, 0), risk_color),
        ('FONTNAME',    (1, 0), (1, 1), 'Helvetica-Bold'),
        ('FONTSIZE',    (1, 0), (1, 0), 16),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1),
            [colors.HexColor('#0a0a0a'), colors.HexColor('#111111')]),
        ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#222222')),
        ('PADDING',     (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # ── Top Features ──────────────────────────────────────
    story.append(Paragraph("2. TOP THREAT INDICATORS", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#333333')))
    story.append(Spacer(1, 8))

    top_features = threat_data.get('top_features', [])
    feat_data    = [['#', 'FEATURE', 'IMPACT']]
    impacts      = ['HIGH', 'HIGH', 'MEDIUM']
    for i, feat in enumerate(top_features[:3]):
        feat_data.append([str(i+1), feat, impacts[i] if i < len(impacts) else 'LOW'])

    feat_table = Table(feat_data, colWidths=[40, 360, 100])
    feat_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#001a2e')),
        ('TEXTCOLOR',   (0, 0), (-1, 0), NEON_BLUE),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',   (0, 1), (-1, -1), WHITE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
            [colors.HexColor('#0a0a0a'), colors.HexColor('#111111')]),
        ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#222222')),
        ('PADDING',     (0, 0), (-1, -1), 8),
        ('ALIGN',       (0, 0), (0, -1), 'CENTER'),
        ('TEXTCOLOR',   (2, 1), (2, 1), NEON_RED),
        ('TEXTCOLOR',   (2, 2), (2, 2), NEON_RED),
        ('TEXTCOLOR',   (2, 3), (2, 3), colors.HexColor('#ffaa00')),
    ]))
    story.append(feat_table)
    story.append(Spacer(1, 16))

    # ── Blockchain Hash ───────────────────────────────────
    story.append(Paragraph("3. BLOCKCHAIN INTEGRITY LOG", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#333333')))
    story.append(Spacer(1, 8))

    hash_val = threat_data.get('hash', 'Not available')
    story.append(Paragraph(
        f"SHA-256 Hash (tamper-proof): <font color='#00d4ff'>{hash_val}</font>",
        body_style))
    story.append(Paragraph(
        "This hash is stored on the blockchain to ensure the integrity of this incident record.",
        body_style))
    story.append(Spacer(1, 16))

    # ── Mitigation ────────────────────────────────────────
    story.append(Paragraph("4. MITIGATION RECOMMENDATIONS", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#333333')))
    story.append(Spacer(1, 8))

    if score > 70:
        recommendations = [
            "🔒 IMMEDIATE: Isolate affected system from network",
            "🔒 IMMEDIATE: Move file to quarantine — do not execute",
            "🔒 IMMEDIATE: Notify SOC team and incident response",
            "📋 SHORT TERM: Run full system scan with updated signatures",
            "📋 SHORT TERM: Review system logs for lateral movement",
            "📋 SHORT TERM: Check backup integrity before restoration",
            "🔄 LONG TERM: Patch all vulnerable software",
            "🔄 LONG TERM: Implement application whitelisting",
        ]
    elif score > 30:
        recommendations = [
            "⚠️  Monitor file behavior closely for 24 hours",
            "⚠️  Run secondary scan with different AV engine",
            "📋 Review file origin and download source",
            "📋 Check file digital signature validity",
            "🔄 Update threat detection signatures",
        ]
    else:
        recommendations = [
            "✅ File appears safe based on current analysis",
            "📋 Continue standard monitoring procedures",
            "🔄 Keep detection models updated regularly",
        ]

    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", body_style))

    story.append(Spacer(1, 20))

    # ── Footer ────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=NEON_BLUE))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Generated by CyberDefense AI Platform — AI-Powered Zero-Day Ransomware Detection",
        ParagraphStyle('Footer', fontSize=8, textColor=GRAY, alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f"✅ Report generated: {filepath}")
    return filepath