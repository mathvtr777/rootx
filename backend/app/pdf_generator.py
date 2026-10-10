"""
Gerador de PDF para relatórios (usando reportlab, sem deps nativas)
"""
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER


# Cores do tema
RED = colors.HexColor("#ef4444")
DARK = colors.HexColor("#1a1a1a")
GRAY = colors.HexColor("#666666")
LIGHT_GRAY = colors.HexColor("#fafafa")
BORDER = colors.HexColor("#e5e5e5")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#3b82f6"),
    "info": colors.HexColor("#6b7280"),
}

HEADER_LABELS = {
    "strict_transport_security": ("HSTS", "Strict-Transport-Security"),
    "content_security_policy": ("CSP", "Content-Security-Policy"),
    "x_frame_options": ("X-Frame-Options", "Proteção contra clickjacking"),
    "x_content_type_options": ("X-Content-Type-Options", "Previne MIME sniffing"),
    "x_xss_protection": ("X-XSS-Protection", "Filtro XSS do browser"),
    "referrer_policy": ("Referrer-Policy", "Controle de referrer"),
    "permissions_policy": ("Permissions-Policy", "Permissões de features"),
}

RISK_LABELS = {
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
}

MODES = {
    "quick": "Rápido (30s)",
    "full": "Profissional (3min)",
    "aggressive": "Completo (10min)",
}


def _get_score_color(score):
    if score >= 70:
        return colors.HexColor("#10b981")
    if score >= 50:
        return colors.HexColor("#eab308")
    if score >= 25:
        return colors.HexColor("#f97316")
    return colors.HexColor("#ef4444")


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        name="NF_Title", parent=ss["Title"], fontSize=22, textColor=DARK,
        spaceAfter=4, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        name="NF_H2", parent=ss["Heading2"], fontSize=14, textColor=DARK,
        spaceBefore=16, spaceAfter=8, borderPadding=4,
        borderWidth=0, borderColor=BORDER,
    ))
    ss.add(ParagraphStyle(
        name="NF_Body", parent=ss["BodyText"], fontSize=10, textColor=DARK,
        leading=14, alignment=TA_LEFT,
    ))
    ss.add(ParagraphStyle(
        name="NF_Mono", parent=ss["BodyText"], fontName="Courier", fontSize=9,
        textColor=GRAY, leading=12,
    ))
    ss.add(ParagraphStyle(
        name="NF_Footer", parent=ss["BodyText"], fontSize=8, textColor=colors.HexColor("#999"),
        alignment=TA_CENTER,
    ))
    return ss


def _build_header(scan, styles):
    elements = []
    # Logo + título
    header_data = [[
        Paragraph('<font color="#ef4444" size="16"><b>▼ SECURITY SCAN</b></font>', styles["NF_Body"]),
        Paragraph(
            f'<font size="9" color="#666">'
            f'Scan ID: <b>{scan.get("scan_id", "?")}</b><br/>'
            f'Gerado: {datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")}<br/>'
            f'Duração: {_format_duration(scan.get("duration_seconds", 0))}'
            f'</font>',
            styles["NF_Body"]
        ),
    ]]
    t = Table(header_data, colWidths=[12 * cm, 6 * cm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 2, RED),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Relatório de Segurança", styles["NF_Title"]))
    elements.append(Paragraph(scan.get("url", "--"), styles["NF_Mono"]))
    return elements


def _format_duration(seconds):
    try:
        seconds = float(seconds or 0)
    except (TypeError, ValueError):
        return "--"
    if seconds >= 60:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds)}s"


def _build_score_box(scan, summary, styles):
    elements = []
    score = scan.get("score", 0) or 0
    score_color = _get_score_color(score)
    risk_level = summary.get("risk_level", "medium")
    scan_type = summary.get("scan_mode", scan.get("scan_type", "quick"))

    score_cell = Table(
        [[Paragraph(f'<font size="32" color="{score_color.hexval()}"><b>{score}</b></font>', styles["NF_Body"])]],
        colWidths=[3 * cm], rowHeights=[3 * cm],
    )
    score_cell.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 2, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
    ]))

    info_text = (
        f'<font size="14"><b>{scan.get("classification", "--")}</b></font><br/>'
        f'<font size="9" color="#666">Nível de risco: <b>{RISK_LABELS.get(risk_level, risk_level)}</b><br/>'
        f'Modo de scan: <b>{MODES.get(scan_type, scan_type)}</b></font>'
    )

    main = Table(
        [[score_cell, Paragraph(info_text, styles["NF_Body"])]],
        colWidths=[3.5 * cm, 14 * cm],
    )
    main.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 16),
    ]))
    elements.append(main)
    return elements


def _build_metrics(scan, findings, technologies, styles):
    elements = []
    elements.append(Paragraph("Métricas", styles["NF_H2"]))

    data = [[
        Paragraph(f'<font size="20"><b>{len(findings)}</b></font><br/><font size="8" color="#666">VULNS</font>', styles["NF_Body"]),
        Paragraph(f'<font size="20"><b>{scan.get("subdomains", 0) or 0}</b></font><br/><font size="8" color="#666">SUBDOMÍNIOS</font>', styles["NF_Body"]),
        Paragraph(f'<font size="20"><b>{scan.get("endpoints", 0) or 0}</b></font><br/><font size="8" color="#666">ENDPOINTS</font>', styles["NF_Body"]),
        Paragraph(f'<font size="20"><b>{len(technologies)}</b></font><br/><font size="8" color="#666">TECNOLOGIAS</font>', styles["NF_Body"]),
    ]]
    t = Table(data, colWidths=[4.4 * cm] * 4, rowHeights=[2 * cm])
    t.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 1, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 1, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
    ]))
    elements.append(t)
    return elements


def _build_severity(summary, styles):
    elements = []
    elements.append(Paragraph("Distribuição por Severidade", styles["NF_H2"]))

    counts = (summary.get("severity_counts", {}) or {})
    total = sum(counts.get(s, 0) or 0 for s in ["critical", "high", "medium", "low"]) or 1

    rows = []
    for sev, label in [("critical", "Crítico"), ("high", "Alto"), ("medium", "Médio"), ("low", "Baixo")]:
        count = counts.get(sev, 0) or 0
        pct = (count / total) * 100

        bar_html = (
            f'<font size="9" color="#666">{label}</font>'
            f'<para leftindent="0" spacebefore="2" spaceafter="2">'
            f'<font color="{SEVERITY_COLORS[sev].hexval()}">'
            f'{"█" * max(1, int(pct / 5)) if count > 0 else ""}'
            f'</font>'
            f'</para>'
        )
        rows.append([
            Paragraph(label, styles["NF_Body"]),
            Paragraph(bar_html, styles["NF_Body"]),
            Paragraph(f'<b>{count}</b>', styles["NF_Body"]),
        ])

    t = Table(rows, colWidths=[3 * cm, 12 * cm, 2 * cm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (2, 0), (2, -1), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t)
    return elements


def _build_technologies(technologies, styles):
    if not technologies:
        return []
    elements = []
    elements.append(Paragraph("Tecnologias Detectadas", styles["NF_H2"]))
    chips = []
    for t in technologies:
        version = f' <font color="#999">{t.get("version", "")}</font>' if t.get("version") else ""
        chips.append(Paragraph(f'<font color="#1a1a1a">{t.get("name", "")}{version}</font>', styles["NF_Body"]))

    # 3 por linha
    rows = []
    for i in range(0, len(chips), 3):
        row = chips[i:i+3]
        while len(row) < 3:
            row.append("")
        rows.append(row)

    t = Table(rows, colWidths=[5.7 * cm] * 3)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    elements.append(t)
    return elements


def _build_headers(headers, styles):
    elements = []
    elements.append(Paragraph("Security Headers", styles["NF_H2"]))

    present = sum(1 for k in HEADER_LABELS if headers.get(k) is True)
    total = len(HEADER_LABELS)
    pct = int((present / total) * 100)

    summary_color = "#10b981" if pct >= 80 else "#eab308" if pct >= 50 else "#ef4444"
    summary_text = (
        f'<font size="10"><b>Headers implementados: </b></font>'
        f'<font size="10" color="{summary_color}"><b>{present}/{total}</b></font>'
    )
    elements.append(Paragraph(summary_text, styles["NF_Body"]))
    elements.append(Spacer(1, 6))

    for key, (name, desc) in HEADER_LABELS.items():
        is_present = headers.get(key) is True
        color = "#10b981" if is_present else "#ef4444"
        symbol = "✓" if is_present else "✗"
        bg = "#f0fdf4" if is_present else "#fef2f2"

        row_html = (
            f'<para backColor="{bg}" borderPadding="4">'
            f'<font color="{color}"><b>{symbol}</b></font>  '
            f'<font color="#1a1a1a"><b>{name}</b></font> '
            f'<font color="#666" size="8">— {desc}</font>'
            f'</para>'
        )
        elements.append(Paragraph(row_html, styles["NF_Body"]))
        elements.append(Spacer(1, 2))
    return elements


def _build_findings(findings, styles):
    elements = []
    elements.append(Paragraph(f"Vulnerabilidades Detectadas ({len(findings)})", styles["NF_H2"]))

    if not findings:
        elements.append(Paragraph('<i>Nenhuma vulnerabilidade encontrada.</i>', styles["NF_Body"]))
        return elements

    for f in findings:
        sev = (f.get("severity", "info") or "info").lower()
        sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        sev_label = sev.upper()
        name = f.get("name", "Vulnerabilidade")
        location = f.get("location", "--")
        description = f.get("description", "")

        content = []
        content.append(Paragraph(
            f'<font backColor="{sev_color.hexval()}" color="#ffffff" size="8">'
            f'<b>&nbsp;{sev_label}&nbsp;</b></font> '
            f'<font size="11" color="#1a1a1a"><b>{name}</b></font>',
            styles["NF_Body"]
        ))
        content.append(Paragraph(location, styles["NF_Mono"]))
        if description:
            # Truncar descrição
            short = description[:300] + ("..." if len(description) > 300 else "")
            content.append(Paragraph(f'<font size="9" color="#444">{short}</font>', styles["NF_Body"]))

        inner = Table([[content]], colWidths=[16 * cm])
        inner.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBEFORE", (0, 0), (0, 0), 3, sev_color),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ]))
        elements.append(KeepTogether(inner))
        elements.append(Spacer(1, 4))
    return elements


def _build_footer():
    return Paragraph(
        "Security Scanner • Use apenas em sistemas que você possui autorização para testar",
        _styles()["NF_Footer"]
    )


def generate_pdf(scan: dict) -> bytes:
    """Gera PDF a partir dos dados do scan. Retorna bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"Security Report - {scan.get('scan_id', '?')}",
        author="Security Scanner",
    )

    summary = scan.get("summary", {}) or {}
    findings = scan.get("findings", []) or []
    technologies = scan.get("technologies", []) or []
    headers = scan.get("security_headers", {}) or {}

    styles = _styles()
    story = []
    story.extend(_build_header(scan, styles))
    story.extend(_build_score_box(scan, summary, styles))
    story.extend(_build_metrics(scan, findings, technologies, styles))
    story.extend(_build_severity(summary, styles))
    story.extend(_build_technologies(technologies, styles))
    story.extend(_build_headers(headers, styles))
    story.append(PageBreak())
    story.extend(_build_findings(findings, styles))
    story.append(Spacer(1, 20))
    story.append(_build_footer())

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
