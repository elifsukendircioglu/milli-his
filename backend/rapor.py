from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm


def tr(text):
    if not text:
        return ""
    text = str(text)
    replacements = {
        'ı': 'i', 'İ': 'I', 'ğ': 'g', 'Ğ': 'G',
        'ü': 'u', 'Ü': 'U', 'ş': 's', 'Ş': 'S',
        'ö': 'o', 'Ö': 'O', 'ç': 'c', 'Ç': 'C',
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text


def severity_color(sev):
    mapping = {
        "critical": colors.HexColor("#b91c1c"),
        "high":     colors.HexColor("#c2410c"),
        "medium":   colors.HexColor("#a16207"),
        "low":      colors.HexColor("#15803d"),
        "unknown":  colors.HexColor("#6b7280"),
    }
    return mapping.get(sev.lower(), colors.HexColor("#6b7280"))


def severity_bg(sev):
    mapping = {
        "critical": colors.HexColor("#fee2e2"),
        "high":     colors.HexColor("#ffedd5"),
        "medium":   colors.HexColor("#fef9c3"),
        "low":      colors.HexColor("#dcfce7"),
        "unknown":  colors.HexColor("#f3f4f6"),
    }
    return mapping.get(sev.lower(), colors.HexColor("#f3f4f6"))


def create_pdf(scan_data, filepath):
    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()

    style_title = ParagraphStyle(
        "title", parent=styles["Normal"],
        fontSize=22, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e3a5f"), spaceAfter=6,
    )
    style_subtitle = ParagraphStyle(
        "subtitle", parent=styles["Normal"],
        fontSize=11, fontName="Helvetica",
        textColor=colors.HexColor("#6b7280"), spaceAfter=4,
    )
    style_section = ParagraphStyle(
        "section", parent=styles["Normal"],
        fontSize=13, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e3a5f"),
        spaceBefore=14, spaceAfter=6,
    )
    style_body = ParagraphStyle(
        "body", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#374151"),
        spaceAfter=3, leading=13,
    )
    style_cve_id = ParagraphStyle(
        "cve_id", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1d4ed8"),
    )
    style_desc = ParagraphStyle(
        "desc", parent=styles["Normal"],
        fontSize=8, fontName="Helvetica",
        textColor=colors.HexColor("#4b5563"), leading=12,
    )
    style_footer = ParagraphStyle(
        "footer", parent=styles["Normal"],
        fontName="Helvetica", fontSize=7,
        textColor=colors.HexColor("#9ca3af"), alignment=1,
    )

    elements = []

    # ── Başlık ──
    elements.append(Paragraph("Milli HIS", style_title))
    elements.append(Paragraph(tr("Yerli Zafiyet Tarama Sistemi - Tarama Raporu"), style_subtitle))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1e3a5f"), spaceAfter=10))

    result = scan_data.get("result", {})
    target = result.get("target", scan_data.get("target", "-"))
    risk_score = scan_data.get("risk_score", 0)
    scanned_at = scan_data.get("scanned_at", "-")

    # hosts: list veya dict olabilir, ikisini de destekle
    hosts_raw = result.get("hosts", [])
    if isinstance(hosts_raw, dict):
        hosts_list = list(hosts_raw.values())
    elif isinstance(hosts_raw, list):
        hosts_list = hosts_raw
    else:
        hosts_list = []

    total_ports = sum(len(h.get("ports", [])) for h in hosts_list)
    total_cves = sum(
        len(p.get("cves", []))
        for h in hosts_list
        for p in h.get("ports", [])
    )
    critical_count = sum(
        1
        for h in hosts_list
        for p in h.get("ports", [])
        for c in p.get("cves", [])
        if c.get("severity", "").lower() == "critical"
    )

    summary_data = [
        [tr("Hedef"),             tr(target)],
        [tr("Tarama Tarihi"),     tr(scanned_at)],
        [tr("Risk Skoru"),        f"{risk_score:.1f} / 10"],
        [tr("Bulunan Cihaz"),     str(len(hosts_list))],
        [tr("Toplam Acik Port"),  str(total_ports)],
        [tr("Toplam CVE"),        str(total_cves)],
        [tr("Critical CVE"),      str(critical_count)],
    ]

    summary_table = Table(summary_data, colWidths=[4*cm, 12*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (0, -1), colors.HexColor("#e8f0fe")),
        ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",       (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE",       (0, 0), (-1, -1), 9),
        ("TEXTCOLOR",      (0, 0), (0, -1), colors.HexColor("#1e3a5f")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("BOX",            (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID",      (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    elements.append(Paragraph(tr("Tarama Detaylari"), style_section))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    if not hosts_list:
        elements.append(Paragraph(tr("Hicbir cihaz bulunamadi."), style_body))
    else:
        for host in hosts_list:
            ip = host.get("ip", "-")
            hostname = host.get("hostname", "")
            ports = host.get("ports", [])
            host_risk = host.get("risk_score", 0)

            # IP başlık satırı
            ip_label = f"{ip}"
            if hostname:
                ip_label += f"  ({hostname})"

            host_header_data = [[
                Paragraph(tr(ip_label), ParagraphStyle(
                    "hip", fontName="Helvetica-Bold", fontSize=11,
                    textColor=colors.white,
                )),
                Paragraph(f"{len(ports)} acik port", ParagraphStyle(
                    "hpc", fontName="Helvetica", fontSize=9,
                    textColor=colors.HexColor("#bfdbfe"),
                )),
                Paragraph(f"Risk: {host_risk:.1f} / 10", ParagraphStyle(
                    "hri", fontName="Helvetica-Bold", fontSize=9,
                    textColor=colors.white,
                )),
            ]]
            host_header_table = Table(host_header_data, colWidths=[7*cm, 5*cm, 4*cm])
            host_header_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#1e3a5f")),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ]))
            elements.append(host_header_table)

            if not ports:
                no_port_data = [[Paragraph(tr("Bu cihazda acik port bulunamadi."), ParagraphStyle(
                    "np", fontName="Helvetica", fontSize=9,
                    textColor=colors.HexColor("#6b7280"),
                ))]]
                no_port_table = Table(no_port_data, colWidths=[16*cm])
                no_port_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
                    ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ]))
                elements.append(no_port_table)
                elements.append(Spacer(1, 10))
                continue

            for p in ports:
                port_num  = p.get("port", "-")
                service   = tr(p.get("service", "-"))
                version   = tr(p.get("version", "-") or "-")
                cves      = p.get("cves", [])
                port_risk = p.get("risk_score", 0)

                port_header_data = [[
                    Paragraph(f"Port {port_num}", ParagraphStyle(
                        "ph", fontName="Helvetica-Bold", fontSize=10, textColor=colors.white,
                    )),
                    Paragraph(service, ParagraphStyle(
                        "ps", fontName="Helvetica-Bold", fontSize=10, textColor=colors.white,
                    )),
                    Paragraph(f"Versiyon: {version}", ParagraphStyle(
                        "pv", fontName="Helvetica", fontSize=9,
                        textColor=colors.HexColor("#bfdbfe"),
                    )),
                    Paragraph(f"Risk: {port_risk:.1f}", ParagraphStyle(
                        "pr", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white,
                    )),
                ]]
                port_header_table = Table(port_header_data, colWidths=[2.5*cm, 4*cm, 7*cm, 2.5*cm])
                port_header_table.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#334155")),
                    ("TOPPADDING",    (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ]))
                elements.append(port_header_table)

                if not cves:
                    no_cve_data = [[Paragraph(tr("✓ Bu port icin zafiyet bulunamadi."), ParagraphStyle(
                        "nc", fontName="Helvetica", fontSize=9,
                        textColor=colors.HexColor("#15803d"),
                    ))]]
                    no_cve_table = Table(no_cve_data, colWidths=[16*cm])
                    no_cve_table.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#86efac")),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                    ]))
                    elements.append(no_cve_table)
                else:
                    cve_table_data = [[
                        Paragraph("CVE ID", ParagraphStyle(
                            "th", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
                        )),
                        Paragraph(tr("Derece"), ParagraphStyle(
                            "th2", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
                        )),
                        Paragraph("CVSS", ParagraphStyle(
                            "th3", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
                        )),
                        Paragraph(tr("Aciklama"), ParagraphStyle(
                            "th4", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white,
                        )),
                    ]]

                    row_bg = []
                    for i, c in enumerate(cves):
                        sev = c.get("severity", "Unknown")
                        cve_table_data.append([
                            Paragraph(tr(c.get("id", "-")), style_cve_id),
                            Paragraph(tr(sev), ParagraphStyle(
                                f"sev{i}", fontName="Helvetica-Bold", fontSize=8,
                                textColor=severity_color(sev),
                            )),
                            Paragraph(str(c.get("cvss_score", "-")), style_body),
                            Paragraph(tr(c.get("description", "-")[:200]), style_desc),
                        ])
                        row_bg.append(("BACKGROUND", (0, i+1), (-1, i+1), severity_bg(sev)))

                    cve_table = Table(cve_table_data, colWidths=[2.8*cm, 2*cm, 1.5*cm, 9.7*cm])
                    cve_table.setStyle(TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#334155")),
                        ("BOX",           (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID",     (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                    ] + row_bg))
                    elements.append(cve_table)

            elements.append(Spacer(1, 16))

    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1")))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        tr("Bu rapor Milli HIS tarafindan otomatik olarak olusturulmustur. Gizlilik derecesi: Dahili Kullanim."),
        style_footer,
    ))

    doc.build(elements)