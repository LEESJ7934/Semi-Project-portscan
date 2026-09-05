# analysis/analysis_report.py
import textwrap
from datetime import datetime
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from db.db_client import get_connection

# 폰트 제거 버전 (기본 폰트)
DEFAULT_FONT = "Helvetica"


def _row(row, key, idx):
    return row[key] if isinstance(row, dict) else row[idx]


def get_vulns(ip: str):
    sql = """
    SELECT 
        h.host_ip, 
        p.port, 
        p.protocol, 
        v.cve_id, 
        v.title, 
        v.severity, 
        v.epss,
        v.cvss,
        v.risk,
        v.source,
        v.status
    FROM vulns v
    JOIN ports p ON v.port_id = p.id
    JOIN hosts h ON p.host_id = h.id
    WHERE h.host_ip = %s
    ORDER BY p.port, v.cve_id;
    """
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute(sql, (ip,))
        rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "host_ip": _row(r, "host_ip", 0),
            "port": _row(r, "port", 1),
            "protocol": _row(r, "protocol", 2),
            "cve_id": _row(r, "cve_id", 3),
            "title": _row(r, "title", 4),
            "severity": _row(r, "severity", 5),
            "epss": float(_row(r, "epss", 6)) if _row(r, "epss", 6) is not None else None,
            "cvss": float(_row(r, "cvss", 7)) if _row(r, "cvss", 7) is not None else None,
            "risk": float(_row(r, "risk", 8)) if _row(r, "risk", 8) is not None else None,
            "source": _row(r, "source", 9),
            "status": _row(r, "status", 10),
        })
    return results


def format_score(value, digits):
    return "N/A" if value is None else f"{value:.{digits}f}"


def draw_text(c, text, x, y, width=95, lh=14, font=DEFAULT_FONT):
    c.setFont(font, 10)
    for line in text.split("\n"):
        for part in textwrap.wrap(line, width):
            if y < 50:
                c.showPage()
                c.setFont(font, 10)
                y = 800
            c.drawString(x, y, part)
            y -= lh
    return y


def generate_analysis_pdf(ip: str, output="reports/analysis_report.pdf"):
    Path(output).parent.mkdir(exist_ok=True)
    vulns = get_vulns(ip)

    c = canvas.Canvas(output)
    y = 800

    # Title
    c.setFont(DEFAULT_FONT, 18)
    c.drawString(50, y, f"EPSS / CVSS / Risk Analysis - {ip}")
    y -= 40

    c.setFont(DEFAULT_FONT, 10)
    c.drawString(50, y, f"Generated: {datetime.utcnow().isoformat()}Z")
    y -= 30

    c.setFont(DEFAULT_FONT, 14)
    c.drawString(50, y, "[1] Vulnerability Analysis (EPSS + CVSS + Risk)")
    y -= 25

    if vulns:
        lines = ["Port/Proto | CVE | Status | Severity | EPSS | CVSS | Risk | Title | Source"]
        for v in vulns:
            lines.append(
                f"{v['port']}/{v['protocol']} | "
                f"{v['cve_id']} | "
                f"{v['status']} | "
                f"{v['severity']} | "
                f"{format_score(v['epss'], 4)} | "
                f"{format_score(v['cvss'], 1)} | "
                f"{format_score(v['risk'], 4)} | "
                f"{v['title']} | "
                f"{v['source']}"
            )

        y = draw_text(c, "\n".join(lines), 60, y)

    else:
        y = draw_text(c, "No stored candidates for this selection; this does not establish security.", 60, y)

    c.save()
    print(f"[+] Analysis PDF saved to {output}")
    return output
