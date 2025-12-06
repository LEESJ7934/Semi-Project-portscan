# analysis/analysis_report.py
import textwrap
from datetime import datetime
from pathlib import Path
from reportlab.pdfgen import canvas

from db.db_client import get_connection
from api.shodan_epss_report import fetch_epss_scores


def _row(row, key, idx):
    return row[key] if isinstance(row, dict) else row[idx]


def get_vulns(ip: str):
    sql = """
    SELECT h.host_ip, p.port, p.protocol, v.cve_id, v.title, v.severity, v.epss, v.source
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
            "epss_db": float(_row(r, "epss", 6) or 0.0),
            "source": _row(r, "source", 7),
        })
    return results


def draw_text(c, text, x, y, width=95, lh=14):
    c.setFont("Helvetica", 10)
    for line in text.split("\n"):
        for part in textwrap.wrap(line, width):
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = 800
            c.drawString(x, y, part)
            y -= lh
    return y


def generate_analysis_pdf(ip: str, output="reports/analysis_report.pdf"):
    Path(output).parent.mkdir(exist_ok=True)
    vulns = get_vulns(ip)

    cves = [v["cve_id"] for v in vulns if v["cve_id"] and v["cve_id"] != "NONE"]
    epss_scores = fetch_epss_scores(cves)

    c = canvas.Canvas(output)
    y = 800

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, f"EPSS / Vulnerability Analysis - {ip}")
    y -= 40

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Generated: {datetime.utcnow().isoformat()}Z")
    y -= 30

    # EPSS Section
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "[1] EPSS Scores")
    y -= 25

    if epss_scores:
        lines = ["CVE | EPSS | Percentile"]
        for cve, data in epss_scores.items():
            lines.append(f"{cve} | {data['epss']:.4f} | {data['percentile']:.4f}")
        y = draw_text(c, "\n".join(lines), 60, y)
    else:
        y = draw_text(c, "No EPSS data.", 60, y)

    # Vulns Section
    c.showPage()
    y = 800
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "[2] Vulnerabilities from DB")
    y -= 25

    if vulns:
        lines = []
        for v in vulns:
            lines.append(
                f"{v['port']}/{v['protocol']} | {v['cve_id']} | "
                f"{v['severity']} | {v['epss_db']:.4f} | {v['title']} | {v['source']}"
            )
        y = draw_text(c, "\n".join(lines), 60, y)
    else:
        y = draw_text(c, "No vulnerabilities.", 60, y)

    c.save()
    print(f"[+] Analysis PDF saved to {output}")
    return output
