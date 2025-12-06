# analysis/run_analysis.py
from db.query_helpers import get_all_ports
from analysis.vuln_mapper import map_vulns
from api.shodan_epss_report import fetch_epss_scores
from analysis.nvd_cvss import fetch_cvss_score
from analysis.save_vulns import save_vulns


def calculate_risk(cvss: float, epss: float) -> float:
    """Risk = 0.7 * (CVSS/10) + 0.3 * EPSS"""
    cvss_norm = cvss / 10.0
    return round(0.7 * cvss_norm + 0.3 * epss, 4)


def sanitize(c):
    """DB 저장 전 누락된 필드를 기본값으로 채운다."""
    c.setdefault("cve_id", "NONE")
    c.setdefault("title", "Unknown Vulnerability")
    c.setdefault("severity", "LOW")
    c.setdefault("status", "POTENTIAL")
    c.setdefault("source", c.get("id", "auto_rule"))
    return c


def run_analysis():
    # 1. DB에서 포트 기록 조회
    ports = get_all_ports()

    # 2. 포트 → 취약점 매핑
    candidates = map_vulns(ports)

    # 3. EPSS, CVSS, Risk 계산
    for c in candidates:
        sanitize(c)

        cve = c["cve_id"]

        # EPSS
        if cve != "NONE":
            epss_obj = fetch_epss_scores([cve])
            epss = epss_obj.get(cve, {}).get("epss", 0.0)
        else:
            epss = 0.0

        # CVSS (NVD)
        cvss = fetch_cvss_score(cve)

        # Risk Score
        risk = calculate_risk(cvss, epss)

        # 결과 저장
        c["epss"] = epss
        c["cvss"] = cvss
        c["risk"] = risk

    # 4. DB 저장
    save_vulns(candidates)


if __name__ == "__main__":
    run_analysis()
