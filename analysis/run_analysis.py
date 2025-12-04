# analysis/run_analysis.py
from db.query_helpers import get_all_ports
from analysis.vuln_mapper import map_vulns
from analysis.epss_client import get_epss_score
from analysis.save_vulns import save_vulns

def run_analysis():
    # 1. DB에서 모든 port 레코드 가져오기
    ports = get_all_ports()
    # 2. 룰 기반 취약점 매핑
    candidates = map_vulns(ports)

    # 3. EPSS 점수 부여
    for c in candidates:
        c["epss"] = get_epss_score(c["cve_id"])

    # 4. DB 저장
    save_vulns(candidates)

if __name__ == "__main__":
    run_analysis()
