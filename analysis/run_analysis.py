# analysis/run_analysis.py
from db.query_helpers import get_all_ports
from analysis.vuln_mapper import map_vulns
from api.shodan_epss_report import fetch_epss_scores
from analysis.save_vulns import save_vulns

def run_analysis():
    ports = get_all_ports()
    candidates = map_vulns(ports)

    # EPSS 점수 부여
    for c in candidates:
        if c["cve_id"] and c["cve_id"] != "NONE":
            scores = fetch_epss_scores([c["cve_id"]])
            c["epss"] = scores.get(c["cve_id"], {}).get("epss", 0.0)
        else:
            c["epss"] = 0.0

    save_vulns(candidates)

if __name__ == "__main__":
    run_analysis()
