# analysis/shodan_epss_report.py
"""
EPSS API 클라이언트 모듈.
FIRST.org EPSS API 에서 CVE 리스트에 대한 점수를 조회한다.

필요 패키지:
    pip install requests
"""

from typing import List, Dict
import requests

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_scores(cve_list: List[str]) -> Dict[str, Dict[str, float]]:
    """
    EPSS API 로 CVE 리스트 점수 조회.
    return 형식:
        {
          "CVE-2023-12345": {"epss": 0.1234, "percentile": 0.9876},
          ...
        }
    """
    if not cve_list:
        return {}

    # 중복 제거 + 정렬 후 comma-separated 로 전달
    params = {
        "cve": ",".join(sorted(set(cve_list)))
    }

    resp = requests.get(EPSS_BASE_URL, params=params, timeout=15)
    resp.raise_for_status()

    data = resp.json().get("data", [])

    result: Dict[str, Dict[str, float]] = {}
    for item in data:
        cve = item.get("cve")
        if not cve:
            continue
        try:
            epss = float(item.get("epss", 0.0))
            percentile = float(item.get("percentile", 0.0))
        except (TypeError, ValueError):
            epss, percentile = 0.0, 0.0

        result[cve] = {
            "epss": epss,
            "percentile": percentile,
        }

    return result
