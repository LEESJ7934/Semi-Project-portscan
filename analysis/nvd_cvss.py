# analysis/nvd_cvss.py
import requests

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss_score(cve_id: str) -> float:
    """
    NVD API에서 CVSS Base Score를 가져온다.
    성공/실패 여부를 print로 출력하여 디버깅 쉽게 만듦.
    """

    print(f"[NVD] 요청 시작 → CVE: {cve_id}")

    if not cve_id or cve_id == "NONE":
        print(f"[NVD] CVE 없음 → 기본값 0.0 반환")
        return 0.0

    params = {"cveId": cve_id}

    try:
        resp = requests.get(NVD_BASE_URL, params=params, timeout=10)
        print(f"[NVD] HTTP 응답 코드: {resp.status_code}")

        resp.raise_for_status()
        data = resp.json()

        items = data.get("vulnerabilities", [])
        if not items:
            print(f"[NVD] vulnerabilities 항목 없음 → 0.0 반환")
            return 0.0

        metrics = items[0].get("cve", {}).get("metrics", {})

        # CVSS 3.1
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            print(f"[NVD] CVSS v3.1 score 획득: {score}")
            return float(score)

        # CVSS 3.0
        if "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            print(f"[NVD] CVSS v3.0 score 획득: {score}")
            return float(score)

        # CVSS 2.0
        if "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            print(f"[NVD] CVSS v2 score 획득: {score}")
            return float(score)

        print(f"[NVD] metrics에 CVSS 정보 없음 → 0.0 반환")

    except Exception as e:
        print(f"[NVD] API 요청 실패: {e} → 0.0 반환")
        return 0.0

    print("[NVD] 모든 조건 불충족 → 0.0 반환")
    return 0.0
