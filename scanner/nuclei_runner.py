# scanner/nuclei_runner.py

import subprocess
import json
import os
import logging
import requests
from .auth import get_dvwa_cookie  # 로그인 모듈

# 경로 설정
NUCLEI_PATH = os.path.join(os.getcwd(), "bin", "nuclei.exe")


def get_epss_score(cve_id: str) -> float:
    """FIRST.org API에서 EPSS(공격 확률) 조회"""
    if not cve_id or not cve_id.lower().startswith("cve-"):
        return 0.0
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return float(data["data"][0].get("epss", 0.0))
    except Exception:
        pass
    return 0.0


def get_cvss_score(cve_id: str) -> float:
    """[Phase 7] NVD API에서 CVSS(기술적 심각성) 점수 조회"""
    if not cve_id:
        return 0.0
    try:
        # NVD API 2.0 사용
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
                metrics = data["vulnerabilities"][0]["cve"]["metrics"]
                # CVSS v3.1 우선, 없으면 v2
                if "cvssMetricV31" in metrics:
                    return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except Exception:
        pass
    return 0.0


def calculate_real_risk(severity: str, cvss: float, epss: float) -> str:
    """[Phase 7] 통합 리스크 산정 로직"""
    # 1. CVSS 점수가 있으면 그걸 우선, 없으면 Nuclei Severity 텍스트 기반
    sev_level = severity.lower()

    if cvss > 0:
        base_score = cvss
    else:
        # 텍스트를 점수로 환산 (Fallback)
        base_score = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 2.0}.get(
            sev_level, 0
        )

    # 2. Risk Matrix (점수 x 확률)
    if base_score >= 9.0 and epss >= 0.1:
        return "CRITICAL (Emergency Patch)"
    elif base_score >= 7.0 and epss >= 0.2:
        return "High (Priority)"
    elif base_score >= 7.0:
        return "High (Monitor)"
    elif sev_level == "critical":  # 점수는 못 가져왔지만 등급이 Critical인 경우
        return "CRITICAL (Check Manually)"
    elif sev_level == "high":
        return "High"
    else:
        return f"{severity.title()} (Routine)"


def run_nuclei(target_ip: str, port: int, service: str) -> list:
    # 웹 서비스 필터링
    if "http" not in service and "https" not in service:
        if port not in [80, 443, 8000, 8080, 8088, 3000, 3330]:
            return []

    protocol = "https" if "https" in service else "http"
    base_url = f"{protocol}://{target_ip}:{port}"

    # [쿠키 획득]
    auth_cookie = None
    if port == 8088 or "dvwa" in service.lower():
        auth_cookie = get_dvwa_cookie(target_ip, port)

    # [타겟 확장] DVWA인 경우 취약점 경로들을 명시적으로 추가
    target_urls = [base_url]
    if auth_cookie:  # 로그인이 성공했을 때만 내부 경로 추가
        target_urls.extend(
            [
                f"{base_url}/vulnerabilities/sqli/",
                f"{base_url}/vulnerabilities/sqli_blind/",
                f"{base_url}/vulnerabilities/exec/",
                f"{base_url}/vulnerabilities/xss_r/",
                f"{base_url}/vulnerabilities/xss_s/",
            ]
        )

    # 타겟 리스트를 파일로 저장 (Nuclei -l 옵션용)
    target_file = f"targets_{port}.txt"
    with open(target_file, "w") as f:
        for url in target_urls:
            f.write(url + "\n")

    print(f"\n[*] 🚀 Launching Nuclei on {len(target_urls)} targets (Authenticated)...")

    command = [
        NUCLEI_PATH,
        "-l",
        target_file,  # URL 리스트 파일 사용
        "-j",
        "-s",
        "medium,high,critical",  # Info, Low 제외 (진짜만 찾기)
        # "-silent"
    ]

    if auth_cookie:
        print("    -> Cookie Injected!")
        command.extend(["-H", f"Cookie: {auth_cookie}"])

    results = []
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        stdout, stderr = process.communicate()

        if stderr:
            # Nuclei 로고 등은 stderr로 나오므로 정상
            pass

        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                vuln = json.loads(line)
                info = vuln.get("info", {})

                name = info.get("name")
                severity = info.get("severity", "low")
                matcher = vuln.get("matcher-name", "-")
                cve_ids = info.get("classification", {}).get("cve-id", [])
                cve_id = cve_ids[0] if cve_ids else None

                # [인텔리전스] API 조회
                epss_score = 0.0
                cvss_score = 0.0

                if cve_id:
                    print(
                        f"    -> Analyzing {cve_id} (EPSS/CVSS)...", end=" ", flush=True
                    )
                    epss_score = get_epss_score(cve_id)
                    cvss_score = get_cvss_score(cve_id)
                    print("Done.")

                # [인텔리전스] 리스크 산정
                risk_status = calculate_real_risk(severity, cvss_score, epss_score)

                finding = {
                    "name": name,
                    "severity": severity,
                    "cve_id": cve_id,
                    "epss": epss_score,
                    "risk_status": risk_status,
                    "matcher": matcher,
                }
                results.append(finding)
                print(f"    [!] Found: {name} | Risk: {risk_status}")

            except json.JSONDecodeError:
                continue

    except Exception as e:
        logging.error(f"Nuclei Error: {e}")
    finally:
        # 임시 파일 삭제
        if os.path.exists(target_file):
            os.remove(target_file)

    return results
