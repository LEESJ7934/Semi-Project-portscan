# scripts/generate_report.py

import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# [수정] 함수 이름을 get_db_connection에서 get_connection으로 변경
from db.db_client import get_connection


def generate_html_report(scan_id: str):
    """
    특정 scan_id에 대한 결과를 DB에서 조회하여 HTML 보고서를 생성합니다.
    """
    # [수정] 여기서도 get_connection() 호출
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # 1. 스캔 정보 조회
        cursor.execute("SELECT * FROM scans WHERE scan_id = %s", (scan_id,))
        scan_info = cursor.fetchone()

        if not scan_info:
            print(f"[!] Scan ID {scan_id} not found.")
            return

        # 2. 호스트 정보 조회 (하나의 스캔에 하나의 타겟만 있다고 가정)
        # hosts 테이블에 scan_id 컬럼이 있는지 확인 필요.
        # 만약 없다면 스키마 구조에 따라 조인이 필요할 수 있음.
        # 일단 기존 로직대로 진행하되, 에러 발생 시 hosts 테이블 구조 확인 필요.
        cursor.execute(
            "SELECT * FROM hosts WHERE last_scan_id = %s", (scan_id,)
        )  # last_scan_id일 가능성이 높음
        host_info = cursor.fetchone()

        if not host_info:
            # 혹시 last_scan_id로 못 찾으면 가장 최근 호스트를 가져오거나 예외 처리
            print("[!] Host info not found for this scan.")
            return

        # 3. 포트 및 취약점 정보 조회
        cursor.execute(
            "SELECT * FROM ports WHERE host_id = %s ORDER BY port ASC",
            (host_info["id"],),
        )
        ports = cursor.fetchall()

        # 취약점(Vulns) 정보를 포트별로 매핑
        for port in ports:
            # vulns 테이블 조회
            cursor.execute("SELECT * FROM vulns WHERE port_id = %s", (port["id"],))
            vulns_data = cursor.fetchall()

            # DB에 저장된 취약점 정보 매핑
            port["vulnerabilities"] = vulns_data

            # 스크린샷 경로 처리
            if port.get("screenshot_path"):  # .get()으로 안전하게 접근
                filename = os.path.basename(port["screenshot_path"])
                port["screenshot"] = f"screenshots/{filename}"
            else:
                port["screenshot"] = None

        # 4. Jinja2 템플릿 로딩
        template_dir = os.path.join(os.getcwd(), "templates")
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")

        # 5. 렌더링
        html_content = template.render(
            scan_id=scan_id,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            host_info=host_info,
            total_open_ports=len(ports),
            scan_type=scan_info.get("scan_type", "TCP"),
            ports=ports,
        )

        # 6. 파일 저장
        output_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        report_file = os.path.join(output_dir, f"report_{scan_id}.html")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"\n[+] 🎉 Report Generated Successfully: {report_file}")
        return report_file

    except Exception as e:
        print(f"[!] Report Generation Failed: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == "__main__":
    try:
        conn = get_connection()
        cur = conn.cursor()
        # [수정] created_at -> started_at (DB 컬럼명이 started_at임)
        # [수정] scan_id 컬럼이 이제 존재하므로 에러 안 남
        cur.execute("SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1")
        last_scan = cur.fetchone()
        conn.close()

        if last_scan:
            print(f"[*] Generating report for Scan ID: {last_scan[0]}")
            generate_html_report(last_scan[0])
        else:
            print("No scans found in DB.")
    except Exception as e:
        print(f"Error connecting to DB: {e}")
