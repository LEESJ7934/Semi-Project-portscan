import os
import subprocess

NUCLEI_PATH = r"C:\Users\Seung Jun\AppData\Local\Programs\nuclei\nuclei.exe"
TEMPLATE_PATH = r"C:\Users\Seung Jun\nuclei-templates\http\cves\2012\dvwa_sqli_cve_2012_1823.yaml"
TARGET = "http://43.200.247.45:80"


def test_nuclei():
    print("[1] nuclei 실행 파일 존재 여부")
    print(os.path.exists(NUCLEI_PATH), NUCLEI_PATH)

    print("[2] 템플릿 파일 존재 여부")
    print(os.path.exists(TEMPLATE_PATH), TEMPLATE_PATH)

    if not os.path.exists(NUCLEI_PATH):
        print("nuclei.exe 경로가 틀림")
        return

    if not os.path.exists(TEMPLATE_PATH):
        print("템플릿 경로가 틀림")
        return

    cmd = [
        NUCLEI_PATH,
        "-u", TARGET,
        "-t", TEMPLATE_PATH,
        "-vv",
    ]

    print("[3] 실행 명령어")
    print(" ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        print("\n[4] returncode")
        print(result.returncode)

        print("\n[5] stdout")
        print(result.stdout if result.stdout.strip() else "(empty)")

        print("\n[6] stderr")
        print(result.stderr if result.stderr.strip() else "(empty)")

        stdout_lower = result.stdout.lower()

        if "[critical]" in stdout_lower or "[high]" in stdout_lower or "[medium]" in stdout_lower:
            print("\n[7] 판정: MATCH 발생 가능성 높음")
        elif "no results" in stdout_lower or "0 matches" in stdout_lower:
            print("\n[7] 판정: 매치 없음")
        else:
            print("\n[7] 판정: 애매함, stdout/stderr 직접 확인 필요")

    except Exception as e:
        print("\n[에러]")
        print(str(e))


if __name__ == "__main__":
    test_nuclei()