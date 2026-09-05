# 4일차: 서비스 식별과 CVE 후보 연결

기준 커밋: `00069145d1d5c1f5c52b76efd55ac951a31a53b9` (3일차 병합).
범위는 포트스캐너입니다. 다크웹 프로젝트는 계획대로 8~12일차에 진행합니다.

## 무엇이 달라졌는가

| 이전 | 이후 |
|---|---|
| 포트 번호를 서비스 식별 결과처럼 사용 | 포트 힌트와 실제 응답에 따른 식별을 구분 |
| 제품명 없이 버전 문자열만 저장 | `service`, `product`, `version`, `fingerprint` 저장 |
| 알 수 없는 배너 전체를 버전으로 저장 | 식별 실패 시 제품/버전을 비워 두고 이유 기록 |
| `-sV`가 화면 출력에만 영향 | `-sV`를 지정하면 TCP 배너 식별 실행 |
| 서비스와 정규식만으로 CVE 연결 | 제품 일치 + 숫자로 비교한 공식 영향 범위 + 출처 필요 |
| OpenSSH 8.9에 9.1 관련 CVE 연결 | 해당 규칙 교체, 9.1 계열만 후보로 연결 |
| 범용 HTTP/DVWA 화면에 CVE 연결 | 관련 없는 DVWA·Telnet·FTP 규칙 폐기 |
| 분석 실행 즉시 DB 저장 및 외부 점수 API 호출 | 기본 미리보기, 명시적 `--save`만 저장; 외부 API 호출 없음 |
| 미조회 점수를 0으로 처리 | DB는 `NULL`, 기존 PDF는 `N/A`로 표시 |
| 후보 이유 미보존 | 배너 근거, 영향 범위, 출처, 규칙 해시, 스캔 ID를 증적으로 저장 |

`CANDIDATE`는 검증 전 후보입니다. 배너는 위장될 수 있고 배포판이 버전
문자열을 유지한 채 패치를 적용할 수 있습니다. 실제 패키지·설정·패치
확인은 5일차 검증 범위입니다. 실습 서버는 일부러 배너만 흉내 냅니다.

## 이번 규칙의 정확한 범위

**공식 공지를 검토한 4개 CVE의 작은 규칙집입니다. 전체 CVE 검색기가 아닙니다.**
규칙 미일치, 버전 미노출, 지원하지 않는 제품은 안전 판정을 의미하지 않습니다.
규칙 파일의 `reviewed_on`은 검토일이며 모든 최신 CVE를 포함한다는 뜻이 아닙니다.

| 제품 | CVE | 후보가 되는 상위 제품 버전 | 출처 |
|---|---|---|---|
| Apache HTTP Server | CVE-2021-41773 | 2.4.49 | [Apache 공식 공지](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773) |
| Apache HTTP Server | CVE-2021-42013 | 2.4.49, 2.4.50 | [Apache 공식 공지](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-42013) |
| OpenSSH | CVE-2023-25136 | 9.1 계열 | [OpenSSH 9.2 릴리스 설명](https://www.openssh.org/txt/release-9.2) |
| nginx | CVE-2021-23017 | 0.6.18~1.20.0 | [nginx 공식 공지](https://nginx.org/en/security_advisories.html) |

Apache는 경로 접근 제어와 CGI 등 설정 확인, nginx는 resolver 사용 여부 확인이
추가로 필요합니다. OpenSSH의 portable 패치 수준과 배포판 보안 패치는 별도 확인합니다.
`severity_basis`에 분류 근거를 보존합니다. OpenSSH의 `MEDIUM`은 프로젝트의
임시 검토 등급이며 공식 CVSS 점수가 아닙니다. CVSS·EPSS·우선순위 계산은 6일차에 보완합니다.

새 규칙은 `analysis/vuln_rules.json`의 검증 가능한 제품·버전 범위 형식을 사용합니다.
새 제품의 버전 규칙이 다르면 `normalized_version()`도 추가해야 합니다.
정규식만 있는 이전 형식, 역전된 버전 범위, 중복 규칙 ID는 오류로 거부합니다.

## 1. 패치 적용 후 코드 확인

프로젝트 루트의 PowerShell에서 실행합니다. 기존 3일차 Python 환경을 사용합니다.
이번 변경에 추가 Python 패키지는 없습니다.

```powershell
py -m unittest discover -s .\tests -p "test_*.py" -v
py -m analysis.run_analysis --input .\examples\day4_ports.json
py -m compileall -q .\scanner .\analysis .\db .\scripts .\verification .\api
py .\scripts\check_secrets.py
git diff --check
```

자동 테스트는 외부 대상에 접속하지 않으며 로컬 루프백의 임시 HTTP 서버만 사용합니다.
DB 연결은 모의 객체로 검사하므로 이 단계에는 MySQL을 실행할 필요가 없습니다.
샘플 결과는 `selected_port_count: 6`, `candidate_count: 3`, `mode: PREVIEW`입니다.
`--input`에 있는 ID는 실습 값이므로 `--save`와 함께 사용할 수 없습니다.

## 2. 기존 V3.1 DB 백업과 V4 적용

이 절차는 3일차 V3/V3.1까지 완료한 기존 DB 기준입니다. 기존 데이터 볼륨을
초기화하지 않습니다. 새 설치에는 V4가 반영된 `sql/init.sql`을 사용합니다.

Docker Desktop을 실행한 뒤 상태를 확인합니다.

```powershell
docker inspect -f "{{.State.Health.Status}}" portscan-mysql
```

`healthy`인 상태에서 백업을 만듭니다.

```powershell
& {
    $backupDirectory = Join-Path $env:LOCALAPPDATA "PortScannerBackups"
    New-Item -ItemType Directory -Force -Path $backupDirectory -ErrorAction Stop | Out-Null
    $backupStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $backupDirectory "port_scan_before_v4_$backupStamp.sql"

    docker exec portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -u root --single-transaction --routines --triggers port_scan > /tmp/port_scan_before_v4.sql'
    if ($LASTEXITCODE -ne 0) { throw "DB 백업 실패" }

    docker cp portscan-mysql:/tmp/port_scan_before_v4.sql "$backupFile"
    if ($LASTEXITCODE -ne 0) { throw "백업 파일 복사 실패" }

    $backupInfo = Get-Item -LiteralPath $backupFile -ErrorAction Stop
    if ($backupInfo.Length -eq 0) { throw "백업 파일이 비어 있습니다" }
    $backupInfo | Select-Object FullName, Length
}
```

백업 명령에 오류가 없고 파일 크기가 0보다 크면 진행합니다.

```powershell
& {
    $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    Get-Content -Raw -Encoding UTF8 .\sql\migration_v4.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
    if ($LASTEXITCODE -ne 0) { throw "V4 마이그레이션 오류. 출력 확인이 필요합니다." }

    Get-Content -Raw -Encoding UTF8 .\sql\verify_v4.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
    if ($LASTEXITCODE -ne 0) { throw "V4 구조 검사 오류" }
}
```

정상 기준:

- `ports.product`: nullable `varchar(100)`.
- `ports.fingerprint`: nullable `json`.
- 마이그레이션 자체는 기존 스캔·자산·포트·취약점·변경이력의 행 수와 값을 유지합니다.
- 기존 `product`/`fingerprint`는 `NULL`; 이후 `-sV` 스캔부터 채워집니다.
- 마지막 `REVIEW_RETIRED_RULE` 출력은 오류가 아니라 폐기한 규칙에서 생성된 기존 기록입니다.

V4 DDL은 MySQL에서 자동 커밋됩니다. 전체 트랜잭션 롤백은 되지 않습니다.
컬럼별 존재 검사를 하므로 중단 후 재실행할 수 있지만 오류 원인을 먼저 확인합니다.
V2/V3 마이그레이션을 다시 실행할 필요는 없습니다.

## 3. 실제 로컬 스캔 → 후보 연결

PowerShell 터미널 A에서 프로젝트 루트로 이동한 후 실행합니다.

```powershell
py -m scripts.day4_demo_server --port 8081
```

`simulated Apache/2.4.50`가 표시되며 프로세스가 계속 실행되는 것이 정상입니다.
이 프로그램은 Python HTTP 서버이고 실제 Apache 취약점을 구현하지 않습니다.
8081 포트가 이미 사용 중이면 서버와 스캔 명령의 포트를 모두 다른 빈 포트로 바꿉니다.

터미널 B에서 먼저 계획을 확인하고 스캔합니다.

```powershell
py -m scripts.run_scan scan --target 127.0.0.1 --ports 8081 -sT -sV --max-workers 2 --timeout 2 --dry-run
py -m scripts.run_scan scan --target 127.0.0.1 --ports 8081 -sT -sV --max-workers 2 --timeout 2
```

기본 예시 스코프는 루프백만 허용합니다. 별도의 승인 스코프를 사용하는 경우
두 명령에 같은 `--scope-file`을 지정합니다. `--dry-run`은 스캔/DB 저장을 하지 않습니다.
두 번째 명령에서 `http`, `apache_http_server`, `2.4.50`과 마지막 `scan_id`가 출력되어야 합니다.

마지막에 출력된 숫자를 아래 변수에 넣습니다. `Read-Host`는 DB ID 입력을 받는 명령입니다.

```powershell
$day4ScanId = [int](Read-Host "방금 출력된 scan_id 숫자")
py -m analysis.run_analysis --scan-id $day4ScanId --output .\reports\day4_preview.json
```

정상 기준은 `candidate_count: 1`, `CVE-2021-42013`, `status: CANDIDATE`입니다.
배너만 흉내 내는 서버에서도 후보가 나오는 것은 이 단계가 실제 취약 여부를 확정하지
않는다는 점을 보여줍니다. `references`, `match_reason`, `conditions_to_verify`가 함께 나옵니다.

후보와 근거를 저장하고 같은 분석을 한 번 더 실행합니다.

```powershell
py -m analysis.run_analysis --scan-id $day4ScanId --save --output .\reports\day4_saved.json
py -m analysis.run_analysis --scan-id $day4ScanId --save
Get-Content -Raw -Encoding UTF8 .\sql\verify_v4.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

- 같은 `saved_vuln_ids`가 나와야 합니다.
- `matching_evidence_count`는 같은 스캔·같은 규칙으로 재실행하면 1을 유지합니다.
- 취약점 상태는 `CANDIDATE`, 미조회 점수는 `NULL`입니다.
- 중복 검사 두 쿼리는 행이 없어야 합니다.
- 3일차 자산의 UUID, 담당자, 중요도와 변경이력은 그대로여야 합니다.

터미널 A에서 `Ctrl+C`로 실습 서버를 종료합니다.

추가 경계 확인이 필요하면 `--version 2.4.51`로 서버를 다시 실행하고 새 `-sV` 스캔 ID로
분석합니다. 이 규칙집에서는 후보가 0개가 되며 이는 해당 두 Apache 규칙 미일치를 의미합니다.
기존 후보를 자동으로 `CLOSED`로 바꾸지 않습니다. 조치 완료 판정은 5일차에 다룹니다.

## 4. 명령과 저장 의미

| 항목 | 의미 |
|---|---|
| `-sT` | TCP 연결 가능 여부 검사 |
| `-sV` | 추가 연결과 배너/HTTP HEAD로 제품·버전 식별 |
| `--scan-id` | 해당 숫자 ID의 아직 최신인 포트 관찰값 선택 |
| `--asset-id` | 자산 UUID로 그 자산의 최신 포트 관찰값 선택 |
| `--all` | 모든 자산의 최신 열린 TCP 포트 관찰값 분석 |
| `--input` | JSON 예시만 분석, DB 저장 불가 |
| `--save` | 후보와 근거를 하나의 DB 트랜잭션으로 저장 |
| `--output` | 사람이 읽을 수 있는 JSON 보고서도 저장 |
| `fingerprint.source` | 제품 식별 근거: HTTP Server 헤더, SSH/FTP/MySQL 인사말 등 |
| `confidence: reported` | 서버가 그렇게 주장했다는 의미; CVE 확률이 아님 |
| `catalog_sha256` | 후보 선정에 사용한 규칙 파일을 식별하는 해시 |

`ports`는 현재 상태 테이블입니다. 분석은 `ports.last_scan_id = hosts.last_scan_id`인
열린 TCP 관찰값만 선택해 오래된 포트를 새 스캔 결과처럼 분석하지 않습니다.
따라서 자산을 다시 스캔한 뒤 예전 `--scan-id`를 지정하면 결과가 없을 수 있습니다.
전체 과거 포트 스냅샷 재생 기능은 이번 범위가 아닙니다. 이미 저장한 후보 근거에는
당시 스캔 ID와 배너 근거가 남습니다.

`-sV` 없이 새 스캔하거나 배너 식별에 실패하면 해당 포트의 예전 제품/버전을
최신 식별 결과로 재사용하지 않고 비웁니다. 이미 남긴 취약점 증적은 보존합니다.

HTTPS 식별은 알려진 HTTPS 힌트 포트(443/8443)에 TLS로 접속합니다.
인증서를 검증하지 않는 식별 연결임을 `tls: certificate_not_validated`에 기록합니다.
이 값은 인증서 신뢰성 판정이 아닙니다. 비밀번호 전송, 로그인, 리다이렉트 추적,
공격 페이로드는 사용하지 않습니다. 호스트명은 HTTP Host/TLS SNI에 전달하되,
실제 연결은 스코프 검사에서 승인된 숫자 IP에 고정합니다.
HTTP/2·QUIC, 모든 임의 TLS 포트, 숨겨진 제품, 미지원 프로토콜의 완전한 식별은 지원하지 않습니다.

## 5. 기존 후보와 검증기

폐기한 규칙의 기록은 삭제하거나 안전한 것으로 재분류하지 않습니다.
`verify_v4.sql`로 확인한 후 5일차에 검토합니다. 기존 범용 검증기는 폐기한 규칙과
`day4:` 출처의 후보를 건너뛰며 상태를 유지합니다. 제품·버전이 맞는다는 이유만으로
범용 HTTP/FTP 검사가 CVE를 `CONFIRMED`로 바꾸는 것을 막기 위한 경계입니다.

같은 후보를 재저장해도 검토된 상태와 `ERROR` 상태를 덮어쓰지 않습니다.
다른 스캔이나 수정한 규칙을 근거로 후보가 다시 발견되면 해당 근거는 추가됩니다.
후보 저장 실패 또는 근거 저장 실패 시 해당 저장 작업 전체를 롤백합니다.

## 6. Git 반영

코드 테스트와 위 DB 실습이 통과한 뒤 변경 파일을 확인합니다.

```powershell
py .\scripts\check_secrets.py
git diff --check
git status --short
```

스테이징과 커밋:

```powershell
git add README.md docs/day4_service_cve_mapping.md docs/database_schema.md
git add scanner/fingerprints.py scanner/banner_grabber.py scanner/tcp_scanner.py scanner/udp_scanner.py scanner/service_fingerprints.py scanner/version_parser.py scanner/scan_runner.py scripts/run_scan.py
git add analysis/fingerprint_parser.py analysis/run_analysis.py analysis/save_vulns.py analysis/vuln_mapper.py analysis/vuln_rules.json api/analysis_report.py
git add db/query_helpers.py db/save_scan_results.py sql/init.sql sql/migration_v4.sql sql/verify_v4.sql verification/run_verification.py
git add scripts/day4_demo_server.py examples/day4_ports.json tests/test_fingerprints.py tests/test_vuln_mapper.py tests/test_analysis_cli.py tests/test_save_vulns.py
git diff --cached --check
git status --short
git commit -m "4일차 서비스 식별 및 근거 기반 CVE 후보 연결"
git push -u origin feature/day4-service-cve-mapping
```

`reports/`, `.env`, 로컬 스코프와 DB 덤프는 커밋 대상이 아닙니다.
공유된 main에 반영할 때는 기존 방식대로 최신 main을 먼저 받은 후 작업 브랜치를 병합합니다.

## 제공 전 확인한 범위

- 기존 42개를 포함한 자동 테스트 82개 통과.
- MySQL 8.0.46의 별도 임시 DB에서 V3.1 → V4 적용과 재실행 확인.
- 기존 행의 값·자산 메타데이터 보존, 신규 init과 마이그레이션의 ports 구조 일치 확인.
- 실제 루프백 HTTP 스캔 → DB → 분석 미리보기 → 후보/근거 저장 확인.
- 재저장 중복 방지, 7개 기존 상태 보존, 근거 저장 실패 시 롤백 확인.
- 새 식별 실패 시 오래된 제품·버전 재사용 차단 확인.
- 실제 루프백 TLS 연결, SNI, HTTPS 제품 식별과 인증서 신뢰 미검증 표시 확인.

위 검사는 별도 검사 환경의 결과입니다. 사용자의 Windows와 Docker DB에는
위 실행 절차를 적용하고 결과를 확인해야 4일차 작업이 완료됩니다.
