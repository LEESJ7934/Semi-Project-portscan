# Infrastructure Security Scanner

자산 식별부터 포트 스캔, 취약점 후보 관리, 검증 증적과 조치
이력까지 연결하는 인프라 보안진단 프로젝트입니다.

포트 스캔은 본인 소유 시스템이나 명시적으로 허가받은
시스템에서만 실행해야 합니다. 기본 스코프는 로컬 루프백
환경만 허용합니다.

## 주요 기능

- 단일 IPv4/IPv6, CIDR, 호스트 이름 입력
- 승인 스코프와 유효기간 사전 검증
- 최대 대상·포트·동시 작업 수 제한
- 자산 고유 ID, 중요도, 담당자, 환경, 데이터 등급 관리
- 개인정보 처리 및 인터넷 노출 여부 관리
- 스캔별 자산 관찰 결과와 자산 변경 감사이력 저장
- 취약점 상태, 검증 증적, 조치이력 관리
- TCP 배너의 제품·버전 식별, 공식 공지 4개 CVE의 검토된 규칙집
- 분석 미리보기와 CANDIDATE 저장, 선정 이유·출처·규칙 해시 보존
- CVE별 읽기 전용 검증과 증적 중복 방지
- CVSS/EPSS/KEV·자산 맥락 기반의 설명 가능한 우선순위
- 현재 관찰값·평가 freshness·증적·조치이력의 JSON/PDF 보고서

## 1. 실행 환경 준비

Windows PowerShell 기준입니다.

Python 3.10 이상과 Docker Desktop이 필요합니다.

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r .\requirements.txt
```

환경변수 파일을 만듭니다.

```powershell
Copy-Item .\.env.example .\.env
```

`.env`의 `replace_locally` 값을 로컬 비밀번호로 변경합니다.
`.env`는 Git에 커밋하지 않습니다.

## 2. MySQL 실행

```powershell
docker compose -f .\docker\docker-compose.yml up -d
docker compose -f .\docker\docker-compose.yml ps
docker inspect -f "{{.State.Health.Status}}" portscan-mysql
```

새 볼륨에서는 V5가 반영된 `sql/init.sql`이 자동 실행됩니다.
기존 DB는 외부 덤프를 백업하고 현재 버전에서 순서대로 마이그레이션합니다.

| 현재 DB | 실행할 파일 |
|---|---|
| V2 | `migration_v3.sql` → `migration_v3_1.sql` → `migration_v4.sql` → `migration_v5.sql` |
| V3 | `migration_v3_1.sql` → `migration_v4.sql` → `migration_v5.sql` |
| V3.1 (3일차 완료) | `migration_v4.sql` → `migration_v5.sql` |
| V4 | `migration_v5.sql` |
| V5 (6일차 완료) | 실행할 마이그레이션 없음 |

백업·오류 확인을 포함한 PowerShell 절차는
[4일차 실행 안내](docs/day4_service_cve_mapping.md)를 따릅니다.
기존 V2/V3 마이그레이션은 재실행하지 않습니다.
현재 기준 DB는 **V5**이며 Day 7에는 migration이 없습니다.
V4에서 V5로 이동할 때는 외부 DB 덤프를 만든 뒤 다음을 실행합니다.

```powershell
Get-Content -Raw -Encoding UTF8 .\sql\verify_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\migration_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\verify_v5.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

각 명령의 오류를 확인하고 다음 명령을 실행합니다.
`existing_counts_preserved=1`, 기존 데이터 건수 유지, EPSS `DECIMAL(10,9)`,
`vuln_risk_assessments` 생성을 확인합니다. MySQL DDL은 전체 rollback 대상이 아닙니다.

## 3. 승인 스코프 준비

로컬 설정 파일을 복사합니다.

```powershell
Copy-Item .\config\scope.example.json .\config\scope.local.json
```

`scope.local.json`에 승인 문서 번호, 승인자, 유효기간,
허용 대상과 실행 한도를 작성합니다. 이 파일은 실제 내부
대상 정보가 포함될 수 있으므로 Git에서 제외됩니다.

먼저 실제 접속이나 DB 저장이 없는 `--dry-run`으로 확인합니다.

```powershell
py -m scripts.run_scan scan `
  --target 127.0.0.1 `
  --ports 22,80,443 `
  --scope-file .\config\scope.local.json `
  --dry-run
```

승인 범위 밖의 대상, 만료된 허가, 한도를 넘는 요청은 스캔
시작 전에 차단됩니다.

## 4. 스캔 실행

```powershell
py -m scripts.run_scan scan `
  -sT -sV `
  --target 127.0.0.1 `
  --ports 1-1024 `
  --scope-file .\config\scope.local.json `
  -oN .\reports\local_scan.txt
```

여러 입력은 `--target`을 반복합니다.

```powershell
py -m scripts.run_scan scan `
  -sT `
  --target 192.168.56.0/30 `
  --target lab.example.com `
  --ports 22,80,443 `
  --scope-file .\config\scope.local.json `
  --dry-run
```

## 5. 자산대장 관리

자산 목록:

```powershell
py -m scripts.manage_assets list
```

수동 등록 또는 분류 보강:

```powershell
py -m scripts.manage_assets register `
  --ip 127.0.0.1 `
  --name local-lab `
  --type SERVER `
  --environment TEST `
  --criticality LOW `
  --data-classification INTERNAL `
  --no-personal-data `
  --no-internet-exposed `
  --changed-by portfolio-owner `
  --reason "로컬 실습 자산 최초 분류"
```

자산 상세 조회와 변경:

```powershell
py -m scripts.manage_assets show --asset-id <ASSET_ID>

py -m scripts.manage_assets update `
  --asset-id <ASSET_ID> `
  --criticality HIGH `
  --owner security-team `
  --changed-by portfolio-owner `
  --reason "업무 영향도 재평가"

py -m scripts.manage_assets history --asset-id <ASSET_ID>
```

`update`는 변경자와 사유를 반드시 받아
`asset_change_history`에 전후 값을 남깁니다.

## 6. 테스트

```powershell
py -m unittest discover -s .\tests -p "test_*.py" -v
py -m compileall -q .\asset_management .\scanner .\db .\scripts .\analysis .\verification .\api
py .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
git diff --check
```

외부 서비스나 브라우저에 의존하는 수동 실습 파일은 자동 단위
테스트와 구분합니다.

## 7. CVE 후보 분석 (4일차)

DB 없이 제공된 예시를 분석합니다. 파일 내 ID는 실습용이며 저장할 수 없습니다.

```powershell
py -m analysis.run_analysis --input .\examples\day4_ports.json
```

실제 DB 관찰값은 `--scan-id <스캔 ID>` 또는 `--asset-id <자산 UUID>`로
선택합니다. 기본은 미리보기이며 `--save`를 추가하면 후보와 근거가 저장됩니다.
전체 절차와 루프백 실습은 [4일차 실행 안내](docs/day4_service_cve_mapping.md)에 있습니다.

규칙집은 공식 공지를 검토한 4개 CVE만 포함합니다. **미일치는 안전 판정이 아닙니다.**
설치 패키지·설정·패치 여부가 원격 읽기 전용 검사만으로 확인되지 않으면 추가 확인이 필요합니다.

## 8. CVE별 안전 검증 (5일차)

아래 `<VULN_ID>`, `<ASSET_ID>`, `<SCAN_ID>`는 실제 DB ID/UUID로 바꿉니다.

```powershell
py -m scripts.run_verification --vuln-id <VULN_ID> --scope-file .\config\scope.local.json --dry-run
py -m scripts.run_verification --vuln-id <VULN_ID> --scope-file .\config\scope.local.json
```

`--dry-run`은 DB 조회만 하며 대상 접속/DB write가 없습니다.
실행 시 승인 범위를 확인한 후 CVE ID별 읽기 전용 verifier를 선택합니다.
배너/버전이나 HTTP 200만으로 CONFIRMED를 만들지 않습니다.
연결·timeout 오류는 ERROR이며 증적·상태·이력을 한 transaction에 저장합니다.

## 9. 우선순위 평가 (6일차)

```powershell
py -m scripts.run_risk_assessment --asset-id <ASSET_ID>
py -m scripts.run_risk_assessment --asset-id <ASSET_ID> --save
```

`--vuln-id`, `--scan-id`, `--asset-id` 중 하나를 선택합니다.
기본 PREVIEW는 DB와 NVD/FIRST/CISA를 읽고 규칙 기반 action/priority를 출력합니다.
`--save`에서만 V5 평가 이력과 조건부 CVSS/EPSS summary를 저장합니다.
취약점 상태와 조치이력은 변경하지 않습니다. `vulns.risk`는 보존된 legacy 필드입니다.
API 오류는 0점/비취약 판정이 아니며 incomplete=true와 exit 1로 남습니다.
KEV 공식 미러로 복구된 원본 조회 오류도 기록하므로 결과 내용을 함께 확인합니다.

## 10. 저장된 결과 보고서 (7일차)

```powershell
py -m scripts.generate_report --asset-id <ASSET_ID> --output-dir .\reports --format both
py -m scripts.generate_report --scan-id <SCAN_ID> --format json
```

자산 UUID 또는 양의 scan ID 중 하나를 선택합니다. 기본은 `reports` 아래 JSON+PDF이며
`--format json|pdf|both`를 지원합니다. stdout JSON에서 출력 경로와 snapshot SHA-256을 확인합니다.
기존 `py -m api.generate_final_report`도 같은 옵션의 호환 진입점입니다. IP 위치 인수는 지원하지 않습니다.

보고서는 하나의 read-only consistent DB transaction으로 V5 결과를 읽습니다.
스캔·분석·검증·위협정보 조회·Shodan 접속을 자동 실행하지 않습니다.
자산은 `p.last_scan_id = h.last_scan_id`, scan은 `p.last_scan_id = 선택한 scan ID`인 관찰만 사용합니다.
scan 선택은 `scan_assets`에 연결된 자산도 보여주지만 자산 metadata는 현재 값입니다.
과거 시점의 포트 상태를 완전히 재현하는 기능은 아닙니다.

최신 평가는 `last_assessed_at`, 동률일 때 `id` 순으로 선택합니다.
현재 상태/자산 정보와 일치하면 CURRENT, 다르면 STALE, 없으면 MISSING입니다.
STALE/MISSING의 요약 우선순위는 UNASSESSED이며 저장된 옛 평가는 이력으로 표시합니다.
CURRENT는 context 일치이며 외부 위협정보의 최신성이나 취약점 확정을 뜻하지 않습니다.

JSON과 PDF는 같은 snapshot을 사용하고 생성 시각을 제외한 내용 해시를 기록합니다.
증적·조치이력·규칙 근거·출처·누락 정보를 포함하며, 증적 JSON 파싱 실패는 개별 표시합니다.
관찰값/후보가 없는 것은 안전 판정이 아닙니다.
PDF는 ReportLab의 설치된 한글 폰트 또는 CJK CID font를 사용하며 외부 font를 다운로드하지 않습니다.
Windows에서는 설치된 맑은 고딕을 포함해 렌더링합니다. CJK fallback은 PDF 뷰어의 한글 글꼴 지원이 필요할 수 있습니다.
보고서에는 내부 자산과 증적 정보가 포함되며 `reports/`는 Git에서 제외됩니다.

전체 실행 흐름은 다음과 같습니다. 각 단계는 별도 명령으로 실행합니다.

**Scan → Analysis → Verification → Risk Assessment → Report**

## 문서

- `docs/database_schema.md`: DB V5 구조와 관계
- `docs/asset_management.md`: 자산관리·스코프·마이그레이션
  상세 절차

- `docs/day4_service_cve_mapping.md`: 서비스 식별·CVE 규칙·V4 적용·로컬 실습
