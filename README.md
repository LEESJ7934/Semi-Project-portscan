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

## 1. 실행 환경 준비

Windows PowerShell 기준입니다.

Python 3.10 이상과 Docker Desktop이 필요합니다.

```powershell
py -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
py -m pip install --upgrade pip
py -m pip install -r .\requirements.txt
py -m playwright install chromium
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

새 볼륨에서는 V4가 반영된 `sql/init.sql`이 자동 실행됩니다.
기존 DB는 외부 덤프를 백업하고 현재 버전에서 순서대로 마이그레이션합니다.

| 현재 DB | 실행할 파일 |
|---|---|
| V2 | `migration_v3.sql` → `migration_v3_1.sql` → `migration_v4.sql` |
| V3 | `migration_v3_1.sql` → `migration_v4.sql` |
| V3.1 (3일차 완료) | `migration_v4.sql` |
| V4 | 실행할 마이그레이션 없음 |

백업·오류 확인을 포함한 PowerShell 절차는
[4일차 실행 안내](docs/day4_service_cve_mapping.md)를 따릅니다.
기존 V2/V3 마이그레이션은 재실행하지 않습니다.

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
실제 설치 패키지·설정·패치 여부 검증은 5일차 범위입니다.

## 문서

- `docs/database_schema.md`: DB V4 구조와 관계
- `docs/asset_management.md`: 자산관리·스코프·마이그레이션
  상세 절차

- `docs/day4_service_cve_mapping.md`: 서비스 식별·CVE 규칙·V4 적용·로컬 실습
