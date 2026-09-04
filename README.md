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

새 볼륨에서는 `sql/init.sql`이 자동 실행됩니다. 기존 V2 DB는
초기화하지 말고 다음 마이그레이션을 한 번만 실행합니다.

```powershell
Get-Content -Raw .\sql\migration_v3.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
Get-Content -Raw -Encoding UTF8 .\sql\migration_v3_1.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

이미 V3를 적용했다면 현재 DB를 백업한 후 `migration_v3_1.sql`만
실행합니다. `migration_v3.sql`은 재실행하지 않습니다. V3.1은
긴 포트 목록을 저장할 수 있도록 `scans.port_range`를 확장합니다.

마이그레이션 전에 DB 덤프를 별도로 생성해야 합니다. 자세한
절차는 `docs/asset_management.md`를 확인합니다.

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
py -m compileall -q .\asset_management .\scanner .\db .\scripts
py .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
git diff --check
```

외부 서비스나 브라우저에 의존하는 수동 실습 파일은 자동 단위
테스트와 구분합니다.

## 문서

- `docs/database_schema.md`: DB V3 구조와 관계
- `docs/asset_management.md`: 자산관리·스코프·마이그레이션
  상세 절차
