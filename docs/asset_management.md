# Day 3 Asset Management and Scan Scope

## 1. 목적

기존 `hosts` 테이블은 IP, 호스트 이름, 최초·최근 발견 시각만
저장했다. 이 구조로는 다음 질문에 답하기 어려웠다.

- 이 IP가 어떤 업무 자산인가?
- 담당자와 업무 부서는 누구인가?
- 운영계인지 테스트계인지?
- 개인정보를 처리하거나 인터넷에 노출되는가?
- 중요도가 높아 우선 조치해야 하는가?
- 누가 어떤 근거로 자산 정보를 변경했는가?
- 해당 스캔은 어떤 승인 범위에서 수행됐는가?

V3에서는 `hosts`를 자산대장으로 확장하고, 승인 스코프와
스캔별 자산 관찰 이력을 별도 테이블로 분리한다.

## 2. 처리 흐름

```text
사용자 입력(IP/CIDR/호스트 이름)
  -> 형식 검증 및 IP 확장
  -> 중복 IP 제거
  -> 승인 유효기간 확인
  -> allowlist 포함 여부 확인
  -> 대상/포트/동시 작업 한도 확인
  -> 스캔 실행
  -> 자산대장 upsert
  -> scan_assets 관찰 이력 저장
```

`--dry-run`은 스코프 검증 단계까지만 수행한다. 네트워크 스캔과
DB 쓰기를 하지 않으므로 실제 실행 전 승인 범위를 확인하는 데
사용한다.

## 3. 스코프 파일

`config/scope.example.json`은 루프백 전용 예시다. 실제 환경에서는
이를 `config/scope.local.json`으로 복사한 뒤 수정한다.

| 필드 | 의미 |
|---|---|
| `scope_uid` | 승인 스코프의 애플리케이션 식별자 |
| `name` | 사람이 읽을 수 있는 스코프 이름 |
| `authorization_ref` | 작업허가서·승인 티켓 번호 |
| `approved_by` | 승인자 또는 자산 책임자 |
| `valid_from` | 승인 시작 시각과 시간대 |
| `valid_until` | 승인 종료 시각과 시간대 |
| `allowed_targets` | 허용 IP, CIDR, 정확한 호스트 이름 |
| `max_targets` | 한 번에 확장 가능한 최대 IP 수 |
| `max_workers` | 최대 동시 작업 수 |
| `max_ports_per_target` | 대상 하나당 최대 포트 수 |

날짜는 시간대가 포함된 ISO 8601 형식이어야 한다.

```text
2026-09-04T09:00:00+09:00
```

정확한 호스트 이름 허용은 와일드카드가 아니다.
`lab.example.com`을 허용해도 `other.example.com`은 허용되지 않는다.

정책 내용은 정규화한 뒤 SHA-256으로 계산하고 DB에 저장한다.
스캔 당시 전체 정책은 `scans.config_snapshot`과 연결 정보로
남으므로 정책 파일이 나중에 변경돼도 실행 근거를 확인할 수 있다.

## 4. 자산대장 필드

| 필드 | 의미 |
|---|---|
| `asset_uid` | IP와 별도로 사용하는 UUID 자산 식별자 |
| `host_ip` | 정규화된 IPv4 또는 IPv6 |
| `host_name` | DNS 또는 수동 입력 호스트 이름 |
| `asset_name` | 업무에서 사용하는 자산명 |
| `asset_type` | 서버, 단말, 네트워크, 클라우드 등 |
| `environment` | 운영, 스테이징, 개발, 테스트 |
| `criticality` | 업무 중요도 |
| `owner` | 자산 담당자 |
| `business_unit` | 담당 부서 |
| `data_classification` | 데이터 분류 등급 |
| `handles_personal_data` | 개인정보 처리 여부 |
| `internet_exposed` | 인터넷 노출 여부 |
| `lifecycle_status` | 활성, 비활성, 폐기 |
| `source` | 자동 발견, 수동 등록, 가져오기 |
| `first_seen` | 최초 발견 시각 |
| `last_seen` | 최근 발견 시각 |

IP에는 UNIQUE 제약조건을 유지한다. 동일 IP를 다시 스캔하면 새
자산을 만들지 않고 `last_seen`과 `last_scan_id`를 갱신한다.
사용자가 설정한 중요도·담당자·상태는 자동 스캔이 덮어쓰지 않는다.

## 5. 감사이력

자산 메타데이터 변경은 `asset_change_history`에 필드별로 기록한다.

- 변경 필드
- 변경 전 값
- 변경 후 값
- 변경 사유
- 변경자
- 변경 시각

SQL 컬럼 이름은 애플리케이션의 고정 allowlist에서만 선택한다.
사용자 입력을 컬럼명으로 직접 연결하지 않아 동적 SQL의 주입
위험을 제한한다. 값은 모두 파라미터 바인딩한다.

## 6. 스캔별 자산 이력

`scan_assets`는 한 번의 스캔과 여러 자산을 연결한다.

| 필드 | 의미 |
|---|---|
| `scan_id` | 실행한 스캔 |
| `host_id` | 확인한 자산 |
| `input_target` | 사용자가 입력한 IP/CIDR/호스트 이름 |
| `resolution_type` | IP, CIDR, HOSTNAME |
| `result_status` | SCANNED 또는 ERROR |
| `open_port_count` | 해당 실행에서 확인한 열린 포트 수 |
| `error_code` | 실패한 경우 오류 코드 |
| `observed_at` | 관찰 시각 |

이 구조를 사용하면 IP 목록만 저장하던 방식과 달리 특정 자산이
어떤 승인 스캔에서 몇 번 확인됐는지 조회할 수 있다.

## 7. V2에서 V3로 마이그레이션

### 7-1. 백업

```powershell
$backupDirectory = Join-Path $env:LOCALAPPDATA "PortScannerBackups"
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null

docker exec portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -u root --single-transaction --routines --triggers port_scan > /tmp/port_scan_before_v3.sql'

$backupFile = Join-Path $backupDirectory "port_scan_before_v3.sql"
docker cp portscan-mysql:/tmp/port_scan_before_v3.sql "$backupFile"
Get-Item $backupFile | Select-Object FullName, Length
```

파일 크기가 0보다 큰지 확인한다.

### 7-2. 적용

```powershell
Get-Content -Raw .\sql\migration_v3.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

이 파일은 V2 DB에서 한 번만 실행한다. 재실행하면 이미 추가된
컬럼 때문에 실패할 수 있다.

마이그레이션은 다음 내부 확인용 복사본도 만든다.

- `migration_backup_scans_v2`
- `migration_backup_hosts_v2`
- `migration_backup_ports_v2`

외부 덤프가 주 백업이고, 위 테이블은 보조 수단이다.

### 7-3. 검증

```powershell
Get-Content -Raw .\sql\verify_v3.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

세 개의 마지막 검사 결과는 각각 `0`, 0행, 0행이어야 한다.

### 7-4. 포트 범위 저장 보완 (V3.1)

초기 Day 3 코드에서는 CLI가 파싱한 포트 목록을 문자열로 바꾸어
저장했다. 기본 범위 `1-1024`도 5,037자로 늘어나 기존
`scans.port_range`의 VARCHAR(100) 제한을 초과했다.

수정 후에는 실제 스캔 포트를 정렬·중복 제거한 결과를
`22,80-82,443` 같은 범위 문자열로 저장한다. 연속되지 않은
개별 포트가 많은 경우에도 자르지 않도록 컬럼을 MEDIUMTEXT로
확장한다. 원래 입력 표현은 `scans.config_snapshot.ports`에 남는다.

이미 V3를 적용했다면 현재 DB를 새 외부 파일로 백업한 후 아래
보완 SQL만 실행한다. V3 마이그레이션을 다시 실행하지 않는다.

```powershell
Get-Content -Raw -Encoding UTF8 .\sql\migration_v3_1.sql | docker exec -i portscan-mysql sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root --default-character-set=utf8mb4 -D port_scan'
```

출력되는 `port_range`의 Type은 `mediumtext`여야 하며, 기존
스캔·자산·포트·취약점·자산 변경 이력 개수가 유지되어야 한다.
새 DB는 최신 `sql/init.sql`에 이 변경이 이미 포함되어 있다.

## 8. 롤백 원칙

마이그레이션 오류가 발생하면 그 뒤의 스캔이나 자산 변경 명령을
실행하지 않는다. 오류 전체와 백업 파일 크기를 먼저 확인한다.
V2 백업 테이블을 수동으로 원복하는 것보다 외부 덤프를 별도 DB에
복원해 검증한 뒤 교체하는 편이 안전하다.

데이터 볼륨 삭제, `docker compose down -v`, 무검증 DROP 명령은
복구 절차로 사용하지 않는다.
