# Validation

## 1. 검증 원칙

이 프로젝트는 테스트를 세 층으로 나눈다.

```text
Unit / Contract Tests
        |
        v
Local DB & Lab Integration
        |
        v
End-to-End Scenario
```

자동 테스트가 통과했다는 사실만으로 실제 Docker, MySQL,
로컬 서비스, 외부 위협정보 API까지 정상이라고 간주하지 않는다.

반대로 로컬 E2E 한 번이 통과했다고 회귀 테스트를 생략하지 않는다.

## 2. 자동 테스트 범위

최종 테스트 명령:

```powershell
py -m unittest discover -s .	ests -p "test_*.py" -v
```

테스트에는 다음 범주가 포함된다.

- target/IP/CIDR 정규화
- 승인 scope와 한도
- TCP/UDP scan 동작
- 서비스 fingerprint와 버전 파싱
- 자산 메타데이터 정규화
- 자산 변경 감사이력
- DB 중복 저장 방지
- CVE catalog 구조와 버전 경계
- CANDIDATE 저장
- CVE별 읽기 전용 verifier
- 오류와 비취약 판정 분리
- evidence 중복 방지
- remediation state transition
- NVD/FIRST/CISA source 처리
- 설명 가능한 risk rule
- 평가 저장·재사용
- 보고서 snapshot/freshness/hash
- JSON/PDF 출력
- secret pattern 검사

보고서 생성 Work 검증에서는 **133개 자동 테스트 PASS**가 기록되었다.
이 수치는 당시 Work의 offline 환경 결과이며, 실제 MySQL/E2E 완료를 의미하지 않는다.

최종에서는 사용자 PC의 현재 가상환경에서 전체 suite를 다시 실행해
최종 숫자와 결과를 재확인한다.

## 3. 정적·구성 검사

문법과 저장소 위생은 다음으로 확인한다.

```powershell
py -m compileall -q .sset_management .\scanner .\db .\scripts .nalysis .
erification .pi
py .\scripts\check_secrets.py
docker compose -f .\docker\docker-compose.yml config --quiet
git diff --check
```

`check_secrets.py`는 등록된 알려진 패턴 검사다.
모든 비밀정보를 탐지하는 DLP 도구라고 해석하지 않는다.

## 4. 실제 DB 검증

MySQL은 Docker의 `portscan-mysql` 컨테이너를 사용한다.

검증 시 다음을 확인했다.

- V5 스키마가 기존 데이터를 보존
- 스캔·자산·포트·취약점 관계 유지
- 취약점·증적·조치이력·평가 이력 count 조회 가능
- 동일 후보/증적/평가를 반복 저장해도 중복이 제한됨
- 최신 상태와 과거 이력이 분리됨

과거 PC 검증 중 실제 DB에는 다음과 같은 구조가 확인되었다.

```text
vulns                  6
vuln_evidence          3
remediation_history   11
vuln_risk_assessments  1
```

이 숫자는 고정된 제품 요구사항이 아니라 해당 실습 DB의 한 시점 결과다.

## 5. 로컬 서비스 식별 E2E

서비스·CVE 매핑에서는 실제 취약 Apache를 배포하지 않고
`demo_banner_server.py`가 Apache 버전 문자열을 흉내 내도록 했다.

예시 흐름:

```text
local demo server
    |
    v
127.0.0.1:<lab port>
    |
    v
-sT -sV
    |
    v
http / apache_http_server / 2.4.50
    |
    v
reviewed version rule
    |
    v
CVE-2021-42013 CANDIDATE
```

이 테스트의 목적은 **취약점 재현**이 아니라
서비스 fingerprint → 제품/버전 → 검토된 영향 범위 → 후보 저장이
연결되는지 확인하는 것이다.

그래서 문서에도 해당 demo server가 실제 Apache 취약점을 구현하지 않는다고 명시한다.

## 6. 검증 상태 E2E

실제 로컬 PC 검증에서 `CVE-2021-42013` 후보에 대해
읽기 전용 verifier를 반복 실행했다.

관찰된 상태 흐름 예:

```text
CANDIDATE
   |
   v
POTENTIAL
   |
   v
ERROR
   |
   v
POTENTIAL
```

이 흐름이 중요한 이유는:

- 네트워크 오류를 false positive로 바꾸지 않음
- 연결이 다시 정상화되면 재검증 가능
- HTTP 응답과 영향 버전이 보여도 자동 CONFIRMED하지 않음
- 같은 증적은 재사용하고 관찰 횟수를 증가시킬 수 있음

실제 PC 로그에서도 같은 verifier의 HTTP 증적이 반복 실행 후
재사용되었고, 별도의 ERROR_LOG가 분리되어 저장된 것이 확인되었다.

## 7. 위험 우선순위 E2E

위험도 평가에서는 저장된 `POTENTIAL` finding에 대해
NVD CVSS, FIRST EPSS, CISA KEV와 자산 context를 결합했다.

실습 결과 예:

```text
status             POTENTIAL
CVSS               9.8
KEV                KNOWN_EXPLOITED
asset criticality  HIGH
action              VERIFY
priority            P2
```

동일 입력으로 다시 평가했을 때 새 평가 row를 계속 만들지 않고
기존 assessment를 재사용하며 observations를 증가시키는 것도 확인했다.

중요한 해석:

- `P2`는 취약 확정 상태가 아니다.
- `VERIFY`는 여전히 추가 기술 검증이 필요하다는 의미다.
- 외부 API 오류는 0점으로 처리하지 않는다.

## 8. 보고서 E2E

보고서 생성 실제 PC에서 local asset 기준으로 JSON과 PDF를 생성했다.

확인된 항목:

- 두 파일 모두 실제 생성됨
- JSON과 PDF가 동일 snapshot을 사용
- snapshot SHA-256 반환
- finding 상태·priority·freshness 포함
- evidence와 remediation history 포함
- 보고서 생성 중 외부 source를 다시 조회하지 않음

실제 한 번의 출력에서는 JSON과 PDF가 모두 0 byte보다 큰 파일로 생성되었다.

보고서 요약 예:

```text
asset_count                  1
open_port_count              1
finding_count                1
POTENTIAL                    1
P2                           1
assessment freshness CURRENT 1
```

이 값도 특정 실습 시점의 결과이며 제품의 고정 기대값은 아니다.

## 9. `CURRENT`의 의미

보고서의 assessment freshness는 다음 세 가지다.

- `CURRENT`: 현재 finding/asset context와 저장된 평가 context 일치
- `STALE`: 저장된 평가 후 상태 또는 context 변경
- `MISSING`: 저장된 평가 없음

`CURRENT`를 다음과 같이 해석하면 안 된다.

- 외부 CVSS가 지금도 최신이다
- EPSS가 지금도 동일하다
- CVE가 확정되었다
- 시스템이 안전하다

단지 **현재 DB snapshot과 저장 당시 평가 입력이 일치한다**는 뜻이다.

## 10. DVWA / Nuclei 검증 경계

프로젝트에는 로컬 DVWA, Nuclei, Selenium screenshot을 위한 코드가 있다.

이 기능은 승인된 실습환경에서 다음을 연습하기 위한 것이다.

- 웹 서비스 접근
- 도구 실행
- 결과 파싱
- screenshot/evidence 저장

다만 현재 CVE 상태 전이의 핵심 검증은
`verification/cve_verifiers.py`의 CVE별 보수적 verifier다.

따라서 면접에서는
"Nuclei 결과로 모든 CVE를 자동 확정했다"고 설명하지 않는다.

## 11. 실패에서 확인한 것

프로젝트 개선 과정에서 단순 happy-path만 확인하지 않았다.

대표적인 경계:

- 긴 포트 범위 문자열이 기존 VARCHAR 길이를 초과할 수 있음
  → compact range 표현 + MEDIUMTEXT
- 배너만으로 CVE를 확정할 위험
  → CANDIDATE와 검증 단계를 분리
- timeout을 비취약으로 오판할 위험
  → ERROR 상태 분리
- 외부 score 조회 오류를 0점으로 오판할 위험
  → NULL/incomplete/UNASSESSED 유지
- 반복 평가가 같은 row를 계속 추가할 위험
  → canonical input hash + observations
- 보고서 생성 때 source를 다시 조회하면 snapshot이 흔들림
  → read-only consistent snapshot

이런 실패 경계를 테스트에 남겨 회귀를 방지했다.

## 12. 최종 최종 재현 체크리스트

최종에는 새 기능을 추가하지 않고 다음을 처음부터 다시 확인한다.

```text
[ ] 가상환경 / requirements
[ ] .env 및 secret 비추적
[ ] Docker MySQL healthy
[ ] 전체 unit/regression tests
[ ] scope dry-run
[ ] loopback scan
[ ] service/version fingerprint
[ ] CVE candidate preview/save
[ ] read-only verifier
[ ] risk preview/save
[ ] JSON/PDF report
[ ] DB duplicate / history checks
[ ] secret checker
[ ] compileall
[ ] docker compose config
[ ] git diff --check
[ ] git working tree clean
```

실제 외부 서버를 무단 스캔하는 항목은 체크리스트에 포함하지 않는다.
