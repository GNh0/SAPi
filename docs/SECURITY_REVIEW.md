# 보안 검토와 수정 기록

2026-09-27 구현 담당과 분리된 에이전트가 소스·검증 경계를 검토했습니다. 검토자는 초기 메시지 구현과 첫 상태 구현의 네 문제를 공개 시험 키·일회용 DB·loopback에서 직접 재현했고, 수정 코드와 회귀 시험을 읽기 전용으로 대조했습니다. 이 기록은 독립 에이전트 검토이며 외부 감사 기관의 인증은 아닙니다.

## 발견과 수정

| ID | 발견 | 수정·검증 |
| --- | --- | --- |
| SAPI-001 | JavaScript의 BOM JSON 수락 차이 | BOM 보존 뒤 strict parser 거절; 네 SDK 헤더·본문 회귀 통과 |
| SAPI-002 | 응답 사용량이 없을 때도 업무 실행 | handler·claim 전에 response reserve; 일회용 closure; 네 SDK 실행 0 확인 |
| SAPI-003 | 과거 DB 복원으로 상태 되살아남 | 필수 외부 HMAC checkpoint; 시작과 매 거래 검증; 복구는 새 빈 DB |
| SAPI-004 | 느린 본문이 종료 시간을 넘김 | 연결/헤더/본문을 포괄하는 absolute deadline; 네 SDK 지속 본문 시험 |
| SAPI-005 | 옛 정상 행 복원·live replay 삭제 | 현재 키·root·active·replay 상태를 checkpoint의 인증 트리에 연결 |
| SAPI-006 | root 행 삭제를 새 KEK로 취급 | 이미 committed root가 있으면 시작 거부; 카운터 초기화 회귀 |
| SAPI-007 | PostgreSQL host 목록의 Unix socket 조건 | 모든 host 항목에서 빈 값·일반/abstract Unix socket 거절; 운영 TLS 검사 |

독립 검토의 원본 시점·소스 해시·직접 재현/보고서 읽기 구분은 [원본 메모](../tests/results/security-review-agent.md)에 있습니다. 후속 소스 검토에서는 Windows protected DACL(현재 사용자·SYSTEM)과 PostgreSQL 연결 조건을 확인했습니다.

구현자가 실행한 최신 회귀와 패키지 소비는 [검증 기록](VALIDATION.md)에 있습니다. 원본 메모의 이전 소스/44개 상태 결과와 최신 실행 증거를 구분합니다.

[이전 alpha.2의 GitHub CI](https://github.com/GNh0/SAPi/actions/runs/36303335452)와 [alpha.3의 CI](https://github.com/GNh0/SAPi/actions/runs/36310806375)는 Windows·Ubuntu·PostgreSQL의 당시 검사를 통과했습니다. 버전별 CI 실행과 소스 해시 대조는 [검증 기록](VALIDATION.md)에 있습니다.

## alpha.3 애플리케이션 처리 검토

추가 기능은 구현 담당과 분리된 에이전트가 SDK·서비스·저장소·패키징/CI 소스를 읽기 전용으로 검토했습니다. 최신 수정과 회귀 코드를 정적으로 재확인했으며 읽은 범위에서 확정한 미해결 결함은 없습니다. [원본 기록](../tests/results/application-review-agent.md)은 읽은 파일·기준 HEAD와 실행하지 않은 범위를 명시합니다.

| 발견 | 수정·실행 검증 |
| --- | --- |
| JS identifier/uuid의 마지막 LF 수락, null 설정 기본값 | 완전 문자열 끝·필드 존재 검사, 네 SDK 동일 벡터 |
| 출력 예산·스키마·다음 버전 실패 뒤 DB 커밋 | 트랜잭션 안에서 결과 검사, 실제 API 요청 후 롤백 확인 |
| .NET command 공급자 예외 시 자원 누락 | 실패 시 Dispose, 소스 경로 대조 |
| quota 기간 연장 뒤 이전 만료 시점에 사용량 초기화 | live global row의 expiry도 원자적으로 연장, 가상 시간 회귀 |
| Python 패키지 소비의 tuple/list 비교 오류 | 반환 tuple과 비교, 격리 소비 실행 |
| TCP 연결 뒤 TLS 협상에 전체 예산 미적용 | SSL 객체를 먼저 보관하고 남은 timeout으로 handshake, 지연 연결·협상 회귀 |
| SQL 열의 대소문자 별칭으로 owner/id 변경 허용 | 네 SDK ASCII casefold 불변 열·중복 검사, 공통 선언 벡터 |
| Content-Length보다 짧은 외부 JSON 응답 수락 | 실제 본문 길이 비교, 유효 JSON prefix를 보내고 닫는 회귀 |

처음 세 항목은 앞선 중간 소스 검토와 수정에서 다뤘고, 원본 추가 검토 기록은 뒤의 다섯 항목과 최종 소스 범위를 포함합니다. 신규 검토자는 실행·외부 연결·재현을 하지 않았으며 실행 결과는 주 담당의 검증 보고서와 CI로 구분합니다. 기관의 독립 보안 인증으로 표현하지 않습니다.

## 의존성

초기 OSV 조회에서 빌드 도구 setuptools 80.9.0과 wheel 0.45.1의 공지를 확인해 각각 84.0.0·0.48.0으로 교체했습니다. [alpha.3 조회](../tests/results/dependency-audit-windows.json)는 설치된 PyPI·Maven 17개 의존성에서 공지 발견 0건입니다. alpha.4에서는 Python 3.9 SDK의 별도 의존성과 복원된 NuGet 런타임·빌드 의존성도 조회합니다. 결과와 실제 조회 버전은 [alpha.4 보고서](../tests/results/alpha4/dependency-audit.json)에 있습니다.

## alpha.4 구버전 호환 검토

구버전 암호화·전송·입력 검증과 패키지/CI 경로를 분리된 에이전트가 소스 검토했습니다. 실행 검증은 주 담당의 [구버전 보고서](../tests/results/alpha4/compatibility.json)와 구분합니다.

| 발견 | 수정·검증 |
| --- | --- |
| Java 8에서 timeout 뒤 동기 disconnect가 호출자를 붙잡을 수 있음 | 제한된 별도 정리 작업으로 분리, 중단된 부분 본문 deadline 회귀 |
| Python 구버전 표준 라이브러리의 IP 분류 차이 | 고정된 특수 주소 범위와 IPv6 public unicast 조건, Python 3.9 주소 회귀 |
| Python 3.9에서 타입 정보 해석 시 최신 union 문법 실패 | Optional/Union 타입으로 변경, 실제 get_type_hints 실행 |
| .NET 구버전 state 전송 실패의 오류 코드 차이 | state_unavailable로 일치시키고 기존 authority 오류 보존 |
| CI에서 SDK Python 의존성 경로와 공지 조회 누락 | 별도 SDK dependency 경로를 검사와 audit 모두 전달 |
| 검증 뒤 추가된 파일과 검증·패키징 도중 소스 변경 | 전체 파일 목록·SHA-256의 시작/종료 및 보고서 일치 검사 |

최종 검토 범위와 한계는 [원본 보고서](../tests/results/alpha4/compatibility-review-agent.md)에 있습니다. 낮은 런타임 버전에서도 동일한 메시지 암호와 인증 규칙을 유지하며, 운영체제·런타임 자체의 보안 패치를 대체하지 않습니다.

## 검토 한계와 신뢰 조건

DB와 체크포인트·KEK/감사 키가 모두 과거로 복원되거나 해당 관리자 신뢰 영역이 침해되면 검증 근거도 잃습니다. 체크포인트 먼저 기록 후 COMMIT 사이의 실제 프로세스 종료는 거부 상태를 유지하며, 가용성 복구는 새 키 발급을 포함한 격리 복구로 수행합니다.

시험 환경의 결과가 임의 파일 시스템의 전원 장애 내구성·운영 PKI·업무 정책·OS/런타임 보안까지 인증하는 것은 아닙니다. PSK의 서명/전방향 비밀성 한계와 처리에 이미 진입한 요청의 폐기 범위는 [보안 모델](../spec/SECURITY.md)에 있습니다.
