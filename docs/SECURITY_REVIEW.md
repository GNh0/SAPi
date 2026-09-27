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

구현자가 최종 소스로 실행한 회귀 결과는 [292개 메시지 시험](../tests/results/verification-windows.json), [49개 상태 시험](../tests/results/state-verification-windows.json), [5종 패키지 소비](../tests/results/package-smoke-windows.json)에 있습니다. 원본 메모의 이전 소스/44개 상태 결과와 최종 실행 증거를 구분합니다.

## 의존성

초기 OSV 조회에서 빌드 도구 setuptools 80.9.0과 wheel 0.45.1의 공지를 확인해 각각 84.0.0·0.48.0으로 교체했습니다. 패키지 build-system의 setuptools 최소 버전도 수정했습니다. [최종 조회](../tests/results/dependency-audit-windows.json)는 설치된 PyPI·Maven 17개 의존성에서 공지 발견 0건입니다.

## 검토 한계와 신뢰 조건

DB와 체크포인트·KEK/감사 키가 모두 과거로 복원되거나 해당 관리자 신뢰 영역이 침해되면 검증 근거도 잃습니다. 체크포인트 먼저 기록 후 COMMIT 사이의 실제 프로세스 종료는 거부 상태를 유지하며, 가용성 복구는 새 키 발급을 포함한 격리 복구로 수행합니다.

시험 환경의 결과가 임의 파일 시스템의 전원 장애 내구성·운영 PKI·업무 정책·OS/런타임 보안까지 인증하는 것은 아닙니다. PSK의 서명/전방향 비밀성 한계와 처리에 이미 진입한 요청의 폐기 범위는 [보안 모델](../spec/SECURITY.md)에 있습니다.
