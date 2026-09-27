# 검증 기록

2026-09-27 Windows에서 `alpha.3` 소스의 메시지 **292/292**, 영속 상태 **50/50**, 처리 보안 **31/31**, 애플리케이션 **14/14**가 통과했습니다. 패키지 **11개**를 생성하고 별도 프로젝트의 소비 **6종**을 실행했습니다. OSV의 정확한 의존성 조회는 **17개, 공지 발견 0건**입니다.

같은 구현 커밋 [`118efb9`](https://github.com/GNh0/SAPi/commit/118efb9da231a45a239cb382a0ecb63a2bf5dd4d)의 [GitHub CI](https://github.com/GNh0/SAPi/actions/runs/36310806375)는 세 작업 모두 통과했습니다. 내려받은 보고서의 SDK·서비스 소스 해시 79개와 네 검증 보고서·패키지 manifest·실제 패키지 SHA-256을 대조했습니다.

| CI 작업 | 메시지 | 영속 상태 | 처리 보안 | 애플리케이션 | 패키지 |
| --- | --- | --- | --- | --- | --- |
| Windows | 292/292 | SQLite 50/50 | 31/31 | 14/14 | 6종 소비, 11개 생성 |
| Ubuntu | 292/292 | SQLite 50/50 | 31/31 | 14/14 | 6종 소비, 11개 생성 |
| PostgreSQL | — | SQLite·PostgreSQL 51/51 | — | SQLite·PostgreSQL 15/15 | — |

PostgreSQL 작업은 공통 상태 50개·애플리케이션 14개에 실제 PostgreSQL을 실행하는 aggregate case를 각각 하나씩 추가합니다. 해당 DB에서 별도 프로세스의 주체 quota·키 수명·재전송, 소유자 조건·데이터 바인딩·동시 기대 버전 변경·상태 전이를 검사합니다. 의존성 조회는 CI Windows 16개·Ubuntu 14개, 공지 발견 0건입니다. Python 버전과 OS에 따라 설치되는 의존성 수는 다릅니다.

로컬 Windows 보고서와 CI Windows 보고서를 별도로 보관합니다. 각각의 패키지 manifest가 자기 실행의 네 보고서 SHA-256을 참조하며 두 실행의 보고서를 섞지 않습니다.

## 검사 범위

| 검사 | 실행 내용 |
| --- | --- |
| 공통 암호 벡터 | HKDF 표준 구현, 고정 JWE 요청·응답 일치 |
| 메시지 상호운용 | 등록된 4개 SDK의 16개 요청·응답 조합 |
| HTTP·HTTPS | 네이티브 클라이언트 × SDK 서버 처리 각각 16개 조합 |
| ASP.NET Core | 실제 Kestrel endpoint, 평문 거절, 4종 클라이언트 |
| 파싱·인증 | 암호문·IV·태그·AAD 변조, BOM/UTF-8/중복 키/숫자/크기/시간 위반 |
| 구조화 차등 퍼징 | SDK마다 seeded JSON 100개와 인증 변조 100개, 총 800회 |
| mTLS·영속 SDK | 실제 관리 서비스와 SDK 16개 조합, SDK 재시작 뒤 replay 차단 |
| 키 수명 | 발급·자동/수동 회전·유예·폐기·응답 예산 사전 확보 |
| 운영 명령 | 관리자/서버 인증서 교체·등록 제거·KEK 제거·운영 lease |
| 프로세스 공유 | 별도 8개 프로세스의 한 번 예약과 전역 사용량 제한 |
| 공유 부하 | 신규 claim 64개와 중복 64개, 동시 8개 작업 |
| 장애·복구 | anchor 기록 실패, COMMIT 전 실제 프로세스 종료, 전체 DB 과거 복원과 새 빈 DB 복구 |
| 상태 무결성 | 서명된 옛 키 행·삭제된 replay·root 카운터·audit/checkpoint 수정 거절 |
| 인증 상태 트리 | 500회 seeded 삽입/수정/삭제와 모델 대조 |
| 시간 제한 | 지속해서 도착하는 HTTP 본문도 네 SDK의 전체 응답 deadline으로 종료 |
| 처리 스키마 | 네 SDK의 닫힌 필드·NoSQL 연산자·타입 혼동·UTF-8·null 설정·완전 문자열 끝 |
| 실제 SQL | 네 SDK SQL 계획을 SQLite에 바인딩 실행, 소유자·변경 열·casefold 불변 열 검사 |
| 처리 파이프라인 | 16개 SDK 조합의 추가 필드·기능 scope·비밀 출력·작업 한도 |
| 주체 quota | 동시 authority·별도 프로세스, 재시작·키 회전·기간 연장, 상태 삭제 탐지 |
| 선언형 서비스 | 네 클라이언트 × HTTP/HTTPS의 SQL·소유권·필드·업무 전이 |
| DB 거래 경계 | 16개 동시 기대 버전 변경 중 1개, 출력 실패 롤백과 버전 상한 |
| 외부 요청 | IP·DNS 고정·리다이렉트·TLS 호스트·시간·헤더·framing·짧은 본문·출력 검사 |
| 패키지 소비 | NuGet, npm, Python SDK/state/application wheel, Java JAR를 별도 프로젝트에서 사용 |

HTTP·HTTPS 조합의 서버 소켓은 Python 전송 어댑터이며 메시지 복호화·정책·처리·응답 암호화는 각 언어의 별도 프로세스가 수행합니다. ASP.NET Core는 실제 Kestrel도 별도로 시험합니다.

상태 시험은 실제 mTLS 서비스와 SQLite를 사용합니다. CI PostgreSQL 작업은 별도 PostgreSQL 18.6 컨테이너에서 두 authority·8개 프로세스·공통 체크포인트·전역 사용량·폐기를 검사하고 서로 다른 authority endpoint 사이의 SDK 16개 조합을 실행합니다. loopback 시험 DB의 plaintext 예외와 운영 `verify-full` 조건은 구분합니다.

## 증거

- [메시지 결과](../tests/results/verification-windows.json)
- [상태·수명·장애 결과](../tests/results/state-verification-windows.json)
- [처리 보안 결과](../tests/results/security-verification-windows.json)
- [애플리케이션 결과](../tests/results/application-verification-windows.json)
- [추가 독립 코드 리뷰](../tests/results/application-review-agent.md)
- [패키지 SHA-256](../tests/results/packages-windows.json)
- [패키지 소비 결과](../tests/results/package-smoke-windows.json)
- [의존성 조회](../tests/results/dependency-audit-windows.json)
- [독립 에이전트 소스 검토](SECURITY_REVIEW.md)
- [CI 실행 요약과 보고서 해시 대조](../tests/results/ci-summary.json)
- [CI Windows 메시지 결과](../tests/results/ci-windows/verification.json)
- [CI Windows 패키지 manifest](../tests/results/ci-windows/packages.json)
- [Ubuntu 메시지 결과](../tests/results/verification-ubuntu.json)
- [Ubuntu 상태 결과](../tests/results/state-verification-ubuntu.json)
- [Ubuntu 처리 보안 결과](../tests/results/security-verification-ubuntu.json)
- [Ubuntu 애플리케이션 결과](../tests/results/application-verification-ubuntu.json)
- [실제 PostgreSQL 상태 결과](../tests/results/state-verification-postgres.json)
- [실제 PostgreSQL 애플리케이션 결과](../tests/results/application-verification-postgres.json)

각 시험 보고서는 사용한 SDK/서비스 소스 SHA-256을 기록하고 패키지는 네 통과 보고서 각각의 소스 일치를 요구합니다. 시험·운영 개인 키는 기록에 포함하지 않습니다.

로컬 Windows 환경은 Python 3.10.4, cryptography 50.0.1, psycopg 3.3.6, Node.js 24.13.1, .NET SDK 9.0.308(net8.0 target), Microsoft JDK 11.0.16.1입니다. Jackson core/databind 2.22.3·annotations 2.22, setuptools 84.0.0·wheel 0.48.0을 사용합니다. 운영 런타임/OS 패치와 미보고 취약점은 의존성 공지 조회와 별개입니다. SQL 계획은 네 SDK가 생성하고 실제 SQLite DB-API로 실행합니다. Java JDBC·.NET ADO.NET 외부 DB 드라이버별 실제 연결 검증과 구분합니다.

## 재현

```text
python tools/bootstrap.py --work-dir /absolute/scratch/sapi
python tools/verify.py --work-dir /absolute/scratch/sapi
python tools/verify_state.py --work-dir /absolute/scratch/sapi
python tools/verify_security.py --work-dir /absolute/scratch/sapi
python tools/verify_application.py --work-dir /absolute/scratch/sapi
python tools/audit_dependencies.py --work-dir /absolute/scratch/sapi
python tools/package.py --work-dir /absolute/scratch/sapi --output-dir /absolute/path/dist
python tools/smoke_packages.py --work-dir /absolute/scratch/sapi --package-dir /absolute/path/dist
```

전용 loopback PostgreSQL 시험 DB가 있을 때 `verify_state.py`와 `verify_application.py`에 `--postgres "postgresql://...@127.0.0.1/...?... "`를 추가합니다. 이 시험은 해당 시험 DB의 SAPI 테이블을 초기화하므로 운영 DB를 지정하지 않습니다.

[GitHub CI](https://github.com/GNh0/SAPi/actions/workflows/conformance.yml)는 Windows·Ubuntu·PostgreSQL 작업과 실행별 결과 파일 및 패키지를 보관합니다. 실제 배포의 전원 장애, 복제본 저장소의 내구성, 업무 거래의 멱등성, 일반 브라우저 실행과 모든 웹 프레임워크를 포괄하는 시험은 이 기록과 구분합니다.
