# SAPi

HTTP와 HTTPS에서 API 요청·응답을 암호화하고, 인증·재전송 방지·권한·입력 검증을 적용하는 메시지 보안 규격과 SDK입니다.

- AES-256-GCM 메시지 암호화와 HKDF-SHA-256 요청·응답 키 분리
- SQLite·PostgreSQL 영속 재전송 저장소와 공유 사용량 관리
- mTLS 기반 키 발급·자동/수동 회전·폐기·루트 키 교체
- 상태 변조·과거 상태 복원 탐지와 검증된 감사 기록
- .NET, Java, Python, JavaScript SDK 및 ASP.NET Core 연결 계층

메시지 규격은 언어·프레임워크와 독립적입니다. 각 SDK는 동일한 메시지와 상태 관리 API를 사용합니다.

## 시작하기

패키지 버전은 `0.1.0-alpha.2`이며, 메시지 규격은 `SAPI/0.1`입니다.
[설치와 SDK 사용법](docs/USAGE.md), [상태 서비스 운영](docs/STATE.md)을 제공합니다.

```text
sapi-state init --directory /secure/sapi/operator --anchor-directory /secure/sapi-checkpoints --service orders --subject client-1
sapi-state serve --config /secure/sapi/operator/config.json
```

다른 터미널에서 클라이언트 키를 발급합니다.

```text
sapi-state issue --config /secure/sapi/operator/config.json --service orders --subject client-1 --scope orders
```

SDK의 `StateClient`를 키 공급자와 재전송 저장소에 연결하면 발급된 키와 영속 상태를 사용합니다. 서버 작업에는 입력 검증, 권한 정책, 업무 함수를 함께 등록합니다.

## 구성

| 경로 | 내용 |
| --- | --- |
| [spec/](spec/PROTOCOL.md) | 메시지 규격과 새 구현 지침 |
| [services/state/](services/state/) | mTLS 상태 서비스, 영속 저장소, 운영 CLI |
| [sdks/](sdks/) | 언어별 패키지와 전송·상태 어댑터 |
| [docs/](docs/ARCHITECTURE.md) | 구조, 사용법, 운영, 검증 |
| [tests/](tests/DRIVER_CONTRACT.md) | 공통 벡터와 상호운용·보안 회귀 검사 |

## 빌드와 검증

Python 3.10+, .NET SDK 8+, Node.js 20+, JDK 11+ 환경에서 실행합니다.

```text
python tools/bootstrap.py --work-dir /absolute/scratch/sapi
python tools/verify.py --work-dir /absolute/scratch/sapi
python tools/verify_state.py --work-dir /absolute/scratch/sapi
python tools/audit_dependencies.py --work-dir /absolute/scratch/sapi
python tools/package.py --work-dir /absolute/scratch/sapi --output-dir /absolute/path/dist
python tools/smoke_packages.py --work-dir /absolute/scratch/sapi --package-dir /absolute/path/dist
```

NuGet, Python wheel/sdist, npm tarball, Java JAR/POM을 생성합니다. 패키지 설치 경로와 검증 기록은 [USAGE](docs/USAGE.md), [VALIDATION](docs/VALIDATION.md)에 있습니다.

공유 키 기반 인증의 신뢰 조건, HTTP에서 노출되는 메타데이터, 키 유출과 복구의 범위는 [보안 모델](spec/SECURITY.md)을 확인하세요. [보안 검토 기록](docs/SECURITY_REVIEW.md)은 발견 사항과 수정 검증을 정리합니다.
