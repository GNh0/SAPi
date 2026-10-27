# SAPi

SAPi는 API 요청과 응답을 암호화하고 인증된 주체에 따라 작업을 처리하는 메시지 규격과 SDK입니다. AES-256-GCM과 HKDF-SHA-256을 사용하며, 서버 작업에 입력·출력 스키마, scope와 권한 정책을 등록합니다. 전송 계층의 HTTPS 설정과 기존 API의 권한 정책을 대신하지는 않습니다.

상태 서비스는 키 발급·회전·폐기와 재전송 및 사용량 상태를 관리합니다. 애플리케이션 서비스에는 소유자별 데이터 접근, 버전과 상태 전이를 다루는 선언형 API가 포함됩니다. .NET, Java, Python, JavaScript SDK와 ASP.NET 연결 계층을 제공합니다. 현재 버전은 실험적인 alpha 릴리스입니다.

## 지원 환경

| 구성 | 최소 환경 |
| --- | --- |
| .NET SDK | .NET Framework 4.6.2, .NET Standard 2.0, .NET 6 |
| ASP.NET 어댑터 | .NET Framework 4.6.2 / ASP.NET Core 6 |
| Java SDK | Java 8, AES-256 활성화 |
| Python SDK | Python 3.9.2 |
| JavaScript SDK | Node.js 16 / Web Crypto를 제공하는 브라우저 |
| 상태·애플리케이션 서비스 | Python 3.10 |

구버전 설정과 설치 예시는 [SDK 사용법](docs/USAGE.md)에 있습니다.

## 시작하기

패키지 버전은 `0.1.0-alpha.4`이며, 메시지 규격은 `SAPI/0.1`입니다.
[애플리케이션 서비스](docs/APPLICATION.md), [SDK 사용법](docs/USAGE.md), [상태 서비스 운영](docs/STATE.md)을 제공합니다.

```text
sapi-state init --directory /secure/sapi/operator --anchor-directory /secure/sapi-checkpoints --service orders --subject client-1
sapi-application init --directory /secure/sapi/application --state-config /secure/sapi/operator/config.json --service orders
sapi-state serve --config /secure/sapi/operator/config.json
```

다른 터미널에서 클라이언트 키를 발급합니다.

```text
sapi-state issue --config /secure/sapi/operator/config.json --service orders --subject client-1 --scope orders_read --scope orders_write
sapi-application serve --config /secure/sapi/application/config.json
```

SDK의 `StateClient`를 연결하면 발급된 키, 재전송 저장소, 주체별 호출 한도를 공유합니다. 서버 작업에는 입력·출력 스키마, 권한 정책, 업무 함수를 함께 등록합니다.

기존 API와 병행하는 방법은 [전환 예제](docs/OPT_IN_MIGRATION.md)를 참고하세요. 이 예제는 로컬 Python 실증이며, 기존 클라이언트나 운영 환경을 자동으로 변환하지 않습니다.

## 구성

| 경로 | 내용 |
| --- | --- |
| [spec/](spec/PROTOCOL.md) | 메시지 규격과 새 구현 지침 |
| [services/state/](services/state/) | mTLS 상태 서비스, 영속 저장소, 운영 CLI |
| [sdks/](sdks/) | 언어별 패키지와 전송·상태 어댑터 |
| [docs/](docs/ARCHITECTURE.md) | 구조, 사용법, 운영, 검증 |
| [tests/](tests/DRIVER_CONTRACT.md) | 공통 벡터와 상호운용·보안 회귀 검사 |

## 빌드와 검증

Python 3.10+, .NET SDK 8+, Node.js 20+, JDK 11+ 환경에서 빌드합니다. 패키지 소비 검사는 .NET 6·8 런타임을 함께 사용합니다.

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

NuGet, Python wheel/sdist, npm tarball, Java JAR/POM을 생성합니다. 패키지 설치 경로와 검증 기록은 [USAGE](docs/USAGE.md), [VALIDATION](docs/VALIDATION.md)에 있습니다.

[애플리케이션 서비스](docs/APPLICATION.md)는 선언한 데이터와 업무 규칙으로 API를 실행합니다. 패키징은 메시지·상태·처리 보안·애플리케이션의 네 통과 보고서와 현재 소스 해시를 각각 확인합니다. [방어 범위](docs/SECURITY_COVERAGE.md)에 구현과 검증을 정리합니다.

공유 키 기반 인증의 신뢰 조건, HTTP에서 노출되는 메타데이터, 키 유출과 복구의 범위는 [보안 모델](spec/SECURITY.md)을 확인하세요. [보안 검토 기록](docs/SECURITY_REVIEW.md)과 [비교 실험의 범위](docs/AUDIT_EVIDENCE.md)에서 기존 검증과 미측정 항목을 볼 수 있습니다.
