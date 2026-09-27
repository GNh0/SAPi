# SAPi

HTTP와 HTTPS 모두에서 사용할 수 있는 **언어 독립적인 API 메시지 보안 규격**과 참조 SDK입니다.
API의 요청·응답 자체를 암호화하고, 서버는 메시지 인증·재전송 검사·권한·입력 검증을 거쳐 등록된 기능만 실행합니다.

현재 버전은 **0.1 실험용 프로토타입**입니다. 외부 보안 감사를 받은 운영용 제품이나 국제 표준으로 주장하지 않습니다.

## 구성

| 경로 | 역할 |
| --- | --- |
| `spec/PROTOCOL.md` | 다른 언어에서도 구현할 수 있는 공통 규격 |
| `spec/SECURITY.md` | 신뢰 조건, 보호 범위와 남은 위험 |
| `spec/IMPLEMENTING.md` | 임의 언어의 새 구현 지침 |
| `docs/ARCHITECTURE.md` | 모듈 책임·의존 방향·확장 원칙 |
| `sdks/dotnet/` | .NET 8+ 라이브러리와 ASP.NET Core 연결 계층 |
| `sdks/java/` | Java 11+ 라이브러리 |
| `sdks/python/` | Python 3.10+ 패키지 |
| `sdks/javascript/` | JavaScript ESM, Web Crypto 기반 |
| `tests/` | 공통 벡터, 공격 실패 검사, 언어 간 상호 운용 검사 |
| `examples/` | HTTP·HTTPS 로컬 데모 |

**지원 언어를 네 개로 제한하지 않습니다.** 위 SDK는 최초의 참조 구현입니다. SDK의 프레임워크 종속성보다 **규격 준수**가 연결 조건입니다. 다른 언어도 UTF-8 JSON, base64url, HKDF-SHA-256, AES-256-GCM을 구현하면 같은 메시지를 처리할 수 있습니다. 등록된 구현 수에 따라 모든 조합을 자동 검사하며, 아직 없는 SDK의 실제 실행을 검증했다고 주장하지 않습니다.

## 보안 모델

- 클라이언트마다 32바이트 무작위 공유 키를 신뢰할 수 있는 별도 경로로 발급합니다.
- 요청과 응답 키를 분리하고, 모든 메시지에 새 무작위 IV를 사용합니다.
- 인증정보 대신 해당 키의 소유를 검증하며, 권한은 서버에 등록된 키의 주체와 범위로 판단합니다.
- 작업 이름, 데이터, 요청 ID, 발급·만료 시간을 암호화합니다.
- 검증 실패 시 업무 처리 함수를 실행하지 않습니다. 정상 인증된 요청의 업무 오류도 암호화해 응답합니다.

키를 공개 JavaScript 번들에 포함시키면 안 됩니다. 일반 HTTP 웹페이지로 처음 받은 실행 코드는 중간자에게 바뀔 수 있고, Web Crypto는 브라우저의 보안 컨텍스트를 요구합니다. Node.js나 신뢰할 수 있게 배포한 애플리케이션의 HTTP 메시지 보호와는 구분해야 합니다.

HTTP에서는 바깥 URL·헤더·트래픽 크기와 시간이 보이며, 차단·지연 공격도 가능합니다. HTTPS 사용 시 TLS 보호가 추가됩니다. [FAPI 2.0](https://openid.net/specs/fapi-security-profile-2_0-final.html)과 달리 이 실험 규격은 TLS를 메시지 보안의 필수 조건으로 두지 않습니다.

## 실행·검증

Python 3.10+, .NET SDK 8+, Node 20+, JDK 11+ 환경에서 의존성·컴파일 중간 출력을 둘 임시 폴더를 지정합니다.

```text
python tools/bootstrap.py --work-dir /absolute/scratch/sapi
python tools/verify.py --work-dir /absolute/scratch/sapi
python tools/package.py --work-dir /absolute/scratch/sapi --output-dir /absolute/path/dist
```

[설치·사용 예제](docs/USAGE.md), [실제 검증 결과](docs/VALIDATION.md), [새 구현 시험 계약](tests/DRIVER_CONTRACT.md)을 제공합니다. NuGet 2개, Python wheel/sdist, npm tarball, Java JAR/POM을 로컬로 만들며 공개 패키지 저장소에는 게시하지 않습니다. 프로젝트 라이선스는 아직 지정하지 않았습니다.
