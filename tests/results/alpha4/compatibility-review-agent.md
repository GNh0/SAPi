# SDK 구버전 호환성 독립 소스 검토

검토일: 2026-09-28. 기준 HEAD: `8809c16dfaa7cafa9afac56c41c523f6c1e2b7ef` 및 검토 시점의 미커밋 변경.

읽은 범위에서 남아 있는 확정 SDK 결함은 발견하지 못했다. 아래 결과는 에이전트의 소스 검토이며 외부 전문기관 감사나 인증이 아니다. 구현 파일을 수정하지 않았으며 이 보고서만 작성했다.

## 검토 범위

- .NET: `sdks/dotnet`의 프로젝트·빌드 설정, `Compatibility/Runtime.cs`, `Compatibility/LegacyTransport.cs`, Codec·Keys·JsonFormat·Schema·OwnedSql·SecureServer·HttpBinding·StateClient·IReplayStore, ASP.NET Core 어댑터, 새 classic ASP.NET `SapiHttpHandler` 및 경로 등록 코드.
- Java: Java 8 빌드 설정과 수정된 Codec·키 제공자·Schema·SecureServer·OwnedSql·SqlPlan·HttpBinding·StateClient·Legacy·Transport.
- Python: SDK 패키지 설정, 수정된 Codec·서버 타입 표기 및 `egress.py`의 주소 정책·TLS·응답 처리. 서비스의 Python 3.10 이상 설정도 확인했다.
- JavaScript: Node 16 패키지 설정, `platform.js`·`http-node.js`, 수정된 codec·http·schema·serialization·server·sql, 실제 Node 상태 클라이언트 호출 경로.
- 실제 호출자와 검증 도구: 네 SDK 드라이버, .NET net462/net6 드라이버와 App.config, 기본 및 구버전 Windows/Linux 구현 목록, `implementations.py`, 네 검증 도구, `verify_compatibility.py`, `package.py`, `smoke_packages.py`, `audit_dependencies.py`, `.github/workflows/conformance.yml`, 관련 사용·패키지 문서.
- 로컬 원문 근거: NuGet System.Text.Json 8.0.6 및 BouncyCastle 2.7.0 패키지 메타데이터, Python 의존성 METADATA/WHEEL, Python 3.10 ipaddress 원문과 Python 3.9.13 배포 ZIP의 ipaddress 바이트코드, Java 8u504 `src.zip`의 연결 해제·청크 스트림 코드. 바이트코드는 코드 객체를 읽어 역어셈블했으며 SDK나 주소 판정 함수를 실행하지 않았다.

## 확인한 수정

- .NET Protocol은 net462/netstandard2.0/net6.0/net8.0을 대상으로 하며 ASP.NET Core는 net6/net8, classic ASP.NET은 net462로 분리되어 있다. 최신 런타임 전용 암호화·PEM·컬렉션·인터페이스 API의 대체 구현과 조건부 컴파일, 드라이버의 실제 호출자를 확인했다. System.Text.Json 8.0.6과 구버전 대상의 BouncyCastle 의존성 연결도 확인했다.
- 구버전 .NET 암호화에서 인증 완료 전 평문을 반환하지 않고, 실패 시 버퍼를 정리한다. PEM 인증서 구성의 예외 정리, 레거시 상태 전송 오류의 `state_unavailable` 변환, 응답 크기·미디어·선언 길이 검사 및 요청 시간 제한 경로를 확인했다.
- Java 8에 없는 API를 대체한 코드와 불변 컬렉션의 null·중복 처리 계약을 읽었다. 시간 제한 시 호출자가 동기 `disconnect()`를 기다리지 않도록 별도의 유한 cleanup 풀에 정리를 맡기는 최종 구현을 확인했다.
- Node 16에서는 네이티브 Web Crypto 및 제한이 있는 HTTP 구현을 연결하며, `Object.hasOwn`·`structuredClone` 등 최소 버전에 없는 API의 대체 코드를 사용한다. 실제 드라이버와 패키지 소비자의 호출 경로도 확인했다.
- Python SDK 최소 버전은 의존성 조건과 일치하는 3.9.2이며, SDK 빌드의 setuptools 하한은 3.9에서 사용할 수 있도록 조정되어 있다. egress는 런타임별 `ipaddress.is_global` 차이를 보완하는 고정 IPv4/IPv6 범위를 적용하고, 예약·사이트 로컬·매핑·전환 주소를 추가로 제한한다.
- 각 검증 도구가 대상 모듈을 가져오기 전에 전체 소스 해시를 확보하고 종료 시 다시 비교한다. 재사용 보고서와 패키징의 시작 검사도 전체 해시 사전의 동등성을 요구하며, 패키징 종료 시 소스가 바뀌었으면 실패하는 최종 코드를 확인했다.
- Python SDK와 검증 하네스의 의존성 경로를 분리해 드라이버·주소 정책 검사·패키지 소비 검사에 전달한다. 의존성 감사가 선택한 SDK 의존성 경로도 읽는 것을 확인했다. 런타임 보고는 PATH 추정 대신 각 실제 드라이버의 응답을 사용한다.
- 구버전 CI의 Node 16·Java 8·Python 3.9·.NET 6/8 및 Windows net462 연결, 필요한 어셈블리의 패키지 포함 검사와 소비자 참조를 읽었다. 실제 CI 실행이나 IIS 요청 처리를 검증했다는 의미는 아니다.
- 후속 소스 검토: `tools/package.py`가 npm 7에서 지원하지 않는 `--pack-destination` 대신 새 scratch 디렉터리에서 SDK 절대 경로를 인자로 `npm pack`을 실행하고, 현재 패키지 이름·버전과 일치하는 tgz를 출력 디렉터리로 복사하는 변경을 확인했으며 확정 결함을 발견하지 못했다.

## 실행 근거와 한계

주 에이전트가 제공한 최종 로컬 실행 결과는 메시지 486/486, 상태 78/78, 처리 보안 57/57, 애플리케이션 18/18, Python 3.9 주소 정책 10개 통과다. 제공된 런타임 정보는 Python 3.9.13, Node 16.0.0, Java 1.8.0_504, .NET 6.0.36 및 8.0.22, Windows Framework CLR 4.x다. 이 검토 에이전트가 테스트를 직접 실행하거나 결과 원본을 독립적으로 재현한 수치가 아니다.

검토 에이전트는 빌드·SDK 실행·HTTP/DB 재현·외부 네트워크·외부 시스템 변경을 수행하지 않았다. net462 대상 실행은 설치된 Windows CLR 4.x를 사용하므로 원래 .NET Framework 4.6.2 런타임에서의 동작 증명과 구분해야 한다. classic ASP.NET의 전체 IIS 요청 경로, 실제 CI 작업, 다른 OS와 브라우저의 동작은 직접 확인하지 않았다. 패키지 빌드·소비 실행의 최종 결과는 주 에이전트의 별도 증거로 판단해야 한다.
