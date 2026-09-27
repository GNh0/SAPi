# 애플리케이션 경로 독립 코드 리뷰

- 검토일: 2026-09-27. 마지막 수정 재확인은 같은 날 수행했다.
- 대상 저장소: `C:\Users\User\Documents\Codex\SApi`.
- 기준 HEAD: `e04b732bd3d17d2c412c6824a78f7a4b71ea4fe2`. 검토 대상은 이 HEAD에 대한 현재 미커밋 변경과 새 파일이며 HEAD 자체의 실행 검증이 아니다.
- 방법: 실제 구현, 호출 경로, 규격, 최신 diff 및 회귀 검사 코드를 읽었다. 구현 파일은 변경하지 않았으며 이 보고서만 작성했다.
- 판정: 아래 5건을 주 에이전트에 전달했고, 주 에이전트가 적용한 수정을 다시 읽어 해당 경로의 정적 결함이 해소된 것을 확인했다. 마지막 읽은 범위에서 추가로 확정한 미해결 결함은 없다. 실행 결과나 기관 인증을 뜻하지 않는다.

## 발견 사항과 재확인

### 1. P2 — quota 기간 확대가 이전 만료 시점에 사용량을 초기화함

초기 코드의 `services/state/sapi_state/vault.py:313-316`은 이전 `expiry`가 지난 카운터를 삭제한 뒤 새 quota를 적용했다. 기존 60초 창의 사용량을 모두 소비한 상태에서 30초에 관리자가 period를 3,600초로 늘리면, 다음 호출이 60초에 올 때 이전 row가 삭제되어 새 요청이 허용됐다. 초기 `quota()`는 정책 row만 갱신하고 실제 global 카운터의 expiry를 연장하지 않았다.

현재 `vault.py:354-360`은 같은 거래에서 global row와 상태 트리의 일치 여부를 검사하고, 아직 살아 있는 row의 started/used를 유지한 채 period를 `max(old,new)`로 늘리고 expiry를 함께 갱신한다. `tools/verify_security.py:121-129`에는 기간 확대, 이전 만료 시점, 기간 축소, 새 만료 시점을 검사하는 가상 시간 벡터가 추가되어 있다. 해당 코드를 읽었으며 직접 실행하지 않았다.

### 2. P2 — Python 패키지 소비 검사가 정상 tuple을 list와 비교함

초기 `tools/smoke_packages.py:49`는 `SqlPlan.bind()[1]`을 `["client","record"]`와 비교했다. `sdks/python/sapi/sql.py`의 identity와 plan values는 tuple이므로 정상 패키지도 이 assert에서 중단되는 경로였다.

현재 `smoke_packages.py:49`는 `("client","record")`와 비교한다. 반환 계약과 비교 타입이 일치하는 것을 다시 읽어 확인했다. 패키징 또는 smoke 실행은 수행하지 않았다.

### 3. P2 — egress TLS handshake가 전체 시간 예산을 넘길 수 있음

초기 `sdks/python/sapi/egress.py:82-87`은 TCP 연결 뒤 timer를 시작했지만 기본 handshake를 포함한 `wrap_socket()`이 끝나기 전까지 transport에는 원래 socket을 남겼다. TLS 전환 중 원래 socket의 fd가 SSL socket으로 넘어가면 timer는 실제 handshake socket을 종료하지 못한다. TCP 연결이 예산 일부를 이미 소비했어도 TLS handshake는 연결 시작 시의 socket timeout을 이어받아 전체 예산을 넘길 수 있었다.

현재 `egress.py:87-88`은 `do_handshake_on_connect=False`로 SSL socket을 먼저 transport에 저장하고 남은 timeout을 설정한 뒤 handshake를 수행한다. `tools/verify_application.py:214-229`는 TCP 연결 지연과 응답하지 않는 TLS peer를 함께 둔 전체 deadline 벡터를 추가했다. 코드 경로를 다시 읽었으며 직접 timing 실험을 하지 않았다.

### 4. P2 — OwnedSql의 대소문자 별칭으로 불변 owner/id 열을 변경할 수 있음

초기 네 SDK의 생성자는 owner/id/write 열의 중복을 대소문자를 구분하여 검사하면서 생성 SQL에는 이름을 따옴표 없이 사용했다. 예를 들어 owner 열이 `owner`이고 write 목록에 `Owner`가 있으면 생성자가 허용했지만 SQLite와 PostgreSQL에서는 `UPDATE accounts SET Owner=? WHERE owner=? AND id=?`가 실제 소유자 열을 변경한다. 대소문자만 다른 identity 열 및 read/write 중복도 같은 문제가 있었다.

현재 수정 위치는 다음과 같다.

- Python: `sdks/python/sapi/sql.py:42-44`.
- JavaScript: `sdks/javascript/src/sql.js:22-23`.
- Java: `sdks/java/src/main/java/io/github/gnh0/sapi/OwnedSql.java:12-13`.
- .NET: `sdks/dotnet/SApi.Protocol/Security/OwnedSql.cs:41-42`.

모두 먼저 ASCII 식별자 형식을 제한하고 소문자 변환으로 identity/write 충돌과 read/write의 case-only 중복을 거절한다. 정상적인 혼합 대소문자 식별자는 유지한다. `tools/verify_security.py:61-63` 및 네 test driver의 `sql_config` 분기를 읽어 공통 벡터가 실제 생성자를 호출하는 것을 확인했다. 실제 DB 실행이나 SDK 빌드는 하지 않았다.

### 5. P2 — 선언 Content-Length보다 짧은 유효 JSON 응답을 수락함

초기 `sdks/python/sapi/egress.py`는 Content-Length의 상한만 검사하고 크기를 지정한 `HTTPResponse.read(limit+1)` 뒤 실제 수신 길이와 선언 길이를 비교하지 않았다. peer가 선언한 길이보다 짧게 보내고 닫아도 받은 prefix 자체가 유효 JSON이면 출력 스키마를 통과할 수 있었다.

현재 `egress.py:103-104`는 선언 길이가 있으면 실제 body 길이와 정확히 일치하는지 검사한다. `tools/verify_application.py:189-191,206-208`의 `/truncated` 벡터는 유효한 JSON body보다 10바이트 긴 Content-Length를 보내는 로컬 upstream 응답을 거절 대상으로 추가했다. 코드를 다시 읽었으며 실제 HTTP 재현은 하지 않았다.

## 확인한 처리 계약

- 입력·출력의 닫힌 object 스키마, 필수/선택 필드, ASCII 필드명, UTF-8 바이트 제한, 유한한 안전 숫자 범위, enum 및 타입 검사가 네 SDK에 구현되어 있다. 명시적인 null 스키마 설정 거절과 마지막 LF 거절 수정도 실제 코드를 읽었다.
- SecureServer는 응답 예약 후 admission/replay, scope, 입력, policy, 만료를 검사하고 업무 함수를 호출한다. 상태 저장소 예외를 실행 허용으로 바꾸는 경로는 발견하지 않았다.
- Records는 서버 주체를 SQL 조건에 포함하고, 출력 스키마·응답 예산·다음 version 범위를 커밋 전에 검사한다. `tools/verify_application.py`의 commit_budget이 이 경로를 검사하도록 작성되어 있다.
- SqlStorage는 SQLite `BEGIN IMMEDIATE`, PostgreSQL의 거래 advisory lock 및 statement/lock timeout을 사용하며 실패 시 롤백하고 연결을 닫는다. PostgreSQL의 동시 갱신 검토는 이 공통 lock을 사용하는 구현 경로를 기준으로 했다.
- .NET SqlPlan.CreateCommand의 예외 시 Dispose와 Java SqlPlan.prepare의 SQLException 정리를 읽었다. 외부 DB 드라이버의 동작을 실행 검증한 것은 아니다.
- 애플리케이션의 고정 endpoint, metadata/body 상한, 실제 socket peer 기준 제한, TLS/CORS 설정과 외부 목적지·DNS 주소 검사·숫자 주소 연결·리다이렉트 거절 경로를 읽었다.

## 실제 읽은 파일 범위

다음 핵심 파일은 전체 구현을 읽었다. 검토 중 주 에이전트가 바꾼 사항은 위에 명시한 부분을 다시 읽었다.

- `services/application/sapi_application/{__init__,application,records,server,cli}.py`, `services/application/pyproject.toml`.
- `sdks/python/sapi/{schema,sql,server,egress,http_limits,serialization,codec,models,constants,replay}.py`, `sdks/python/pyproject.toml`.
- `sdks/javascript/src/{schema,sql,server,serialization,codec,replay}.js`, `sdks/javascript/package.json`.
- `sdks/java/src/main/java/io/github/gnh0/sapi/{Schema,OwnedSql,SqlPlan,SecureServer,MemoryReplayStore,Sapi,KeyRecord}.java`, `sdks/java/pom.xml`.
- `sdks/dotnet/SApi.Protocol/Security/{Schema,OwnedSql}.cs`, `Server/SecureServer.cs`, `Replay/MemoryReplayStore.cs`, `Serialization/JsonFormat.cs`, `Keys/KeyRecord.cs`, `sdks/dotnet/Directory.Build.props`.
- `services/state/sapi_state/{storage,vault,server,pki}.py`, `services/state/pyproject.toml`.
- `spec/{APPLICATION_SECURITY,STATE_API}.md`, `docs/{APPLICATION,USAGE}.md`.
- `.github/workflows/conformance.yml`, `tools/{package,smoke_packages,verify_security,verify_application}.py`.

다음은 관련 계약·분기만 선택해서 읽었으며 파일 전체 리뷰로 간주하지 않는다.

- `sdks/dotnet/SApi.Protocol/Messages/Codec.cs`: 1-100 및 관련 Parse/PrepareResponse 호출 검색.
- `sdks/python/sapi/state.py`, `sdks/javascript/src/state-node.js`, Java/.NET StateClient: admission/claim 연결 분기와 주변 코드.
- Java `ReplayStore.java`, .NET `IReplayStore.cs`: admission 기본 거절 계약.
- `services/state/sapi_state/cli.py`: load, initialize 및 quota/운영 CLI 연결 경로.
- `tools/verify_state.py`: admission·quota·PostgreSQL 관련 검색과 선택한 코드행.
- `tests/drivers/{python_driver.py,javascript_driver.mjs,JavaDriver.java,dotnet/Program.cs}`: sql_config 분기와 주변 SQL 계획 반환 코드.

`git status`, 최신 diff/stat 및 파일 목록을 읽어 검토가 현재 작업 경로에 속하는지 확인했다. 상위 및 저장소 경로에서 적용할 AGENTS.md는 발견되지 않았다.

## 한계와 실행 결과의 출처

이 리뷰에서는 외부 네트워크, 외부 시스템, 빌드, 테스트, HTTP/DB 재현, 실제 배포, 인증서 체인 실험 또는 부하 시험을 수행하지 않았다. 내부 구현 파일도 수정하지 않았다. 실제 PostgreSQL·JDBC·ADO.NET/DB-API 드라이버, 플랫폼별 socket/TLS timing, 패키지 설치, 운영 권한/인증서 파일 상태는 독립적으로 확인하지 않았다.

주 에이전트가 초기 메시지로 제공한 수치는 메시지 292개, 상태 50개, 처리 규격 30개, 애플리케이션 13개 통과였다. 이는 주 에이전트가 제공한 당시의 실행 정보이며 이 리뷰어가 직접 실행하거나 결과 파일로 검증한 숫자가 아니다. 검토 중 추가된 회귀가 포함된 최신 통과 수나 실행 성공을 이 수치로 주장하지 않는다.

이 문서는 지정한 범위의 정적 코드 리뷰 기록이다. 발견되지 않은 결함의 부재, 미래 공격에 대한 절대 안전성, 제3자 기관 인증 또는 배포 승인을 증명하지 않는다.
