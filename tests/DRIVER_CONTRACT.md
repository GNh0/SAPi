# 공통 적합성 드라이버 계약

드라이버는 시험 도구다. 어느 언어로 작성해도 된다. 표준 입력/출력에 한 줄당 하나의 UTF-8 JSON 명령/응답을 주고받고 stdout에 로그를 섞지 않는다. 서버/클라이언트 드라이버는 별도 프로세스다. 테스트 키는 `init`으로 전달하며 실제 키나 인증서 검증 우회 기본값을 제공하지 않는다.

| action | 추가 입력 | 출력 |
| --- | --- | --- |
| `init` | `keys` = `{kid:{key:base64url32bytes,subject,scopes:[]}}`, `now` 고정 Unix 초, 선택 `service`/`capacity`/`store:"fail"` | `{"ready":true}`; 상태·카운터 초기화 |
| `derive` | `kid`, `dir` | `{"key":소문자 hex 32바이트}` |
| `seal` | `kid`, `dir`, `payload` | `{"wire":JWE}`; SDK의 실제 무작위 IV 사용 |
| `open` | `wire`, `dir` | `{"kid":...,"payload":...}` |
| `request` | `kid`, `op`, `data`, 선택 `slot` | `{"wire":...}`; slot별 context 저장 |
| `accept` | `wire`, 선택 `slot` | `{"payload":...}`; context 검증·한 번만 수락 |
| `handle` | `wire` | `{"wire":암호화 응답}` |
| `parallel` | `wire` | `{"wires":[16개 응답]}`; 같은 요청을 동시에 16번 처리 |
| `http` | `url`, `wire`, 시험용 CA PEM 경로 `ca` | `{"wire":...}` 또는 `{"error":"transport_error"}`; 인증서·호스트명 검사 유지 |
| `stats` | 없음 | `{"executions":handler 실행 수}` |
| `bad_registration` | 없음 | `{"rejected":true}`; policy 없는 등록 거부 확인 |
| `schema` | schema, value | compiled와 valid, 또는 compiled=false |
| `inventory` | 없음 | operations 배열(name/scope/requests/period) |
| `sql` | kid, kind, id, 선택 changes/dialect | text와 values, 또는 blocked=true; 고정 accounts 열 목록 사용 |
| `sql_config` | id_column, owner_column, read, write | compiled; SQL 열의 casefold 충돌·불변 열 검사 |

프로토콜 실패는 `{"error":SAPI 오류 코드}`다. 기본 slot은 `default`, 기본 service는 `demo`, 기본 캐시 capacity는 10,000이다. `store:"fail"`은 예약 시 항상 예외를 내는 저장소다.

init 시 등록할 시험 업무:

- `echo`, scope `echo`: data는 UTF-8 4,096바이트 이하의 문자열 `message` 한 항목만 허용; policy는 true; handler는 카운터를 올리고 data를 반환한다.
- `own`, scope `orders`: 문자열 `owner` 한 항목; policy는 서버 key record의 subject와 owner가 같을 때만 true; handler는 카운터를 올리고 data를 반환한다.
- `fail`, scope `echo`: validator/policy는 true; handler는 내부 예외를 던지며 카운터는 올리지 않는다. 예외 내용이 응답에 나오면 실패다.
- `limited`, scope `echo`: echo 스키마, 2회/60초 제한.
- `admin`, scope `admin`: 빈 입력·출력 object, 카운터 증가.
- `leak`, scope `echo`: 빈 입력, 선언되지 않은 secret 출력; 출력 검사에서 거절.

모든 작업은 닫힌 입력·출력 스키마와 policy를 등록합니다. `verify_security.py`는 스키마 계약·실제 SQLite SQL·N×N 처리·영속 주체 제한을 검사하고 `verify_application.py`는 같은 registry의 클라이언트로 실제 선언형 서비스를 호출합니다.

실제 웹 어댑터 시험은 선택 기능이다. registry의 `features:["http_server"]`를 제공하는 드라이버는 `http_server_start` → `{"url":루프백 /sapi URL}`, `http_server_stop` → `{"stopped":true}`를 지원한다. 전달되는 요청은 실제 프레임워크의 엔드포인트가 처리한다.

`tests/implementations.json`에 새 이름과 argv 형식 `command`, 선택 `build`를 추가한다. 변수 `{root}`, `{work}`, `{python}`, `{pathsep}`를 사용할 수 있다. 이 registry는 신뢰한 로컬 빌드 명령이므로 불특정 외부 JSON을 실행하지 않는다. `--implementations`로 확장 registry를 넘길 수 있으며 언어 이름 자체는 허용 여부를 결정하지 않는다.
