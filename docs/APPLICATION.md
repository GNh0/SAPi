# 애플리케이션 서비스

`sapi-application`은 설정으로 선언한 데이터 API를 실행합니다. 인증·권한·입출력 검사 뒤에 고정된 DB 작업과 업무 상태 전이를 수행합니다. 클라이언트는 공통 SAPi 메시지를 사용하므로 서버 구현과 별개로 자신의 언어·프레임워크에서 연결합니다.

## 설치와 실행

로컬 패키지 폴더에서 설치하고 상태 서비스를 실행하기 전에 인증서를 준비합니다.

```text
python -m pip install --find-links /absolute/path/dist sapi-application==0.1.0a3
sapi-state init --directory /secure/sapi/operator --anchor-directory /secure/sapi-checkpoints --service orders --subject client-1
sapi-application init --directory /secure/sapi/application --state-config /secure/sapi/operator/config.json --service orders
sapi-application inventory --config /secure/sapi/application/config.json
```

초기화는 기존 디렉터리를 덮어쓰지 않습니다. 서비스의 관리 인증서·개인 키, 공개 CA, 별도 API 서버 인증서와 업무 DB를 준비합니다. CA 개인 키·관리자 개인 키·KEK·감사 키는 애플리케이션 디렉터리에 복사하지 않습니다. 이 명령은 CA 운영 lease를 사용하므로 상태 서버를 시작하기 전에 실행합니다.

상태 서버를 먼저 실행합니다. 별도 터미널에서 키를 발급하고 애플리케이션 서버를 실행합니다.

```text
sapi-state serve --config /secure/sapi/operator/config.json
sapi-state issue --config /secure/sapi/operator/config.json --service orders --subject client-1 --scope orders_read --scope orders_write
sapi-application serve --config /secure/sapi/application/config.json
```

기본 데이터 endpoint는 `https://127.0.0.1:8444/sapi`입니다. `serve --http`를 지정하면 HTTP에서 같은 암호화 메시지를 처리합니다. 상태 관리 연결은 HTTPS/mTLS를 유지합니다. 설정·인증서 변경과 `inventory`는 해당 서버를 중지한 상태에서 실행합니다.

## 데이터 API

기본 `orders` 컬렉션은 `description` 문자열(UTF-8 256바이트), `quantity` 정수(1..1000)를 받습니다.

| 작업 | 입력 | scope | 동작 |
| --- | --- | --- | --- |
| orders_create | id, data | orders_write | 주체 소유 레코드 생성, version=1, phase=created |
| orders_get | id | orders_read | 본인 레코드 조회 |
| orders_update | id, version, data | orders_write | created 상태에서 같은 버전일 때 수정 |
| orders_delete | id, version | orders_write | created 상태에서 같은 버전일 때 삭제 |
| orders_submit | id, version | orders_write | created → submitted |
| orders_complete | id, version | orders_write | submitted → completed |

`id`는 최대 64바이트의 identifier입니다. `owner`, `phase`, 관리자 권한, SQL, URL 같은 미선언 필드는 입력할 수 없습니다. 소유자는 인증된 키의 주체로 정하며 SQL 조건에 포함합니다. 없는 레코드와 다른 주체의 레코드는 모두 조회 `found=false`, 변경 `changed=false`로 응답합니다.

조회 결과는 `found`와 `records`를 반환하며 레코드는 `id`, `version`, `phase`, `data`로 구성됩니다. 변경 결과는 `changed`와 `records`를 반환합니다. 버전이 다르면 변경하지 않습니다. 출력 스키마·메시지 예산·버전 범위를 DB 트랜잭션 안에서 확인하며 실패 시 롤백합니다.

Python 요청 예시입니다. 다른 SDK도 관리된 요청 함수에 같은 작업·데이터를 전달합니다.

```python
from sapi import Codec
from sapi.state import StateClient
from sapi.http import exchange

state = StateClient("https://127.0.0.1:8443",
    ca_file="/secure/client/ca.pem", certificate="/secure/client/client.pem",
    private_key="/secure/client/client.key")
client = Codec("orders", state)
context = state.request(client, "client-1", "orders_create", {
    "id": "order-1", "data": {"description": "O'Reilly book", "quantity": 1}})
# API 서버 인증서를 신뢰하는 TLS 환경에서 전송합니다.
wire = exchange("https://api.example/sapi", context.wire)
result = client.accept_response(context, wire)
```

## 설정

`config.json`은 보호하는 배포 설정입니다. `collections`에 이름, 닫힌 `schema`, `read_scope`, `write_scope`를 선언합니다. `initial`은 초기 상태, `write_phases`는 수정·삭제 가능한 상태(기본 초기 상태), `transitions`는 `{작업명:{from,to,scope}}`입니다. 결제·승인 등 각 업무의 권한은 별도 scope와 필요한 정책으로 정의합니다.

SQL은 고정된 `sapi_app_records` 테이블에서 값 바인딩으로 실행합니다. `database`는 별도 업무 SQLite 파일 또는 `sslmode=verify-full`의 PostgreSQL DSN입니다. 상태 DB와 업무 DB는 구분합니다. DB 역할에는 필요한 테이블 권한만 부여합니다.

`targets`의 각 목적지는 `origin`, `path`, `input`, `output`, `scope`로 선언합니다.

```json
{"catalog":{"origin":"https://catalog.example","path":"/products","scope":"catalog_read","input":{"type":"object","properties":{"sku":{"type":"string","format":"identifier","maxBytes":64}}},"output":{"type":"object","properties":{"name":{"type":"string","maxBytes":120}}}}}
```

`fetch_catalog`는 검사된 scalar 입력을 GET query 값으로만 보냅니다. 클라이언트는 URL·헤더를 선택하지 않습니다. DNS의 모든 주소를 검사하고 검증한 숫자 주소에 연결하며 원래 호스트명으로 TLS를 검증합니다. 내부·메타데이터·loopback 주소, 혼합 DNS, 리다이렉트, 과도한 응답·헤더, 압축 응답, 잘못된 JSON과 미선언 출력 필드를 거부합니다. DNS 작업은 동시에 최대 4개, 외부 요청은 기본 3초·65,000바이트로 제한합니다.

브라우저 Origin은 `allowed_origins`의 정확한 HTTPS origin 목록으로 제한합니다. 기본은 빈 목록입니다. Origin 없는 서비스 요청도 SAPi 인증을 통과해야 합니다. 인증 비밀을 브라우저 코드에 직접 넣지 않습니다.

수신은 기본 동시 연결 32개, 연결 수명 10초, 실제 socket peer당 분당 120개, metadata 16KiB, wire 128KiB로 제한합니다. 프록시 헤더를 주체나 peer의 근거로 사용하지 않습니다. 인증 주체의 호출 제한은 별도로 State Authority가 영속 관리합니다.

직접 작성하는 핸들러는 [SDK 사용법](USAGE.md)의 스키마·policy와 `OwnedSql`을 사용합니다. 선언형 서비스의 고정 DB/외부 요청 경로 밖의 별도 코드에도 해당 처리가 필요합니다.
