# SAPI State API v1

다른 런타임의 상태 어댑터는 다음 공통 API를 사용합니다. 관리 서비스 origin은 신뢰한 설정으로 고정하고 메시지가 임의 관리 URL을 선택하도록 허용하지 않습니다.

## 연결

`POST /v1/state`, HTTPS + 클라이언트 인증서 필수, `Content-Type: application/json`. 리다이렉트는 허용하지 않습니다. 서버 인증서의 체인·서버 용도·만료·호스트명을 검증합니다. 서버는 클라이언트 인증서 SHA-256 fingerprint를 등록된 역할·서비스·주체로 매핑합니다.

요청은 UTF-8 JSON 객체이고 중복 필드·BOM·잘못된 UTF-8·알 수 없는 필드는 거부합니다. 요청 16KiB, 응답 1MiB 이내입니다. 키 바이트는 canonical unpadded base64url입니다. 전체 응답 종료 시간을 제한합니다.

## 명령

| action | 필수 필드 | 선택 필드 | 응답 | 역할 |
| --- | --- | --- | --- | --- |
| `issue` | service, subject, scopes | ttl, message_limit | kid | admin |
| `rotate` | service, kid | — | 새 kid | admin |
| `revoke` | service, kid | — | revoked | admin |
| `active` | service, subject | — | kid | admin / 같은 서비스 / 본인 client |
| `key` | service, kid | — | master, subject, scopes | admin / 같은 서비스 / 본인 client |
| `reserve` | service, kid, direction | — | master, subject, scopes | admin / service:res / client:req |
| `claim` | name, expiry | — | claimed | admin / 같은 service |
| `admit` | service, kid, operation | requests, period | admitted | admin / 같은 service |
| `quota` | service, subject, requests, period | — | configured | admin |
| `rewrap` | root_id | — | rewrapped | admin |
| `audit` | — | after, anchor | checkpoint, events, next | admin |

`name=service|kid|request_id`. `request_id`는 소문자 hex 32자리입니다. 관리 서비스 시간 기준으로 `now < expiry <= now+65`를 검사합니다. service/kid/subject/scope는 메시지 규격의 name 문법입니다. scopes는 1..64개, TTL은 300..2,592,000초, message_limit은 1..1,048,576회입니다.

```json
{"action":"reserve","service":"orders","kid":"k_example","direction":"req"}
```

성공은 HTTP 200과 명령 응답입니다. 실패는 제한된 `{"error":"code"}`이며 인증 전 TLS 실패는 JSON 응답 없이 연결을 거부할 수 있습니다. 권한 부족은 403, 잘못된 입력·키 상태는 400, 관리/상태 검증 장애는 503입니다. 비밀 키·내부 예외는 오류에 포함하지 않습니다.

`reserve`는 SQL 거래에서 전역 한도를 한 번 소비하고 사용할 키를 반환합니다. 응답 유실 후 동일 예약을 재시도하면 다시 소비하며 한도를 되돌리지 않습니다. 클라이언트는 `active` 후 요청을 만들고 회전 경합의 `key_retired` / `key_rotation_required`만 최대 두 번 다시 선택합니다.

서버는 복호화 뒤 response reserve를 확보하고 admit·claim·scope·입력·policy·만료 검사 후 업무 함수를 실행합니다. response 예약은 해당 함수에서 한 번만 사용합니다. admit=false 또는 claim=false이면 업무를 실행하지 않습니다. 저장소 예외를 허용으로 바꾸거나 로컬 메모리로 전환하지 않습니다.

`admit`는 kid의 현재 인증 상태에서 주체를 얻고 service/subject 전역 한도와 작업 한도를 같은 거래에서 소비합니다. 전역·작업 기본값은 60회/60초입니다. requests는 1..10,000, period는 1..3,600초입니다. 작업 한도는 신뢰한 서버 등록값이고 전역 quota 변경은 admin만 가능합니다. 카운터는 키 회전·재시작에도 유지하며 작업 변경으로 전역 한도를 초기화하지 않습니다. live 기간을 줄여 카운터를 초기화하지 않습니다. 카운터/정책은 인증 상태 트리에 연결하며 기본 용량은 각각 100,000개, 만료 정리는 호출당 최대 1,000개입니다.

`audit`는 seq 오름차순으로 최대 100개 이벤트를 반환합니다. `after`는 마지막 받은 seq이고 `next`가 같으면 페이지가 끝납니다. 선택 `anchor={seq,tag}`는 독립적으로 보관한 감사 chain prefix 검증에 사용합니다. 필수 운영 checkpoint는 별도 파일의 HMAC·시간·상태 root까지 검증되며 이 선택 인자로 대체하지 않습니다.
