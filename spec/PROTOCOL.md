# SAPI/0.1 PSK 프로필

실험 규격. 이 문서의 MUST는 본 프로필의 상호 운용 조건을 뜻하며 IETF 표준 지위를 뜻하지 않는다.

## 전송과 신뢰

클라이언트와 서버는 사전에 신뢰할 수 있게 배포한 구현과, 클라이언트/서비스별 32바이트 무작위 공유 키를 가진다. 비밀번호를 직접 키로 쓰지 않는다. `kid`는 공개 키 식별자이며 서버의 키 레코드가 주체(subject)와 권한(scopes)을 지정한다. 요청 내용이 주장하는 주체는 신뢰하지 않는다.

`service`, `kid`, 작업 이름은 `[A-Za-z0-9_-]{1,64}`이다. HTTP 바인딩은 `POST /sapi`, `Content-Type: application/sapi+jwe`, ASCII JWE Compact 본문이다. HTTPS는 동일한 메시지 형식을 사용한다. 인증 키/토큰을 외부 헤더나 URL에 싣지 않는다. 작업 선택은 복호화한 `op`만 사용한다. 다른 바인딩은 전송된 원래 메시지 바이트를 보존해야 한다.

## 암호 형식

RFC 7516 JWE Compact Serialization: `protected..iv.ciphertext.tag`. `alg=dir`, `enc=A256GCM`만 허용한다. 두 번째(암호화된 키) 구간은 비어 있어야 한다. IV는 매번 CSPRNG로 새로 생성한 12바이트이며 태그는 16바이트다. 압축, 알고리즘 협상, 인증 없는 모드는 허용하지 않는다.

보호 헤더는 아래 8개 항목을 정확히 가진다. 중복 JSON 키, 알 수 없는 필드, 다른 버전은 거부한다. `crit` 배열은 아래 값/순서다. 수신자는 보호 헤더의 base64url 문자열 자체를 ASCII AAD로 사용한다. 재직렬화해서 AAD를 만들지 않는다.

```json
{"alg":"dir","enc":"A256GCM","typ":"sapi+jwe","kid":"alice-k1","sapi":"0.1","dir":"req","svc":"demo","crit":["sapi","dir","svc"]}
```

응답은 `dir=res`다. base64url은 패딩 없는 정규 표현이며 재인코딩 결과가 원래 값과 같아야 한다. 보호 헤더 최대 1,024바이트, 복호화 본문 최대 65,536바이트, 전송 메시지 최대 131,072바이트, JSON 깊이 최대 32다. 보안 메타데이터는 0..2^53-1 범위이며 boolean이 아닌 소수 부분 없는 JSON 수다. JSON은 UTF-8, 중복 항목/비유한 숫자/유효하지 않은 UTF-8/단독 surrogate를 거부한다. 데이터 안의 정수도 절댓값 2^53-1 이하여야 하고 소수는 유한 binary64 범위다. 고정밀 값은 문자열로 표현한다.

## 키 분리

RFC 5869 HKDF-SHA-256:

```
IKM  = 사전 공유 키 (32 bytes)
salt = UTF8("SAPI/0.1 HKDF-SHA-256")
info = UTF8("SAPI/0.1|" + service + "|" + kid + "|" + direction)
L    = 32 bytes
```

`req`와 `res` 키가 다르며 서비스/kid도 키 파생에 묶인다. 키별·방향별 전체 암호화 횟수가 2^20회를 넘기기 전에 새 키로 교체한다. 관리된 SDK는 [State API](STATE_API.md)의 reserve로 프로세스/복제본의 합산 한도를 소비한다. 서버는 handler 호출 전에 응답 사용량도 확보하고 그 예약으로 응답을 한 번 암호화한다.

## 요청

정확히 다음 필드를 가진다. `id`는 새 CSPRNG 16바이트를 소문자 32자리 hex로 표현한 값이다. `data`는 JSON 객체다.

```json
{"id":"00112233445566778899aabbccddeeff","iat":1700000000,"exp":1700000060,"op":"echo","data":{"message":"hello"}}
```

Unix 초 단위 `iat`, `exp`를 검사한다. `1 <= exp-iat <= 60`, `iat <= now+5`, `now < exp`이어야 한다. 만료 유예는 없다. 검증한 요청 ID는 `(service, kid, id)` 범위에서 `exp`까지 원자적으로 단 한 번만 예약한다. 인증·시간 검증 전에 재전송 캐시를 채우지 않는다. 캐시 장애/용량 초과는 거부한다.

모든 작업은 입력 validator, 권한 policy, handler를 함께 등록해야 한다. 누락된 정책의 작업 등록, 알 수 없는 작업, 권한 부족, 입력 오류는 거부한다. 키 소유 확인은 개인 사용자 로그인/SSO를 대체하지 않는다. 업무별 소유권 등은 서버 policy가 지정한다.

## 응답

성공은 `id,iat,exp,req,ok,data`, 실패는 `id,iat,exp,req,ok,error`를 정확히 가진다. `req=base64url(SHA256(ASCII(원래 요청 JWE)))`이며 요청과 응답을 묶는다. `ok`는 JSON boolean이다. 오류 코드만 노출하며 예외/스택/데이터를 보내지 않는다.

```json
{"id":"00112233445566778899aabbccddeeff","iat":1700000001,"exp":1700000061,"req":"...","ok":true,"data":{"message":"hello"}}
```

클라이언트는 자신이 보관한 요청 context의 `kid`, `id`, `req`와 응답을 비교하고 같은 context에서 응답을 한 번만 받아들인다. 응답 시간도 요청과 같은 기준으로 검사한다. 인증된 요청에 대한 업무 실패는 암호화한다. 복호화 불가능한 요청 등 인증 전 실패는 고정된 빈 HTTP 400 응답으로 처리한다. 응답의 신뢰 근거는 외부 HTTP 상태가 아니라 검증된 암호 메시지다.

## 근거 표준

- [JWE, RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html)
- [JWA/A256GCM, RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html)
- [HKDF, RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)
