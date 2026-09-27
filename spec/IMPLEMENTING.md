# 어떤 언어에서든 구현하기

구현 언어·프레임워크 제한은 없다. [PROTOCOL.md](PROTOCOL.md)의 메시지 형식·검증 순서, [APPLICATION_SECURITY.md](APPLICATION_SECURITY.md)의 처리 계약을 지킨다. 암호 라이브러리의 AES-256-GCM과 HKDF-SHA-256을 사용하고 직접 암호 알고리즘을 구현하지 않는다. JWE 라이브러리를 사용할 경우 `crit` 확장과 정확한 원본 AAD 처리가 가능해야 한다. 일반 JWT/JWS 검증만으로 이 프로필을 처리할 수 없다.

## 송신 의사 코드

```text
require trusted provisioning of 32 random bytes for this client/service
payload := {id: random16bytes.hexlower(), iat: now, exp: now+60, op, data}
validate exact fields, interoperable JSON, size, and lifetime
key := HKDF_SHA256(master, fixed_salt, service|kid|req, 32)
header := exact SAPI/0.1 protected fields and crit
protected := base64url_no_padding(UTF8_JSON(header))
iv := CSPRNG(12 bytes)  // never caller-supplied in regular SDK API
ciphertext, tag := AES256GCM.encrypt(key, iv, UTF8_JSON(payload), ASCII(protected))
wire := protected + ".." + b64(iv) + "." + b64(ciphertext) + "." + b64(tag)
retain context {wire, kid, id} for verifying response
```

HKDF는 RFC 5869 전체 extract/expand를 수행한다. 여기서 출력 길이는 SHA-256 한 블록인 32바이트다. `info`의 정확한 문자열은 PROTOCOL.md를 따른다. GCM API가 암호문 뒤에 태그를 붙여 반환하면 마지막 16바이트를 분리한다. 응답은 `res` 파생 키를 사용한다.

## 수신·처리 순서

1. 원본 ASCII wire의 길이·5개 구간·빈 두 번째 구간을 검사한다.
2. 정규 base64url, 헤더 최대 크기, 엄격한 UTF-8 JSON, 중복 키, 정확한 헤더 필드와 허용 알고리즘/버전/방향/서비스/crit를 확인한다.
3. 서버의 `kid` 레코드로 키를 선택한다. 메시지에 키 URL이나 외부 키를 지정하도록 허용하지 않는다.
4. IV 12바이트·태그 16바이트·본문 크기를 확인하고 **원본 protected 문자열**을 AAD로 인증 복호화한다. 인증 실패 시 평문을 사용하지 않는다.
5. 본문의 중복 필드·유효한 유니코드·숫자 범위·깊이·정확한 필드·시간을 검사한다.
6. 응답 키와 방향별 사용량을 먼저 예약한다. 예약은 한 번만 응답에 사용한다. 주체·작업 admission 후 `(service,kid,id)`를 `exp`까지 원자적으로 예약한다. 저장 장애·중복·용량 초과면 handler를 호출하지 않는다.
7. 등록 작업·scope·닫힌 입력 스키마·객체 policy를 확인하고 handler 직전에 만료를 다시 확인한다.
8. 통과한 경우에만 handler를 호출한다. 닫힌 출력 스키마·JSON·크기를 검사한 뒤 요청 해시·ID에 묶은 응답을 `res` 키로 암호화한다. 업무 오류도 제한된 코드로 암호화한다.

클라이언트는 응답 인증/시간과 context의 kid·id·요청 wire 해시를 **각각** 검사한다. 하나라도 틀리면 context를 소비하지 않는다. 유효한 응답을 받아들인 context는 재사용하지 않는다.

## 언어별 직렬화 주의점

- 객체 항목 순서나 JSON 이스케이프 차이는 허용한다. 수신자가 원본 AAD를 사용하므로 JSON canonicalization에 의존하지 않는다.
- 기본 JSON parser가 중복 필드의 마지막 값만 남기는 경우 별도 중복 감지가 필요하다.
- 비유한 수, 잘못된 UTF-8, 단독 surrogate, 2^53-1보다 큰 정수는 거부한다. 보안 timestamp는 boolean이 아닌, 음수가 없고 소수 부분이 없는 수다. `1700000000.0`처럼 값이 정수인 표현은 허용된다.
- 애플리케이션 데이터의 소수는 각 런타임의 유한 IEEE-754 binary64 범위에 맞춘다. 정확한 금액, 큰 ID, 고정밀 수는 문자열로 표현하고 업무 validator로 검사한다.
- 같은 key/kid/방향의 합산 암호화 한도와 회전은 모든 프로세스·장치에 걸쳐 관리한다. 재전송 저장소도 같은 범위를 공유해야 한다.

공통 벡터와 적합성 시험을 통과해도 독립 보안 감사나 운영 환경 검증을 대신하지 않는다. 언어 추가는 문법 번역보다 파서/동시성/키 수명/오류 처리의 의미를 맞추는 작업이다.
