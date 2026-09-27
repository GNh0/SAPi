# 방어 범위

SAPi는 암호화된 메시지와 인증 뒤의 실행 경로를 함께 보호합니다. 작업 등록, 스키마, 인증 주체·scope, 저장소와 데이터/외부 요청 도구를 통해 방어를 적용합니다.

| 문제 | 구현 | 실행 검증 |
| --- | --- | --- |
| SQL 인젝션·저장된 공격 문자열 | 고정 식별자, 별도 값 바인딩, 명령 문자열 입력 불가 | 네 SDK SQL을 실제 SQLite에서 바인딩 실행; 서비스 SQLite/PostgreSQL 레코드 |
| 객체 권한 우회 | 인증 주체를 WHERE owner 조건에 포함 | 다른 사용자의 조회·수정·삭제 결과 없음 |
| 관리자 권한·필드 대량 변경 | 닫힌 중첩 스키마, 변경 열 목록, owner/id/phase 고정 | role/is_admin/owner·미선언 중첩 필드 거절 |
| NoSQL 연산자·타입 혼동 | 연산자 필드·임의 객체·강제 변환 거절 | $ne/$regex, 문자열 숫자, boolean 정수, prototype 필드 |
| 기능 권한 우회 | 등록한 작업과 scope 확인, 업무 전 정책 검사 | 관리자 작업 거절, 실행 횟수 0 |
| 응답 과다 노출 | 필수 출력 스키마와 바이트 예산 | 비밀 필드 거절; 선언형 DB 변경 롤백 |
| 재전송·키 회전으로 한도 초기화 | 영속 claim과 service/subject quota, 상태 무결성 | 재시작, 동시 프로세스, 회전과 상태 삭제 |
| 자원·업무 흐름 남용 | peer/주체/작업 제한, bounded JSON, 기대 버전과 전이 | 호출 제한, 동시 변경 한 건, 단계 건너뛰기 거절 |
| SSRF·DNS 재바인딩 | 고정 HTTPS 목적지, 모든 주소 검사, 숫자 주소 연결, TLS 호스트 검증 | 내부/메타데이터 IP, 혼합 DNS, 재조회 방지, 리다이렉트·잘못된 인증서 |
| 외부 API 응답 신뢰 | 엄격한 JSON·닫힌 출력, 크기/헤더/시간 제한 | 비밀 필드, 중복 JSON, framing 충돌, 큰 헤더, 지속 본문 deadline |
| 파싱·전송 혼동 | 중복 필드, 비정상 UTF-8, Content-Length/TE/CE 검사 | SDK 공통 벡터·차등 검사와 실제 HTTP 수신 |
| 미관리 endpoint | 등록 목록 생성, 단일 선언형 endpoint | 미등록 작업·명령·임의 SQL/URL 실행 거절 |

SQL 문자열의 `OR 1=1` 같은 단어를 지우는 방식이 아닙니다. 허용된 값은 데이터로 저장되며 명령과 분리됩니다. 승인 규칙은 운영자가 scope·정책·전이로 선언합니다. 추가 핸들러의 SQL·파일·명령 실행이 자동으로 안전해지는 것은 아닙니다.

HTTP에서도 메시지의 암호화·인증은 적용됩니다. 주소·헤더·연결 메타데이터와 서비스 거부 공격까지 숨기지는 않으며 HTTPS에서 전송 보호가 추가됩니다. 유출된 서비스 키·운영 권한, 호스트 침해, 빠진 업무 규칙, 미래 취약점은 각각 대응해야 합니다. 전체 API 해킹의 무조건적인 차단이나 기관 인증을 주장하지 않습니다.

[OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [REST Security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)을 범위의 기준으로 사용합니다. [실행 결과](VALIDATION.md)와 [검토 기록](SECURITY_REVIEW.md)에 확인 범위를 기록합니다.
