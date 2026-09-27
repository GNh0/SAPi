# 상태 서비스 운영

State Authority는 키 수명·사용량과 재전송 예약을 여러 SDK에서 공유합니다. 데이터 API의 전송 방식과 별개로 관리 연결은 HTTPS/mTLS를 사용합니다.

## 설치와 초기화

빌드한 패키지 폴더에서 설치합니다.

```text
python -m pip install --find-links /absolute/path/dist sapi-state==0.1.0a2
python -m pip install --find-links /absolute/path/dist "sapi-state[postgres]==0.1.0a2"
```

첫 명령은 SQLite용이고 두 번째 명령은 PostgreSQL 드라이버도 설치합니다. 초기화는 기존 운영 디렉터리나 비밀 파일을 덮어쓰지 않습니다.

```text
sapi-state init --directory /secure/sapi/operator --anchor-directory /secure/sapi-checkpoints --service orders --subject client-1 --host 127.0.0.1 --port 8443
sapi-state serve --config /secure/sapi/operator/config.json
```

생성 파일은 운영 설정, DB 외부 KEK/감사 키, CA와 서버·관리자·서비스·클라이언트 인증서입니다. Unix에서는 파일 0600·디렉터리 0700, Windows에서는 현재 사용자·SYSTEM만 접근하도록 ACL을 제한합니다. DB·설정·개인 키·체크포인트는 소스 저장소에 넣지 않습니다.

`pki/client.pem`·`client.key`는 해당 클라이언트에, `service.pem`·`service.key`는 해당 API 서비스에 안전하게 전달합니다. `ca.pem`을 명시적으로 신뢰하며 관리자·CA 개인 키와 KEK는 배포하지 않습니다. 기본 leaf 인증서 유효 기간은 30일입니다.

## 발급·회전·폐기

서버가 실행된 상태에서 관리자 mTLS 인증서로 호출합니다. 출력에는 키 ID나 처리 결과만 들어갑니다.

```text
sapi-state issue --config /secure/sapi/operator/config.json --service orders --subject client-1 --scope orders --ttl 86400
sapi-state rotate --config /secure/sapi/operator/config.json --service orders --kid KEY_ID
sapi-state revoke --config /secure/sapi/operator/config.json --service orders --kid KEY_ID
sapi-state audit --config /secure/sapi/operator/config.json --output /secure/reports/audit.json
```

TTL 범위는 300초..30일이고 방향별 사용량 최대는 2^20회입니다. 활성 키 조회 시 사용량 80% 또는 만료 180초 전부터 자동 회전합니다. SDK의 관리된 요청 함수는 활성 키 선택과 회전 경합의 재시도를 수행합니다.

이전 키는 회전 즉시 요청 암호화가 금지되며 최대 120초간 기존 요청 복호화·응답 암호화를 허용합니다. 폐기는 이후 키 조회·예약과 재전송 예약을 차단합니다. 처리에 이미 진입한 업무 취소는 업무 서비스가 담당합니다.

## 루트 키 교체

모든 상태 서비스를 중지하고 새 루트 키를 추가한 뒤 재시작합니다. 로컬 운영 lease는 같은 설정으로 실행 중인 서버와 설정/비밀 파일 변경 명령의 동시 실행을 거부합니다.

```text
sapi-state root-add --config /secure/sapi/operator/config.json --root-id root-2
sapi-state serve --config /secure/sapi/operator/config.json
```

관리자 명령으로 기존 키를 새 KEK로 다시 암호화합니다.

```text
sapi-state rewrap --config /secure/sapi/operator/config.json --root-id root-2
```

모든 상태 서비스를 중지한 뒤 기존 루트 키를 제거합니다. 해당 KEK를 참조하는 키가 남아 있거나 primary KEK이면 제거를 거부합니다. 이전 비밀 파일/백업 사본의 보관·폐기는 별도의 운영 저장소 정책으로 관리합니다.

```text
sapi-state root-retire --config /secure/sapi/operator/config.json --root-id root-1
sapi-state serve --config /secure/sapi/operator/config.json
```

## 인증서 등록과 제거

서버를 중지한 상태에서 로컬 관리 명령으로 인증서를 발급하고 fingerprint ACL을 갱신합니다. 새 인증서를 안전하게 전달한 뒤 서버를 재시작합니다.

```text
sapi-state enroll --config /secure/sapi/operator/config.json --name client-2 --role client --service orders --subject client-2
sapi-state identity-revoke --config /secure/sapi/operator/config.json --fingerprint CERT_SHA256
```

새 클라이언트의 메시지 키는 별도 `issue`로 발급합니다. 인증서 교체 시 새 fingerprint 등록 후 이전 fingerprint를 제거합니다. 등록되지 않은 동일 CA 인증서도 거부하며 마지막 관리자 제거도 거부합니다.

관리자 인증서를 `enroll --role admin`으로 추가하면 CLI의 기본 관리자 인증서도 새 인증서로 바꿉니다. 설정된 관리자 인증서는 대체 인증서를 등록한 뒤 제거합니다. 서버 TLS 인증서는 서버를 중지한 상태에서 다음 명령으로 새 파일을 발급하고 재시작합니다.

```text
sapi-state server-renew --config /secure/sapi/operator/config.json --name server-2
```

## 저장소와 복제본

SQLite는 로컬 디스크에서 WAL·synchronous=FULL·BEGIN IMMEDIATE를 사용합니다. 네트워크 파일 시스템에 SQLite DB를 두지 않습니다.

PostgreSQL 설정은 `init --database "postgresql://.../sapi?sslmode=verify-full&sslrootcert=/secure/db-ca.pem"`으로 지정합니다. 운영 연결에는 호스트명 검증이 포함된 TLS가 필수입니다. 시험 도구의 `--postgres`에는 명시적인 loopback 시험 예외가 있습니다.

PostgreSQL을 공유하는 복제본은 동일 KEK/감사 키, DB, primary root, 역할 ACL을 사용하고 동일한 최신 외부 체크포인트를 공유해야 합니다. 체크포인트 저장소는 강한 일관성·원자적 교체·fsync 내구성을 제공해야 합니다. 각 트랜잭션은 공통 PostgreSQL advisory lock으로 체크포인트 변경까지 직렬화합니다. 서로 독립적인 체크포인트 파일이나 비동기 복제 사본을 사용하면 안전하게 공유 상태를 관리할 수 없습니다.

기본 관리 서비스는 동시 연결 32개, 요청 전체 수명 10초, 관리 본문 16KiB, 응답 1MiB, DB 잠금/statement 5초, live replay 100,000개를 제한합니다. 만료 정리는 claim마다 최대 1,000개씩 진행합니다. 초과·장애 시 업무 처리를 허용하지 않습니다.

## 백업과 복구

SQLite 백업은 SQLite backup API 또는 서비스를 정지하고 checkpoint한 파일로 만들고, PostgreSQL은 일관된 DB 백업을 사용합니다. KEK·감사 키와 최신 체크포인트는 DB 백업과 분리해 보호합니다. 저장소의 과거 상태와 최신 체크포인트가 맞지 않으면 서비스는 시작 또는 접근을 거부합니다.

DB 커밋 전 체크포인트만 flush된 장애에서도 자동으로 과거 상태를 신뢰하지 않습니다. 상태 서비스를 모두 정지하고 새 디렉터리에서 복구합니다.

```text
sapi-state recover --config /secure/sapi/operator/config.json --directory /secure/sapi-recovered --anchor-directory /secure/sapi-recovered-checkpoints
sapi-state serve --config /secure/sapi-recovered/config.json
```

복구는 원본을 보존하고 새 KEK·감사 키·빈 상태를 만듭니다. 기존 키는 가져오지 않습니다. 신뢰한 현재 인증서 ACL을 유지하고 이전 체크포인트를 recovery 기록으로 보관하며, 관리자 확인 후 클라이언트 키를 다시 `issue`합니다.

서비스 실행 계정, DB 역할, 비밀 파일·체크포인트 저장소 접근 권한을 분리하고 보안 패치를 유지합니다. 운영 변경·배포 전 [검증 명령](VALIDATION.md)을 실행합니다.
