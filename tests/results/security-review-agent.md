# SAPi 독립 에이전트 소스 보안 검토

검토 시점: 2026-09-27 07:11:36 UTC. 구현 담당 에이전트와 분리된 검토이며, 외부 감사 기관의 인증 또는 운영 배포에 대한 보증은 아니다. 검토자는 저장소 소스를 수정하지 않았다.

## 직접 실행한 검증과 읽은 결과

초기 커밋 `dc7db3b`의 BOM 파싱 차이, 응답 사용량 소진 뒤 handler 실행, 느린 HTTP 본문 대기를 공개 시험 키·루프백 환경에서 직접 재현했다. 첫 상태 authority 구현의 DB 전체 백업 복원으로 폐기·재전송·사용량이 되살아나는 조건도 임시 DB에서 직접 재현했다. 초기 재현 스크립트와 JSON 결과는 이 임시 폴더 및 상위 TEMP에 있다.

수정 단계는 소스와 기존 회귀 시험을 읽기 전용으로 대조했다. 마지막 지시에 따라 수정 버전의 시험은 검토자가 새로 실행하지 않았다.

- `sapi-01-validation/verification.json`: 2026-09-27 07:10:29 UTC, **288/288 통과** 기록. 네 SDK의 BOM 본문·헤더 거절을 포함한다.
- `sapi-01-validation/state-verification.json`: 2026-09-27 07:06:28 UTC, **44/44 통과** 기록. 실제 mTLS SDK 16조합, 재시작 후 replay, 응답 예산, 역할, 8프로세스, 전체·부분 DB rollback, 500회 인증 딕셔너리 모델 전이, KEK 재포장, 느린 본문 종료를 포함한다. backend는 **SQLite**다.
- 현재 `vault.py`는 44개 시험 보고서의 해시와 다르다. 이후 추가된 root 삭제 consistency, 실제 프로세스 종료와 64개 동시 claim 시험은 **소스 존재 및 시험 논리만 확인**했고, 이 메모에서는 통과했다고 주장하지 않는다.

## 발견 사항별 수정 확인

| 발견 | 현재 소스 및 판정 | 근거 범위 |
| --- | --- | --- |
| SAPI-001 BOM 파싱 차이 | `sdks/javascript/src/serialization.js:2`의 `ignoreBOM:true`가 BOM을 보존하여 엄격한 JSON reader가 거절한다. | 소스 확인 + 기존 288개 보고서의 네 SDK 거절 결과 |
| SAPI-002 실행 뒤 응답 예산 소진 | Python `server.py:22`, JS `server.js:14`, .NET `SecureServer.cs:23`, Java `SecureServer.java:28`에서 claim·handler 전에 응답 예산을 예약한다. closure는 각각 lock/used, 동기 used, Interlocked, AtomicBoolean으로 한 번만 사용한다. | 소스 확인 + 44개 보고서의 네 SDK 실행0·replay 미추가 결과 |
| SAPI-003 전체 DB 과거 복원 | `vault.py:35,43,86`은 외부 HMAC checkpoint를 필수로 요구하고 시작 시 전체 audit, 각 트랜잭션의 끝 seq/tag와 root를 대조한다. anchor를 먼저 fsync/replace하고 SQL COMMIT하며 불일치는 거부한다. `cli.py:133` 복구는 과거 키를 가져오지 않는 새 DB/KEK/audit key를 만든다. | 소스 확인 + 기존 rollback/fault/recovery 결과 |
| SAPI-004 느린 본문 종료 시간 | Python `http.py:35`는 socket shutdown timer, JS `http.js:13`은 Promise.race deadline, Java `HttpBinding.java:43`은 future의 전체 완료 제한, .NET `HttpBinding.cs:33`은 headers/body 공통 취소를 적용한다. | 소스 확인 + 44개 보고서의 네 SDK 500ms deadline 결과 |
| SAPI-005 부분 상태 과거 복원 | `vault.py:113`의 row tag가 checkpoint-root에 연결된 `tree.py` 경로를 통해 현재값과 비교된다. `vault.py:285`의 replay SQL 행/committed digest 비교는 삭제된 live replay를 거부한다. active pointer·replay count도 같은 root에 묶였다. | 소스 확인 + 기존 signed key row 복원/live replay 삭제 거절 및 500회 모델 결과 |
| SAPI-006 root 행 삭제 후 카운터 초기화 | `vault.py:56`은 SQL root가 없더라도 committed `root|root_id`가 남으면 `state_tampered`로 거부한다. `verify_state.py:233`에 회귀 검사가 있다. | **수정 소스·시험 논리 확인**; 이번 보고서에서 실행 통과를 확인하지 않음 |

mTLS는 `server.py:31`에서 client certificate를 요구하고 `:38`의 인증서 SHA-256 fingerprint ACL로 Identity를 결정한다. vault의 역할·service·subject 검사가 작업마다 호출된다. .NET `StateClient.cs:16`의 PEM factory는 Windows PFX 재수입 후 소유 인증서를 Dispose한다. 실제 시험 드라이버 `Program.cs:31`이 이 factory를 사용한다. `locking.py:9` 및 `cli.py:153`은 serve와 로컬 운영 변경에 같은 config-path lease를 적용한다.

## 남은 검증 범위

이 검토에서 직접 확인한 발견 사항은 소스상 수정됐으며, 새 root consistency check도 존재한다. PostgreSQL 서버/장애 전환, 복제본의 공통 checkpoint 저장소 일관성, 전원 장애와 파일 시스템 내구성, 운영 PKI·배포 설정·부하 전체를 직접 검증한 것은 아니다. 인증서 ACL 변경은 코드상 재시작이 필요하다. PSK 특성상 키 양쪽 소유자는 메시지를 만들 수 있고 전방향 비밀성을 제공하지 않는다. 이 사실과 보안 감사 기관 인증 여부는 실행된 시험의 통과와 별개다.

## 검토한 파일 SHA-256

아래 해시는 위 시점의 읽은 파일 내용에 대한 것이다. 이후 수정은 이 검토의 동일 소스 증거로 취급하지 않는다.

```text
a388c30427543d9d7b97a556bb0690470a1f0ea0bfb59517a8d85a2a2251795c  services/state/sapi_state/vault.py
421fbd0d014475cc42802678addfe92cc67d04c85df52442f08a6fefca9cf817  services/state/sapi_state/storage.py
d990f840f6bf10e59cfe1e60cbf467cdc61219bc32d5869a8b83e71617345b65  services/state/sapi_state/tree.py
618e779ccc48ffe988c59164b9be97c2dea4bf3d519701c36bedf481bec932a8  services/state/sapi_state/files.py
7611400eecb60d2922ff52e48c4b10ec9355b94dc3d0ac6024efce41bd245834  services/state/sapi_state/server.py
fcd777e912ed281766c4f95592f982161b1f0aba3187b1f3073c4a16c82bface  services/state/sapi_state/cli.py
3cb36d3b61ac3f9e530937034f66721d997333f7758e18f86b52745aabeaaf94  services/state/sapi_state/pki.py
cc3fba722bc5a1bd732d586f493f48827ca60a3c65488c6c2fb88e6d41b85a0c  services/state/sapi_state/locking.py
6a4be7069d856ed75b02cc686aee180e3409220ea90c6d8130ef9c052b23297b  sdks/python/sapi/codec.py
26996f78eb9fc14151b831c458a46dff9d6bbb84c761d821aae78c05c1b551f7  sdks/python/sapi/server.py
facb2c61b256b9eeb700903181d0afd82004f3040e126a6988fa076ed963baea  sdks/python/sapi/keys.py
1f6428359ad7079121ab12b7d64f8469e203a5bd68671c3189b19f97bf161c1b  sdks/python/sapi/http.py
41ddabfe721dd4fe789771734801ae1042966db579a2afe5b0b536ca5e128d10  sdks/python/sapi/state.py
3d90c6b14d5fd5019728872441bfce19b40704d736d7aab0cbca9149a4e0a0ae  sdks/javascript/src/codec.js
0252f62fe4c07a716252373b063d74e4d7413525ac2746372f2e655cd2dc8f65  sdks/javascript/src/server.js
1d9a7d7b50865fa26424fd08a88f5617275eaa57e63d6ab60b670136c7a5a910  sdks/javascript/src/serialization.js
1f7a78d0aa9b0d304fab5831e72695706cd29b257383b9442d0c7383fd3ef2b3  sdks/javascript/src/http.js
3406e11550e41230f3e0e9cfc0a9edaf5a3d54a725c6f846074a0b62b75f21b9  sdks/javascript/src/state-node.js
ff394d13f69892054acc09fb343987eb95e2b974589691540e042f1623c55340  sdks/dotnet/SApi.Protocol/Messages/Codec.cs
1cb38a19421f07d28255888f4c126d8ed28cc793a837375f8d8bc73aec783980  sdks/dotnet/SApi.Protocol/Server/SecureServer.cs
7deaa266e67c2ddc4d81b9344c76e0a00a987663a87b6687bedb43d8c9015396  sdks/dotnet/SApi.Protocol/Keys/IKeyProvider.cs
a7c5a60068106998a0feaa0a9acdfabfd666adc202a27460e8a5be920c770c67  sdks/dotnet/SApi.Protocol/State/StateClient.cs
eaf9a4d01625acae9c4c805d04e9066d36fba46799da7dc02bc59da7f4463f4a  sdks/dotnet/SApi.Protocol/Transport/HttpBinding.cs
fe7f87ac20d7f145b8295dd758a4d5a66884b1157c23cc259d2708a6f12876a1  sdks/java/src/main/java/io/github/gnh0/sapi/Codec.java
f0eac9054ade6618260ae52c8d4c00c9e3a9797a30c1a81c0f0fb994a2b4cc93  sdks/java/src/main/java/io/github/gnh0/sapi/SecureServer.java
c23537837ce41630a8ea3133bdee6ad1832a223e7a7019af5e75d4534aa2e256  sdks/java/src/main/java/io/github/gnh0/sapi/KeyProvider.java
7226331f230ea856e6525f7bb5fe2b542982e5a875283bf48d86c16f8e734c37  sdks/java/src/main/java/io/github/gnh0/sapi/HttpBinding.java
8fa59081ed54292d0a4e1d9dd6c732fa5f8760804c848654500821b32b7b2eee  sdks/java/src/main/java/io/github/gnh0/sapi/StateClient.java
330314b36e83ad232f28511eb903bdad2d0cbfe569fe17df98dff43206af7aae  tools/verify.py
219b121f7d0fa2aa2e5d6dc0c002af84b934565057447e1db0a4634c42ae632e  tools/verify_state.py
8fc134b79c85348817480f8086c2f2f8524bdba5d4e865e8bf568f2488addac8  tests/drivers/dotnet/Program.cs
a88e3757a2857a6d645381408fcb30405d115e167af0e0a0f76b2795564bbb13  tests/state_worker.py

58119372249a06f6ab5352ccc3e66ca6a34971bb6e463981a66400cd210a6a9c  TEMP/sapi-01-validation/state-verification.json
317d0407f5ba9bd1d063ea4e72e2c9ee5a924b1395de53333b7875e8cabb83be  TEMP/sapi-01-validation/verification.json
```
