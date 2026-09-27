# 검증 기록

2026-09-27, Windows에서 최종 SDK 소스로 **280/280 테스트케이스 통과**. 패키지 생성 후 격리된 소비 프로젝트의 4종 사용 검사도 모두 통과했다. 실행 기록의 소스 해시와 패키지 해시를 함께 보관한다.

## 확인한 범위

| 검사 | 결과 |
| --- | --- |
| HKDF 표준 구현과 고정 요청/응답 벡터 | 최초 참조 구현 4개 일치 |
| 암호 메시지 요청/응답 상호 운용 | 등록된 4개 구현의 16개 조합 통과 |
| 실제 HTTP·HTTPS 통신 | 언어별 네이티브 클라이언트 × 서버 Codec/처리기, 각각 16개 조합 통과 |
| 실제 ASP.NET Core 어댑터 | 4종 클라이언트로 Kestrel `POST /sapi` 호출; 평문 입력은 거부 |
| 인증서 검사 | 시험 CA를 명시적으로 신뢰; 잘못된 호스트명 인증서는 4종 클라이언트 모두 거부 |
| 암호/파싱 공격 | 잘못된 키, 암호문·IV·태그 변조, 보호 헤더 원본 변경, 다운그레이드, 대상/방향/버전, 중복 JSON, 잘못된 UTF-8, surrogate, 크기·깊이·정수·시간 위반 차단 |
| 재전송·응답 결합 | 요청/응답 재사용, 동시 16회 재전송, 응답 교환, 동일 ID의 잘못된 요청 해시/키 검사 |
| 업무 처리 경계 | scope·소유권·입력 오류·누락 policy에서 handler 차단; 캐시 용량/장애도 차단; 내부 예외는 제한된 암호 오류 |
| 패키지 사용 | Python wheel, npm exports, NuGet 전이 의존성/어댑터 assembly, Java JAR를 새 프로젝트에서 참조하여 교환 |

HTTP/HTTPS 16개 조합의 서버 측 전송 소켓은 공통 Python 데모 어댑터다. 이 어댑터는 원본 wire를 각 언어의 별도 서버 프로세스에 전달하며, 복호화·권한 검사·handler·응답 암호화는 해당 언어 SDK가 담당한다. ASP.NET Core는 별도로 실제 Kestrel 엔드포인트를 시험했다. Java/Python/JavaScript의 모든 웹 프레임워크를 시험했다는 뜻은 아니다.

## 환경과 증거

- Python 3.10.4, cryptography 50.0.1
- Node.js 24.13.1
- .NET SDK 9.0.308, 라이브러리/소비 프로젝트 target `net8.0`
- Microsoft OpenJDK 11.0.16.1, `javac --release 11`
- Jackson core/databind 2.22.3, annotations 2.22; 다운로드 파일 SHA-256 고정

[프로토콜 시험 기록](../tests/results/verification-windows.json), [패키지 SHA-256 기록](../tests/results/packages-windows.json), [패키지 소비 기록](../tests/results/package-smoke-windows.json).

## 재현

```text
python tools/bootstrap.py --work-dir /absolute/scratch/sapi
python tools/verify.py --work-dir /absolute/scratch/sapi
python tools/package.py --work-dir /absolute/scratch/sapi --output-dir /absolute/path/dist
python tools/smoke_packages.py --work-dir /absolute/scratch/sapi --package-dir /absolute/path/dist
```

검증 기록은 특정 소스·환경의 결과다. 새 구현을 registry에 추가하면 N×N 조합을 생성하며 케이스 수는 달라진다. 최초 소스 커밋 `4af623f`의 [Windows·Ubuntu CI](https://github.com/GNh0/SAPi/actions/runs/36299470368)도 시험·패키징·패키지 소비 단계까지 모두 통과했다. 이후 변경은 각 커밋의 CI 실행 결과로 판단한다. CI Actions는 현재 공식 릴리스의 커밋 SHA에 고정했다.

이 기록은 독립 보안 감사, 퍼징, 부하·분산/재시작 내구성, 일반 브라우저 실행, Maven 빌드, 공개 레지스트리 게시, 아직 없는 SDK/프레임워크의 검증을 포함하지 않는다. 기본 메모리 재전송 저장소의 운영 제약과 PSK/전방향 비밀성 제약은 [SECURITY.md](../spec/SECURITY.md)를 따른다.
