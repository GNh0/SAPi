# SAPi

[English](README.md) | 한국어

SAPi는 인증되고 암호화된 API 요청을 위한 실험적인 SAPI/0.1 메시지 프로토콜과 SDK입니다. AES-256-GCM과 HKDF-SHA-256을 사용하며 작업 스키마, scope, 정책 검사와 재전송 방지 기능을 제공합니다. HTTPS나 애플리케이션의 인가 정책을 대신하지는 않습니다. 현재 패키지는 알파 버전이며 독립 보안 감사를 받지 않았습니다.

## 설치와 실행

다음 로컬 예제는 Node.js 24와 이 저장소의 체크아웃을 사용합니다. 별도의 빈 프로젝트 디렉터리에서 체크아웃 경로를 지정해 JavaScript SDK를 설치합니다.

```sh
npm install /absolute/path/to/SAPi/sdks/javascript
```

아래 내용을 그 프로젝트에 `example.mjs`로 저장하고 `node example.mjs`를 실행합니다.

```javascript
import {Codec, SecureServer, StaticKeyProvider} from 'sapi-protocol';

const keys = new StaticKeyProvider({demo: {
  master: crypto.getRandomValues(new Uint8Array(32)),
  subject: 'client1', scopes: ['echo']
}});
const codec = new Codec('demo', keys);
const server = new SecureServer(codec);
const schema = {type: 'object', properties: {message: {type: 'string', maxBytes: 128}}};
server.register('echo', 'echo', schema, schema,
  principal => principal.subject === 'client1',
  (_principal, data) => ({message: data.message}));
const request = await codec.request('demo', 'echo', {message: 'hello'});
const reply = await server.handle(request.wire);
console.log(await codec.acceptResponse(request, reply));
```

응답에는 `ok: true`와 `data.message: 'hello'`가 포함됩니다. 이 예제의 임의 키와 재전송 상태는 한 프로세스의 메모리에만 유지되므로 배포 설정이 아닙니다. 네 언어의 패키지와 상태 서비스 연동 예제는 [SDK 사용법](docs/USAGE.md)을 참고하세요.

## 지원 구성요소

| 구성요소 | 대상 환경 |
| --- | --- |
| .NET SDK와 ASP.NET 어댑터 | .NET Framework 4.6.2, .NET Standard 2.0, .NET 6; ASP.NET Core 6 |
| Java SDK | AES-256이 활성화된 Java 8 |
| Python SDK | Python 3.9.2 이상 |
| JavaScript SDK | Node.js 16 이상; 보안 컨텍스트의 브라우저 Web Crypto |
| 상태·애플리케이션 서비스 | Python 3.10 이상 |

JavaScript 프로토콜 핵심 모듈은 Web Crypto를 사용합니다. 현재 자동 테스트에는 브라우저 실행이 포함되지 않습니다. 런타임 호환성이 전체 배포 환경의 보안을 보장하지는 않습니다.

## 보안과 제약

상태 서비스는 키 수명주기, 재전송 및 공유 요청 허용 상태를 제공하고, 애플리케이션 서비스는 선언형 작업, 소유권 기반 SQL, 제한된 외부 요청을 제공합니다. 여러 프로세스에서 배포하려면 적절히 공유되는 상태와 신뢰할 수 있는 키 공급이 필요합니다. 예제의 메모리 저장소는 이러한 보장을 제공하지 않습니다.

TLS 인증서 준비와 신뢰 설정은 운영자의 책임입니다. GNho 실유입 연결과 운영 Worker/D1 동작은 전반적으로 검증되지 않았습니다. 로컬 합성 결과는 실유입 검증의 증거가 아닙니다. 배포 전에 [보안 제약](spec/SECURITY.md), [상태 서비스 운영](docs/STATE.md), [애플리케이션 서비스](docs/APPLICATION.md)를 확인하세요.

JavaScript SDK는 선택형 [D1 재생 방지 및 admission 어댑터](docs/d1-replay.md)를 `sapi-protocol/state-d1`으로 제공합니다. 전용 재생 저장소의 명시적 소유 설정과 별도의 관리자 초기화가 필요하며 일반 요청은 마이그레이션이나 정책 등록을 실행하지 않습니다. 기본 메모리 저장소는 해당 인스턴스에 한정됩니다. D1 어댑터의 주체 길이와 운영 제약은 해당 문서에 설명되어 있으며, 로컬 시험은 운영 환경의 분산 동작을 증명하지 않습니다.

## 개발과 검증

저장소 루트에서 로컬 Python 단위 테스트와 격리된 JavaScript Web Crypto 테스트를 실행할 수 있습니다.

```sh
python -m unittest discover -s tests -p 'test_*.py'
node --experimental-vm-modules tests/test_worker_inspector.mjs
```

JavaScript 테스트는 Node VM 시뮬레이션이며 Cloudflare Worker 또는 D1 테스트가 아닙니다. 의존성, 언어 간 적합성, 패키지 빌드와 추가 검사는 [검증 문서](docs/VALIDATION.md)를 참고하세요. [프로토콜 명세](spec/PROTOCOL.md), [아키텍처](docs/ARCHITECTURE.md), [전환 예제](docs/OPT_IN_MIGRATION.md), [보안 검증 범위](docs/SECURITY_COVERAGE.md)도 제공합니다.

## 라이선스

SAPi 소스는 [Apache License 2.0](LICENSE)을 따릅니다. 의존성에는 각각의 라이선스가 적용되므로 배포 시 해당 조건을 확인하세요.
