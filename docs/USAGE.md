# 설치와 사용

현재는 로컬 설치 가능한 실험용 패키지다. 공개 패키지 저장소에 게시하지 않았다. 운영 키는 신뢰한 별도 경로로 발급하고 서버는 해당 키에 연결된 주체와 scope를 등록해야 한다. 소스의 `tests/vectors.json`에는 공개 시험 키만 있으며 실사용하면 안 된다.

## 검증과 패키징

Python 3.10+, .NET SDK 8+, Node 20+, JDK 11+가 필요하다. Maven/Gradle 없이 Java 시험을 실행할 수 있다. 아래 Windows PowerShell 예시는 의존성과 중간 결과를 임시 폴더에 둔다.

```powershell
$sapiWork = Join-Path $env:TEMP 'sapi-validation'
python tools/bootstrap.py --work-dir $sapiWork
python tools/verify.py --work-dir $sapiWork
python tools/package.py --work-dir $sapiWork --output-dir "$PWD/dist"
python tools/smoke_packages.py --work-dir $sapiWork --package-dir "$PWD/dist"
```

Linux/macOS에서는 같은 명령의 `--work-dir`에 임시 경로를 넘긴다. 패키징은 통과한 검증 보고서의 SDK 소스 해시가 현재 소스와 같을 때만 진행된다. 네이티브 SDK는 생산 환경에서 Python 시험 도구를 필요로 하지 않는다.

`dist/` 산출물:

| 구현 | 로컬 설치/참조 |
| --- | --- |
| .NET | `dotnet add package SApi.Protocol --version 0.1.0-alpha.1 --source /absolute/path/dist`; ASP.NET Core는 `SApi.AspNetCore`도 추가 |
| Python | `python -m pip install /absolute/path/dist/sapi_protocol-0.1.0a1-py3-none-any.whl` |
| JavaScript | `npm install /absolute/path/dist/sapi-protocol-0.1.0-alpha.1.tgz` |
| Java | JAR와 Jackson 의존성을 classpath에 추가하거나, 동봉 POM과 함께 `mvn install:install-file -Dfile=...jar -DpomFile=...pom`으로 로컬 Maven 저장소에 등록 |

Java 프로젝트의 일반 Maven 빌드는 `mvn -f sdks/java/pom.xml package`다. 이 작업에서는 Maven 실행 파일 없이 javac/JAR 경로를 검증했다. 생성 JAR에 Jackson을 내장하지 않으므로 POM의 의존성을 함께 제공해야 한다.

## Python 요청·서버 처리

아래는 같은 프로세스에서 경계를 보여주는 예제다. 실제 배포는 서로 다른 프로세스의 별도 registry에서 같은 키를 신뢰하게 설치한다. 샘플 key는 매 실행 새로 생성하며 본문만 암호화된 wire를 전송한다.

```python
import secrets
from sapi import Codec, KeyRecord, SecureServer
from sapi.http import exchange

key = secrets.token_bytes(32)
keys = {"client-k1": KeyRecord(key, "client", frozenset({"echo"}))}
client = Codec("demo", keys)
server = SecureServer(Codec("demo", keys))
server.register(
    "echo", "echo",
    validator=lambda data: set(data) == {"message"} and isinstance(data["message"], str),
    policy=lambda principal, data: principal.subject == "client",
    handler=lambda principal, data: data,
)
context = client.request("client-k1", "echo", {"message": "안녕"})
response_wire = server.handle(context.wire)
response = client.accept_response(context, response_wire)
assert response["ok"] and response["data"] == {"message": "안녕"}
# 원격 전송: response_wire = exchange("https://api.example/sapi", context.wire)
```

루프백 데모 서버는 `examples/http_server.py --keys /secure/path/registry.json`으로 실행한다. 레코드 형식은 `{kid:{"key":패딩 없는 base64url 32바이트,"subject":주체,"scopes":[...]}}`이다. 기본 URL은 `http://127.0.0.1:8080/sapi`다. HTTPS에는 `--certificate ... --private-key ...`가 둘 다 필요하다. 다른 머신에 노출하는 운영 서버로 사용하지 않는다.

## .NET / ASP.NET Core

ASP.NET Core의 기존 `Program.cs`에 연결하는 예제다. `SAPI_KEY`는 외부에서 안전하게 발급한 32바이트 키의 base64url 표현이다. 값 자체를 설정 파일/소스에 넣지 않는다.

```csharp
using SApi.Protocol;
using SApi.AspNetCore;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var keys = new Dictionary<string, KeyRecord> {
    ["client-k1"] = new(Codec.UnB64(
        Environment.GetEnvironmentVariable("SAPI_KEY")
        ?? throw new InvalidOperationException("key provisioning required")),
        "client", new[] { "echo" })
};
var codec = new Codec("demo", keys);
var server = new SecureServer(codec);
server.Register("echo", "echo",
    data => data.TryGetProperty("message", out var value)
        && value.ValueKind == System.Text.Json.JsonValueKind.String,
    (principal, data) => principal.Subject == "client",
    (principal, data) => data);
app.MapSapi(server);
app.Run();

// 별도 클라이언트:
// var context = codec.Request("client-k1", "echo", Codec.Json(new { message = "안녕" }));
// var wire = await HttpBinding.ExchangeAsync(new Uri("https://api.example/sapi"), context.Wire);
// var response = codec.AcceptResponse(context, wire);
```

이 validator는 짧은 연결 예시다. 실제 업무의 필드 허용 목록, 길이·형식, 객체별 권한은 엄격하게 지정한다. 평문으로 같은 handler를 호출하는 별도 API를 열면 해당 경로는 SAPI의 보호를 받지 않는다.

## JavaScript와 Java

JavaScript의 공개 진입점은 `sapi-protocol`, 전송은 `sapi-protocol/http`다. `Codec.request`, `Codec.acceptResponse`, `SecureServer.register`와 `handle`은 Promise 기반이다. `keys[kid]`는 `{master: Uint8Array(32), subject, scopes: [...]}` 레코드다. browser의 Web Crypto/secure context/CORS/mixed-content 제약은 그대로 적용된다. 공개 번들에 공유 키를 포함하지 않는다.

Java의 공개 타입은 `io.github.gnh0.sapi.Codec`, `KeyRecord`, `RequestContext`, `SecureServer`, `ReplayStore`, `MemoryReplayStore`, `SapiException`, `HttpBinding`이다. data는 Jackson `JsonNode`다. `Sapi.object()`로 객체를 생성할 수 있고 `Codec.request`/`acceptResponse`, `SecureServer.register`/`handle`은 같은 처리 계약을 제공한다. Spring 등에 연결할 때 원본 ASCII 요청 본문을 `handle`에 전달하는 얇은 어댑터를 작성한다. Spring 어댑터의 실행 검증은 아직 하지 않았다.

## 다른 언어

[구현 지침](../spec/IMPLEMENTING.md)과 [드라이버 계약](../tests/DRIVER_CONTRACT.md)을 따른다. 기존 네 언어의 런타임을 불러야 하는 조건은 없다. 새 구현을 registry에 추가하면 언어 간 모든 조합으로 시험한다. 특정 언어의 SDK가 아직 없다는 사실과 프로토콜이 해당 언어를 제한한다는 말은 다르다.
