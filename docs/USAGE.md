# 설치와 SDK 사용

패키지 버전은 `0.1.0-alpha.4`(Python `0.1.0a4`)입니다. 공개 레지스트리 게시 없이 로컬 패키지로 설치합니다.

## 실행 환경

| SDK | 최소 환경 |
| --- | --- |
| `SApi.Protocol` | .NET Framework 4.6.2, .NET Standard 2.0, .NET 6 |
| `SApi.AspNet` | 클래식 ASP.NET / .NET Framework 4.6.2 |
| `SApi.AspNetCore` | ASP.NET Core 6 |
| Python | 3.9.2 이상, cryptography 50.0.1 이상 |
| Java | Java 8, AES-256을 허용하는 암호화 정책 |
| JavaScript | Node.js 16 이상 또는 Web Crypto 브라우저 |

서비스 프로세스는 Python 3.10 이상에서 실행하며, 구버전 SDK는 동일한 HTTP(S) 메시지와 mTLS 상태 API로 연결합니다. 개발 언어의 웹 프레임워크를 서비스 런타임으로 바꿀 필요는 없습니다.

## 빌드

Python 3.10+, .NET SDK 8+, Node.js 20+, JDK 11+를 빌드 도구로 사용합니다. 패키지 소비 검사를 위해 .NET 6·8 런타임도 설치합니다. Windows에서는 .NET Framework용 패키지도 소비 검사합니다.

```powershell
$sapiWork = Join-Path $env:TEMP 'sapi-validation'
python tools/bootstrap.py --work-dir $sapiWork
python tools/verify.py --work-dir $sapiWork
python tools/verify_state.py --work-dir $sapiWork
python tools/verify_security.py --work-dir $sapiWork
python tools/verify_application.py --work-dir $sapiWork
python tools/audit_dependencies.py --work-dir $sapiWork
python tools/package.py --work-dir $sapiWork --output-dir "$PWD/dist"
python tools/smoke_packages.py --work-dir $sapiWork --package-dir "$PWD/dist"
```

Linux/macOS는 같은 명령에 절대 scratch 경로를 지정합니다. 패키징은 메시지·상태·처리 보안·애플리케이션 네 보고서와 현재 SDK/서비스 전체 소스 목록 및 해시를 대조합니다.

| 패키지 | 설치·참조 |
| --- | --- |
| .NET | `dotnet add package SApi.Protocol --version 0.1.0-alpha.4 --source /absolute/path/dist` |
| 클래식 ASP.NET | `SApi.AspNet` 같은 버전 추가 |
| ASP.NET Core | `SApi.AspNetCore` 같은 버전 추가 |
| Python | `python -m pip install /absolute/path/dist/sapi_protocol-0.1.0a4-py3-none-any.whl` |
| 상태 서비스 | `python -m pip install --find-links /absolute/path/dist sapi-state==0.1.0a4` |
| JavaScript | `npm install /absolute/path/dist/sapi-protocol-0.1.0-alpha.4.tgz` |
| Java | JAR와 Jackson 의존성을 classpath에 추가하거나 JAR/POM을 로컬 Maven 저장소에 등록 |

Java 일반 프로젝트는 `mvn -f sdks/java/pom.xml package`를 사용할 수 있습니다. 공통 시험·패키징 도구는 javac/JAR 경로를 사용합니다.

## 공통 준비

[상태 서비스 운영](STATE.md)의 절차로 `orders` 서비스에 `client-1` 키를 발급하고 `echo` scope를 부여합니다. 아래 예시는 클라이언트 인증서와 서버 인증서를 따로 사용합니다. 인증서·개인 키 경로와 서비스 주소는 신뢰한 배포 설정으로 지정합니다.

```text
sapi-state issue --config /secure/sapi/operator/config.json --service orders --subject client-1 --scope echo
```

`StateClient`는 키 공급자와 재전송 저장소를 함께 구현합니다. 클라이언트 요청 함수는 활성 키 조회·자동 회전 경합 처리를 포함합니다. `SecureServer`에는 입력 스키마·출력 스키마·policy·handler가 모두 있어야 합니다.

## Python

```python
from sapi import Codec, SecureServer
from sapi.state import StateClient
from sapi.http import exchange

client_state = StateClient("https://127.0.0.1:8443",
    ca_file="/secure/ca.pem", certificate="/secure/client.pem",
    private_key="/secure/client.key")
service_state = StateClient("https://127.0.0.1:8443",
    ca_file="/secure/ca.pem", certificate="/secure/service.pem",
    private_key="/secure/service.key")
client = Codec("orders", client_state)
server = SecureServer(Codec("orders", service_state), service_state)
schema = {"type":"object","properties":{"message":{"type":"string","maxBytes":128}}}
server.register("echo", "echo", schema, schema,
    lambda p, d: p.subject == "client-1",
    lambda p, d: {"message": d["message"]})

context = client_state.request(client, "client-1", "echo", {"message": "hello"})
response = server.handle(context.wire)
payload = client.accept_response(context, response)
# 별도 API 서버를 호출할 때:
# response = exchange("https://api.example/sapi", context.wire)
```

## JavaScript / Node.js

```javascript
import {Codec, SecureServer} from 'sapi-protocol';
import {StateClient} from 'sapi-protocol/state-node';
import {exchange} from 'sapi-protocol/http';

const options = role => ({
  caFile: '/secure/ca.pem',
  certificate: '/secure/' + role + '.pem',
  privateKey: '/secure/' + role + '.key',
});
const clientState = new StateClient('https://127.0.0.1:8443', options('client'));
const serviceState = new StateClient('https://127.0.0.1:8443', options('service'));
const client = new Codec('orders', clientState);
const server = new SecureServer(new Codec('orders', serviceState), serviceState);
const schema = {type:'object', properties:{message:{type:'string',maxBytes:128}}};
server.register('echo', 'echo', schema, schema,
  p => p.subject === 'client-1',
  (p, d) => ({message: d.message}));
const context = await clientState.request(client, 'client-1', 'echo', {message: 'hello'});
const response = await server.handle(context.wire);
const payload = await client.acceptResponse(context, response);
```

핵심 ESM은 Web Crypto를 사용하고 Node.js 상태 어댑터는 별도 export입니다. 브라우저에 개인 인증서·공유 키를 배포하지 않습니다. 다른 런타임은 동일 `get/reserve`·`admit/claim` 계약을 해당 환경의 신뢰한 상태 연결로 구현할 수 있습니다.

## .NET / ASP.NET Core

```csharp
using SApi.Protocol;
using SApi.AspNetCore;

using var clientState = StateClient.FromPemFiles(new Uri("https://127.0.0.1:8443"),
    "/secure/ca.pem", "/secure/client.pem", "/secure/client.key");
using var serviceState = StateClient.FromPemFiles(new Uri("https://127.0.0.1:8443"),
    "/secure/ca.pem", "/secure/service.pem", "/secure/service.key");
var client = new Codec("orders", clientState);
var server = new SecureServer(new Codec("orders", serviceState), serviceState);
var schema = Codec.Json(new {type="object",properties=new {message=new {type="string",maxBytes=128}}});
server.Register("echo", "echo", schema, schema,
    (p, d) => p.Subject == "client-1",
    (p, d) => d);
var context = clientState.Request(client, "client-1", "echo", Codec.Json(new {message = "hello"}));
var payload = client.AcceptResponse(context, server.Handle(context.Wire));

// ASP.NET Core 앱의 실제 endpoint:
// app.MapSapi(server);  // POST /sapi
// var response = await HttpBinding.ExchangeAsync(new Uri("https://api.example/sapi"), context.Wire);
```

기존 인증서 저장소/HSM 개인 키는 `StateClient(Uri, trustedRoot, clientIdentity)` 생성자에 전달할 수 있습니다. PEM 파일 factory는 Windows TLS 인증서 로딩도 처리합니다.

## Java

```java
import io.github.gnh0.sapi.*;
import java.io.File;
import java.net.URI;

StateClient clientState = new StateClient(URI.create("https://127.0.0.1:8443"),
    new File("/secure/ca.pem"), new File("/secure/client.pem"), new File("/secure/client.key"));
StateClient serviceState = new StateClient(URI.create("https://127.0.0.1:8443"),
    new File("/secure/ca.pem"), new File("/secure/service.pem"), new File("/secure/service.key"));
Codec client = new Codec("orders", clientState);
SecureServer server = new SecureServer(new Codec("orders", serviceState), serviceState);
com.fasterxml.jackson.databind.node.ObjectNode schema = Sapi.object().put("type","object");
schema.set("properties", Sapi.object().set("message", Sapi.object().put("type","string").put("maxBytes",128)));
server.register("echo", "echo", schema, schema,
    (p, d) -> p.subject.equals("client-1"),
    (p, d) -> d);
RequestContext context = clientState.request(client, "client-1", "echo", Sapi.object().put("message", "hello"));
com.fasterxml.jackson.databind.JsonNode payload = client.acceptResponse(context, server.handle(context.wire));
```

Java 상태 어댑터는 PKCS#8 PEM EC/RSA 키를 지원하고 인증서 trust store·키 store를 구성합니다.

## 전송과 처리

원본 ASCII wire를 `POST /sapi`, `application/sapi+jwe`로 전송합니다. 네이티브 바인딩은 HTTP·HTTPS, 인증서 검증, 응답 크기 제한, 전체 응답 종료 시간, 리다이렉트 금지를 적용합니다. 서버는 인증 전 실패를 빈 HTTP 400으로 처리하며 정상 인증된 업무 오류는 암호화합니다.

요청 context는 응답의 kid·ID·원래 요청 해시를 각각 검증하고 한 번만 소비합니다. 입력·출력 스키마와 policy를 등록하며 업무 소유권은 인증 주체와 실제 DB 조건으로 검사합니다. handler가 상태 서비스나 전송 어댑터를 우회해 평문 경로로 노출되지 않도록 endpoint를 연결합니다.

`StaticKeyProvider`·`MemoryReplayStore`는 격리된 로컬 예제에 사용할 수 있습니다. 영속 배포는 위처럼 `StateClient`를 사용합니다. [메시지 규격](../spec/PROTOCOL.md), [새 구현 지침](../spec/IMPLEMENTING.md), [상태 API](../spec/STATE_API.md)에 공통 연결 계약이 있습니다.

## 처리 보안과 alpha.3 변경

`register/Register`에는 닫힌 입력·출력 object 스키마가 필수입니다. 예전 validator callback은 스키마를 대신하지 않습니다. [공통 스키마](../spec/APPLICATION_SECURITY.md)의 타입·필드·깊이·바이트·숫자 범위를 모든 SDK가 검사합니다. handler 직전에 만료를 다시 확인하고 잘못된 출력은 암호화된 오류로 처리합니다.

`OwnedSql`은 고정된 테이블·id/owner 열과 조회·변경 열 목록을 받아 select/update/insert/delete 계획을 만듭니다. `Principal/KeyRecord`와 id를 넣으며 사용자 요청에 owner·열 이름·SQL을 선택하게 하지 않습니다. Python `SqlPlan.execute(connection)`은 DB-API, JavaScript `execute(client)`는 PostgreSQL query, .NET `CreateCommand(connection)`은 ADO.NET parameters, Java `prepare(connection)`은 JDBC PreparedStatement를 사용합니다. Python/JavaScript/.NET의 `bind/Bind`, Java의 `text(dialect)`와 `values()`는 qmark/format/dollar/named 문법과 값을 분리합니다.

작업의 호출 제한은 기본 60회/60초입니다. `inventory/Inventory`는 name/scope/requests/period를 반환합니다. 관리된 배포는 `StateClient`를 재전송 저장소로 전달하여 모든 프로세스의 주체별 quota와 작업별 한도를 공유합니다. custom ReplayStore는 `admit/Admit` 계약도 구현해야 하며 미구현·장애 시 처리하지 않습니다. 메모리 저장소는 재시작과 별도 프로세스 사이에서 상태를 공유하지 않습니다.

선언형 DB·업무 상태·고정 외부 요청 서버는 [애플리케이션 서비스](APPLICATION.md)에 있습니다. 자유롭게 추가한 handler의 외부 부작용은 출력 검사만으로 되돌릴 수 없으므로 실제 거래 경계 안에서 검사와 커밋을 구성합니다.

## .NET Framework와 구버전 설정

NuGet은 프로젝트에 맞는 `net462`, `netstandard2.0`, `net6.0`, `net8.0` 어셈블리를 선택합니다. .NET Framework 클라이언트는 `SApi.Protocol`, 클래식 ASP.NET 서버는 `SApi.AspNet`을 참조합니다.

```csharp
using SApi.AspNet;
using System.Web.Routing;
// Application_Start에서 입력·출력 스키마와 정책을 등록한 서버를 연결합니다.
RouteTable.Routes.MapSapi(server);
```

.NET Framework의 `App.config` 또는 ASP.NET의 `Web.config`에 다음 TLS 설정을 추가하고, 설치된 Windows와 .NET 보안 업데이트를 적용합니다. 인증서·호스트명 검증은 SDK가 유지합니다.

```xml
<configuration>
  <runtime>
    <AppContextSwitchOverrides value="Switch.System.Net.DontEnableSchUseStrongCrypto=false;Switch.System.Net.DontEnableSystemDefaultTlsVersions=false" />
  </runtime>
</configuration>
```

.NET Framework 어셈블리는 최신 컴파일러로 빌드한 뒤 구버전 프로젝트에서 참조할 수 있습니다. 사용자 프로젝트의 C# 문법 버전을 올릴 필요는 없습니다. 직접 `IReplayStore`를 구현한다면 `Claim`과 `Admit`을 모두 원자적으로 구현해야 합니다.

Java 8은 AES-256을 활성화해야 하며 일반적으로 8u161 이후 업데이트에서 기본 활성화됩니다. `Cipher.getMaxAllowedKeyLength("AES") >= 256`을 확인할 수 있습니다. Java SDK는 Java 8 바이트코드를 배포합니다.

Node.js 16에서는 SDK가 `node:crypto`의 Web Crypto와 Node의 HTTP(S) 모듈을 사용합니다. 전역 `crypto`·`fetch`를 설치하거나 보안 기능을 비활성화하는 설정은 필요하지 않습니다. 브라우저는 Web Crypto 및 fetch 환경에서 기존 모듈을 사용합니다.

구버전 호환성은 SAPi 코드와 메시지 계약의 범위이며, 실행 환경 자체의 보안 업데이트를 제공하지는 않습니다.
