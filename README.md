# SAPi

English | [한국어](README.ko.md)

SAPi is an experimental SAPI/0.1 message protocol and SDK for authenticated, encrypted API requests. It uses AES-256-GCM and HKDF-SHA-256, with operation schemas, scopes, policy checks and replay protection. It does not replace HTTPS or an application's authorization policy. The current packages are alpha releases and have not received an independent security audit.

## Install and try

The following local example uses Node.js 24 and a checkout of this repository. In a separate empty project directory, install the JavaScript SDK from the checkout (replace the path):

```sh
npm install /absolute/path/to/SAPi/sdks/javascript
```

Save this as `example.mjs` in that project and run `node example.mjs`:

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

The response contains `ok: true` and `data.message: 'hello'`. This example keeps its random key and replay state in one process; it is not a deployment configuration. See [SDK usage](docs/USAGE.md) for packages and state-backed examples in all four languages.

## Supported components

| Component | Target |
| --- | --- |
| .NET SDK and ASP.NET adapters | .NET Framework 4.6.2, .NET Standard 2.0, .NET 6; ASP.NET Core 6 |
| Java SDK | Java 8 with AES-256 enabled |
| Python SDK | Python 3.9.2 or later |
| JavaScript SDK | Node.js 16 or later; browser Web Crypto in a secure context |
| State and application services | Python 3.10 or later |

The core JavaScript protocol modules use Web Crypto. Browser execution is not covered by the current automated tests. Runtime compatibility does not establish the security of a complete deployment.

## Security and limits

The state service provides key lifecycle, replay and shared admission state; the application service provides declarative operations, owned SQL and constrained outbound requests. A multi-process deployment needs appropriately shared state and trusted key provisioning. The in-memory stores in the example do not provide those guarantees.

TLS certificate provisioning and trust configuration remain the operator's responsibility. The GNho live-traffic integration and production Worker/D1 behavior have not been validated. Local synthetic results are not evidence of live traffic coverage. Read [security limits](spec/SECURITY.md), [state operations](docs/STATE.md), and [application service](docs/APPLICATION.md) before deployment.

## Development and verification

From the repository root, the local Python unit tests and the isolated JavaScript Web Crypto test can be run with:

```sh
python -m unittest discover -s tests -p 'test_*.py'
node --experimental-vm-modules tests/test_worker_inspector.mjs
```

The JavaScript test is a Node VM simulation, not a Cloudflare Worker or D1 test. For dependencies, cross-language conformance, package builds and broader checks, see [validation](docs/VALIDATION.md). See also the [protocol specification](spec/PROTOCOL.md), [architecture](docs/ARCHITECTURE.md), [migration example](docs/OPT_IN_MIGRATION.md), and [security coverage](docs/SECURITY_COVERAGE.md).

## License

SAPi source is licensed under [Apache License 2.0](LICENSE). Dependencies retain their own licenses; consult their license terms when distributing them.
