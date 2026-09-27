import {MAX_BODY, NAME} from './constants.js';
import {SapiError} from './errors.js';
import {MemoryReplayStore} from './replay.js';
import {object, encode, digest} from './serialization.js';
import {Schema} from './schema.js';

export class SecureServer {
  #operations = new Map();
  constructor(codec, replayStore = new MemoryReplayStore()) { this.codec = codec; this.replay = replayStore; }
  register(name, scope, input, output, policy, handler, {requests=60,period=60} = {}) {
    if (typeof name !== 'string' || !NAME.test(name) || typeof scope !== 'string' || !NAME.test(scope) || this.#operations.has(name) || [policy, handler].some(x => typeof x !== 'function') || !Number.isSafeInteger(requests) || requests<1 || requests>10000 || !Number.isSafeInteger(period) || period<1 || period>3600) throw new TypeError('operation, schemas, policy, handler and bounded rate required');
    this.#operations.set(name, {scope, input:new Schema(input,{rootObject:true}), output:new Schema(output,{rootObject:true}), policy, handler, requests, period});
  }
  inventory() {return [...this.#operations].sort(([a],[b]) => a.localeCompare(b,'en')).map(([name,o]) => ({name,scope:o.scope,requests:o.requests,period:o.period}));}
  async handle(wire) {
    const {kid, payload: request} = await this.codec.open(wire, 'req'), principal = await this.codec.principal(kid), finish = await this.codec.prepareResponse(kid), now = this.codec.clock();
    const response = {id: request.id, iat: now, exp: now + 60, req: await digest(wire), ok: false};
    try {
      const o = this.#operations.get(request.op);
      if (await this.replay.admit(this.codec.service,kid,principal.subject,o ? request.op : 'unknown',this.codec.clock(),o?.requests ?? 60,o?.period ?? 60) !== true) throw new SapiError('rate_limited');
      if (await this.replay.claim(`${this.codec.service}|${kid}|${request.id}`, request.exp, this.codec.clock()) !== true) throw new SapiError('replay');
      if (!o) throw new SapiError('unknown_operation');
      if (!principal.scopes.has(o.scope)) throw new SapiError('forbidden');
      if (!o.input.validate(request.data)) throw new SapiError('invalid_input');
      if (await o.policy(principal, request.data) !== true) throw new SapiError('forbidden');
      if (!o.input.validate(request.data)) throw new SapiError('invalid_input');
      if (this.codec.clock() >= request.exp) throw new SapiError('invalid_input');
      const data = structuredClone(await o.handler(principal, request.data));
      if (!object(data) || !o.output.validate(data) || encode(data).length > MAX_BODY - 512) throw new Error('invalid handler result');
      response.ok = true; response.data = data;
    } catch (e) {
      response.error = e instanceof SapiError && ['replay', 'replay_capacity', 'rate_limited', 'rate_capacity', 'unknown_operation', 'forbidden', 'invalid_input'].includes(e.code) ? e.code : 'internal_error';
    }
    return finish(response);
  }
}
