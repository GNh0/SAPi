import {MAX_BODY, NAME} from './constants.js';
import {SapiError} from './errors.js';
import {MemoryReplayStore} from './replay.js';
import {object, encode, digest} from './serialization.js';

export class SecureServer {
  #operations = new Map();
  constructor(codec, replayStore = new MemoryReplayStore()) { this.codec = codec; this.replay = replayStore; }
  register(name, scope, validator, policy, handler) {
    if (typeof name !== 'string' || !NAME.test(name) || typeof scope !== 'string' || !NAME.test(scope) || this.#operations.has(name) || [validator, policy, handler].some(x => typeof x !== 'function')) throw new TypeError('operation, scope and all callbacks required');
    this.#operations.set(name, {scope, validator, policy, handler});
  }
  async handle(wire) {
    const {kid, payload: request} = await this.codec.open(wire, 'req'), principal = this.codec.principal(kid), now = this.codec.clock();
    const response = {id: request.id, iat: now, exp: now + 60, req: await digest(wire), ok: false};
    try {
      if (await this.replay.claim(`${this.codec.service}|${kid}|${request.id}`, request.exp, this.codec.clock()) !== true) throw new SapiError('replay');
      const o = this.#operations.get(request.op); if (!o) throw new SapiError('unknown_operation');
      if (!principal.scopes.has(o.scope)) throw new SapiError('forbidden');
      if (await o.validator(request.data) !== true) throw new SapiError('invalid_input');
      if (await o.policy(principal, request.data) !== true) throw new SapiError('forbidden');
      const data = await o.handler(principal, request.data);
      if (!object(data) || encode(data).length > MAX_BODY - 512) throw new Error('invalid handler result');
      response.ok = true; response.data = data;
    } catch (e) {
      response.error = e instanceof SapiError && ['replay', 'replay_capacity', 'unknown_operation', 'forbidden', 'invalid_input'].includes(e.code) ? e.code : 'internal_error';
    }
    return this.codec.seal(kid, 'res', response);
  }
}
