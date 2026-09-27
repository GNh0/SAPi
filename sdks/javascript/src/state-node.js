// Optional Node.js mTLS adapter. Core protocol remains Web Crypto only.
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {SapiError} from './errors.js';
import {encode, parse, unb64} from './serialization.js';

export class StateClient {
  constructor(url, {caFile, certificate, privateKey, timeout = 10000}) {
    const origin = new URL(url);
    if (origin.protocol !== 'https:' || !['', '/'].includes(origin.pathname) || origin.search || origin.hash || origin.username || origin.password || !Number.isFinite(timeout) || timeout <= 0) throw new TypeError('HTTPS authority origin required');
    this.url = new URL('/v1/state', origin);
    this.options = {ca: readFileSync(caFile), cert: readFileSync(certificate), key: readFileSync(privateKey), minVersion: 'TLSv1.2', rejectUnauthorized: true, timeout};
  }
  call(action, parameters = {}) {
    const body = encode({action, ...parameters});
    return new Promise((resolve, reject) => {
      let timer; const fail = code => reject(new SapiError(code));
      const request = https.request(this.url, {...this.options, method: 'POST', headers: {'Content-Type': 'application/json', 'Content-Length': body.length, Connection: 'close'}}, response => {
        const chunks = []; let count = 0;
        response.on('data', chunk => {
          count += chunk.length;
          if (count > 1048576) {request.destroy(); fail('state_unavailable'); return;}
          chunks.push(chunk);
        });
        response.on('error', () => {clearTimeout(timer); fail('state_unavailable');});
        response.on('end', () => {
          clearTimeout(timer);
          try {
            if (response.headers['content-type'] !== 'application/json') throw new Error();
            const result = parse(Buffer.concat(chunks));
            if (response.statusCode !== 200 || result.error) fail(typeof result.error === 'string' ? result.error : 'state_unavailable');
            else resolve(result);
          } catch {fail('state_unavailable');}
        });
      });
      timer = setTimeout(() => {request.destroy(); fail('state_unavailable');}, this.options.timeout);
      request.on('error', () => {clearTimeout(timer); fail('state_unavailable');});
      request.end(body);
    });
  }
  async get(service, kid) {return this.#record(await this.call('key', {service, kid}));}
  async reserve(service, kid, direction) {return this.#record(await this.call('reserve', {service, kid, direction}));}
  #record(value) {return {master: unb64(value.master), subject: value.subject, scopes: new Set(value.scopes)};}
  async claim(name, expiry, now) {return (await this.call('claim', {name, expiry})).claimed === true;}
  async admit(service,kid,subject,operation,now,requests=60,period=60) {return (await this.call('admit',{service,kid,operation,requests,period})).admitted === true;}
  async request(codec, subject, operation, data) {
    for (let n = 0; n < 3; n++) {
      const {kid} = await this.call('active', {service: codec.service, subject});
      try {return await codec.request(kid, operation, data);}
      catch (e) {if (!['key_retired', 'key_rotation_required'].includes(e.code) || n === 2) throw e;}
    }
  }
}
