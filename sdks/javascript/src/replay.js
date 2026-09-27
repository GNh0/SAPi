import {SapiError} from './errors.js';

export class MemoryReplayStore {
  #entries = new Map();
  #rates = new Map();
  constructor(capacity = 10000) { if (!Number.isInteger(capacity) || capacity < 1) throw new TypeError('positive capacity required'); this.capacity = capacity; }
  claim(key, expiry, now) {
    for (const [k, exp] of this.#entries) if (exp <= now) this.#entries.delete(k);
    if (this.#entries.has(key)) return false;
    if (this.#entries.size >= this.capacity) throw new SapiError('replay_capacity');
    this.#entries.set(key, expiry); return true;
  }
  admit(service,kid,subject,operation,now,requests=60,period=60) {
    for (const [name,value] of this.#rates) if (value[0]+value[2]<=now) this.#rates.delete(name);
    const pending = [];
    for (const [name,count,seconds] of [[`global|${service}|${subject}`,60,60],[`op|${service}|${subject}|${operation}`,requests,period]]) {
      let [start,used,previous] = this.#rates.get(name) ?? [now,0,seconds];
      if (now >= start + Math.max(seconds,previous)) {start=now; used=0;previous=seconds;}
      if (used >= count) return false;
      if (!this.#rates.has(name) && this.#rates.size + pending.filter(([k]) => !this.#rates.has(k)).length >= 10000) throw new SapiError('rate_capacity');
      pending.push([name,[start,used+1,Math.max(seconds,previous)]]);
    }
    for (const [name,value] of pending) this.#rates.set(name,value);
    return true;
  }
}
