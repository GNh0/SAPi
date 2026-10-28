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

// Opt-in, single-isolate prototype. It is neither durable nor distributed.
// An overridden asynchronous claim must itself provide atomic duplicate reservation.
export class SplitBudgetMemoryReplayStore extends MemoryReplayStore {
  #costs = new Map();
  #costLimit;
  #costPeriod;
  constructor(capacity=10000, {costLimit=120,costPeriod=60}={}) {
    super(capacity);
    if (!Number.isSafeInteger(costLimit) || costLimit<1 || costLimit>10000 || !Number.isSafeInteger(costPeriod) || costPeriod<1 || costPeriod>3600) throw new TypeError('bounded cost policy required');
    this.#costLimit=costLimit; this.#costPeriod=costPeriod;
  }
  async claimBounded(service,subject,key,expiry,now) {
    for (const [k,[start]] of this.#costs) if (start+this.#costPeriod<=now) this.#costs.delete(k);
    const costKey=JSON.stringify([service,subject]);
    const [start,count]=this.#costs.get(costKey) ?? [now,0];
    if (count>=this.#costLimit) return 'rate_limited';
    if (!this.#costs.has(costKey) && this.#costs.size>=this.capacity) throw new SapiError('rate_capacity');
    this.#costs.set(costKey,[start,count+1]);
    const claimed=await this.claim(key,expiry,now);
    if (claimed !== true && claimed !== false) throw new TypeError('claim must return boolean');
    return claimed ? 'accepted' : 'replay';
  }
}
