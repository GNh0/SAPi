import {SapiError} from './errors.js';

export class MemoryReplayStore {
  #entries = new Map();
  constructor(capacity = 10000) { if (!Number.isInteger(capacity) || capacity < 1) throw new TypeError('positive capacity required'); this.capacity = capacity; }
  claim(key, expiry, now) {
    for (const [k, exp] of this.#entries) if (exp <= now) this.#entries.delete(k);
    if (this.#entries.has(key)) return false;
    if (this.#entries.size >= this.capacity) throw new SapiError('replay_capacity');
    this.#entries.set(key, expiry); return true;
  }
}
