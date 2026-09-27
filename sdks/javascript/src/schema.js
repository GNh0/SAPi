// Closed bounded schemas. No regex from configuration, coercion or remote references.
const SAFE = Number.MAX_SAFE_INTEGER, banned = new Set(['__proto__', 'constructor', 'prototype']);
const field = /^[A-Za-z][A-Za-z0-9_]{0,63}(?![\s\S])/, identifier = /^[A-Za-z0-9][A-Za-z0-9_.:-]*(?![\s\S])/, uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}(?![\s\S])/;
const option = (schema,key,fallback) => Object.hasOwn(schema,key) ? schema[key] : fallback;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
export class Schema {
  #definition;
  constructor(definition, {rootObject = false} = {}) {
    this.#definition = structuredClone(definition); let nodes = 0;
    const bounds = (s, lo, hi, a, b, cap) => {const min = option(s,lo,a), max = option(s,hi,b); if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || min > max || max > cap) throw new TypeError('invalid bounds');};
    const compile = (s, depth) => {
      const allowed = {object:['properties','optional'], array:['items','minItems','maxItems'], string:['minBytes','maxBytes','format','enum'], integer:['min','max'], number:['min','max'], boolean:[], null:[]};
      if (++nodes > 256 || depth > 16 || !plain(s) || typeof s.type !== 'string' || !Object.hasOwn(allowed, s.type) || Object.keys(s).some(k => k !== 'type' && !allowed[s.type].includes(k))) throw new TypeError('bounded schema required');
      if (s.type === 'object') {
        if (!plain(s.properties) || Object.keys(s.properties).length > 64 || Object.keys(s.properties).some(k => !field.test(k) || banned.has(k))) throw new TypeError('safe properties required');
        const optional = option(s,'optional',[]); if (!Array.isArray(optional) || optional.some(k => typeof k !== 'string' || !Object.hasOwn(s.properties,k)) || new Set(optional).size !== optional.length) throw new TypeError('invalid optional');
        Object.values(s.properties).forEach(v => compile(v, depth + 1));
      } else if (s.type === 'array') {bounds(s,'minItems','maxItems',0,16,64); compile(s.items,depth+1);}
      else if (s.type === 'string') {
        bounds(s,'minBytes','maxBytes',0,4096,65536); if (!['text','identifier','uuid'].includes(option(s,'format','text'))) throw new TypeError('unsupported format');
        if (s.enum !== undefined && (!Array.isArray(s.enum) || s.enum.length < 1 || s.enum.length > 64 || new Set(s.enum).size !== s.enum.length || s.enum.some(v => typeof v !== 'string' || !this.#validate({...s, enum:undefined},v)))) throw new TypeError('invalid enum');
      } else if (['integer','number'].includes(s.type)) {
        const min = option(s,'min',-SAFE), max = option(s,'max',SAFE);
        if ([min,max].some(v => typeof v !== 'number' || !Number.isFinite(v) || Math.abs(v) > SAFE || (s.type === 'integer' && !Number.isSafeInteger(v))) || min > max) throw new TypeError('invalid numeric bounds');
      }
    };
    compile(this.#definition, 0); if (rootObject && this.#definition.type !== 'object') throw new TypeError('object schema required');
  }
  validate(value) {return this.#validate(this.#definition, value);}
  #validate(s,v) {
    if (s.type === 'object') return plain(v) && Object.keys(v).every(k => Object.hasOwn(s.properties,k)) && Object.keys(s.properties).every(k => (s.optional ?? []).includes(k) || Object.hasOwn(v,k)) && Object.entries(v).every(([k,x]) => this.#validate(s.properties[k],x));
    if (s.type === 'array') return Array.isArray(v) && v.length >= (s.minItems ?? 0) && v.length <= (s.maxItems ?? 16) && v.every(x => this.#validate(s.items,x));
    if (s.type === 'string') {
      if (typeof v !== 'string' || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(v) || /[\uD800-\uDFFF]/u.test(v)) return false;
      const n = new TextEncoder().encode(v).length; if (n < (s.minBytes ?? 0) || n > (s.maxBytes ?? 4096)) return false;
      if ((s.format === 'identifier' && !identifier.test(v)) || (s.format === 'uuid' && !uuid.test(v))) return false;
      return s.enum === undefined || s.enum.includes(v);
    }
    if (s.type === 'integer') return Number.isSafeInteger(v) && v >= (s.min ?? -SAFE) && v <= (s.max ?? SAFE);
    if (s.type === 'number') return typeof v === 'number' && Number.isFinite(v) && v >= (s.min ?? -SAFE) && v <= (s.max ?? SAFE);
    return s.type === 'boolean' ? typeof v === 'boolean' : v === null;
  }
}
