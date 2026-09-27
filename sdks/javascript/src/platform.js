// Browser Web Crypto or Node's native provider; never install globals or use a PRNG fallback.
export const isNode = typeof process !== 'undefined' && !!process.versions?.node;
export const secureCrypto = globalThis.crypto?.subtle ? globalThis.crypto : isNode ? (await import('node:crypto')).webcrypto : undefined;
export const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
export function clone(value, depth = 0) {
  if (depth > 32) throw new TypeError('bounded JSON required');
  if (value === null || ['undefined','string','number','boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(v => clone(v, depth + 1));
  if (typeof value !== 'object' || ![null,Object.prototype].includes(Object.getPrototypeOf(value))) throw new TypeError('JSON object required');
  const result = Object.create(null);
  for (const key of Object.keys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value,key);
    if (!hasOwn(descriptor,'value')) throw new TypeError('JSON data properties required');
    result[key] = clone(descriptor.value,depth + 1);
  }
  return result;
}
