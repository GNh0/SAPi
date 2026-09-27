import {SapiError} from './errors.js';
const encoder = new TextEncoder(), decoder = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true});

export function b64(bytes) {
  let s = ''; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new SapiError();
  try {
    const bytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
    if (b64(bytes) !== s) throw new SapiError();
    return bytes;
  } catch { throw new SapiError(); }
}
export function object(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function tree(v, depth = 0) {
  if (depth > 32) throw new SapiError();
  if (v === null || typeof v === 'boolean') return;
  if (typeof v === 'string') {
    for (const c of v) { const n = c.codePointAt(0); if (n >= 0xd800 && n <= 0xdfff) throw new SapiError(); }
  } else if (typeof v === 'number') {
    if (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v))) throw new SapiError();
  } else if (Array.isArray(v)) { for (const x of v) tree(x, depth + 1); }
  else if (object(v) && [null, Object.prototype].includes(Object.getPrototypeOf(v))) {
    for (const [k, x] of Object.entries(v)) { tree(k, depth + 1); tree(x, depth + 1); }
  } else throw new SapiError();
}
export function encode(v) { tree(v); return encoder.encode(JSON.stringify(v)); }
// Small strict JSON reader: JSON.parse alone silently accepts duplicate members.
export function parse(bytes) {
  const s = decoder.decode(bytes); let i = 0;
  const ws = () => { while (i < s.length && /[\x20\t\r\n]/.test(s[i])) i++; };
  function string() {
    const start = i++; let escaped = false;
    while (i < s.length) {
      const c = s[i++];
      if (escaped) { escaped = false; continue; }
      if (c === '\\') { escaped = true; continue; }
      if (c === '"') return JSON.parse(s.slice(start, i));
    }
    throw new SapiError();
  }
  function read(depth) {
    if (depth > 32) throw new SapiError(); ws();
    if (s[i] === '"') return string();
    if (s[i] === '{') {
      i++; const v = Object.create(null), seen = new Set(); ws();
      if (s[i] === '}') { i++; return v; }
      while (true) {
        ws(); if (s[i] !== '"') throw new SapiError(); const k = string();
        if (seen.has(k)) throw new SapiError(); seen.add(k); ws();
        if (s[i++] !== ':') throw new SapiError(); v[k] = read(depth + 1); ws();
        const c = s[i++]; if (c === '}') return v; if (c !== ',') throw new SapiError();
      }
    }
    if (s[i] === '[') {
      i++; const v = []; ws(); if (s[i] === ']') { i++; return v; }
      while (true) { v.push(read(depth + 1)); ws(); const c = s[i++]; if (c === ']') return v; if (c !== ',') throw new SapiError(); }
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (s.startsWith(literal, i)) { i += literal.length; return value; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(s.slice(i));
    if (!match) throw new SapiError(); i += match[0].length; return Number(match[0]);
  }
  const v = read(0); ws(); if (i !== s.length) throw new SapiError(); tree(v); return v;
}
export function exact(v, fields) {
  if (!object(v) || Object.keys(v).length !== fields.length || fields.some(k => !Object.hasOwn(v, k))) throw new SapiError();
}
export async function digest(wire) { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(wire)))); }
