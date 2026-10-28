// Contract adapter only. Backend must atomically implement claim and multi-limit admit.
// No D1 schema or production implementation is supplied here.
export function atomicReplayAdapter(backend) {
  if (typeof backend?.claim !== 'function' || typeof backend?.admit !== 'function') throw new TypeError('atomic backend required');
  async function boolean(method,args) {
    const value=await backend[method](...args);
    if (typeof value !== 'boolean') throw new TypeError('atomic backend must return boolean');
    return value;
  }
  return {claim:(...args)=>boolean('claim',args),admit:(...args)=>boolean('admit',args)};
}
