// Contract adapter only. Backend must atomically implement claim and multi-limit admit.
// No D1 schema or production implementation is supplied here.
export function atomicReplayAdapter(backend, {splitBudget=false}={}) {
  if (typeof backend?.claim !== 'function' || typeof backend?.admit !== 'function') throw new TypeError('atomic backend required');
  if (typeof splitBudget !== 'boolean' || (splitBudget && typeof backend.claimBounded !== 'function')) throw new TypeError('atomic split-budget backend required');
  async function boolean(method,args) {
    const value=await backend[method](...args);
    if (typeof value !== 'boolean') throw new TypeError('atomic backend must return boolean');
    return value;
  }
  const adapter={claim:(...args)=>boolean('claim',args),admit:(...args)=>boolean('admit',args)};
  if (splitBudget) adapter.claimBounded=async (...args)=>{
    const value=await backend.claimBounded(...args);
    if (!['accepted','replay','rate_limited'].includes(value)) throw new TypeError('invalid atomic replay decision');
    return value;
  };
  return adapter;
}
