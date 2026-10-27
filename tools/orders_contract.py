"""Independent expected dummy table state for the documented orders sequence."""
import hashlib
import json


def expected_digest(step_index, after):
    # State is described from the contract, not derived from observed implementation.
    position = step_index + int(after)
    rows = [('demo', 'orders', 'bob', 'foreign', 1, 'created', {'description':'fixture','quantity':1})]
    if position >= 2:
        version = 4 if position >= 14 else 3 if position >= 12 else 2 if position >= 6 else 1
        phase = 'completed' if position >= 14 else 'submitted' if position >= 12 else 'created'
        data = {'description':'updated fixture','quantity':2} if position >= 6 else {'description':'fixture','quantity':1}
        rows.append(('demo', 'orders', 'alice', 'own', version, phase, data))
    if position == 16:
        rows.append(('demo', 'orders', 'alice', 'disposable', 1, 'created', {'description':'fixture','quantity':1}))
    rows.sort(key=lambda r: (r[0], r[1], r[2], r[3]))
    encoded = [(*r[:-1], json.dumps(r[-1], ensure_ascii=False, separators=(',',':'))) for r in rows]
    return hashlib.sha256(json.dumps(encoded, ensure_ascii=True, separators=(',',':')).encode()).hexdigest()
