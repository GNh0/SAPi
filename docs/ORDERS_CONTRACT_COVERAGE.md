# Synthetic orders contract and coverage

This contract is scoped to the default orders collection in `APPLICATION.md`, not every possible SAPi application. `verify_order_parity.py` checks fixed outputs and `orders_contract.py` independently declares expected dummy table contents after each step. The oracle does not derive its expectation from observed variants. Shared implementation bugs outside these explicit expectations can still escape. “Covered” means only the listed local synthetic path was exercised.

| Contract | Fixture / coverage |
| --- | --- |
| Missing or deleted record returns `found=false` | `missing_get`, `deleted_get` |
| Create own record, initial version 1 and phase created; duplicate leaves state unchanged | `create`, `duplicate_create` |
| Owner and read-scoped principal can retrieve own record | `get`, `reader_get` |
| Created record updates with correct version, stale version does not change state | `update`, `stale_update` |
| Different owner's record is neither returned nor changed | `foreign_get`, `foreign_update` |
| Invalid input or missing scope is rejected before business handler | `invalid_schema`, `missing_scope` |
| Submit created record; forbid subsequent update; complete submitted record; forbid completed deletion | `submit`, `post_submit_update`, `complete`, `completed_delete` |
| Delete created record with current version | `create_for_delete`, `delete` |
| All fields and identifiers, additional ownership/workflow edges, concurrent updates, retries, transaction failure and rollback | **Not measured** by this sequence |
| TLS, production keys/state, real inbound traffic, external effects and actual customer APIs | **Not measured** |

The fixed oracle checks the complete dummy record table at each step; it is not evidence about non-dummy databases. The fixtures' expected response values and state are versioned source artifacts; change them only with a reviewed contract change and a negative control. A mutation that changes all variants identically must still fail the oracle.
