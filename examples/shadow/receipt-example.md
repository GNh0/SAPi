# Synthetic receipt example

This local example demonstrates a receipt and a business effect committed together, output validation before the write, ownership checks, and a bounded key tied to the subject and normalized operation. It uses invented in-memory identities and isolated SQLite fixtures. It is not an authentication system, a production database schema, or a deployed service.

The operation key is globally unique in this example. A different principal cannot independently reuse the same key. A fresh wire retry can call the handler again, while the committed business effect remains at most once. A lost response after commit must be resolved by receipt lookup; absence of a receipt at one instant does not prove that an in-flight write cannot commit later. Server object replacement in the test is not a process restart, and this example does not test key rotation or distributed replay.

Run with Node.js 22.13 or later (the test requires the experimental node:sqlite API):

    node tests/test_receipt_contract.mjs

The test uses an in-memory SQLite adapter. It is not evidence of distributed D1 concurrency or production response delivery guarantees.
