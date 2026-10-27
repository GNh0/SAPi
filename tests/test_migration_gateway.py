"""Opt-in migration proof using the real Python SDK and a shared business function."""
from pathlib import Path
import secrets
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'sdks/python'))
sys.path.insert(0, str(ROOT / 'examples/migration'))
from sapi import Codec, KeyRecord, MemoryReplayStore, SapiError
from gateway import MigrationGateway


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.codec = Codec('demo', {'client': KeyRecord(secrets.token_bytes(32), 'alice', frozenset({'read'})),
                                    'limited': KeyRecord(secrets.token_bytes(32), 'alice', frozenset())})
        self.calls = []
        self.schema = {'type': 'object', 'properties': {'value': {'type': 'string', 'maxBytes': 32}}}

    def gateway(self, mode):
        def business(principal, data):
            self.calls.append(principal.subject)
            return {'value': data['value']}
        # Simulates an existing route whose host has already authenticated a caller.
        def legacy(request):
            return business(self.codec.principal('client'), request)
        return MigrationGateway(mode=mode, codec=self.codec, replay_store=MemoryReplayStore(),
                                legacy_handler=legacy, operation='echo', scope='read',
                                input_schema=self.schema, output_schema=self.schema,
                                policy=lambda p, d: p.subject == 'alice', business_handler=business)

    def test_parallel_success_and_no_fallback_on_error(self):
        gateway = self.gateway('dual')
        self.assertEqual(gateway.dispatch('legacy', {'value': 'hello'}), {'value': 'hello'})
        ctx = self.codec.request('client', 'echo', {'value': 'hello'})
        result = self.codec.accept_response(ctx, gateway.dispatch('sapi', ctx.wire))
        self.assertEqual(result['data'], {'value': 'hello'})
        self.assertEqual(self.calls, ['alice', 'alice'])
        _, replay = self.codec.open(gateway.dispatch('sapi', ctx.wire), 'res')
        self.assertEqual(replay['error'], 'replay')
        with self.assertRaises(SapiError): gateway.dispatch('sapi', 'invalid')
        denied = self.codec.request('limited', 'echo', {'value': 'hello'})
        result = self.codec.accept_response(denied, gateway.dispatch('sapi', denied.wire))
        self.assertEqual(result['error'], 'forbidden')
        invalid = self.codec.request('client', 'echo', {'value': 42})
        result = self.codec.accept_response(invalid, gateway.dispatch('sapi', invalid.wire))
        self.assertEqual(result['error'], 'invalid_input')
        self.assertEqual(self.calls, ['alice', 'alice'])

    def test_cutover_and_rollback_are_explicit(self):
        for mode, allowed, disabled in [('legacy_only', 'legacy', 'sapi'), ('sapi_only', 'sapi', 'legacy')]:
            gateway = self.gateway(mode)
            with self.assertRaises(ValueError): gateway.dispatch(disabled, 'ignored')
            if allowed == 'legacy': self.assertEqual(gateway.dispatch(allowed, {'value': 'ok'}), {'value': 'ok'})
            else:
                ctx = self.codec.request('client', 'echo', {'value': 'ok'})
                self.assertEqual(self.codec.accept_response(ctx, gateway.dispatch(allowed, ctx.wire))['data'], {'value': 'ok'})
        with self.assertRaises(ValueError): self.gateway('automatic')

if __name__ == '__main__': unittest.main()
