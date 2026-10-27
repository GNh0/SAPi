"""Illustrative in-process opt-in routing; the host owns HTTP and legacy auth."""
from sapi import SecureServer


class MigrationGateway:
    def __init__(self, *, mode, codec, replay_store, legacy_handler, operation,
                 scope, input_schema, output_schema, policy, business_handler):
        if mode not in ('legacy_only', 'dual', 'sapi_only'):
            raise ValueError('explicit migration mode required')
        if not callable(legacy_handler) or replay_store is None:
            raise ValueError('legacy handler and explicit replay store required')
        self.mode = mode
        self._legacy = legacy_handler
        self._sapi = SecureServer(codec, replay_store)
        self._sapi.register(operation, scope, input_schema, output_schema, policy, business_handler)

    def dispatch(self, route, request):
        # The host maps fixed routes to these values; never infer from content or failure.
        if route == 'legacy' and self.mode in ('legacy_only', 'dual'):
            return self._legacy(request)
        if route == 'sapi' and self.mode in ('sapi_only', 'dual'):
            return self._sapi.handle(request)
        raise ValueError('route disabled or unknown')
