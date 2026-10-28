// Isolated SDK probe only: no listener, storage, logging, fetch or application handlers.
import { Codec, SecureServer, SapiError } from '../../sdks/javascript/src/index.js';

export function createIsolatedInspector({ service, keyProvider, replayStore }) {
  if (!keyProvider || !replayStore) throw new TypeError('explicit isolated key provider and replay store required');
  const codec = new Codec(service, keyProvider);
  const server = new SecureServer(codec, replayStore); // No business operations are registered.
  return {
    async inspect(bytes) {
      if (!(bytes instanceof Uint8Array) || bytes.length > 8192) return {result:'unsupported',stage:'not_evaluated'};
      if (bytes.some(b => b > 127)) return {result:'unsupported',stage:'not_evaluated'};
      const wire = new TextDecoder('ascii').decode(bytes);
      try {
        const response = await server.handle(wire);
        const {payload} = await codec.open(response, 'res');
        if (payload.error === 'unknown_operation') return {result:'authenticated_no_handler',stage:'message_authentication'};
        if (payload.error === 'replay') return {result:'replay',stage:'replay'};
        return {result:'not_measured',stage:'secure_server'};
      } catch (error) {
        return error instanceof SapiError ? {result:'wire_rejected_under_test_keys',stage:'message_or_authentication'} : {result:'not_measured',stage:'evaluation_error'};
      }
    },
  };
}
