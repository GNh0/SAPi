// Stable public SDK entry point; transport is an optional separate import.
export {Codec} from './codec.js';
export {SapiError} from './errors.js';
export {MemoryReplayStore} from './replay.js';
export {SecureServer} from './server.js';
export {StaticKeyProvider} from './keys.js';
export {b64, unb64, digest} from './serialization.js';
export {Schema} from './schema.js';
export {OwnedSql,SqlPlan} from './sql.js';
