export class SapiError extends Error {
  constructor(code = 'invalid_message') { super(code); this.code = code; }
}
