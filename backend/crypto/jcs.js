/**
 * JSON Canonicalization (RFC 8785 / JCS) for I-JSON data.
 *
 * - Object keys are sorted by UTF-16 code units (the default JS sort order, as JCS requires).
 * - Strings and numbers use ECMAScript's JSON.stringify serialization, which is the
 *   serialization RFC 8785 mandates.
 * - Non-finite numbers and BigInt cannot be represented in JSON and are rejected, so two
 *   different inputs can never silently canonicalize to the same bytes.
 */
export function canonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError('Cannot canonicalize a non-finite number.');
      }
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map(v => (v === undefined || typeof v === 'function' ? 'null' : canonicalize(v))).join(',') + ']';
      }
      const parts = [];
      for (const key of Object.keys(value).sort()) {
        const v = value[key];
        if (v === undefined || typeof v === 'function') continue; // same as JSON.stringify
        parts.push(JSON.stringify(key) + ':' + canonicalize(v));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new TypeError(`Cannot canonicalize value of type ${typeof value}.`);
  }
}
