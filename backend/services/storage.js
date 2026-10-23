import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Data directory (override with DATA_DIR; tests use a temp dir). */
export const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, '..', 'data');

fs.mkdirSync(DATA_DIR, { recursive: true });

export const dataPath = (name) => path.join(DATA_DIR, name);

export function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch (err) {
    console.error(`[storage] Failed to read ${path.basename(file)}: ${err.message}`);
    return fallback;
  }
}

/** Atomic write (temp file + rename) so a crash can never leave half-written JSON. */
export function writeJson(file, value, { secret = false } = {}) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: 'utf-8', mode: secret ? 0o600 : 0o644 });
  fs.renameSync(tmp, file);
}
