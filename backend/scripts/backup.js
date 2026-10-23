// Consistent online backup of the SQLite database (safe while the server is running).
//   npm run backup            -> backend/data/backups/aegis-<timestamp>.db
//   npm run backup -- <file>  -> custom path
import fs from 'fs';
import path from 'path';
import { DatabaseSync } from 'node:sqlite';
import { DATA_DIR } from '../services/storage.js';

const src = path.join(DATA_DIR, 'aegis.db');
if (!fs.existsSync(src)) { console.error(`No database at ${src}`); process.exit(1); }

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const out = path.resolve(process.argv[2] || path.join(DATA_DIR, 'backups', `aegis-${stamp}.db`));
fs.mkdirSync(path.dirname(out), { recursive: true });
if (fs.existsSync(out)) { console.error(`Refusing to overwrite ${out}`); process.exit(1); }

const db = new DatabaseSync(src);
db.exec(`VACUUM INTO '${out.replace(/'/g, "''")}'`);
db.close();
console.log(`Backup written to ${out}`);
