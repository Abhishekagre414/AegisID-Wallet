import dotenv from 'dotenv';
dotenv.config({ quiet: true });

// Imported after dotenv so services see the environment.
const { validateProductionConfig } = await import('./middleware/security.js');
const { errors, warnings } = validateProductionConfig();
warnings.forEach(w => console.warn(`[config] ${w}`));
if (errors.length) {
  errors.forEach(e => console.error(`[config] ${e}`));
  console.error('[config] Refusing to start with an unsafe production configuration.');
  process.exit(1);
}

const { createApp } = await import('./app.js');
const { closeDb } = await import('./services/db.js');

const PORT = process.env.PORT || 5000;
const app = createApp();

const server = app.listen(PORT, () => {
  console.log(`[AegisID] Backend running at http://localhost:${PORT} (${process.env.NODE_ENV || 'development'})`);
  console.log('[AegisID] Ed25519 / SHA-256 / JCS | did:key | VC Data Model 1.1 | StatusList2021 revocation');
});

// Graceful shutdown: stop accepting requests, let in-flight ones finish, flush the database.
let stopping = false;
function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  console.log(`[AegisID] ${signal} received, shutting down...`);
  server.close(() => { closeDb(); process.exit(0); });
  setTimeout(() => { closeDb(); process.exit(1); }, 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (err) => console.error('[unhandledRejection]', err));
