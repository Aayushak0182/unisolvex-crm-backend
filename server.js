// Deprecated: this backend is no longer used by the CRM UI.
// Keep as a thin wrapper so `npm start` inside `backend/` still works.
// Source of truth: repo root `server.mjs`.

/* eslint-disable no-console */

console.warn('[DEPRECATED] backend/server.js is a wrapper. Starting ../server.mjs instead.');
console.warn('Run from repo root for clarity: `npm run server`');

import('../server.mjs').catch((err) => {
  console.error('Failed to start ../server.mjs:', err);
  process.exitCode = 1;
});

