#!/usr/bin/env node
/**
 * Migration script for sessions.db provenance schema
 *
 * Adds provenance tracking fields to sessions and session_outputs tables:
 * - origin_session TEXT
 * - created_at_ts INTEGER
 * - signature TEXT
 *
 * Usage: node migrate-sessions-db.mjs
 *
 * Security: V1.3 - Sessions database authentication and integrity (Round 2 audit)
 */

import { migrateSessionsDbProvenance } from '../src/shared/sessions-db-utils.js';

async function main() {
  console.log('Migrating sessions.db to add provenance tracking...');

  const result = migrateSessionsDbProvenance();

  if (result.success) {
    console.log('✓ Migration successful');
    process.exit(0);
  } else {
    console.error('✗ Migration failed:', result.error);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Uncaught error:', err);
  process.exit(1);
});
