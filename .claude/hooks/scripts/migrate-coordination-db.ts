#!/usr/bin/env node
/**
 * Migration script for coordination.db provenance schema
 *
 * Adds provenance tracking fields to agents and broadcasts tables:
 * - origin_session TEXT
 * - origin_agent TEXT
 * - created_at_ts INTEGER
 * - signature TEXT
 *
 * Usage: node migrate-coordination-db.mjs
 *
 * Security: V1.1 - Database authentication and integrity (Round 2 audit)
 */

import { migrateCoordinationDbProvenance } from '../src/shared/db-utils.js';

async function main() {
  console.log('Migrating coordination.db to add provenance tracking...');

  const result = migrateCoordinationDbProvenance();

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
