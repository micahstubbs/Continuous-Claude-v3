#!/usr/bin/env node
/**
 * Migration script for memory.db provenance schema
 *
 * Adds provenance tracking fields to learnings table:
 * - origin_session TEXT
 * - origin_agent TEXT
 * - created_at_ts INTEGER
 * - signature TEXT
 *
 * Usage: node migrate-memory-db.mjs
 *
 * Security: V1.2 - Memory database authentication and integrity (Round 2 audit)
 */

import { migrateMemoryDbProvenance } from '../src/shared/memory-db-utils.js';

async function main() {
  console.log('Migrating memory.db to add provenance tracking...');

  const result = migrateMemoryDbProvenance();

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
