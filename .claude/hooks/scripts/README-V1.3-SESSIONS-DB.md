# V1.3: Sessions Database Provenance Schema

Security audit Round 2, V1.3 - Adding provenance tracking to sessions.db

## Overview

This migration adds provenance tracking fields to session tracking tables in `sessions.db` to prevent session metadata tampering and enable integrity verification.

## New Fields

The `sessions` and `session_outputs` tables now include:

- `origin_session TEXT` - Parent session that spawned this (if applicable)
- `created_at_ts INTEGER` - Unix timestamp for creation
- `signature TEXT` - HMAC-SHA256 signature for integrity verification

## Migration

### Automatic Migration

New session registration automatically includes provenance fields. The schema auto-migrates when the database is accessed.

### Manual Migration

To migrate an existing database:

```bash
cd .claude/hooks
node scripts/migrate-sessions-db.mjs
```

### Verification

After migration, verify the schema:

```bash
sqlite3 .claude/cache/sessions.db "PRAGMA table_info(sessions)"
```

Expected output should include:
```
...
origin_session|TEXT|0||0
created_at_ts|INTEGER|0||0
signature|TEXT|0||0
```

## Database Location

Sessions database is stored per-project at `.claude/cache/sessions.db` for session history tracking.

## Schema

### sessions table
- `id` - Unique session identifier (PRIMARY KEY)
- `project_dir` - Project directory path
- `started_at` - ISO timestamp of session start
- `ended_at` - ISO timestamp of session end (NULL if running)
- `status` - Session status ('running' or 'ended')
- `exit_reason` - Reason for session end (e.g., 'completed', 'error', 'timeout')
- **Provenance fields** - origin_session, created_at_ts, signature

### session_outputs table
- `id` - Auto-increment primary key
- `session_id` - Foreign key to sessions table
- `output_type` - Type of output (e.g., 'file', 'commit', 'artifact')
- `content` - Output content or path
- `created_at` - ISO timestamp
- **Provenance fields** - origin_session, created_at_ts, signature

## Security Benefits

1. **Session Authenticity**: Each session record is traceable to its origin
2. **Integrity**: Signatures prevent tampering with session history
3. **Audit Trail**: Timestamps enable forensic analysis
4. **Parent-Child Tracking**: origin_session enables session spawn tree reconstruction

## Implementation Details

- Schema changes are backward compatible (new columns allow NULL)
- Existing sessions will have NULL provenance fields until updated
- Future session registrations will populate all provenance fields
- Signature generation/verification uses V1.4 crypto-signing module

## Related Changes

- V1.4: Signing/hashing infrastructure (crypto-signing.ts)
- V1.7: Update write paths for sessions.db provenance
- V1.10: Update read paths to validate signatures

## CWE Mitigations

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-732: Incorrect Permission Assignment for Critical Resource

## CVSS Score

8.1 (High) - Unauthenticated session stores enable history tampering
