# V1.1: Coordination Database Provenance Schema

Security audit Round 2, V1.1 - Adding provenance tracking to coordination.db

## Overview

This migration adds provenance tracking fields to the `agents` and `broadcasts` tables in `coordination.db` to prevent agent impersonation and enable integrity verification.

## New Fields

All tables now include:

- `origin_session TEXT` - Session that created this entry
- `origin_agent TEXT` - Agent that created this entry (if applicable)
- `created_at_ts INTEGER` - Unix timestamp for creation
- `signature TEXT` - HMAC-SHA256 signature for integrity verification

## Migration

### Automatic Migration

New agent registrations automatically include provenance fields. The schema auto-migrates when the database is accessed.

### Manual Migration

To migrate an existing database:

```bash
cd .claude/hooks
node scripts/migrate-coordination-db.mjs
```

### Verification

After migration, verify the schema:

```bash
sqlite3 .claude/cache/agentica-coordination/coordination.db "PRAGMA table_info(agents)"
```

Expected output should include:
```
...
origin_session|TEXT|0||0
origin_agent|TEXT|0||0
created_at_ts|INTEGER|0||0
signature|TEXT|0||0
```

## Security Benefits

1. **Authentication**: Each database entry is traceable to its origin session/agent
2. **Integrity**: Signatures prevent tampering with database entries
3. **Audit Trail**: Timestamps enable forensic analysis
4. **Impersonation Prevention**: Unsigned entries can be rejected

## Implementation Details

- Schema changes are backward compatible (new columns allow NULL)
- Existing entries will have NULL provenance fields until updated
- Future writes will populate all provenance fields
- Signature generation/verification uses V1.4 crypto-signing module

## Related Changes

- V1.4: Signing/hashing infrastructure (crypto-signing.ts)
- V1.5-V1.7: Update write paths to populate signatures
- V1.8-V1.10: Update read paths to validate signatures

## CWE Mitigations

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-287: Improper Authentication

## CVSS Score

8.1 (High) - Unauthenticated coordination/memory stores enable agent impersonation
