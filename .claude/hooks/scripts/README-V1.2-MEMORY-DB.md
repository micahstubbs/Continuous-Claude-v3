# V1.2: Memory Database Provenance Schema

Security audit Round 2, V1.2 - Adding provenance tracking to memory.db

## Overview

This migration adds provenance tracking fields to the `learnings` table in `memory.db` to prevent learning tampering and enable integrity verification.

## New Fields

The learnings table now includes:

- `origin_session TEXT` - Session that created this learning
- `origin_agent TEXT` - Agent that created this learning (if applicable)
- `created_at_ts INTEGER` - Unix timestamp for creation
- `signature TEXT` - HMAC-SHA256 signature for integrity verification

## Migration

### Automatic Migration

New learning storage automatically includes provenance fields. The schema auto-migrates when the database is accessed.

### Manual Migration

To migrate an existing database:

```bash
cd .claude/hooks
node scripts/migrate-memory-db.mjs
```

### Verification

After migration, verify the schema:

```bash
sqlite3 ~/.claude/memory.db "PRAGMA table_info(learnings)"
```

Expected output should include:
```
...
origin_session|TEXT|0||0
origin_agent|TEXT|0||0
created_at_ts|INTEGER|0||0
signature|TEXT|0||0
```

## Database Location

Memory database is stored globally at `~/.claude/memory.db` for cross-project learning persistence.

## Security Benefits

1. **Authenticity**: Each learning entry is traceable to its origin session/agent
2. **Integrity**: Signatures prevent tampering with learnings
3. **Audit Trail**: Timestamps enable forensic analysis
4. **Recall Trust**: Unsigned learnings can be filtered or flagged

## Full-Text Search

FTS5 index (`learnings_fts`) is preserved and automatically synced via triggers. Provenance fields are excluded from search (metadata only).

## Implementation Details

- Schema changes are backward compatible (new columns allow NULL)
- Existing learnings will have NULL provenance fields until re-saved
- Future writes will populate all provenance fields
- Signature generation/verification uses V1.4 crypto-signing module

## Related Changes

- V1.4: Signing/hashing infrastructure (crypto-signing.ts)
- V1.6: Update write paths for memory.db provenance
- V1.9: Update read paths to validate signatures

## CWE Mitigations

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-20: Improper Input Validation (via signature verification)

## CVSS Score

8.1 (High) - Unauthenticated memory stores enable recall poisoning
