/**
 * Memory Database Utilities
 *
 * Utilities for memory.db (learnings storage) provenance tracking.
 *
 * Security: V1.2 - Memory database authentication and integrity
 * Audit: Round 2 V1 - Unauthenticated memory stores (CVSS 8.1)
 */

import { join } from 'path';
import { existsSync } from 'fs';
import { runPythonQuery } from './db-utils.js';
import { generateSessionKey, signEntry } from './crypto-signing.js';

/**
 * Get the path to the memory database.
 *
 * Memory database is stored in user's home directory for global persistence.
 *
 * @returns Absolute path to memory.db
 */
export function getMemoryDbPath(): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  return join(home, '.claude', 'memory.db');
}

/**
 * Migrate memory.db schema to add provenance tracking fields.
 *
 * Adds the following fields to learnings table:
 * - origin_session TEXT: Session that created this learning
 * - origin_agent TEXT: Agent that created this learning
 * - created_at_ts INTEGER: Unix timestamp of creation
 * - signature TEXT: HMAC-SHA256 signature for integrity verification
 *
 * Security: V1.2 - Database authentication and integrity (Round 2 audit, CVSS 8.1)
 *
 * @returns Object with success boolean and any error message
 */
export function migrateMemoryDbProvenance(): { success: boolean; error?: string } {
  const dbPath = getMemoryDbPath();

  // Skip if database doesn't exist yet - will be created with new schema
  if (!existsSync(dbPath)) {
    return { success: true };
  }

  const pythonScript = `
import sqlite3
import sys
from pathlib import Path

db_path = sys.argv[1]

try:
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Create learnings table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS learnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            content TEXT NOT NULL,
            learning_type TEXT,
            created_at TEXT NOT NULL,
            origin_session TEXT,
            origin_agent TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    # Migrate learnings table if it exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='learnings'"
    )
    if cursor.fetchone() is not None:
        cursor = conn.execute("PRAGMA table_info(learnings)")
        columns = {row[1] for row in cursor.fetchall()}

        if 'origin_session' not in columns:
            conn.execute("ALTER TABLE learnings ADD COLUMN origin_session TEXT")
        if 'origin_agent' not in columns:
            conn.execute("ALTER TABLE learnings ADD COLUMN origin_agent TEXT")
        if 'created_at_ts' not in columns:
            conn.execute("ALTER TABLE learnings ADD COLUMN created_at_ts INTEGER")
        if 'signature' not in columns:
            conn.execute("ALTER TABLE learnings ADD COLUMN signature TEXT")

    # Create or rebuild FTS index with content only (provenance fields excluded from search)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS learnings_fts USING fts5(
            content,
            content=learnings,
            content_rowid=id
        )
    """)

    # Create triggers to keep FTS in sync (if they don't exist)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS learnings_ai AFTER INSERT ON learnings BEGIN
            INSERT INTO learnings_fts(rowid, content) VALUES (new.id, new.content);
        END
    """)

    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS learnings_ad AFTER DELETE ON learnings BEGIN
            INSERT INTO learnings_fts(learnings_fts, rowid, content)
            VALUES('delete', old.id, old.content);
        END
    """)

    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS learnings_au AFTER UPDATE ON learnings BEGIN
            INSERT INTO learnings_fts(learnings_fts, rowid, content)
            VALUES('delete', old.id, old.content);
            INSERT INTO learnings_fts(rowid, content) VALUES (new.id, new.content);
        END
    """)

    # Create index for session_id lookup
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_learnings_session_id
        ON learnings(session_id, created_at DESC)
    """)

    conn.commit()
    conn.close()
    print("ok")
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

  const result = runPythonQuery(pythonScript, [dbPath]);

  if (!result.success || result.stdout !== 'ok') {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Migration failed'
    };
  }

  return { success: true };
}

/**
 * Store a learning with provenance metadata and signature.
 *
 * V1.6: Adds HMAC-SHA256 signature to learning entries.
 *
 * @param sessionId - Session that created this learning
 * @param content - Learning content
 * @param learningType - Type of learning (e.g., 'debugging', 'pattern', 'gotcha')
 * @param originAgent - Agent ID that created this learning (optional)
 * @returns Object with success boolean and any error message
 */
export function storeLearning(
  sessionId: string,
  content: string,
  learningType: string = 'general',
  originAgent: string | null = null
): { success: boolean; error?: string; id?: number } {
  const dbPath = getMemoryDbPath();

  try {
    // V1.6: Generate session key if not exists and sign the learning
    generateSessionKey(sessionId);

    // Build data to sign
    const now_ts = Math.floor(Date.now() / 1000);
    const origin_session = sessionId;
    const origin_agent_val = originAgent || process.env.AGENT_ID || null;

    const dataToSign = {
      session_id: sessionId,
      content: content,
      learning_type: learningType,
      origin_session: origin_session,
      origin_agent: origin_agent_val,
      created_at_ts: now_ts,
    };

    // Sign the entry
    const signature = signEntry(dataToSign, sessionId);

    // Pass signature to Python script
    return storeLearningWithSignature(
      sessionId,
      content,
      learningType,
      origin_agent_val,
      now_ts,
      signature,
      dbPath
    );
  } catch (err) {
    return {
      success: false,
      error: `Signing failed: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}

/**
 * Internal: Store learning with pre-computed signature
 */
function storeLearningWithSignature(
  sessionId: string,
  content: string,
  learningType: string,
  originAgent: string | null,
  created_at_ts: number,
  signature: string,
  dbPath: string
): { success: boolean; error?: string; id?: number } {
  const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

db_path = sys.argv[1]
session_id = sys.argv[2]
content = sys.argv[3]
learning_type = sys.argv[4]
origin_agent = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] != 'null' else None
created_at_ts = int(sys.argv[6]) if len(sys.argv) > 6 else None
signature = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] != 'null' else None

try:
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Ensure table exists with provenance fields
    conn.execute("""
        CREATE TABLE IF NOT EXISTS learnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            content TEXT NOT NULL,
            learning_type TEXT,
            created_at TEXT NOT NULL,
            origin_session TEXT,
            origin_agent TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    # Use provided timestamp if given, otherwise compute
    if created_at_ts is None:
        created_at_ts = int(datetime.now(timezone.utc).timestamp())

    # Insert with provenance and signature
    cursor = conn.execute(
        """
        INSERT INTO learnings
        (session_id, content, learning_type, created_at, origin_session, origin_agent, created_at_ts, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, content, learning_type, now, session_id, origin_agent, created_at_ts, signature)
    )

    learning_id = cursor.lastrowid
    conn.commit()
    conn.close()
    print(f"ok:{learning_id}")
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

  const args = [
    dbPath,
    sessionId,
    content,
    learningType,
    originAgent || 'null',
    String(created_at_ts),
    signature
  ];

  const result = runPythonQuery(pythonScript, args);

  if (!result.success || !result.stdout.startsWith('ok:')) {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Failed to store learning'
    };
  }

  const learningId = parseInt(result.stdout.split(':')[1], 10);
  return { success: true, id: learningId };
}
