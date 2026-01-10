/**
 * Sessions Database Utilities
 *
 * Utilities for sessions.db (session metadata tracking) with provenance.
 *
 * Security: V1.3 - Sessions database authentication and integrity
 * Audit: Round 2 V1 - Unauthenticated session stores (CVSS 8.1)
 */

import { join } from 'path';
import { existsSync } from 'fs';
import { runPythonQuery } from './db-utils.js';
import { generateSessionKey, signEntry } from './crypto-signing.js';

/**
 * Get the path to the sessions database.
 *
 * Sessions database is stored per-project for session tracking.
 *
 * @returns Absolute path to sessions.db
 */
export function getSessionsDbPath(): string {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return join(projectDir, '.claude', 'cache', 'sessions.db');
}

/**
 * Migrate sessions.db schema to add provenance tracking fields.
 *
 * Adds the following fields to sessions table:
 * - origin_session TEXT: Parent session that spawned this (if applicable)
 * - created_at_ts INTEGER: Unix timestamp of creation
 * - signature TEXT: HMAC-SHA256 signature for integrity verification
 *
 * Security: V1.3 - Database authentication and integrity (Round 2 audit, CVSS 8.1)
 *
 * @returns Object with success boolean and any error message
 */
export function migrateSessionsDbProvenance(): { success: boolean; error?: string } {
  const dbPath = getSessionsDbPath();

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

    # Create sessions table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            project_dir TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT DEFAULT 'running',
            exit_reason TEXT,
            origin_session TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    # Migrate sessions table if it exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
    )
    if cursor.fetchone() is not None:
        cursor = conn.execute("PRAGMA table_info(sessions)")
        columns = {row[1] for row in cursor.fetchall()}

        if 'origin_session' not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN origin_session TEXT")
        if 'created_at_ts' not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN created_at_ts INTEGER")
        if 'signature' not in columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN signature TEXT")

    # Create session_outputs table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS session_outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            output_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            origin_session TEXT,
            created_at_ts INTEGER,
            signature TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        )
    """)

    # Migrate session_outputs table if it exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='session_outputs'"
    )
    if cursor.fetchone() is not None:
        cursor = conn.execute("PRAGMA table_info(session_outputs)")
        columns = {row[1] for row in cursor.fetchall()}

        if 'origin_session' not in columns:
            conn.execute("ALTER TABLE session_outputs ADD COLUMN origin_session TEXT")
        if 'created_at_ts' not in columns:
            conn.execute("ALTER TABLE session_outputs ADD COLUMN created_at_ts INTEGER")
        if 'signature' not in columns:
            conn.execute("ALTER TABLE session_outputs ADD COLUMN signature TEXT")

    # Create indexes for session lookup
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_sessions_project
        ON sessions(project_dir, started_at DESC)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_session_outputs_session_id
        ON session_outputs(session_id, created_at DESC)
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
 * Register a new session with provenance metadata and signature.
 *
 * V1.7: Adds HMAC-SHA256 signature to session entries.
 *
 * @param sessionId - Unique session identifier
 * @param projectDir - Project directory path
 * @param originSession - Parent session ID (if spawned from another session)
 * @returns Object with success boolean and any error message
 */
export function registerSession(
  sessionId: string,
  projectDir: string,
  originSession: string | null = null
): { success: boolean; error?: string } {
  const dbPath = getSessionsDbPath();

  try {
    // V1.7: Generate session key if not exists and sign the session entry
    generateSessionKey(sessionId);

    // Build data to sign
    const now_ts = Math.floor(Date.now() / 1000);
    const origin_session_val = originSession;

    const dataToSign = {
      id: sessionId,
      project_dir: projectDir,
      status: 'running',
      origin_session: origin_session_val,
      created_at_ts: now_ts,
    };

    // Sign the entry
    const signature = signEntry(dataToSign, sessionId);

    // Pass signature to Python script
    return registerSessionWithSignature(
      sessionId,
      projectDir,
      origin_session_val,
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
 * Internal: Register session with pre-computed signature
 */
function registerSessionWithSignature(
  sessionId: string,
  projectDir: string,
  originSession: string | null,
  created_at_ts: number,
  signature: string,
  dbPath: string
): { success: boolean; error?: string } {
  const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

db_path = sys.argv[1]
session_id = sys.argv[2]
project_dir = sys.argv[3]
origin_session = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != 'null' else None
created_at_ts = int(sys.argv[5]) if len(sys.argv) > 5 else None
signature = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] != 'null' else None

try:
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Ensure table exists with provenance fields
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            project_dir TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT DEFAULT 'running',
            exit_reason TEXT,
            origin_session TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    # Use provided timestamp if given, otherwise compute
    if created_at_ts is None:
        created_at_ts = int(datetime.now(timezone.utc).timestamp())

    # Insert with provenance and signature
    conn.execute(
        """
        INSERT OR REPLACE INTO sessions
        (id, project_dir, started_at, status, origin_session, created_at_ts, signature)
        VALUES (?, ?, ?, 'running', ?, ?, ?)
        """,
        (session_id, project_dir, now, origin_session, created_at_ts, signature)
    )

    conn.commit()
    conn.close()
    print("ok")
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

  const args = [
    dbPath,
    sessionId,
    projectDir,
    originSession || 'null',
    String(created_at_ts),
    signature
  ];

  const result = runPythonQuery(pythonScript, args);

  if (!result.success || result.stdout !== 'ok') {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Failed to register session'
    };
  }

  return { success: true };
}

/**
 * Mark a session as ended with exit reason.
 *
 * @param sessionId - Session identifier to end
 * @param exitReason - Reason for session end (e.g., 'completed', 'error', 'timeout')
 * @returns Object with success boolean and any error message
 */
export function endSession(
  sessionId: string,
  exitReason: string = 'completed'
): { success: boolean; error?: string } {
  const dbPath = getSessionsDbPath();

  // Skip if database doesn't exist
  if (!existsSync(dbPath)) {
    return { success: true };
  }

  const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone

db_path = sys.argv[1]
session_id = sys.argv[2]
exit_reason = sys.argv[3]

try:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    conn.execute(
        """
        UPDATE sessions
        SET ended_at = ?, status = 'ended', exit_reason = ?
        WHERE id = ?
        """,
        (now, exit_reason, session_id)
    )

    conn.commit()
    conn.close()
    print("ok")
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

  const args = [dbPath, sessionId, exitReason];

  const result = runPythonQuery(pythonScript, args);

  if (!result.success || result.stdout !== 'ok') {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Failed to end session'
    };
  }

  return { success: true };
}
