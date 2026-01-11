/**
 * Active Session Registry
 *
 * Tracks active sessions and agents to validate database entries.
 *
 * Security: V1.12 - Session/agent ID validation (Round 2 audit, CVSS 8.1)
 * Audit: Round 2 V1 - Prevent impersonation via fake session/agent IDs
 */

import { existsSync } from 'fs';
import { runPythonQuery } from './db-utils.js';
import { getSessionsDbPath } from './sessions-db-utils.js';
import { verifyEntry } from './crypto-signing.js';

/**
 * Check if a session ID is currently active
 *
 * @param sessionId - Session ID to validate
 * @returns true if session exists and is running
 */
export function isActiveSession(sessionId: string): boolean {
  const dbPath = getSessionsDbPath();

  if (!existsSync(dbPath)) {
    // No sessions database = no active sessions
    // Allow first session to bootstrap
    return true;
  }

  const pythonScript = `
import sqlite3
import sys

db_path = sys.argv[1]
session_id = sys.argv[2]

try:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Check if sessions table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'"
    )
    if cursor.fetchone() is None:
        print("no_table")
        conn.close()
        sys.exit(0)

    # V1.10: Include provenance fields for validation
    cursor = conn.execute(
        "SELECT status, origin_session, signature, created_at_ts FROM sessions WHERE id = ?",
        (session_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row and row[0] == 'running':
        # V1.10: Check if provenance exists and output for validation
        if row[1] and row[2] and row[3]:
            print(f"active|{row[1]}|{row[2]}|{row[3]}")
        else:
            # Legacy entry without provenance - accept for now
            print("active|legacy")
    else:
        print("inactive")
except Exception:
    print("error")
`;

  const result = runPythonQuery(pythonScript, [dbPath, sessionId]);

  // Allow if:
  // - Query succeeded and returned "active" (with or without valid provenance)
  // - Database doesn't exist yet (bootstrap case)
  // - Table doesn't exist yet (bootstrap case)
  if (!result.success) {
    return false;
  }

  // Handle bootstrap cases
  if (result.stdout === 'no_table') {
    return true;
  }

  // Parse response
  const parts = result.stdout.split('|');
  const status = parts[0];

  if (status !== 'active') {
    return false;
  }

  // V1.10: Validate provenance if present
  if (parts.length === 4 && parts[1] !== 'legacy') {
    const [, originSession, signature, createdAtTs] = parts;

    try {
      // Reconstruct signed content (must match write path format in sessions-db-utils.ts)
      const dataToVerify = {
        id: sessionId,
        status: 'running',
        origin_session: originSession,
        created_at_ts: parseInt(createdAtTs, 10)
      };

      const isValid = verifyEntry(dataToVerify, signature, originSession);
      if (!isValid) {
        console.error(`SECURITY: Session ${sessionId} has invalid signature`);
        return false; // Reject sessions with invalid signatures
      }
    } catch (err) {
      console.error(`SECURITY: Session ${sessionId} signature verification error: ${err}`);
      return false;
    }
  }

  // Legacy entries (parts[1] === 'legacy') are accepted for migration path
  return true;
}

/**
 * Check if an agent ID is currently active
 *
 * @param agentId - Agent ID to validate
 * @returns true if agent exists and is running
 */
export function isActiveAgent(agentId: string): boolean {
  const pythonScript = `
import sqlite3
import sys
from pathlib import Path

db_path = sys.argv[1]
agent_id = sys.argv[2]

try:
    # Get coordination.db path
    if not Path(db_path).exists():
        print("no_db")
        sys.exit(0)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Check if agents table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='agents'"
    )
    if cursor.fetchone() is None:
        print("no_table")
        conn.close()
        sys.exit(0)

    # V1.10: Include provenance fields for validation
    cursor = conn.execute(
        "SELECT status, origin_session, signature, created_at_ts FROM agents WHERE id = ?",
        (agent_id,)
    )
    row = cursor.fetchone()
    conn.close()

    if row and row[0] == 'running':
        # V1.10: Check if provenance exists and output for validation
        if row[1] and row[2] and row[3]:
            print(f"active|{row[1]}|{row[2]}|{row[3]}")
        else:
            # Legacy entry without provenance - accept for now
            print("active|legacy")
    else:
        print("inactive")
except Exception:
    print("error")
`;

  // Use coordination.db path
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const coordDbPath = `${projectDir}/.claude/cache/agentica-coordination/coordination.db`;

  const result = runPythonQuery(pythonScript, [coordDbPath, agentId]);

  // Allow if:
  // - Query succeeded and returned "active" (with or without valid provenance)
  // - Database doesn't exist yet (bootstrap case)
  // - Table doesn't exist yet (bootstrap case)
  if (!result.success) {
    return false;
  }

  // Handle bootstrap cases
  if (result.stdout === 'no_table' || result.stdout === 'no_db') {
    return true;
  }

  // Parse response
  const parts = result.stdout.split('|');
  const status = parts[0];

  if (status !== 'active') {
    return false;
  }

  // V1.10: Validate provenance if present
  if (parts.length === 4 && parts[1] !== 'legacy') {
    const [, originSession, signature, createdAtTs] = parts;

    try {
      // Reconstruct signed content (must match write path format in db-utils.ts)
      const dataToVerify = {
        id: agentId,
        status: 'running',
        origin_session: originSession,
        created_at_ts: parseInt(createdAtTs, 10)
      };

      const isValid = verifyEntry(dataToVerify, signature, originSession);
      if (!isValid) {
        console.error(`SECURITY: Agent ${agentId} has invalid signature`);
        return false; // Reject agents with invalid signatures
      }
    } catch (err) {
      console.error(`SECURITY: Agent ${agentId} signature verification error: ${err}`);
      return false;
    }
  }

  // Legacy entries (parts[1] === 'legacy') are accepted for migration path
  return true;
}

/**
 * Validate session ID format and activity
 *
 * @param sessionId - Session ID to validate
 * @returns Object with valid boolean and error message if invalid
 */
export function validateSession(sessionId: string): {
  valid: boolean;
  error?: string;
} {
  // Check format (basic sanity check)
  if (!sessionId || sessionId.length === 0) {
    return {
      valid: false,
      error: 'Session ID is empty'
    };
  }

  if (sessionId.length > 64) {
    return {
      valid: false,
      error: 'Session ID exceeds maximum length'
    };
  }

  // Check if session is active
  if (!isActiveSession(sessionId)) {
    return {
      valid: false,
      error: `Session ${sessionId} is not active`
    };
  }

  return { valid: true };
}

/**
 * Validate agent ID format and activity
 *
 * @param agentId - Agent ID to validate
 * @returns Object with valid boolean and error message if invalid
 */
export function validateAgent(agentId: string): {
  valid: boolean;
  error?: string;
} {
  // Null/undefined agent is valid (not all operations have agents)
  if (!agentId) {
    return { valid: true };
  }

  // Check format
  if (agentId.length > 64) {
    return {
      valid: false,
      error: 'Agent ID exceeds maximum length'
    };
  }

  // Check if agent is active
  if (!isActiveAgent(agentId)) {
    return {
      valid: false,
      error: `Agent ${agentId} is not active`
    };
  }

  return { valid: true };
}
