/**
 * Shared database utilities for Claude Code hooks.
 *
 * Extracted from pre-tool-use-broadcast.ts as part of the
 * pattern-aware hooks architecture (Phase 2).
 *
 * Exports:
 * - getDbPath(): Returns path to coordination.db
 * - queryDb(): Executes Python subprocess to query SQLite
 * - runPythonQuery(): Alternative that returns success/stdout/stderr object
 * - getActiveAgentCount(): Returns count of running agents (Phase 2: Resource Limits)
 */

import { spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';
import type { QueryResult } from './types.js';
import { generateSessionKey, signEntry } from './crypto-signing.js';

// Re-export SAFE_ID_PATTERN and isValidId from pattern-router for convenience
export { SAFE_ID_PATTERN, isValidId } from './pattern-router.js';

/**
 * Get the path to the coordination database.
 *
 * Uses CLAUDE_PROJECT_DIR environment variable if set,
 * otherwise falls back to process.cwd().
 *
 * @returns Absolute path to coordination.db
 */
export function getDbPath(): string {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return join(projectDir, '.claude', 'cache',
    'agentica-coordination', 'coordination.db');
}

/**
 * Execute a Python query against the coordination database.
 *
 * Uses spawnSync with argument array to prevent command injection.
 * The Python code receives arguments via sys.argv.
 *
 * @param pythonQuery - Python code to execute (receives args via sys.argv)
 * @param args - Arguments passed to Python (sys.argv[1], sys.argv[2], ...)
 * @returns stdout from Python subprocess
 * @throws Error if Python subprocess fails
 */
export function queryDb(pythonQuery: string, args: string[]): string {
  // Use spawnSync with argument array to prevent command injection
  const result = spawnSync('python3', ['-c', pythonQuery, ...args], {
    encoding: 'utf-8',
    maxBuffer: 1024 * 1024
  });

  if (result.status !== 0) {
    const errorMsg = result.stderr || `Python exited with code ${result.status}`;
    throw new Error(`Python query failed: ${errorMsg}`);
  }

  return result.stdout.trim();
}

/**
 * Execute a Python query and return structured result.
 *
 * Unlike queryDb(), this function does not throw on error.
 * Instead, it returns a result object with success, stdout, and stderr.
 *
 * @param script - Python code to execute (receives args via sys.argv)
 * @param args - Arguments passed to Python (sys.argv[1], sys.argv[2], ...)
 * @returns Object with success boolean, stdout string, and stderr string
 */
export function runPythonQuery(script: string, args: string[]): QueryResult {
  try {
    const result = spawnSync('python3', ['-c', script, ...args], {
      encoding: 'utf-8',
      maxBuffer: 1024 * 1024
    });

    return {
      success: result.status === 0,
      stdout: result.stdout?.trim() || '',
      stderr: result.stderr || ''
    };
  } catch (err) {
    return {
      success: false,
      stdout: '',
      stderr: String(err)
    };
  }
}

/**
 * Register a new agent in the coordination database.
 *
 * Inserts a new agent record with status='running'.
 * Creates the database and tables if they don't exist.
 * Automatically detects source from environment (AGENTICA_SERVER env var).
 *
 * @param agentId - Unique agent identifier
 * @param sessionId - Session that spawned the agent
 * @param pattern - Coordination pattern (swarm, hierarchical, etc.)
 * @param pid - Process ID for orphan detection (optional)
 * @returns Object with success boolean and any error message
 */
export function registerAgent(
  agentId: string,
  sessionId: string,
  pattern: string | null = null,
  pid: number | null = null
): { success: boolean; error?: string } {
  const dbPath = getDbPath();

  // Detect source: if AGENTICA_SERVER env var is set, it's from agentica
  // Otherwise it's from the CLI (Task tool)
  const source = process.env.AGENTICA_SERVER ? 'agentica' : 'cli';

  // V1.5: Generate session key if not exists and sign the agent entry
  try {
    // Generate or retrieve session key (idempotent)
    generateSessionKey(sessionId);

    // Build data to sign (matches what will be stored, minus signature)
    const now_ts = Math.floor(Date.now() / 1000);
    const origin_session = sessionId;
    const origin_agent = process.env.AGENT_ID || null;

    const dataToSign = {
      id: agentId,
      session_id: sessionId,
      pattern: pattern,
      pid: pid,
      origin_session: origin_session,
      origin_agent: origin_agent,
      created_at_ts: now_ts,
      source: source,
    };

    // Sign the entry
    const signature = signEntry(dataToSign, sessionId);

    // Pass signature to Python script
    return registerAgentWithSignature(
      agentId,
      sessionId,
      pattern,
      pid,
      source,
      origin_session,
      origin_agent,
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
 * Internal: Register agent with pre-computed signature
 */
function registerAgentWithSignature(
  agentId: string,
  sessionId: string,
  pattern: string | null,
  pid: number | null,
  source: string,
  origin_session: string,
  origin_agent: string | null,
  created_at_ts: number,
  signature: string,
  dbPath: string
): { success: boolean; error?: string } {

  const pythonScript = `
import sqlite3
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

db_path = sys.argv[1]
agent_id = sys.argv[2]
session_id = sys.argv[3]
pattern = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != 'null' else None
pid = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5] != 'null' else None
source = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] != 'null' else None
origin_session = sys.argv[7] if len(sys.argv) > 7 else session_id
origin_agent = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] != 'null' else None
created_at_ts = int(sys.argv[9]) if len(sys.argv) > 9 else None
signature = sys.argv[10] if len(sys.argv) > 10 and sys.argv[10] != 'null' else None

try:
    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Create table if not exists (with source and provenance columns)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            premise TEXT,
            model TEXT,
            scope_keys TEXT,
            pattern TEXT,
            parent_agent_id TEXT,
            pid INTEGER,
            ppid INTEGER,
            spawned_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT DEFAULT 'running',
            error_message TEXT,
            source TEXT,
            origin_session TEXT,
            origin_agent TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    # Migration: add source and provenance columns if they don't exist
    cursor = conn.execute("PRAGMA table_info(agents)")
    columns = {row[1] for row in cursor.fetchall()}
    if 'source' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN source TEXT")
    if 'origin_session' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN origin_session TEXT")
    if 'origin_agent' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN origin_agent TEXT")
    if 'created_at_ts' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN created_at_ts INTEGER")
    if 'signature' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN signature TEXT")

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    # Use provided timestamp if given, otherwise compute
    if created_at_ts is None:
        created_at_ts = int(datetime.now(timezone.utc).timestamp())
    ppid = os.getppid() if pid else None

    conn.execute(
        """
        INSERT OR REPLACE INTO agents
        (id, session_id, pattern, pid, ppid, spawned_at, status, source,
         origin_session, origin_agent, created_at_ts, signature)
        VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?)
        """,
        (agent_id, session_id, pattern, pid, ppid, now, source,
         origin_session, origin_agent, created_at_ts, signature)
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
    agentId,
    sessionId,
    pattern || 'null',
    pid !== null ? String(pid) : 'null',
    source,
    origin_session,
    origin_agent || 'null',
    String(created_at_ts),
    signature
  ];

  const result = runPythonQuery(pythonScript, args);

  if (!result.success || result.stdout !== 'ok') {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Unknown error'
    };
  }

  return { success: true };
}

/**
 * Mark an agent as completed in the coordination database.
 *
 * Updates the agent's status and sets completed_at timestamp.
 *
 * @param agentId - Agent identifier to complete
 * @param status - Final status ('completed' or 'failed')
 * @param errorMessage - Optional error message for failed status
 * @returns Object with success boolean and any error message
 */
export function completeAgent(
  agentId: string,
  status: string = 'completed',
  errorMessage: string | null = null
): { success: boolean; error?: string } {
  const dbPath = getDbPath();

  // Return success if database doesn't exist (nothing to update)
  if (!existsSync(dbPath)) {
    return { success: true };
  }

  const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone

db_path = sys.argv[1]
agent_id = sys.argv[2]
status = sys.argv[3]
error_message = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] != 'null' else None

try:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Check if agents table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='agents'"
    )
    if cursor.fetchone() is None:
        print("ok")
        conn.close()
        sys.exit(0)

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    conn.execute(
        """
        UPDATE agents
        SET completed_at = ?, status = ?, error_message = ?
        WHERE id = ?
        """,
        (now, status, error_message, agent_id)
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
    agentId,
    status,
    errorMessage || 'null'
  ];

  const result = runPythonQuery(pythonScript, args);

  if (!result.success || result.stdout !== 'ok') {
    return {
      success: false,
      error: result.stderr || result.stdout || 'Unknown error'
    };
  }

  return { success: true };
}

/**
 * Record a broadcast message with provenance and signature.
 *
 * V1.5: Adds signature and provenance fields to broadcasts.
 *
 * @param swarmId - Swarm identifier
 * @param senderAgent - Agent sending the broadcast
 * @param broadcastType - Type of broadcast (e.g., 'started', 'done', 'progress')
 * @param payload - Broadcast payload (will be JSON stringified)
 * @param sessionId - Session for signing
 * @returns Object with success boolean and any error message
 */
export function recordBroadcast(
  swarmId: string,
  senderAgent: string,
  broadcastType: string,
  payload: unknown,
  sessionId: string
): { success: boolean; error?: string; broadcastId?: string } {
  const dbPath = getDbPath();

  try {
    // Generate session key if not exists
    generateSessionKey(sessionId);

    // Build data to sign
    const now_ts = Math.floor(Date.now() / 1000);
    const origin_session = sessionId;
    const origin_agent = process.env.AGENT_ID || null;
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);

    // Generate broadcast ID
    const broadcastId = generateBroadcastId();

    const dataToSign = {
      id: broadcastId,
      swarm_id: swarmId,
      sender_agent: senderAgent,
      broadcast_type: broadcastType,
      payload: payloadStr,
      origin_session: origin_session,
      origin_agent: origin_agent,
      created_at_ts: now_ts,
    };

    // Sign the entry
    const signature = signEntry(dataToSign, sessionId);

    // Insert into database
    const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

db_path = sys.argv[1]
broadcast_id = sys.argv[2]
swarm_id = sys.argv[3]
sender_agent = sys.argv[4]
broadcast_type = sys.argv[5]
payload = sys.argv[6]
origin_session = sys.argv[7]
origin_agent = sys.argv[8] if len(sys.argv) > 8 and sys.argv[8] != 'null' else None
created_at_ts = int(sys.argv[9]) if len(sys.argv) > 9 else None
signature = sys.argv[10] if len(sys.argv) > 10 and sys.argv[10] != 'null' else None

try:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")

    # Create broadcasts table if not exists (from V1.1 migration)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS broadcasts (
            id TEXT PRIMARY KEY,
            swarm_id TEXT NOT NULL,
            sender_agent TEXT NOT NULL,
            broadcast_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            origin_session TEXT,
            origin_agent TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

    conn.execute(
        """
        INSERT INTO broadcasts
        (id, swarm_id, sender_agent, broadcast_type, payload, created_at,
         origin_session, origin_agent, created_at_ts, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (broadcast_id, swarm_id, sender_agent, broadcast_type, payload, now,
         origin_session, origin_agent, created_at_ts, signature)
    )

    conn.commit()
    conn.close()
    print(f"ok:{broadcast_id}")
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

    const args = [
      dbPath,
      broadcastId,
      swarmId,
      senderAgent,
      broadcastType,
      payloadStr,
      origin_session,
      origin_agent || 'null',
      String(now_ts),
      signature
    ];

    const result = runPythonQuery(pythonScript, args);

    if (!result.success || !result.stdout.startsWith('ok:')) {
      return {
        success: false,
        error: result.stderr || result.stdout || 'Failed to record broadcast'
      };
    }

    return { success: true, broadcastId };
  } catch (err) {
    return {
      success: false,
      error: `Broadcast signing failed: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}

/**
 * Generate a unique broadcast ID.
 *
 * @returns 12-character hex ID
 */
function generateBroadcastId(): string {
  // Generate random 6 bytes, convert to 12-char hex
  const bytes = new Uint8Array(6);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    // Fallback for Node.js without webcrypto
    const nodeCrypto = require('crypto') as typeof import('crypto');
    nodeCrypto.randomFillSync(bytes);
  }
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Detect if this agent is part of a swarm (concurrent spawn pattern).
 *
 * Checks if there are multiple agents in the same session spawned within
 * a short time window (5 seconds). If so, updates all of them to pattern="swarm".
 *
 * This enables automatic swarm detection for Claude Code Task tool spawns
 * without requiring explicit PATTERN_TYPE environment variable.
 *
 * @param sessionId - Session to check for concurrent spawns
 * @returns true if swarm pattern was detected and applied
 */
export function detectAndTagSwarm(sessionId: string): boolean {
  const dbPath = getDbPath();

  if (!existsSync(dbPath)) {
    return false;
  }

  const pythonScript = `
import sqlite3
import sys
from datetime import datetime, timezone, timedelta

db_path = sys.argv[1]
session_id = sys.argv[2]

try:
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

    # Get agents in this session spawned in the last 5 seconds
    # that are still running and have pattern='task' or NULL
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = (now - timedelta(seconds=5)).isoformat()

    cursor = conn.execute(
        """
        SELECT id FROM agents
        WHERE session_id = ?
          AND spawned_at > ?
          AND status = 'running'
          AND (pattern = 'task' OR pattern IS NULL)
        """,
        (session_id, cutoff)
    )
    concurrent_agents = cursor.fetchall()

    # If more than 1 concurrent agent, tag all as swarm
    if len(concurrent_agents) > 1:
        agent_ids = [row[0] for row in concurrent_agents]
        placeholders = ','.join('?' * len(agent_ids))
        conn.execute(
            f"UPDATE agents SET pattern = 'swarm' WHERE id IN ({placeholders})",
            agent_ids
        )
        conn.commit()
        print(f"swarm:{len(concurrent_agents)}")
    else:
        print("no_swarm")

    conn.close()
except Exception as e:
    print(f"error: {e}")
    sys.exit(1)
`;

  const result = runPythonQuery(pythonScript, [dbPath, sessionId]);

  if (!result.success) {
    return false;
  }

  return result.stdout.startsWith('swarm:');
}

/**
 * Get the count of active (running) agents across all sessions.
 *
 * Queries the coordination database for agents with status='running'.
 * Returns 0 if:
 * - Database doesn't exist
 * - Database query fails
 * - agents table doesn't exist
 *
 * Uses runPythonQuery() pattern to safely execute the SQLite query.
 *
 * @returns Number of running agents, or 0 on any error
 */
export function getActiveAgentCount(): number {
  const dbPath = getDbPath();

  // Return 0 if database doesn't exist
  if (!existsSync(dbPath)) {
    return 0;
  }

  const pythonScript = `
import sqlite3
import sys
import os

db_path = sys.argv[1]

try:
    # Check if file exists and is a valid SQLite database
    if not os.path.exists(db_path):
        print("0")
        sys.exit(0)

    conn = sqlite3.connect(db_path)
    # Set busy_timeout to prevent indefinite blocking (Finding 3: STARVATION_FINDINGS.md)
    conn.execute("PRAGMA busy_timeout = 5000")
    # Enable WAL mode for better concurrent access
    conn.execute("PRAGMA journal_mode = WAL")

    # Check if agents table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='agents'"
    )
    if cursor.fetchone() is None:
        print("0")
        conn.close()
        sys.exit(0)

    # Query running agent count
    cursor = conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'running'")
    count = cursor.fetchone()[0]
    conn.close()
    print(count)
except Exception:
    print("0")
`;

  const result = runPythonQuery(pythonScript, [dbPath]);

  if (!result.success) {
    return 0;
  }

  const count = parseInt(result.stdout, 10);
  return isNaN(count) ? 0 : count;
}

/**
 * Migrate coordination.db schema to add provenance tracking fields.
 *
 * Adds the following fields to agents and broadcasts tables:
 * - origin_session TEXT: Session that created this entry
 * - origin_agent TEXT: Agent that created this entry
 * - created_at_ts INTEGER: Unix timestamp of creation (in addition to ISO string)
 * - signature TEXT: HMAC-SHA256 signature for integrity verification
 *
 * Security: V1.1 - Database authentication and integrity (Round 2 audit, CVSS 8.1)
 *
 * @returns Object with success boolean and any error message
 */
export function migrateCoordinationDbProvenance(): { success: boolean; error?: string } {
  const dbPath = getDbPath();

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

    # Migrate agents table
    cursor = conn.execute("PRAGMA table_info(agents)")
    columns = {row[1] for row in cursor.fetchall()}

    if 'origin_session' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN origin_session TEXT")
    if 'origin_agent' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN origin_agent TEXT")
    if 'created_at_ts' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN created_at_ts INTEGER")
    if 'signature' not in columns:
        conn.execute("ALTER TABLE agents ADD COLUMN signature TEXT")

    # Create broadcasts table if it doesn't exist
    conn.execute("""
        CREATE TABLE IF NOT EXISTS broadcasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            swarm_id TEXT NOT NULL,
            sender_agent TEXT NOT NULL,
            broadcast_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            origin_session TEXT,
            origin_agent TEXT,
            created_at_ts INTEGER,
            signature TEXT
        )
    """)

    # Migrate broadcasts table if it exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='broadcasts'"
    )
    if cursor.fetchone() is not None:
        cursor = conn.execute("PRAGMA table_info(broadcasts)")
        columns = {row[1] for row in cursor.fetchall()}

        if 'origin_session' not in columns:
            conn.execute("ALTER TABLE broadcasts ADD COLUMN origin_session TEXT")
        if 'origin_agent' not in columns:
            conn.execute("ALTER TABLE broadcasts ADD COLUMN origin_agent TEXT")
        if 'created_at_ts' not in columns:
            conn.execute("ALTER TABLE broadcasts ADD COLUMN created_at_ts INTEGER")
        if 'signature' not in columns:
            conn.execute("ALTER TABLE broadcasts ADD COLUMN signature TEXT")

    # Create index for broadcasts swarm_id lookup
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_broadcasts_swarm_id
        ON broadcasts(swarm_id, created_at DESC)
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
