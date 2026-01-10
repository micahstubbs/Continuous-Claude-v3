#!/usr/bin/env node

// src/shared/sessions-db-utils.ts
import { join } from "path";
import { existsSync } from "fs";

// src/shared/db-utils.ts
import { spawnSync } from "child_process";
function runPythonQuery(script, args) {
  try {
    const result = spawnSync("python3", ["-c", script, ...args], {
      encoding: "utf-8",
      maxBuffer: 1024 * 1024
    });
    return {
      success: result.status === 0,
      stdout: result.stdout?.trim() || "",
      stderr: result.stderr || ""
    };
  } catch (err) {
    return {
      success: false,
      stdout: "",
      stderr: String(err)
    };
  }
}

// src/shared/sessions-db-utils.ts
function getSessionsDbPath() {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return join(projectDir, ".claude", "cache", "sessions.db");
}
function migrateSessionsDbProvenance() {
  const dbPath = getSessionsDbPath();
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
  if (!result.success || result.stdout !== "ok") {
    return {
      success: false,
      error: result.stderr || result.stdout || "Migration failed"
    };
  }
  return { success: true };
}

// scripts/migrate-sessions-db.ts
async function main() {
  console.log("Migrating sessions.db to add provenance tracking...");
  const result = migrateSessionsDbProvenance();
  if (result.success) {
    console.log("\u2713 Migration successful");
    process.exit(0);
  } else {
    console.error("\u2717 Migration failed:", result.error);
    process.exit(1);
  }
}
main().catch((err) => {
  console.error("Uncaught error:", err);
  process.exit(1);
});
