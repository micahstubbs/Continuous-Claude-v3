#!/usr/bin/env node

// src/shared/db-utils.ts
import { spawnSync } from "child_process";
import { existsSync } from "fs";
import { join } from "path";
function getDbPath() {
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  return join(
    projectDir,
    ".claude",
    "cache",
    "agentica-coordination",
    "coordination.db"
  );
}
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
function migrateCoordinationDbProvenance() {
  const dbPath = getDbPath();
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
  if (!result.success || result.stdout !== "ok") {
    return {
      success: false,
      error: result.stderr || result.stdout || "Migration failed"
    };
  }
  return { success: true };
}

// scripts/migrate-coordination-db.ts
async function main() {
  console.log("Migrating coordination.db to add provenance tracking...");
  const result = migrateCoordinationDbProvenance();
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
