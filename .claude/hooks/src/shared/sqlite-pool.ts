/**
 * SQLite Connection Pool for TypeScript
 *
 * Provides secure SQLite connections with:
 * - Connection pooling to reduce overhead
 * - 5000ms busy timeout to prevent lock contention
 * - WAL mode for better concurrent access
 * - Automatic cleanup of stale connections
 *
 * Note: This module is for better-sqlite3 (synchronous) usage.
 * For async Python subprocess queries, see db-utils.ts.
 */

// Note: better-sqlite3 is a peer dependency
// This module provides the pooling logic; consumers import better-sqlite3

import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

// =============================================================================
// Types
// =============================================================================

/**
 * Configuration for SQLite pool.
 */
export interface SQLitePoolConfig {
  /** Maximum connections per database file (default: 3) */
  maxConnectionsPerDb?: number;
  /** Busy timeout in milliseconds (default: 5000) */
  busyTimeoutMs?: number;
  /** Stale connection cleanup interval in ms (default: 60000) */
  cleanupIntervalMs?: number;
  /** Max age for idle connections in ms (default: 300000 = 5 min) */
  maxIdleAgeMs?: number;
}

/**
 * Statistics about pool usage.
 */
export interface PoolStats {
  totalConnections: number;
  activeConnections: number;
  idleConnections: number;
  databases: string[];
}

// =============================================================================
// Pool Implementation (Generic - works with any better-sqlite3-like interface)
// =============================================================================

interface PooledConnection<T> {
  db: T;
  inUse: boolean;
  lastUsed: number;
  dbPath: string;
}

const DEFAULT_CONFIG: Required<SQLitePoolConfig> = {
  maxConnectionsPerDb: 3,
  busyTimeoutMs: 5000,
  cleanupIntervalMs: 60000,
  maxIdleAgeMs: 300000,
};

/**
 * Generic connection pool for SQLite databases.
 *
 * This is a factory-based implementation that works with any
 * better-sqlite3-compatible database module.
 *
 * @example
 * import Database from 'better-sqlite3';
 *
 * const pool = createSQLitePool((dbPath, timeout) => {
 *   const db = new Database(dbPath, { timeout });
 *   db.pragma('journal_mode = WAL');
 *   db.pragma(`busy_timeout = ${timeout}`);
 *   return db;
 * });
 *
 * const db = pool.acquire('/path/to/db.sqlite');
 * try {
 *   db.prepare('SELECT * FROM users').all();
 * } finally {
 *   pool.release(db);
 * }
 */
export function createSQLitePool<T extends { close(): void }>(
  factory: (dbPath: string, busyTimeoutMs: number) => T,
  config: SQLitePoolConfig = {}
) {
  const cfg = { ...DEFAULT_CONFIG, ...config };
  const pools = new Map<string, PooledConnection<T>[]>();
  let cleanupTimer: ReturnType<typeof setInterval> | null = null;

  /**
   * Start periodic cleanup of stale connections.
   */
  function startCleanup(): void {
    if (cleanupTimer) return;
    cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [dbPath, pool] of pools.entries()) {
        const stale = pool.filter(
          conn => !conn.inUse && now - conn.lastUsed > cfg.maxIdleAgeMs
        );
        for (const conn of stale) {
          try {
            conn.db.close();
          } catch {
            // Ignore close errors
          }
          pool.splice(pool.indexOf(conn), 1);
        }
        if (pool.length === 0) {
          pools.delete(dbPath);
        }
      }
    }, cfg.cleanupIntervalMs);
  }

  /**
   * Stop cleanup timer.
   */
  function stopCleanup(): void {
    if (cleanupTimer) {
      clearInterval(cleanupTimer);
      cleanupTimer = null;
    }
  }

  /**
   * Acquire a connection from the pool.
   *
   * @param dbPath - Path to SQLite database file
   * @returns Database connection
   * @throws Error if pool is exhausted
   */
  function acquire(dbPath: string): T {
    // Ensure directory exists
    const dir = dirname(dbPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    // Get or create pool for this database
    let pool = pools.get(dbPath);
    if (!pool) {
      pool = [];
      pools.set(dbPath, pool);
    }

    // Find available connection
    for (const conn of pool) {
      if (!conn.inUse) {
        conn.inUse = true;
        conn.lastUsed = Date.now();
        return conn.db;
      }
    }

    // Create new connection if under limit
    if (pool.length < cfg.maxConnectionsPerDb) {
      const db = factory(dbPath, cfg.busyTimeoutMs);
      const conn: PooledConnection<T> = {
        db,
        inUse: true,
        lastUsed: Date.now(),
        dbPath,
      };
      pool.push(conn);
      startCleanup();
      return db;
    }

    throw new Error(
      `SQLite pool exhausted for ${dbPath} (max: ${cfg.maxConnectionsPerDb})`
    );
  }

  /**
   * Release a connection back to the pool.
   *
   * @param db - Database connection to release
   */
  function release(db: T): void {
    for (const pool of pools.values()) {
      const conn = pool.find(c => c.db === db);
      if (conn) {
        conn.inUse = false;
        conn.lastUsed = Date.now();
        return;
      }
    }
    // Connection not from pool - just close it
    try {
      db.close();
    } catch {
      // Ignore
    }
  }

  /**
   * Execute a function with an acquired connection.
   * Connection is automatically released after function completes.
   *
   * @param dbPath - Path to SQLite database file
   * @param fn - Function to execute with connection
   * @returns Result of function
   */
  function withConnection<R>(dbPath: string, fn: (db: T) => R): R {
    const db = acquire(dbPath);
    try {
      return fn(db);
    } finally {
      release(db);
    }
  }

  /**
   * Get pool statistics.
   */
  function getStats(): PoolStats {
    let total = 0;
    let active = 0;
    const databases: string[] = [];

    for (const [dbPath, pool] of pools.entries()) {
      databases.push(dbPath);
      for (const conn of pool) {
        total++;
        if (conn.inUse) active++;
      }
    }

    return {
      totalConnections: total,
      activeConnections: active,
      idleConnections: total - active,
      databases,
    };
  }

  /**
   * Close all connections and clear the pool.
   */
  function shutdown(): void {
    stopCleanup();
    for (const pool of pools.values()) {
      for (const conn of pool) {
        try {
          conn.db.close();
        } catch {
          // Ignore
        }
      }
    }
    pools.clear();
  }

  return {
    acquire,
    release,
    withConnection,
    getStats,
    shutdown,
    startCleanup,
    stopCleanup,
  };
}

// =============================================================================
// Retry Utilities
// =============================================================================

/**
 * Error type for SQLITE_BUSY errors.
 */
export function isSqliteBusyError(err: unknown): boolean {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    return msg.includes('sqlite_busy') || msg.includes('database is locked');
  }
  return false;
}

/**
 * Retry a function with exponential backoff on SQLITE_BUSY errors.
 *
 * @param fn - Function to retry
 * @param maxRetries - Maximum retry attempts (default: 3)
 * @param baseDelayMs - Initial delay in milliseconds (default: 100)
 * @returns Result of fn if successful
 * @throws Last error if all retries fail
 */
export async function retryOnBusy<T>(
  fn: () => T | Promise<T>,
  maxRetries = 3,
  baseDelayMs = 100
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      if (!isSqliteBusyError(err)) {
        throw err;
      }

      lastError = err as Error;
      const delayMs = baseDelayMs * Math.pow(2, attempt);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  throw lastError;
}

/**
 * Synchronous version of retryOnBusy.
 */
export function retryOnBusySync<T>(
  fn: () => T,
  maxRetries = 3,
  baseDelayMs = 100
): T {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return fn();
    } catch (err) {
      if (!isSqliteBusyError(err)) {
        throw err;
      }

      lastError = err as Error;
      const delayMs = baseDelayMs * Math.pow(2, attempt);
      // Synchronous sleep using Atomics
      const sharedBuffer = new SharedArrayBuffer(4);
      const view = new Int32Array(sharedBuffer);
      Atomics.wait(view, 0, 0, delayMs);
    }
  }

  throw lastError;
}

// =============================================================================
// Constants for External Use
// =============================================================================

export const SQLITE_DEFAULTS = {
  busyTimeoutMs: 5000,
  journalMode: 'WAL',
  maxConnectionsPerDb: 3,
} as const;

// =============================================================================
// Exports
// =============================================================================

export default {
  createSQLitePool,
  retryOnBusy,
  retryOnBusySync,
  isSqliteBusyError,
  SQLITE_DEFAULTS,
};
