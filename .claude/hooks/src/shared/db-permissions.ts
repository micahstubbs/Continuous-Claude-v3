/**
 * Database File Permissions Enforcement
 *
 * Ensures all SQLite databases have secure file permissions (0600).
 *
 * Security: V1.11 - File permissions enforcement (Round 2 audit, CVSS 8.1)
 * Audit: Round 2 V1 - Prevent unauthorized database access
 */

import { existsSync, chmodSync, statSync } from 'fs';

/**
 * Check if a file has secure permissions (0600 - owner read/write only)
 *
 * @param filePath - Path to check
 * @returns true if permissions are 0600
 */
export function hasSecurePermissions(filePath: string): boolean {
  if (!existsSync(filePath)) {
    return true; // File doesn't exist yet - will be created with secure perms
  }

  try {
    const stats = statSync(filePath);
    const mode = stats.mode & 0o777; // Extract permission bits
    return mode === 0o600; // Owner read/write only
  } catch {
    return false;
  }
}

/**
 * Enforce secure permissions on a database file
 *
 * Sets permissions to 0600 (owner read/write only) if they are not already secure.
 *
 * @param filePath - Database file path
 * @returns Object with success boolean and any error message
 */
export function enforceSecurePermissions(filePath: string): { success: boolean; error?: string } {
  if (!existsSync(filePath)) {
    return { success: true }; // Nothing to enforce yet
  }

  try {
    if (!hasSecurePermissions(filePath)) {
      chmodSync(filePath, 0o600);
    }
    return { success: true };
  } catch (err) {
    return {
      success: false,
      error: `Failed to set permissions on ${filePath}: ${err instanceof Error ? err.message : String(err)}`
    };
  }
}

/**
 * Enforce secure permissions on all SQLite databases
 *
 * @param dbPaths - Array of database file paths
 * @returns Object with success boolean and any error messages
 */
export function enforceAllDatabasePermissions(dbPaths: string[]): {
  success: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  for (const dbPath of dbPaths) {
    const result = enforceSecurePermissions(dbPath);
    if (!result.success && result.error) {
      errors.push(result.error);
    }

    // Also enforce permissions on WAL and SHM files if they exist
    const walPath = `${dbPath}-wal`;
    const shmPath = `${dbPath}-shm`;

    if (existsSync(walPath)) {
      const walResult = enforceSecurePermissions(walPath);
      if (!walResult.success && walResult.error) {
        errors.push(walResult.error);
      }
    }

    if (existsSync(shmPath)) {
      const shmResult = enforceSecurePermissions(shmPath);
      if (!shmResult.success && shmResult.error) {
        errors.push(shmResult.error);
      }
    }
  }

  return {
    success: errors.length === 0,
    errors
  };
}

/**
 * Verify all databases have secure permissions
 *
 * @param dbPaths - Array of database file paths
 * @returns Object with verification status and list of insecure files
 */
export function verifyDatabasePermissions(dbPaths: string[]): {
  secure: boolean;
  insecure: string[];
} {
  const insecure: string[] = [];

  for (const dbPath of dbPaths) {
    if (existsSync(dbPath) && !hasSecurePermissions(dbPath)) {
      insecure.push(dbPath);
    }

    // Check WAL and SHM files
    const walPath = `${dbPath}-wal`;
    const shmPath = `${dbPath}-shm`;

    if (existsSync(walPath) && !hasSecurePermissions(walPath)) {
      insecure.push(walPath);
    }

    if (existsSync(shmPath) && !hasSecurePermissions(shmPath)) {
      insecure.push(shmPath);
    }
  }

  return {
    secure: insecure.length === 0,
    insecure
  };
}
