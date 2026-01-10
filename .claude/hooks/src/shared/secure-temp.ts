/**
 * Secure Temporary File Handling
 *
 * Provides secure utilities for creating and managing temporary files:
 * - Creates temp files with restrictive permissions (600)
 * - Uses fs.mkdtemp for secure directory creation
 * - Ensures cleanup in finally blocks
 * - Provides alternatives to temp files (stdin, in-memory)
 *
 * Security benefits:
 * - Prevents other users from reading sensitive temp data
 * - Uses cryptographic randomness for file names
 * - Automatic cleanup to prevent data leakage
 */

import {
  mkdtempSync,
  writeFileSync,
  unlinkSync,
  chmodSync,
  existsSync,
  rmSync,
  readdirSync,
} from 'fs';
import { promises as fsPromises } from 'fs';
import { tmpdir } from 'os';
import { join, basename } from 'path';
import { randomBytes } from 'crypto';

// =============================================================================
// Types
// =============================================================================

export interface TempFileOptions {
  /** Prefix for the temp file name */
  prefix?: string;
  /** File extension (without dot) */
  extension?: string;
  /** File permissions (default: 0o600 - owner read/write only) */
  mode?: number;
  /** Custom temp directory (default: os.tmpdir()) */
  tempDir?: string;
}

export interface TempDirOptions {
  /** Prefix for the temp directory name */
  prefix?: string;
  /** Directory permissions (default: 0o700 - owner only) */
  mode?: number;
  /** Custom base directory (default: os.tmpdir()) */
  baseDir?: string;
}

export interface TempFileResult {
  path: string;
  cleanup: () => void;
}

export interface TempDirResult {
  path: string;
  cleanup: () => void;
}

// =============================================================================
// Constants
// =============================================================================

/** Default file permissions: owner read/write only */
const DEFAULT_FILE_MODE = 0o600;

/** Default directory permissions: owner only */
const DEFAULT_DIR_MODE = 0o700;

/** Default prefix for temp files */
const DEFAULT_PREFIX = 'claude-hook-';

/** Random bytes for unique names */
const RANDOM_BYTES = 8;

// =============================================================================
// Synchronous API
// =============================================================================

/**
 * Generate a secure random filename.
 */
function generateSecureFilename(prefix: string, extension?: string): string {
  const random = randomBytes(RANDOM_BYTES).toString('hex');
  const ext = extension ? `.${extension}` : '';
  return `${prefix}${random}${ext}`;
}

/**
 * Create a secure temporary directory.
 *
 * Uses fs.mkdtempSync which:
 * - Creates a unique directory with random suffix
 * - Sets appropriate permissions
 * - Is atomic (no race conditions)
 */
export function createSecureTempDirSync(options: TempDirOptions = {}): TempDirResult {
  const {
    prefix = DEFAULT_PREFIX,
    mode = DEFAULT_DIR_MODE,
    baseDir = tmpdir(),
  } = options;

  // Create temp directory
  const dirPath = mkdtempSync(join(baseDir, prefix));

  // Ensure restrictive permissions
  chmodSync(dirPath, mode);

  return {
    path: dirPath,
    cleanup: () => {
      try {
        if (existsSync(dirPath)) {
          rmSync(dirPath, { recursive: true, force: true });
        }
      } catch {
        // Silent fail on cleanup
      }
    },
  };
}

/**
 * Write content to a secure temporary file.
 *
 * Creates file with:
 * - Random filename (cryptographic)
 * - Restrictive permissions (600 by default)
 * - Exclusive creation flag (fails if exists)
 */
export function writeSecureTempFileSync(
  content: string | Buffer,
  options: TempFileOptions = {}
): TempFileResult {
  const {
    prefix = DEFAULT_PREFIX,
    extension = 'tmp',
    mode = DEFAULT_FILE_MODE,
    tempDir = tmpdir(),
  } = options;

  const filename = generateSecureFilename(prefix, extension);
  const filePath = join(tempDir, filename);

  // Write with exclusive flag (fails if exists) and restrictive mode
  writeFileSync(filePath, content, {
    mode,
    flag: 'wx', // Write exclusive - fail if exists
  });

  return {
    path: filePath,
    cleanup: () => {
      try {
        if (existsSync(filePath)) {
          unlinkSync(filePath);
        }
      } catch {
        // Silent fail on cleanup
      }
    },
  };
}

/**
 * Execute a function with a temporary file, ensuring cleanup.
 *
 * @example
 * const result = withSecureTempFileSync(sensitiveData, (path) => {
 *   return spawnSync('processor', [path]);
 * });
 */
export function withSecureTempFileSync<T>(
  content: string | Buffer,
  fn: (filePath: string) => T,
  options: TempFileOptions = {}
): T {
  const temp = writeSecureTempFileSync(content, options);

  try {
    return fn(temp.path);
  } finally {
    temp.cleanup();
  }
}

/**
 * Execute a function with a temporary directory, ensuring cleanup.
 */
export function withSecureTempDirSync<T>(
  fn: (dirPath: string) => T,
  options: TempDirOptions = {}
): T {
  const temp = createSecureTempDirSync(options);

  try {
    return fn(temp.path);
  } finally {
    temp.cleanup();
  }
}

// =============================================================================
// Async API
// =============================================================================

/**
 * Create a secure temporary directory (async).
 */
export async function createSecureTempDir(options: TempDirOptions = {}): Promise<TempDirResult> {
  const {
    prefix = DEFAULT_PREFIX,
    mode = DEFAULT_DIR_MODE,
    baseDir = tmpdir(),
  } = options;

  const dirPath = await fsPromises.mkdtemp(join(baseDir, prefix));
  await fsPromises.chmod(dirPath, mode);

  return {
    path: dirPath,
    cleanup: async () => {
      try {
        await fsPromises.rm(dirPath, { recursive: true, force: true });
      } catch {
        // Silent fail
      }
    },
  };
}

/**
 * Write content to a secure temporary file (async).
 */
export async function writeSecureTempFile(
  content: string | Buffer,
  options: TempFileOptions = {}
): Promise<TempFileResult> {
  const {
    prefix = DEFAULT_PREFIX,
    extension = 'tmp',
    mode = DEFAULT_FILE_MODE,
    tempDir = tmpdir(),
  } = options;

  const filename = generateSecureFilename(prefix, extension);
  const filePath = join(tempDir, filename);

  await fsPromises.writeFile(filePath, content, {
    mode,
    flag: 'wx',
  });

  return {
    path: filePath,
    cleanup: async () => {
      try {
        await fsPromises.unlink(filePath);
      } catch {
        // Silent fail
      }
    },
  };
}

/**
 * Execute an async function with a temporary file, ensuring cleanup.
 */
export async function withSecureTempFile<T>(
  content: string | Buffer,
  fn: (filePath: string) => Promise<T>,
  options: TempFileOptions = {}
): Promise<T> {
  const temp = await writeSecureTempFile(content, options);

  try {
    return await fn(temp.path);
  } finally {
    await temp.cleanup();
  }
}

/**
 * Execute an async function with a temporary directory, ensuring cleanup.
 */
export async function withSecureTempDir<T>(
  fn: (dirPath: string) => Promise<T>,
  options: TempDirOptions = {}
): Promise<T> {
  const temp = await createSecureTempDir(options);

  try {
    return await fn(temp.path);
  } finally {
    await temp.cleanup();
  }
}

// =============================================================================
// Cleanup Utilities
// =============================================================================

/**
 * Clean up old temporary files matching a prefix.
 *
 * Useful for cleaning up files from crashed processes.
 *
 * @param maxAgeMs Maximum age in milliseconds (default: 1 hour)
 */
export function cleanupOldTempFiles(
  prefix: string = DEFAULT_PREFIX,
  maxAgeMs: number = 60 * 60 * 1000,
  tempDir: string = tmpdir()
): { cleaned: string[]; errors: string[] } {
  const cleaned: string[] = [];
  const errors: string[] = [];
  const now = Date.now();

  try {
    const files = readdirSync(tempDir);

    for (const file of files) {
      if (!file.startsWith(prefix)) continue;

      const filePath = join(tempDir, file);

      try {
        const stats = require('fs').statSync(filePath);
        const age = now - stats.mtimeMs;

        if (age > maxAgeMs) {
          if (stats.isDirectory()) {
            rmSync(filePath, { recursive: true, force: true });
          } else {
            unlinkSync(filePath);
          }
          cleaned.push(filePath);
        }
      } catch (err) {
        errors.push(`${filePath}: ${err}`);
      }
    }
  } catch (err) {
    errors.push(`readdir: ${err}`);
  }

  return { cleaned, errors };
}

// =============================================================================
// Best Practices: Alternatives to Temp Files
// =============================================================================

/**
 * BEST PRACTICE: Pass data via stdin instead of temp files.
 *
 * Example usage:
 * ```typescript
 * import { spawnSync } from 'child_process';
 *
 * // Instead of:
 * // writeFileSync('/tmp/data.txt', sensitiveData);
 * // spawnSync('processor', ['/tmp/data.txt']);
 *
 * // Do this:
 * spawnSync('processor', [], {
 *   input: sensitiveData,
 *   encoding: 'utf-8',
 * });
 * ```
 *
 * This function documents the pattern for reference.
 */
export function documentStdinPattern(): string {
  return `
SECURE: Pass sensitive data via stdin instead of temp files.

const result = spawnSync('python', ['script.py'], {
  input: sensitiveData,  // Via stdin, never touches filesystem
  encoding: 'utf-8',
  timeout: 30000,
});

Benefits:
- Data never written to disk
- No file permission issues
- No cleanup required
- No race conditions
`;
}

// =============================================================================
// Exports
// =============================================================================

export default {
  // Sync API
  createSecureTempDirSync,
  writeSecureTempFileSync,
  withSecureTempFileSync,
  withSecureTempDirSync,

  // Async API
  createSecureTempDir,
  writeSecureTempFile,
  withSecureTempFile,
  withSecureTempDir,

  // Cleanup
  cleanupOldTempFiles,

  // Documentation
  documentStdinPattern,
};
