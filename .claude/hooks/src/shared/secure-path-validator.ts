/**
 * Secure Path Validator - Path Traversal Prevention
 *
 * Provides secure path validation for user-supplied file paths.
 * Prevents F3 vulnerability (Arbitrary File Read via Path Traversal, CVSS 6.5).
 *
 * Mitigations:
 * - Enforces file_path is under CLAUDE_PROJECT_DIR
 * - Rejects absolute paths outside project
 * - Detects and blocks path traversal (../)
 * - Resolves symlinks and verifies target is within project
 * - Blocks null bytes and Unicode-based path manipulation
 *
 * @see audit-report.md for repo-security-analysis-cgk (0854d47)
 */

import { resolve, relative, isAbsolute, normalize } from 'path';
import { existsSync, realpathSync, statSync, lstatSync } from 'fs';

// =============================================================================
// Security Limits
// =============================================================================

/** Maximum path length to prevent DoS via long paths */
export const MAX_PATH_LENGTH = 4096;

/** Maximum symlink depth to prevent infinite loops */
export const MAX_SYMLINK_DEPTH = 10;

// =============================================================================
// Path Validation Types
// =============================================================================

export interface PathValidationResult {
  valid: boolean;
  error?: string;
  resolvedPath?: string;
  relativePath?: string;
  isSymlink?: boolean;
}

export interface PathValidationOptions {
  /** Base directory to restrict paths to (defaults to CLAUDE_PROJECT_DIR or cwd) */
  baseDir?: string;
  /** Whether to allow symlinks (they will be resolved and target validated) */
  allowSymlinks?: boolean;
  /** Whether the file must exist */
  mustExist?: boolean;
  /** Additional allowed directories (outside baseDir) */
  allowedPaths?: string[];
}

// =============================================================================
// Character Patterns
// =============================================================================

/** Null bytes that could bypass path checks */
const NULL_BYTE = /\x00/;

/** Control characters that should not appear in paths */
const CONTROL_CHARS = /[\x00-\x1f\x7f]/;

/** Unicode line separators that could bypass newline-based path parsing */
const UNICODE_LINE_SEPARATORS = /[\u0085\u2028\u2029]/;

/** Path traversal patterns */
const TRAVERSAL_PATTERNS = [
  /\.\.\//,      // ../
  /\.\.\\/,      // ..\
  /^\.\.$/,      // standalone ..
  /\/\.\.$/,     // trailing /..
  /\\\.\.$/,     // trailing \..
];

/** Encoded path traversal patterns (URL encoding, Unicode) */
const ENCODED_TRAVERSAL = [
  /%2e%2e/i,     // URL-encoded ..
  /%252e%252e/i, // Double URL-encoded ..
  /\u002e\u002e/, // Unicode period
  /%c0%ae/i,     // Overlong UTF-8 for .
  /%c0%2e/i,     // Alternate overlong
];

// =============================================================================
// Core Validation Functions
// =============================================================================

/**
 * Validate a file path for security issues.
 *
 * This function:
 * 1. Checks for null bytes and control characters
 * 2. Detects path traversal attempts (including encoded)
 * 3. Resolves symlinks and validates target
 * 4. Ensures path is within allowed boundaries
 *
 * @param filePath - The user-supplied file path to validate
 * @param options - Validation options
 * @returns PathValidationResult with validation status and resolved path
 */
export function validateFilePath(
  filePath: string,
  options: PathValidationOptions = {}
): PathValidationResult {
  const {
    baseDir = process.env.CLAUDE_PROJECT_DIR || process.cwd(),
    allowSymlinks = true,
    mustExist = false,
    allowedPaths = [],
  } = options;

  // Empty or missing path
  if (!filePath || typeof filePath !== 'string') {
    return { valid: false, error: 'File path is required' };
  }

  // Check length
  if (filePath.length > MAX_PATH_LENGTH) {
    return { valid: false, error: `Path exceeds maximum length (${MAX_PATH_LENGTH})` };
  }

  // Check for null bytes (critical - can bypass string termination)
  if (NULL_BYTE.test(filePath)) {
    return { valid: false, error: 'Null byte detected in path' };
  }

  // Check for control characters
  if (CONTROL_CHARS.test(filePath)) {
    return { valid: false, error: 'Control characters not allowed in path' };
  }

  // Check for Unicode line separators
  if (UNICODE_LINE_SEPARATORS.test(filePath)) {
    return { valid: false, error: 'Unicode line separators not allowed in path' };
  }

  // Check for path traversal patterns
  for (const pattern of TRAVERSAL_PATTERNS) {
    if (pattern.test(filePath)) {
      return { valid: false, error: 'Path traversal detected' };
    }
  }

  // Check for encoded path traversal
  for (const pattern of ENCODED_TRAVERSAL) {
    if (pattern.test(filePath)) {
      return { valid: false, error: 'Encoded path traversal detected' };
    }
  }

  // Normalize the path
  const normalizedPath = normalize(filePath);

  // Re-check for traversal after normalization
  for (const pattern of TRAVERSAL_PATTERNS) {
    if (pattern.test(normalizedPath)) {
      return { valid: false, error: 'Path traversal detected after normalization' };
    }
  }

  // Resolve to absolute path
  const resolvedBase = resolve(baseDir);
  let resolvedPath: string;

  if (isAbsolute(filePath)) {
    resolvedPath = resolve(filePath);
  } else {
    resolvedPath = resolve(resolvedBase, filePath);
  }

  // Check if file exists (before symlink resolution)
  if (mustExist && !existsSync(resolvedPath)) {
    return { valid: false, error: 'File does not exist' };
  }

  // Check for symlinks and resolve them
  let isSymlink = false;
  let realPath = resolvedPath;

  if (existsSync(resolvedPath)) {
    try {
      const lstats = lstatSync(resolvedPath);
      isSymlink = lstats.isSymbolicLink();

      if (isSymlink) {
        if (!allowSymlinks) {
          return { valid: false, error: 'Symlinks not allowed' };
        }

        // Resolve symlink and validate target
        try {
          realPath = realpathSync(resolvedPath);
        } catch (err) {
          return { valid: false, error: 'Failed to resolve symlink target' };
        }
      }
    } catch (err) {
      return { valid: false, error: 'Failed to stat file' };
    }
  }

  // Validate path is within baseDir (after symlink resolution)
  if (!isPathWithinDir(realPath, resolvedBase)) {
    // Check if in allowed paths
    const isAllowed = allowedPaths.some(allowedPath => {
      const resolvedAllowed = resolve(allowedPath);
      return isPathWithinDir(realPath, resolvedAllowed);
    });

    if (!isAllowed) {
      return {
        valid: false,
        error: `Path outside allowed directory: ${resolvedBase}`,
      };
    }
  }

  // Calculate relative path for logging/display
  const relativePath = relative(resolvedBase, realPath);

  return {
    valid: true,
    resolvedPath: realPath,
    relativePath,
    isSymlink,
  };
}

/**
 * Check if a path is within a directory.
 * Handles edge cases like exact match and trailing slashes.
 */
function isPathWithinDir(path: string, dir: string): boolean {
  const normalizedPath = normalize(path);
  const normalizedDir = normalize(dir);

  // Exact match
  if (normalizedPath === normalizedDir) {
    return true;
  }

  // Path is under directory
  const dirWithSlash = normalizedDir.endsWith('/') ? normalizedDir : `${normalizedDir}/`;
  return normalizedPath.startsWith(dirWithSlash);
}

/**
 * Validate a path specifically for TLDR hook use.
 *
 * This is a convenience wrapper that uses CLAUDE_PROJECT_DIR as baseDir
 * and enforces stricter defaults suitable for the TLDR read enforcer.
 *
 * @param filePath - User-supplied file path from hook input
 * @returns PathValidationResult
 */
export function validateTLDRPath(filePath: string): PathValidationResult {
  const projectDir = process.env.CLAUDE_PROJECT_DIR;

  if (!projectDir) {
    return { valid: false, error: 'CLAUDE_PROJECT_DIR not set' };
  }

  return validateFilePath(filePath, {
    baseDir: projectDir,
    allowSymlinks: true,    // Allow but resolve and validate target
    mustExist: true,        // File must exist for TLDR to read
    allowedPaths: [],       // No paths outside project allowed
  });
}

/**
 * Sanitize a file path by removing dangerous characters.
 *
 * WARNING: Prefer validation over sanitization. Only use this when you
 * absolutely need to accept a modified path rather than reject entirely.
 *
 * @param filePath - The file path to sanitize
 * @returns Sanitized path (may be empty if path is entirely invalid)
 */
export function sanitizeFilePath(filePath: string): string {
  if (!filePath || typeof filePath !== 'string') {
    return '';
  }

  let sanitized = filePath;

  // Remove null bytes (use global flag via new RegExp)
  sanitized = sanitized.replace(/\x00/g, '');

  // Remove control characters (global regex)
  sanitized = sanitized.replace(/[\x00-\x1f\x7f]/g, '');

  // Remove Unicode line separators (global regex)
  sanitized = sanitized.replace(/[\u0085\u2028\u2029]/g, '');

  // Remove path traversal sequences
  sanitized = sanitized.replace(/\.\.\//g, '');
  sanitized = sanitized.replace(/\.\.\\/g, '');

  // Normalize multiple slashes
  sanitized = sanitized.replace(/\/+/g, '/');

  return sanitized;
}

// =============================================================================
// Exports
// =============================================================================

export default {
  validateFilePath,
  validateTLDRPath,
  sanitizeFilePath,
  isPathWithinDir,
  MAX_PATH_LENGTH,
  MAX_SYMLINK_DEPTH,
};
