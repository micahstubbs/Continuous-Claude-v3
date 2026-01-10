/**
 * Binary Path Resolution and Validation
 *
 * Resolves absolute paths to security-sensitive binaries at startup and validates
 * they exist in trusted locations. Prevents PATH hijacking attacks.
 *
 * Security: CWE-426 (Untrusted Search Path) mitigation
 * Audit: Round 2 V2 - PATH hijack for security-sensitive subprocesses
 */

import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { resolve } from 'path';

/**
 * Trusted binary directories (allowlist)
 */
const TRUSTED_BINARY_DIRS = [
  '/usr/bin',
  '/usr/local/bin',
  '/bin',
  '/opt/homebrew/bin', // macOS Homebrew
  '/home/linuxbrew/.linuxbrew/bin', // Linux Homebrew
];

/**
 * Required binaries for hook operations
 */
const REQUIRED_BINARIES = [
  'python3',
  'sqlite3',
  'uv',
  'nc',
  'tmux',
] as const;

/**
 * Optional binaries (hooks degrade gracefully if missing)
 */
const OPTIONAL_BINARIES = [
  'lean',
  'lake',
  'rg', // ripgrep
] as const;

type RequiredBinary = typeof REQUIRED_BINARIES[number];
type OptionalBinary = typeof OPTIONAL_BINARIES[number];
type Binary = RequiredBinary | OptionalBinary;

/**
 * Resolved binary paths (cached after initialization)
 */
const resolvedPaths = new Map<Binary, string>();

/**
 * Minimal sanitized PATH for subprocess invocations
 */
let sanitizedPath: string | null = null;

/**
 * Resolve the absolute path to a binary using `which`
 *
 * @param binary - Binary name to resolve
 * @returns Absolute path or null if not found
 */
function resolveBinaryPath(binary: string): string | null {
  try {
    // Use `which` to find the binary (itself must be in PATH initially)
    const result = execFileSync('which', [binary], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000,
    });

    const path = result.trim();

    // Validate the path exists and is in a trusted directory
    if (!existsSync(path)) {
      return null;
    }

    // Check if path is in a trusted directory
    const isTrusted = TRUSTED_BINARY_DIRS.some(dir =>
      path.startsWith(resolve(dir) + '/')
    );

    if (!isTrusted) {
      console.error(`[binary-resolver] Rejected untrusted binary path: ${path}`);
      return null;
    }

    return path;
  } catch (err) {
    // Binary not found or `which` failed
    return null;
  }
}

/**
 * Initialize binary path resolution
 *
 * Must be called at hook startup. Fails closed if required binaries are missing.
 *
 * @throws Error if required binaries cannot be resolved
 */
export function initializeBinaryPaths(): void {
  // Resolve required binaries
  for (const binary of REQUIRED_BINARIES) {
    const path = resolveBinaryPath(binary);
    if (!path) {
      throw new Error(
        `Required binary '${binary}' not found in trusted directories. ` +
        `Trusted: ${TRUSTED_BINARY_DIRS.join(', ')}`
      );
    }
    resolvedPaths.set(binary, path);
  }

  // Resolve optional binaries (log but don't fail)
  for (const binary of OPTIONAL_BINARIES) {
    const path = resolveBinaryPath(binary);
    if (path) {
      resolvedPaths.set(binary, path);
    } else {
      console.warn(`[binary-resolver] Optional binary '${binary}' not found`);
    }
  }

  // Create sanitized PATH from trusted directories only
  sanitizedPath = TRUSTED_BINARY_DIRS.filter(existsSync).join(':');

  console.log(`[binary-resolver] Initialized ${resolvedPaths.size} binary paths`);
}

/**
 * Get the absolute path to a binary
 *
 * @param binary - Binary name
 * @returns Absolute path
 * @throws Error if binary was not resolved during initialization
 */
export function getBinaryPath(binary: Binary): string {
  const path = resolvedPaths.get(binary);
  if (!path) {
    throw new Error(
      `Binary '${binary}' not resolved. Call initializeBinaryPaths() first.`
    );
  }
  return path;
}

/**
 * Get sanitized PATH for subprocess invocations
 *
 * @returns Minimal PATH containing only trusted directories
 * @throws Error if not initialized
 */
export function getSanitizedPath(): string {
  if (!sanitizedPath) {
    throw new Error('Binary paths not initialized. Call initializeBinaryPaths() first.');
  }
  return sanitizedPath;
}

/**
 * Get sanitized environment for subprocess invocations
 *
 * Returns a minimal environment with:
 * - Sanitized PATH
 * - Removed potentially dangerous vars
 * - LC_ALL=C for consistent behavior
 *
 * @returns Sanitized environment object
 */
export function getSanitizedEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: getSanitizedPath(),
    HOME: process.env.HOME || '',
    USER: process.env.USER || '',
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
  };

  // Preserve specific safe env vars if present
  const safeEnvVars = [
    'TMPDIR',
    'CLAUDE_PROJECT_DIR',
    'CLAUDE_CACHE_DIR',
  ];

  for (const key of safeEnvVars) {
    if (process.env[key]) {
      env[key] = process.env[key];
    }
  }

  return env;
}

/**
 * Check if a binary is available
 *
 * @param binary - Binary name
 * @returns true if binary was resolved
 */
export function isBinaryAvailable(binary: Binary): boolean {
  return resolvedPaths.has(binary);
}
