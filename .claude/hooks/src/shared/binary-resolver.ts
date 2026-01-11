/**
 * Binary Path Resolution and Validation
 *
 * Resolves absolute paths to security-sensitive binaries at startup and validates
 * they exist in trusted locations. Prevents PATH hijacking attacks.
 *
 * Security: CWE-426 (Untrusted Search Path) mitigation
 * Security: CWE-59 (Link Following) mitigation
 * Audit: Round 2 V2 - PATH hijack for security-sensitive subprocesses
 * Audit: Round 3 V3 - Symlink bypass and untrusted which (CVSS 8.1)
 */

import { execFileSync } from 'child_process';
import { existsSync, realpathSync, statSync } from 'fs';
import { resolve } from 'path';

// ============================================================================
// R3-V3: Trusted which path
// ============================================================================

/**
 * Absolute path to trusted `which` binary
 * R3-V3: Use hardcoded path instead of PATH-dependent resolution
 */
const TRUSTED_WHICH_PATHS = [
  '/usr/bin/which',
  '/bin/which',
] as const;

/**
 * Cached trusted which path (resolved once at first use)
 */
let trustedWhichPath: string | null = null;

/**
 * Get the trusted `which` binary path
 * R3-V3: Validates the which binary exists and is a real file
 *
 * @returns Absolute path to trusted which, or null if not found
 */
function getTrustedWhichPath(): string | null {
  if (trustedWhichPath) {
    return trustedWhichPath;
  }

  for (const whichPath of TRUSTED_WHICH_PATHS) {
    if (existsSync(whichPath)) {
      try {
        // Resolve symlinks and validate it's a regular file
        const realPath = realpathSync(whichPath);
        const stat = statSync(realPath);
        if (stat.isFile()) {
          trustedWhichPath = whichPath;
          return trustedWhichPath;
        }
      } catch {
        // Skip invalid paths
      }
    }
  }

  return null;
}

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
 * Resolve the absolute path to a binary using trusted `which`
 *
 * R3-V3: Uses absolute path to trusted which, resolves symlinks with realpath,
 * and validates the resolved path is in a trusted directory
 *
 * @param binary - Binary name to resolve
 * @returns Absolute path or null if not found
 */
function resolveBinaryPath(binary: string): string | null {
  try {
    // R3-V3: Use trusted which instead of PATH-dependent resolution
    const whichPath = getTrustedWhichPath();
    if (!whichPath) {
      console.error('[binary-resolver] No trusted which binary found');
      return null;
    }

    // Use trusted which with minimal PATH
    const result = execFileSync(whichPath, [binary], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 5000,
      env: {
        // R3-V3: Use fixed minimal PATH during resolution
        PATH: TRUSTED_BINARY_DIRS.filter(existsSync).join(':'),
      },
    });

    const path = result.trim();

    // Validate the path exists
    if (!existsSync(path)) {
      return null;
    }

    // R3-V3: Resolve symlinks to get the actual file location
    let realPath: string;
    try {
      realPath = realpathSync(path);
    } catch (err) {
      console.error(`[binary-resolver] Failed to resolve symlinks for: ${path}`);
      return null;
    }

    // R3-V3: Validate the RESOLVED path (not the symlink) is in a trusted directory
    const isTrusted = TRUSTED_BINARY_DIRS.some(dir => {
      const resolvedDir = resolve(dir);
      return realPath.startsWith(resolvedDir + '/') || realPath === resolvedDir;
    });

    if (!isTrusted) {
      console.error(`[binary-resolver] Rejected: symlink ${path} resolves to untrusted ${realPath}`);
      return null;
    }

    // R3-V3: Validate it's a regular file (not a directory, device, etc.)
    try {
      const stat = statSync(realPath);
      if (!stat.isFile()) {
        console.error(`[binary-resolver] Rejected: ${realPath} is not a regular file`);
        return null;
      }
    } catch {
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
