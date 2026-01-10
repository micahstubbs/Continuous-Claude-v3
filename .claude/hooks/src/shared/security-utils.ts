/**
 * Security Utilities for Continuous-Claude-v3
 *
 * Centralized security functions for input validation, sanitization,
 * and prompt injection detection.
 *
 * Usage: Import these utilities in all hooks that process external input.
 */

import { spawnSync, SpawnSyncOptions } from 'child_process';
import { resolve, relative, isAbsolute } from 'path';
import { existsSync, statSync } from 'fs';

// =============================================================================
// Input Validation
// =============================================================================

/**
 * Validates that a string contains only safe characters for file paths.
 * Prevents path traversal and shell injection via file names.
 */
export function isValidPath(path: string): boolean {
    // Reject null bytes, control characters
    if (/[\x00-\x1f\x7f]/.test(path)) {
        return false;
    }
    // Reject obvious path traversal
    if (path.includes('..') || path.includes('\0')) {
        return false;
    }
    return true;
}

/**
 * Validates that a path is within a base directory (prevents path traversal).
 */
export function isPathWithin(path: string, baseDir: string): boolean {
    const resolvedPath = resolve(path);
    const resolvedBase = resolve(baseDir);
    return resolvedPath.startsWith(resolvedBase + '/') || resolvedPath === resolvedBase;
}

/**
 * Validates identifier strings (agent names, pattern names, etc.).
 * Only allows alphanumeric, underscore, and hyphen.
 */
export function isValidIdentifier(id: string): boolean {
    return /^[a-zA-Z][a-zA-Z0-9_-]*$/.test(id) && id.length <= 100;
}

/**
 * Validates a JSON string is parseable and optionally checks structure.
 */
export function isValidJson(str: string, maxSize: number = 1_000_000): boolean {
    if (str.length > maxSize) {
        return false;
    }
    try {
        JSON.parse(str);
        return true;
    } catch {
        return false;
    }
}

// =============================================================================
// Prompt Injection Detection
// =============================================================================

/**
 * Normalizes text for security scanning by:
 * 1. Unicode NFKC normalization (converts fullwidth, compatibility characters)
 * 2. Common homoglyph replacement (Cyrillic lookalikes, etc.)
 * 3. Stripping zero-width characters that could hide content
 *
 * This prevents evasion via Unicode tricks like:
 * - "ｉｇｎｏｒｅ" (fullwidth) -> "ignore"
 * - "іgnore" (Cyrillic і) -> "ignore"
 * - "ig\u200Bnore" (zero-width space) -> "ignore"
 */
function normalizeForSecurityScan(content: string): string {
    let normalized = content;

    // 1. NFKC normalization (fullwidth -> ASCII, compatibility chars)
    normalized = normalized.normalize('NFKC');

    // 2. Remove zero-width and invisible characters that could hide content
    // U+200B Zero Width Space, U+200C Zero Width Non-Joiner,
    // U+200D Zero Width Joiner, U+FEFF BOM, U+00AD Soft Hyphen
    normalized = normalized.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, '');

    // 3. Common Cyrillic/Greek homoglyphs -> ASCII
    // These are often used to bypass text filters
    const homoglyphMap: Record<string, string> = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', // Cyrillic
        'і': 'i', 'ј': 'j', 'ѕ': 's', // More Cyrillic
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', // Greek capitals
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
        'ο': 'o', 'ν': 'v', // Greek lowercase
        'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v', // Roman numerals
    };

    for (const [homoglyph, ascii] of Object.entries(homoglyphMap)) {
        normalized = normalized.split(homoglyph).join(ascii);
    }

    return normalized;
}

/**
 * Patterns that indicate potential prompt injection attempts.
 * These are heuristic-based and may have false positives.
 */
const INJECTION_PATTERNS = [
    // System prompt manipulation
    /<\s*SYSTEM\s*>/i,
    /<\s*IMPORTANT\s*>/i,
    /<\s*OVERRIDE[_\s]?SAFETY\s*>/i,
    /<\s*ADMIN\s*>/i,
    /<\s*DEVELOPER[_\s]?MODE\s*>/i,

    // Instruction override attempts
    /ignore\s+(all\s+)?(previous\s+)?instructions/i,
    /disregard\s+(all\s+)?(previous\s+)?instructions/i,
    /forget\s+(all\s+)?(previous\s+)?instructions/i,
    /override\s+(all\s+)?safety/i,
    /bypass\s+(all\s+)?restrictions/i,

    // Role manipulation
    /you\s+are\s+now\s+(a|an|in)/i,
    /pretend\s+(you\s+are|to\s+be)/i,
    /act\s+as\s+(a|an|if)/i,

    // Jailbreak markers
    /\bDAN\b/,  // "Do Anything Now"
    /jailbreak/i,
    /uncensored/i,

    // Command injection markers
    /;\s*(rm|cat|curl|wget|nc|bash|sh|python)\s/,
    /\|\s*(bash|sh|python|perl|ruby)/,
    /`[^`]*`/,  // Backtick commands
    /\$\([^)]+\)/,  // $(command) substitution
];

/**
 * Scans content for potential prompt injection patterns.
 * Returns array of detected patterns (empty if none found).
 *
 * Content is normalized before scanning to detect Unicode-based evasion:
 * - Fullwidth characters (ｉｇｎｏｒｅ -> ignore)
 * - Cyrillic/Greek homoglyphs (іgnore -> ignore)
 * - Zero-width spaces hiding content
 */
export function detectPromptInjection(content: string): string[] {
    const detected: string[] = [];

    // Normalize to catch Unicode-based evasion attempts
    const normalized = normalizeForSecurityScan(content);

    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(normalized)) {
            detected.push(pattern.source);
        }
    }

    return detected;
}

/**
 * Checks if content appears to contain prompt injection.
 * Use this for quick boolean checks.
 *
 * Content is normalized before scanning to detect Unicode-based evasion.
 */
export function containsPromptInjection(content: string): boolean {
    // Normalize to catch Unicode-based evasion attempts
    const normalized = normalizeForSecurityScan(content);
    return INJECTION_PATTERNS.some(pattern => pattern.test(normalized));
}

/**
 * Sanitizes content by removing potential injection patterns.
 * WARNING: This is a best-effort sanitization and may not catch all attacks.
 * Prefer validation and rejection over sanitization when possible.
 */
export function sanitizeContent(content: string): string {
    let sanitized = content;

    // Remove XML-like tags that could be interpreted as instructions
    sanitized = sanitized.replace(/<\s*(SYSTEM|IMPORTANT|OVERRIDE|ADMIN|DEVELOPER)[^>]*>/gi, '[REMOVED]');

    // Remove command injection patterns
    sanitized = sanitized.replace(/`[^`]*`/g, '[REMOVED]');
    sanitized = sanitized.replace(/\$\([^)]*\)/g, '[REMOVED]');

    return sanitized;
}

// =============================================================================
// Safe Command Execution
// =============================================================================

/**
 * Options for safe command execution.
 */
export interface SafeExecOptions {
    cwd?: string;
    timeout?: number;
    maxOutputSize?: number;
    env?: Record<string, string>;
}

/**
 * Result of safe command execution.
 */
export interface SafeExecResult {
    success: boolean;
    stdout: string;
    stderr: string;
    exitCode: number | null;
    error?: string;
}

/**
 * SECURE: Execute a command with argument array (no shell interpolation).
 *
 * This is the preferred way to execute external commands.
 * User input should NEVER be interpolated into command strings.
 * Instead, pass user input as elements in the args array.
 *
 * @example
 * // SECURE: User input as argument
 * safeExec('grep', [userPattern, '/path/to/file'])
 *
 * // INSECURE (never do this):
 * execSync(`grep "${userPattern}" /path/to/file`)
 */
export function safeExec(
    command: string,
    args: string[],
    options: SafeExecOptions = {}
): SafeExecResult {
    const {
        cwd = process.cwd(),
        timeout = 30000,
        maxOutputSize = 10_000_000,
        env = process.env as Record<string, string>,
    } = options;

    try {
        // Validate command is not a path (prevent execution of arbitrary binaries)
        if (command.includes('/') || command.includes('\\')) {
            return {
                success: false,
                stdout: '',
                stderr: '',
                exitCode: null,
                error: 'Command must be a program name, not a path',
            };
        }

        // Validate cwd exists
        if (cwd && !existsSync(cwd)) {
            return {
                success: false,
                stdout: '',
                stderr: '',
                exitCode: null,
                error: 'Working directory does not exist',
            };
        }

        const spawnOptions: SpawnSyncOptions = {
            cwd,
            timeout,
            maxBuffer: maxOutputSize,
            encoding: 'utf-8',
            env,
            stdio: ['pipe', 'pipe', 'pipe'],
        };

        const result = spawnSync(command, args, spawnOptions);

        return {
            success: result.status === 0,
            stdout: result.stdout?.toString() || '',
            stderr: result.stderr?.toString() || '',
            exitCode: result.status,
            error: result.error?.message,
        };
    } catch (err) {
        return {
            success: false,
            stdout: '',
            stderr: '',
            exitCode: null,
            error: err instanceof Error ? err.message : 'Unknown error',
        };
    }
}

/**
 * SECURE: Execute command with input via stdin.
 *
 * Use this when you need to pass user content to a command.
 * Data passed via stdin cannot escape to shell.
 *
 * @example
 * // SECURE: User content via stdin
 * safeExecWithStdin('python', ['script.py'], userPrompt)
 */
export function safeExecWithStdin(
    command: string,
    args: string[],
    stdinData: string,
    options: SafeExecOptions = {}
): SafeExecResult {
    const {
        cwd = process.cwd(),
        timeout = 30000,
        maxOutputSize = 10_000_000,
        env = process.env as Record<string, string>,
    } = options;

    try {
        if (command.includes('/') || command.includes('\\')) {
            return {
                success: false,
                stdout: '',
                stderr: '',
                exitCode: null,
                error: 'Command must be a program name, not a path',
            };
        }

        const result = spawnSync(command, args, {
            cwd,
            timeout,
            maxBuffer: maxOutputSize,
            encoding: 'utf-8',
            env,
            input: stdinData,  // SECURE: data passed via stdin
            stdio: ['pipe', 'pipe', 'pipe'],
        });

        return {
            success: result.status === 0,
            stdout: result.stdout?.toString() || '',
            stderr: result.stderr?.toString() || '',
            exitCode: result.status,
            error: result.error?.message,
        };
    } catch (err) {
        return {
            success: false,
            stdout: '',
            stderr: '',
            exitCode: null,
            error: err instanceof Error ? err.message : 'Unknown error',
        };
    }
}

// =============================================================================
// Content Security Policies
// =============================================================================

/**
 * Configuration for content security scanning.
 */
export interface ContentSecurityConfig {
    allowPromptInjection?: boolean;
    allowCommandPatterns?: boolean;
    maxContentSize?: number;
    customBlockedPatterns?: RegExp[];
}

/**
 * Result of content security scan.
 */
export interface ContentSecurityResult {
    safe: boolean;
    issues: string[];
    sanitized?: string;
}

/**
 * Scans content for security issues based on configuration.
 */
export function scanContent(
    content: string,
    config: ContentSecurityConfig = {}
): ContentSecurityResult {
    const issues: string[] = [];

    // Size check
    const maxSize = config.maxContentSize || 1_000_000;
    if (content.length > maxSize) {
        issues.push(`Content exceeds maximum size (${maxSize} bytes)`);
    }

    // Prompt injection check
    if (!config.allowPromptInjection) {
        const injections = detectPromptInjection(content);
        if (injections.length > 0) {
            issues.push(`Potential prompt injection: ${injections.join(', ')}`);
        }
    }

    // Command pattern check
    if (!config.allowCommandPatterns) {
        if (/[;&|`$]/.test(content)) {
            const cmdPatterns = content.match(/[;&|`$][^\s]*/g);
            if (cmdPatterns) {
                issues.push(`Potential command patterns: ${cmdPatterns.slice(0, 5).join(', ')}`);
            }
        }
    }

    // Custom blocked patterns
    if (config.customBlockedPatterns) {
        for (const pattern of config.customBlockedPatterns) {
            if (pattern.test(content)) {
                issues.push(`Blocked pattern: ${pattern.source}`);
            }
        }
    }

    return {
        safe: issues.length === 0,
        issues,
        sanitized: issues.length > 0 ? sanitizeContent(content) : undefined,
    };
}

// =============================================================================
// File Security
// =============================================================================

/**
 * Validates that a file is safe to read/execute.
 */
export function isFileSafe(filePath: string, baseDir: string): boolean {
    try {
        // Must be within base directory
        if (!isPathWithin(filePath, baseDir)) {
            return false;
        }

        // Must exist
        const resolved = resolve(filePath);
        if (!existsSync(resolved)) {
            return false;
        }

        // Must be a regular file (not symlink, not directory)
        const stats = statSync(resolved);
        if (!stats.isFile()) {
            return false;
        }

        // Check for suspicious file names
        const fileName = resolved.split('/').pop() || '';
        if (/^\./.test(fileName) && !/^\.claude/.test(fileName)) {
            // Hidden files outside .claude are suspicious
            return false;
        }

        return true;
    } catch {
        return false;
    }
}

// =============================================================================
// Exports
// =============================================================================

export default {
    // Validation
    isValidPath,
    isPathWithin,
    isValidIdentifier,
    isValidJson,

    // Prompt injection
    detectPromptInjection,
    containsPromptInjection,
    sanitizeContent,

    // Safe execution
    safeExec,
    safeExecWithStdin,

    // Content security
    scanContent,

    // File security
    isFileSafe,
};
