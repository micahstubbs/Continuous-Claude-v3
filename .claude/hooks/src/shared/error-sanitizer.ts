/**
 * Error Sanitizer Utility
 *
 * Provides sanitized error logging to prevent information leaks.
 * Redacts paths, env vars, SQL snippets, and other sensitive details.
 *
 * Security: V6 - Sanitize error handling (Round 2 audit, CVSS 3.1)
 * Audit: Round 2 V6 - Error messages leak internal details
 */

/**
 * Patterns to redact from error messages
 */
const REDACTION_PATTERNS: Array<{
  pattern: RegExp;
  replacement: string;
  description: string;
}> = [
  // File paths - absolute paths on Unix-like systems
  {
    pattern: /\/(?:home|Users|var|tmp|etc|opt)\/[^\s'"`:)}\]]+/gi,
    replacement: '[PATH]',
    description: 'Unix file paths',
  },
  // Windows paths
  {
    pattern: /[A-Z]:\\[^\s'"`:)}\]]+/gi,
    replacement: '[PATH]',
    description: 'Windows file paths',
  },
  // Environment variable values (KEY=value patterns in errors)
  {
    pattern: /\b[A-Z][A-Z0-9_]{2,}=["']?[^"'\s]+["']?/g,
    replacement: '[ENV_VAR]',
    description: 'Environment variable assignments',
  },
  // SQL snippets - SELECT, INSERT, UPDATE, DELETE, CREATE, DROP
  {
    pattern: /\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\s+[^;]{10,}/gi,
    replacement: '[SQL_QUERY]',
    description: 'SQL query fragments',
  },
  // Connection strings (postgres://, mysql://, redis://, etc.)
  {
    pattern: /\b(postgres|mysql|redis|mongodb|sqlite):\/\/[^\s'"]+/gi,
    replacement: '[CONNECTION_STRING]',
    description: 'Database connection strings',
  },
  // API keys/tokens (common patterns)
  {
    pattern: /\b(api[_-]?key|token|secret|password|auth)[=:]\s*["']?[A-Za-z0-9_\-./+=]{16,}["']?/gi,
    replacement: '[REDACTED_CREDENTIAL]',
    description: 'API keys and tokens',
  },
  // Base64 encoded data (long strings)
  {
    pattern: /\b[A-Za-z0-9+/]{64,}={0,2}\b/g,
    replacement: '[BASE64_DATA]',
    description: 'Base64 encoded data',
  },
  // Session IDs (common UUID and custom formats)
  {
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    replacement: '[SESSION_ID]',
    description: 'UUID-format session IDs',
  },
  // Stack trace function names with file locations
  {
    pattern: /at\s+\S+\s+\([^)]+:[0-9]+:[0-9]+\)/g,
    replacement: 'at [STACK_FRAME]',
    description: 'Stack trace frames',
  },
];

/**
 * Sanitize an error message by redacting sensitive information
 *
 * @param message - Raw error message
 * @returns Sanitized message safe for logging
 */
export function sanitizeError(message: string): string {
  if (!message) {
    return 'Unknown error';
  }

  let sanitized = message;

  for (const { pattern, replacement } of REDACTION_PATTERNS) {
    sanitized = sanitized.replace(pattern, replacement);
  }

  return sanitized;
}

/**
 * Sanitize an Error object
 *
 * @param error - Error object or unknown error
 * @returns Sanitized error message
 */
export function sanitizeErrorObject(error: unknown): string {
  if (error instanceof Error) {
    return sanitizeError(error.message);
  }

  if (typeof error === 'string') {
    return sanitizeError(error);
  }

  if (error && typeof error === 'object' && 'message' in error) {
    return sanitizeError(String((error as { message: unknown }).message));
  }

  return 'Unknown error occurred';
}

/**
 * Security event types for structured logging
 */
export type SecurityEventType =
  | 'INJECTION_DETECTED'
  | 'SIGNATURE_INVALID'
  | 'SESSION_INACTIVE'
  | 'PROVENANCE_MISSING'
  | 'PROVENANCE_INVALID'
  | 'SIZE_LIMIT_EXCEEDED'
  | 'TRUST_VIOLATION'
  | 'SANITIZATION_APPLIED'
  | 'VERIFICATION_FAILED'
  | 'GENERIC_ERROR';

/**
 * Structured security log entry
 */
export interface SecurityLogEntry {
  timestamp: string;
  event_type: SecurityEventType;
  component: string;
  message: string;
  context?: Record<string, unknown>;
}

/**
 * Create a structured security log entry
 *
 * @param eventType - Type of security event
 * @param component - Component that generated the event
 * @param message - Human-readable message (will be sanitized)
 * @param context - Additional context (keys sanitized, values redacted)
 * @returns Structured log entry
 */
export function createSecurityLogEntry(
  eventType: SecurityEventType,
  component: string,
  message: string,
  context?: Record<string, unknown>
): SecurityLogEntry {
  const entry: SecurityLogEntry = {
    timestamp: new Date().toISOString(),
    event_type: eventType,
    component: sanitizeError(component),
    message: sanitizeError(message),
  };

  // Sanitize context values if provided
  if (context) {
    entry.context = {};
    for (const [key, value] of Object.entries(context)) {
      // Sanitize the key
      const sanitizedKey = sanitizeError(key);

      // Redact sensitive values by key name
      const sensitiveKeys = ['path', 'password', 'token', 'key', 'secret', 'credential'];
      if (sensitiveKeys.some((k) => sanitizedKey.toLowerCase().includes(k))) {
        entry.context[sanitizedKey] = '[REDACTED]';
      } else if (typeof value === 'string') {
        entry.context[sanitizedKey] = sanitizeError(value);
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        entry.context[sanitizedKey] = value;
      } else {
        entry.context[sanitizedKey] = '[COMPLEX_VALUE]';
      }
    }
  }

  return entry;
}

/**
 * Log a security event to stderr with sanitization
 *
 * V6: Replacement for direct console.error with sensitive data
 *
 * @param eventType - Type of security event
 * @param component - Component that generated the event
 * @param message - Human-readable message
 * @param context - Additional context
 */
export function logSecurityEvent(
  eventType: SecurityEventType,
  component: string,
  message: string,
  context?: Record<string, unknown>
): void {
  const entry = createSecurityLogEntry(eventType, component, message, context);

  // Output as JSON for structured logging
  console.error(JSON.stringify(entry));
}

/**
 * Log a generic error with sanitization
 *
 * V6: Replacement for console.error(err) patterns
 *
 * @param component - Component where error occurred
 * @param error - Error object or message
 */
export function logError(component: string, error: unknown): void {
  logSecurityEvent('GENERIC_ERROR', component, sanitizeErrorObject(error));
}

/**
 * Create a user-safe error message
 *
 * Returns a generic message suitable for display to users
 * without leaking internal details.
 *
 * @param category - Error category (e.g., 'database', 'validation', 'network')
 * @returns Generic user-safe error message
 */
export function userSafeError(category: string): string {
  const messages: Record<string, string> = {
    database: 'A database error occurred. Please try again.',
    validation: 'The input could not be validated.',
    network: 'A network error occurred. Please check your connection.',
    permission: 'Permission denied.',
    not_found: 'The requested resource was not found.',
    timeout: 'The operation timed out. Please try again.',
    configuration: 'A configuration error occurred.',
    default: 'An unexpected error occurred.',
  };

  return messages[category] || messages.default;
}
