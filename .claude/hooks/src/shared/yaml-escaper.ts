/**
 * YAML Escaper - Safe YAML Serialization Utilities
 *
 * Provides secure YAML output that prevents:
 * - YAML Scalar Injection (F1, CVSS 6.3) - unquoted values breaking YAML structure
 * - List-Item Injection (F2, CVSS 5.5) - newlines in list items creating new fields
 *
 * These utilities should be used when serializing user-derived content into YAML,
 * especially for:
 * - TodoWrite content
 * - Session names
 * - Transcript-derived strings
 *
 * @see audit-report.md for repo-security-analysis-dog (d447d24)
 */

// =============================================================================
// Security Limits
// =============================================================================

/**
 * Maximum length for a single-line scalar value.
 * Prevents excessively long lines that could cause parsing issues.
 */
export const MAX_SCALAR_LENGTH = 1000;

/**
 * Maximum length for session names/identifiers.
 * Session names should be short and safe.
 */
export const MAX_SESSION_NAME_LENGTH = 100;

// =============================================================================
// Character Patterns
// =============================================================================

/**
 * Characters that can break YAML structure if unquoted.
 * These require the value to be quoted.
 */
const YAML_STRUCTURE_CHARS = /[:#{}&*!|>'"\[\]@`\\]/;

/**
 * Characters that indicate block scalar or document markers.
 * These are dangerous at the start of a value.
 */
const YAML_BLOCK_MARKERS = /^(?:---|\.\.\.|[|>])/;

/**
 * YAML tag patterns that could trigger special parsing.
 */
const YAML_TAG_PATTERNS = /!![a-zA-Z]+\//;

/**
 * Safe session name pattern - alphanumeric, underscore, hyphen only.
 */
const SAFE_SESSION_NAME_PATTERN = /^[a-zA-Z0-9_-]+$/;

/**
 * Control characters that should be stripped from YAML values.
 */
const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// =============================================================================
// Core Escaping Functions
// =============================================================================

/**
 * Escape a string for safe inclusion as a YAML scalar value.
 *
 * This function:
 * 1. Strips control characters
 * 2. Truncates to maximum length
 * 3. Converts to single-line (replaces newlines with spaces)
 * 4. Quotes the value if it contains YAML-sensitive characters
 *
 * @param value - The string value to escape
 * @param options - Escaping options
 * @returns Safe YAML scalar string (may be quoted)
 */
export function escapeYamlScalar(
  value: string,
  options: {
    maxLength?: number;
    singleLine?: boolean;
    forceQuote?: boolean;
  } = {}
): string {
  const {
    maxLength = MAX_SCALAR_LENGTH,
    singleLine = true,
    forceQuote = false,
  } = options;

  // Strip control characters
  let escaped = value.replace(CONTROL_CHARS, '');

  // Check for leading/trailing spaces BEFORE trimming
  const hadLeadingSpace = escaped.startsWith(' ') || escaped.startsWith('\t');
  const hadTrailingSpace = escaped.endsWith(' ') || escaped.endsWith('\t');

  // Convert to single line if requested
  if (singleLine) {
    escaped = escaped.replace(/[\r\n]+/g, ' ').trim();
  }

  // Truncate to max length
  if (escaped.length > maxLength) {
    escaped = escaped.slice(0, maxLength - 3) + '...';
  }

  // Determine if quoting is needed
  const needsQuoting =
    forceQuote ||
    escaped.length === 0 ||
    YAML_STRUCTURE_CHARS.test(escaped) ||
    YAML_BLOCK_MARKERS.test(escaped) ||
    YAML_TAG_PATTERNS.test(escaped) ||
    hadLeadingSpace ||
    hadTrailingSpace ||
    escaped === 'true' ||
    escaped === 'false' ||
    escaped === 'null' ||
    escaped === 'yes' ||
    escaped === 'no' ||
    escaped === 'on' ||
    escaped === 'off' ||
    /^-?\d+(\.\d+)?$/.test(escaped) || // Numbers
    /^0[xXoObB]/.test(escaped); // Hex/octal/binary

  if (needsQuoting) {
    // Use double quotes and escape internal quotes and backslashes
    const quotedValue = escaped
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
    return `"${quotedValue}"`;
  }

  return escaped;
}

/**
 * Escape a value for safe inclusion as a YAML list item.
 *
 * List items are particularly vulnerable because newlines can
 * create entirely new YAML structures.
 *
 * @param value - The list item value
 * @param maxLength - Maximum length for the item
 * @returns Safe YAML scalar for use after "- "
 */
export function escapeYamlListItem(value: string, maxLength: number = MAX_SCALAR_LENGTH): string {
  return escapeYamlScalar(value, {
    maxLength,
    singleLine: true,
    forceQuote: true, // Always quote list items for safety
  });
}

/**
 * Validate and sanitize a session name.
 *
 * Session names are used as identifiers and filenames, so they
 * need strict validation to prevent injection attacks.
 *
 * @param name - The session name to validate
 * @returns Sanitized session name
 * @throws Error if the name is too long or contains invalid characters
 */
export function validateSessionName(name: string): string {
  if (!name || typeof name !== 'string') {
    throw new Error('Session name is required');
  }

  // Strip control characters and whitespace
  const cleaned = name.replace(CONTROL_CHARS, '').trim();

  // Check length
  if (cleaned.length === 0) {
    throw new Error('Session name cannot be empty');
  }

  if (cleaned.length > MAX_SESSION_NAME_LENGTH) {
    throw new Error(`Session name exceeds maximum length (${MAX_SESSION_NAME_LENGTH})`);
  }

  // Validate characters
  if (!SAFE_SESSION_NAME_PATTERN.test(cleaned)) {
    // Try to sanitize by replacing unsafe characters
    const sanitized = cleaned
      .replace(/[^a-zA-Z0-9_-]/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');

    if (sanitized.length === 0) {
      throw new Error('Session name contains no valid characters');
    }

    return sanitized;
  }

  return cleaned;
}

// =============================================================================
// YAML Object Serialization
// =============================================================================

/**
 * Safely serialize a simple object to YAML format.
 *
 * Only supports:
 * - String values (escaped)
 * - Number values
 * - Boolean values
 * - Null values
 * - Arrays of strings (escaped)
 *
 * Does NOT support nested objects (use JSON for complex structures).
 *
 * @param obj - The object to serialize
 * @returns Safe YAML string
 */
export function serializeToSafeYaml(obj: Record<string, unknown>): string {
  const lines: string[] = [];

  // Check for dangerous keys that Object.entries() might miss
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
  for (const dangerousKey of dangerousKeys) {
    if (Object.prototype.hasOwnProperty.call(obj, dangerousKey)) {
      throw new Error(`Dangerous YAML key rejected: ${dangerousKey}`);
    }
  }

  for (const [key, value] of Object.entries(obj)) {
    // Validate key (must be a safe identifier)
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
      throw new Error(`Invalid YAML key: ${key}`);
    }

    // Reject dangerous keys
    if (['__proto__', 'constructor', 'prototype'].includes(key)) {
      throw new Error(`Dangerous YAML key rejected: ${key}`);
    }

    if (value === null || value === undefined) {
      lines.push(`${key}: null`);
    } else if (typeof value === 'boolean') {
      lines.push(`${key}: ${value}`);
    } else if (typeof value === 'number') {
      lines.push(`${key}: ${value}`);
    } else if (typeof value === 'string') {
      lines.push(`${key}: ${escapeYamlScalar(value)}`);
    } else if (Array.isArray(value)) {
      if (value.length === 0) {
        lines.push(`${key}: []`);
      } else {
        lines.push(`${key}:`);
        for (const item of value) {
          if (typeof item === 'string') {
            lines.push(`  - ${escapeYamlListItem(item)}`);
          } else if (item === null || item === undefined) {
            lines.push(`  - null`);
          } else if (typeof item === 'number' || typeof item === 'boolean') {
            lines.push(`  - ${item}`);
          } else {
            // Skip complex items
            lines.push(`  - ${escapeYamlListItem(String(item))}`);
          }
        }
      }
    } else if (typeof value === 'object') {
      // Reject nested objects - use JSON for complex structures
      throw new Error(`Nested objects not supported in safe YAML serialization: ${key}`);
    } else {
      lines.push(`${key}: ${escapeYamlScalar(String(value))}`);
    }
  }

  return lines.join('\n');
}

// =============================================================================
// TodoWrite-Specific Escaping
// =============================================================================

/**
 * Escape TodoWrite task content for safe YAML embedding.
 *
 * TodoWrite tasks are a primary injection vector because they come
 * from user/tool input and are embedded directly into YAML output.
 *
 * This function:
 * 1. Strips all YAML structure characters that could break parsing
 * 2. Removes any embedded YAML directives (---, ...)
 * 3. Strips potential key patterns (word:)
 * 4. Enforces single-line output
 *
 * @param task - The task content from TodoWrite
 * @returns Safe string for YAML embedding
 */
export function escapeTodoWriteContent(task: string): string {
  if (!task || typeof task !== 'string') {
    return '';
  }

  let escaped = task;

  // Strip control characters
  escaped = escaped.replace(CONTROL_CHARS, '');

  // Remove document markers
  escaped = escaped.replace(/^---$/gm, '');
  escaped = escaped.replace(/^\.\.\.$/gm, '');

  // Remove YAML tags
  escaped = escaped.replace(/!![a-zA-Z]+\/[a-zA-Z]+/g, '');

  // Remove potential key injections at line start (word followed by :)
  // This prevents "now: malicious" from being treated as a key
  escaped = escaped.replace(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:/gm, '$1 -');

  // Convert to single line
  escaped = escaped.replace(/[\r\n]+/g, ' ').trim();

  // Truncate
  if (escaped.length > MAX_SCALAR_LENGTH) {
    escaped = escaped.slice(0, MAX_SCALAR_LENGTH - 3) + '...';
  }

  return escapeYamlScalar(escaped, { forceQuote: true });
}

// =============================================================================
// Exports
// =============================================================================

export default {
  escapeYamlScalar,
  escapeYamlListItem,
  validateSessionName,
  serializeToSafeYaml,
  escapeTodoWriteContent,
  MAX_SCALAR_LENGTH,
  MAX_SESSION_NAME_LENGTH,
};
