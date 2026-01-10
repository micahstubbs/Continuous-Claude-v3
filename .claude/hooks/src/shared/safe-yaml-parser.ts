/**
 * Safe YAML Parser
 *
 * Provides secure YAML parsing that prevents:
 * - Code execution via !!js/function and similar tags
 * - Prototype pollution via __proto__, constructor, prototype
 * - Prompt injection in parsed content
 * - Resource exhaustion via large inputs
 *
 * Uses regex-based parsing for simple YAML structures instead of full
 * YAML parser to avoid deserialization vulnerabilities entirely.
 *
 * RECOMMENDATION: Use JSON (parseJsonSecure) for untrusted content.
 * YAML is inherently more dangerous due to its tag system.
 */

import { containsPromptInjection, detectPromptInjection } from './security-utils.js';

// =============================================================================
// Security Limits
// =============================================================================

/**
 * Maximum content size (100KB default).
 * Prevents memory exhaustion from large YAML files.
 */
export const MAX_YAML_SIZE = 100 * 1024;

/**
 * Maximum number of keys allowed.
 * Prevents object size explosion attacks.
 */
export const MAX_KEY_COUNT = 100;

/**
 * Maximum line count.
 * Prevents parsing performance attacks.
 */
export const MAX_LINE_COUNT = 1000;

// =============================================================================
// Types
// =============================================================================

export interface ParseResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  warnings: string[];
}

export interface HandoffData {
  context?: string;
  next_steps?: string[];
  state?: Record<string, unknown>;
  session_id?: string;
  timestamp?: string;
  [key: string]: unknown;
}

// =============================================================================
// Dangerous Patterns
// =============================================================================

/**
 * YAML tags that can execute code or cause security issues.
 * Extended list based on security research.
 */
const DANGEROUS_YAML_TAGS = [
  // JavaScript
  /!!js\/function/gi,
  /!!js\/regexp/gi,
  /!!js\/undefined/gi,
  /!<tag:yaml.org,2002:js\/function>/gi,

  // Python
  /!!python\/object/gi,
  /!!python\/name/gi,
  /!!python\/module/gi,
  /!!python\/object\/apply/gi,
  /!!python\/object\/new/gi,

  // Ruby
  /!!ruby\/object/gi,
  /!!ruby\/hash/gi,
  /!!ruby\/sym/gi,
  /!ruby\/object:Gem::Installer/gi,
  /!ruby\/object:Gem::Requirement/gi,

  // Perl
  /!!perl\/code/gi,
  /!!perl\/glob/gi,

  // PHP
  /!php\/object/gi,

  // Any custom tag that could be dangerous
  /!<[^>]*>/g,  // Generic custom tags
];

/**
 * Prototype pollution patterns.
 */
const PROTOTYPE_POLLUTION_PATTERNS = [
  /__proto__\s*:/gi,
  /constructor\s*:/gi,
  /prototype\s*:/gi,
  /\["__proto__"\]/gi,
  /\['__proto__'\]/gi,
];

// =============================================================================
// Validation
// =============================================================================

/**
 * Check if YAML content contains dangerous tags.
 */
export function containsDangerousTags(content: string): boolean {
  return DANGEROUS_YAML_TAGS.some(pattern => pattern.test(content));
}

/**
 * Check if content contains prototype pollution attempts.
 */
export function containsPrototypePollution(content: string): boolean {
  return PROTOTYPE_POLLUTION_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Validate YAML content for security issues.
 */
export function validateYamlSecurity(content: string): {
  safe: boolean;
  issues: string[];
} {
  const issues: string[] = [];

  // Check for dangerous YAML tags
  for (const pattern of DANGEROUS_YAML_TAGS) {
    if (pattern.test(content)) {
      issues.push(`Dangerous YAML tag detected: ${pattern.source}`);
    }
  }

  // Check for prototype pollution
  for (const pattern of PROTOTYPE_POLLUTION_PATTERNS) {
    if (pattern.test(content)) {
      issues.push(`Prototype pollution pattern detected: ${pattern.source}`);
    }
  }

  // Check for prompt injection
  if (containsPromptInjection(content)) {
    const patterns = detectPromptInjection(content);
    issues.push(`Prompt injection patterns: ${patterns.slice(0, 3).join(', ')}`);
  }

  return {
    safe: issues.length === 0,
    issues,
  };
}

// =============================================================================
// Simple YAML Parser (Safe)
// =============================================================================

/**
 * Parse simple YAML key-value pairs safely.
 * Only supports:
 * - String values
 * - Simple arrays (- item format)
 * - Nested objects (one level)
 *
 * Does NOT support:
 * - YAML tags (!!type)
 * - Anchors and aliases
 * - Multi-line strings with | or >
 * - Complex nested structures
 */
export function parseSimpleYaml(content: string): ParseResult<Record<string, unknown>> {
  const warnings: string[] = [];

  // Size limit check
  if (content.length > MAX_YAML_SIZE) {
    return {
      success: false,
      error: `YAML content exceeds maximum size (${MAX_YAML_SIZE} bytes)`,
      warnings,
    };
  }

  // Security check first
  const securityCheck = validateYamlSecurity(content);
  if (!securityCheck.safe) {
    return {
      success: false,
      error: `Security validation failed: ${securityCheck.issues.join('; ')}`,
      warnings,
    };
  }

  try {
    const result: Record<string, unknown> = {};
    const lines = content.split('\n');

    // Line count limit
    if (lines.length > MAX_LINE_COUNT) {
      return {
        success: false,
        error: `YAML exceeds maximum line count (${MAX_LINE_COUNT})`,
        warnings,
      };
    }

    let keyCount = 0;
    let currentKey: string | null = null;
    let currentArray: string[] | null = null;

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Array item
      if (trimmed.startsWith('- ')) {
        if (currentArray !== null && currentKey) {
          currentArray.push(trimmed.slice(2).trim());
        }
        continue;
      }

      // Key-value pair
      const kvMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$/);
      if (kvMatch) {
        // Save previous array if any
        if (currentArray !== null && currentKey) {
          result[currentKey] = currentArray;
          currentArray = null;
        }

        const [, key, value] = kvMatch;

        // Key count limit
        keyCount++;
        if (keyCount > MAX_KEY_COUNT) {
          return {
            success: false,
            error: `YAML exceeds maximum key count (${MAX_KEY_COUNT})`,
            warnings,
          };
        }

        // Check for dangerous keys
        if (['__proto__', 'constructor', 'prototype'].includes(key)) {
          return {
            success: false,
            error: `Dangerous key rejected: ${key}`,
            warnings,
          };
        }

        if (value === '' || value === '[]') {
          // Empty value or empty array - start collecting array items
          currentKey = key;
          currentArray = [];
        } else if (value.startsWith('[') && value.endsWith(']')) {
          // Inline array
          const items = value.slice(1, -1).split(',').map(s => s.trim()).filter(Boolean);
          result[key] = items;
          currentKey = null;
        } else if (value === 'true') {
          result[key] = true;
          currentKey = null;
        } else if (value === 'false') {
          result[key] = false;
          currentKey = null;
        } else if (value === 'null') {
          result[key] = null;
          currentKey = null;
        } else if (/^-?\d+$/.test(value)) {
          result[key] = parseInt(value, 10);
          currentKey = null;
        } else if (/^-?\d+\.\d+$/.test(value)) {
          result[key] = parseFloat(value);
          currentKey = null;
        } else {
          // String value - remove quotes if present
          let stringValue = value;
          if ((value.startsWith('"') && value.endsWith('"')) ||
              (value.startsWith("'") && value.endsWith("'"))) {
            stringValue = value.slice(1, -1);
          }
          result[key] = stringValue;
          currentKey = null;
        }
      }
    }

    // Save final array if any
    if (currentArray !== null && currentKey) {
      result[currentKey] = currentArray;
    }

    return {
      success: true,
      data: result,
      warnings,
    };
  } catch (err) {
    return {
      success: false,
      error: `Parse error: ${err instanceof Error ? err.message : 'Unknown error'}`,
      warnings,
    };
  }
}

// =============================================================================
// Handoff File Parser
// =============================================================================

/**
 * Parse a handoff file with security validation.
 */
export function parseHandoffFile(content: string): ParseResult<HandoffData> {
  const warnings: string[] = [];

  // Extract frontmatter if present
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);

  let yamlContent: string;
  let bodyContent: string;

  if (frontmatterMatch) {
    yamlContent = frontmatterMatch[1];
    bodyContent = frontmatterMatch[2];
  } else {
    // Try to parse entire content as YAML
    yamlContent = content;
    bodyContent = '';
  }

  // Parse YAML portion
  const parseResult = parseSimpleYaml(yamlContent);

  if (!parseResult.success) {
    return {
      success: false,
      error: parseResult.error,
      warnings: [...warnings, ...parseResult.warnings],
    };
  }

  const data = parseResult.data as HandoffData;

  // Add body as context if present and no context field
  if (bodyContent && !data.context) {
    // Check body for injection
    if (containsPromptInjection(bodyContent)) {
      warnings.push('Handoff body contains potential prompt injection');
    }
    data.context = bodyContent.trim();
  }

  // Validate specific fields for injection
  if (data.context && containsPromptInjection(data.context)) {
    warnings.push('Context field contains potential prompt injection');
  }

  if (data.next_steps && Array.isArray(data.next_steps)) {
    for (const step of data.next_steps) {
      if (typeof step === 'string' && containsPromptInjection(step)) {
        warnings.push('Next steps contain potential prompt injection');
        break;
      }
    }
  }

  return {
    success: true,
    data,
    warnings: [...warnings, ...parseResult.warnings],
  };
}

// =============================================================================
// JSON Alternative (Safer)
// =============================================================================

/**
 * Parse JSON with security validation.
 * Preferred over YAML for untrusted content.
 */
export function parseJsonSecure<T>(content: string): ParseResult<T> {
  const warnings: string[] = [];

  // Check for prompt injection in raw content
  if (containsPromptInjection(content)) {
    warnings.push('JSON content contains potential prompt injection patterns');
  }

  try {
    const parsed = JSON.parse(content);

    // Check for prototype pollution in keys
    const checkObject = (obj: unknown, path: string = ''): string[] => {
      const issues: string[] = [];
      if (typeof obj === 'object' && obj !== null) {
        for (const key of Object.keys(obj)) {
          if (['__proto__', 'constructor', 'prototype'].includes(key)) {
            issues.push(`Dangerous key at ${path}.${key}`);
          }
          issues.push(...checkObject((obj as Record<string, unknown>)[key], `${path}.${key}`));
        }
      }
      return issues;
    };

    const pollutionIssues = checkObject(parsed);
    if (pollutionIssues.length > 0) {
      return {
        success: false,
        error: `Prototype pollution detected: ${pollutionIssues.join(', ')}`,
        warnings,
      };
    }

    return {
      success: true,
      data: parsed as T,
      warnings,
    };
  } catch (err) {
    return {
      success: false,
      error: `JSON parse error: ${err instanceof Error ? err.message : 'Unknown error'}`,
      warnings,
    };
  }
}

// =============================================================================
// Exports
// =============================================================================

export default {
  containsDangerousTags,
  containsPrototypePollution,
  validateYamlSecurity,
  parseSimpleYaml,
  parseHandoffFile,
  parseJsonSecure,
};
