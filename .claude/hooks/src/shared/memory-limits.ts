/**
 * Memory Query Size Limits
 *
 * Enforces size and rate limits on memory/vector recall queries to prevent
 * context flooding and DoS attacks.
 *
 * Security: V5 - Memory query size limits (Round 2 audit, CVSS 7.1)
 * Audit: Round 2 V5 - Unbounded recall payload size
 */

/**
 * Memory query limits configuration
 */
export interface MemoryLimits {
  /** Maximum size of a single learning entry in bytes */
  maxEntryBytes: number;

  /** Maximum total bytes returned from a single query */
  maxTotalBytes: number;

  /** Maximum number of results to return */
  maxResults: number;

  /** Maximum execution time for a query in milliseconds */
  maxExecutionMs: number;
}

/**
 * Default memory query limits
 *
 * Conservative limits to prevent context flooding while allowing
 * reasonable recall functionality.
 */
export const DEFAULT_MEMORY_LIMITS: MemoryLimits = {
  maxEntryBytes: 2048,      // 2KB per entry (typical learning is 200-500 bytes)
  maxTotalBytes: 10240,     // 10KB total (5 × 2KB entries)
  maxResults: 10,           // Max 10 results
  maxExecutionMs: 5000,     // 5 second timeout
};

/**
 * Truncate text to maximum size with clear marker
 *
 * @param text - Text to truncate
 * @param maxBytes - Maximum size in bytes
 * @returns Truncated text with marker if needed
 */
export function truncateToSize(text: string, maxBytes: number): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);

  if (bytes.length <= maxBytes) {
    return text;
  }

  // Reserve bytes for truncation marker
  const marker = ' [TRUNCATED]';
  const markerBytes = encoder.encode(marker).length;
  const targetBytes = maxBytes - markerBytes;

  if (targetBytes <= 0) {
    return marker;
  }

  // Truncate to fit within target bytes
  // We need to decode from bytes to handle multi-byte UTF-8 correctly
  const decoder = new TextDecoder();
  const truncatedBytes = bytes.slice(0, targetBytes);

  try {
    const truncated = decoder.decode(truncatedBytes, { stream: false });
    return truncated + marker;
  } catch {
    // If decode fails, fall back to character-based truncation
    return text.slice(0, Math.floor(targetBytes / 2)) + marker;
  }
}

/**
 * Apply size limits to a memory query result
 *
 * @param results - Array of result objects with 'content' field
 * @param limits - Memory limits configuration
 * @returns Limited results with truncation applied
 */
export function applyMemoryLimits<T extends { content: string }>(
  results: T[],
  limits: MemoryLimits = DEFAULT_MEMORY_LIMITS
): T[] {
  const limitedResults: T[] = [];
  let totalBytes = 0;
  const encoder = new TextEncoder();

  for (const result of results) {
    // Stop if we've hit the max result count
    if (limitedResults.length >= limits.maxResults) {
      break;
    }

    // Truncate entry if it exceeds max entry size
    const content = result.content;
    const contentBytes = encoder.encode(content).length;

    let limitedContent = content;
    if (contentBytes > limits.maxEntryBytes) {
      limitedContent = truncateToSize(content, limits.maxEntryBytes);
    }

    const limitedBytes = encoder.encode(limitedContent).length;

    // Stop if adding this entry would exceed total byte limit
    if (totalBytes + limitedBytes > limits.maxTotalBytes) {
      break;
    }

    limitedResults.push({
      ...result,
      content: limitedContent
    });

    totalBytes += limitedBytes;
  }

  return limitedResults;
}

/**
 * Check if memory query size is within limits
 *
 * @param results - Query results to check
 * @param limits - Memory limits configuration
 * @returns Object with within_limits boolean and stats
 */
export function checkMemoryLimits<T extends { content: string }>(
  results: T[],
  limits: MemoryLimits = DEFAULT_MEMORY_LIMITS
): {
  within_limits: boolean;
  result_count: number;
  total_bytes: number;
  max_entry_bytes: number;
  exceeded?: string[];
} {
  const encoder = new TextEncoder();
  let totalBytes = 0;
  let maxEntryBytes = 0;
  const exceeded: string[] = [];

  for (const result of results) {
    const contentBytes = encoder.encode(result.content).length;
    totalBytes += contentBytes;
    maxEntryBytes = Math.max(maxEntryBytes, contentBytes);

    if (contentBytes > limits.maxEntryBytes) {
      exceeded.push('max_entry_bytes');
    }
  }

  if (results.length > limits.maxResults) {
    exceeded.push('max_results');
  }

  if (totalBytes > limits.maxTotalBytes) {
    exceeded.push('max_total_bytes');
  }

  return {
    within_limits: exceeded.length === 0,
    result_count: results.length,
    total_bytes: totalBytes,
    max_entry_bytes: maxEntryBytes,
    exceeded: exceeded.length > 0 ? exceeded : undefined
  };
}

/**
 * Format size in human-readable format
 *
 * @param bytes - Size in bytes
 * @returns Formatted string (e.g., "1.5KB", "2.3MB")
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes}B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)}KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
