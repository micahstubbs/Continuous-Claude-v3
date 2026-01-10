/**
 * Rate Limiter for Hook Execution
 *
 * Provides rate limiting to prevent resource exhaustion from:
 * - Rapid prompt submissions triggering multiple Python processes
 * - DoS attacks via automated prompt flooding
 * - Accidental infinite loops in hook chains
 *
 * Uses in-memory token bucket algorithm (no external dependencies).
 * Limits are per-session to allow concurrent legitimate users.
 */

import { freemem, totalmem, loadavg } from 'os';
import { appendFileSync } from 'fs';
import { join } from 'path';

// =============================================================================
// Types
// =============================================================================

export interface RateLimitConfig {
  /** Maximum tokens (requests) allowed */
  maxTokens: number;
  /** Tokens refilled per second */
  refillRate: number;
  /** Key prefix for namespacing */
  keyPrefix?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetMs: number;
  reason?: string;
}

export interface ResourceThresholds {
  /** Maximum memory usage percent before blocking */
  maxMemoryPercent: number;
  /** Maximum load average before blocking */
  maxLoadAverage: number;
}

export interface ResourceCheckResult {
  available: boolean;
  memoryPercent: number;
  loadAverage: number;
  reason?: string;
}

// =============================================================================
// Token Bucket Implementation
// =============================================================================

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

/**
 * In-memory rate limiter using token bucket algorithm.
 *
 * Each key (e.g., session ID) gets its own bucket.
 * Tokens are consumed on requests and refilled over time.
 */
class RateLimiter {
  private buckets: Map<string, TokenBucket> = new Map();
  private config: Required<RateLimitConfig>;

  constructor(config: RateLimitConfig) {
    this.config = {
      maxTokens: config.maxTokens,
      refillRate: config.refillRate,
      keyPrefix: config.keyPrefix || 'rl',
    };
  }

  /**
   * Check if a request is allowed and consume a token if so.
   */
  consume(key: string): RateLimitResult {
    const fullKey = `${this.config.keyPrefix}:${key}`;
    const now = Date.now();

    // Get or create bucket
    let bucket = this.buckets.get(fullKey);
    if (!bucket) {
      bucket = {
        tokens: this.config.maxTokens,
        lastRefill: now,
      };
      this.buckets.set(fullKey, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsedMs = now - bucket.lastRefill;
    const tokensToAdd = (elapsedMs / 1000) * this.config.refillRate;
    bucket.tokens = Math.min(this.config.maxTokens, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    // Try to consume a token
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        resetMs: Math.ceil((this.config.maxTokens - bucket.tokens) / this.config.refillRate * 1000),
      };
    }

    // Rate limited
    const resetMs = Math.ceil((1 - bucket.tokens) / this.config.refillRate * 1000);
    return {
      allowed: false,
      remaining: 0,
      resetMs,
      reason: `Rate limited. Try again in ${Math.ceil(resetMs / 1000)}s`,
    };
  }

  /**
   * Check remaining tokens without consuming.
   */
  peek(key: string): number {
    const fullKey = `${this.config.keyPrefix}:${key}`;
    const bucket = this.buckets.get(fullKey);
    if (!bucket) return this.config.maxTokens;

    const now = Date.now();
    const elapsedMs = now - bucket.lastRefill;
    const tokensToAdd = (elapsedMs / 1000) * this.config.refillRate;
    return Math.min(this.config.maxTokens, Math.floor(bucket.tokens + tokensToAdd));
  }

  /**
   * Reset a bucket (e.g., on session end).
   */
  reset(key: string): void {
    const fullKey = `${this.config.keyPrefix}:${key}`;
    this.buckets.delete(fullKey);
  }

  /**
   * Clean up old buckets (call periodically).
   */
  cleanup(maxAgeMs: number = 60 * 60 * 1000): number {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > maxAgeMs) {
        this.buckets.delete(key);
        cleaned++;
      }
    }

    return cleaned;
  }
}

// =============================================================================
// Pre-configured Rate Limiters
// =============================================================================

/**
 * Rate limiter for Python script executions.
 * Allows 5 executions per 10 seconds per session.
 */
export const pythonExecLimiter = new RateLimiter({
  maxTokens: 5,
  refillRate: 0.5, // 5 tokens per 10 seconds
  keyPrefix: 'python',
});

/**
 * Rate limiter for general hook executions.
 * Allows 20 hooks per 10 seconds per session.
 */
export const hookExecLimiter = new RateLimiter({
  maxTokens: 20,
  refillRate: 2, // 20 tokens per 10 seconds
  keyPrefix: 'hook',
});

/**
 * Rate limiter for network operations.
 * Allows 10 network calls per 30 seconds.
 */
export const networkLimiter = new RateLimiter({
  maxTokens: 10,
  refillRate: 0.33, // 10 tokens per 30 seconds
  keyPrefix: 'network',
});

// =============================================================================
// Resource Monitoring
// =============================================================================

const DEFAULT_THRESHOLDS: ResourceThresholds = {
  maxMemoryPercent: 85,
  maxLoadAverage: 4.0,
};

/**
 * Check if system resources are available.
 */
export function checkResourceAvailability(
  thresholds: ResourceThresholds = DEFAULT_THRESHOLDS
): ResourceCheckResult {
  const free = freemem();
  const total = totalmem();
  const memoryPercent = ((total - free) / total) * 100;
  const [load1] = loadavg(); // 1-minute load average

  const issues: string[] = [];

  if (memoryPercent > thresholds.maxMemoryPercent) {
    issues.push(`Memory usage ${memoryPercent.toFixed(1)}% exceeds ${thresholds.maxMemoryPercent}%`);
  }

  if (load1 > thresholds.maxLoadAverage) {
    issues.push(`Load average ${load1.toFixed(2)} exceeds ${thresholds.maxLoadAverage}`);
  }

  return {
    available: issues.length === 0,
    memoryPercent,
    loadAverage: load1,
    reason: issues.length > 0 ? issues.join('; ') : undefined,
  };
}

/**
 * Combined check: rate limit AND resource availability.
 */
export function canExecute(
  limiter: RateLimiter,
  key: string,
  checkResources: boolean = true
): { allowed: boolean; reason?: string } {
  // Check rate limit
  const rateResult = limiter.consume(key);
  if (!rateResult.allowed) {
    return { allowed: false, reason: rateResult.reason };
  }

  // Check resources if enabled
  if (checkResources) {
    const resourceResult = checkResourceAvailability();
    if (!resourceResult.available) {
      return { allowed: false, reason: resourceResult.reason };
    }
  }

  return { allowed: true };
}

// =============================================================================
// Logging
// =============================================================================

/**
 * Log rate limit events for monitoring.
 */
export function logRateLimitEvent(
  projectDir: string,
  event: {
    type: 'blocked' | 'allowed' | 'resource_warning';
    limiter: string;
    key: string;
    remaining?: number;
    reason?: string;
  }
): void {
  try {
    const logPath = join(projectDir, '.claude', 'rate-limit.log');
    const logEntry = {
      timestamp: new Date().toISOString(),
      ...event,
    };
    appendFileSync(logPath, JSON.stringify(logEntry) + '\n', { flag: 'a' });
  } catch {
    // Silent fail
  }
}

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Check if Python execution is allowed for a session.
 */
export function canExecutePython(sessionId: string, projectDir?: string): boolean {
  const result = canExecute(pythonExecLimiter, sessionId, true);

  if (!result.allowed && projectDir) {
    logRateLimitEvent(projectDir, {
      type: 'blocked',
      limiter: 'python',
      key: sessionId,
      reason: result.reason,
    });
  }

  return result.allowed;
}

/**
 * Check if hook execution is allowed for a session.
 */
export function canExecuteHook(sessionId: string, projectDir?: string): boolean {
  const result = canExecute(hookExecLimiter, sessionId, false);

  if (!result.allowed && projectDir) {
    logRateLimitEvent(projectDir, {
      type: 'blocked',
      limiter: 'hook',
      key: sessionId,
      reason: result.reason,
    });
  }

  return result.allowed;
}

/**
 * Get current resource status summary.
 */
export function getResourceStatus(): string {
  const resources = checkResourceAvailability();
  const pythonRemaining = pythonExecLimiter.peek('current');
  const hookRemaining = hookExecLimiter.peek('current');

  return [
    `Memory: ${resources.memoryPercent.toFixed(1)}%`,
    `Load: ${resources.loadAverage.toFixed(2)}`,
    `Python tokens: ${pythonRemaining}`,
    `Hook tokens: ${hookRemaining}`,
    resources.available ? 'Status: OK' : `Status: CONSTRAINED (${resources.reason})`,
  ].join(' | ');
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a custom rate limiter.
 */
export function createRateLimiter(config: RateLimitConfig): RateLimiter {
  return new RateLimiter(config);
}

// =============================================================================
// Exports
// =============================================================================

export default {
  // Pre-configured limiters
  pythonExecLimiter,
  hookExecLimiter,
  networkLimiter,

  // Resource monitoring
  checkResourceAvailability,
  canExecute,

  // Convenience functions
  canExecutePython,
  canExecuteHook,
  getResourceStatus,

  // Logging
  logRateLimitEvent,

  // Factory
  createRateLimiter,
};
