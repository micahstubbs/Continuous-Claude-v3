/**
 * Context Broker Monitoring and Audit Logging
 *
 * Provides persistent logging, metrics tracking, and alerting for context broker security events.
 *
 * Security: V4.7 - Monitoring and logging for context trust events
 * Audit: Round 2 V4 - Incomplete isolation between hook outputs
 */

import { appendFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import type { SecurityEvent, AssembledContext, TrustTier } from './context-broker.js';

/**
 * Audit log entry with additional context
 */
export interface AuditLogEntry {
  timestamp: string;
  session_id: string;
  hook_name: string;
  event_type: string;
  trust_tier?: string;
  source_type?: string;
  block_id?: string;
  pattern_matched?: string;
  total_blocks?: number;
  requires_confirmation?: boolean;
  trust_distribution?: Record<string, number>;
}

/**
 * Write security event to persistent audit log
 *
 * Log format: JSON Lines (.jsonl)
 * Location: .claude/logs/context-broker-audit.jsonl
 *
 * @param event - Security event to log
 * @param sessionId - Current session ID
 * @param hookName - Name of hook generating the event
 */
export function logSecurityEvent(
  event: SecurityEvent,
  sessionId: string,
  hookName: string
): void {
  try {
    const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
    const logDir = join(projectDir, '.claude', 'logs');

    // Ensure log directory exists
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true, mode: 0o700 }); // Owner-only permissions
    }

    const logPath = join(logDir, 'context-broker-audit.jsonl');

    // Build audit log entry
    const logEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      hook_name: hookName,
      event_type: event.type,
      trust_tier: event.trust_tier,
      source_type: event.source_type,
      block_id: event.block_id,
      pattern_matched: event.pattern_matched,
    };

    // Write as JSON Lines (one JSON object per line)
    const logLine = JSON.stringify(logEntry) + '\n';
    appendFileSync(logPath, logLine, { mode: 0o600 }); // Owner-only permissions
  } catch (err) {
    // Silent fail - don't disrupt hook execution
    // Log to stderr for debugging
    console.error(`[context-broker-monitor] Failed to log security event: ${err}`);
  }
}

/**
 * Log assembled context summary
 *
 * Tracks overall trust distribution and confirmation requirements per hook invocation.
 *
 * @param assembled - Assembled context from broker
 * @param sessionId - Current session ID
 * @param hookName - Name of hook generating the context
 */
export function logAssembledContext(
  assembled: AssembledContext,
  sessionId: string,
  hookName: string
): void {
  try {
    const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
    const logDir = join(projectDir, '.claude', 'logs');

    // Ensure log directory exists
    if (!existsSync(logDir)) {
      mkdirSync(logDir, { recursive: true, mode: 0o700 });
    }

    const logPath = join(logDir, 'context-broker-audit.jsonl');

    // Build summary entry
    const logEntry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      hook_name: hookName,
      event_type: 'context_assembled',
      total_blocks: assembled.blocks.length,
      requires_confirmation: assembled.requires_confirmation,
      trust_distribution: assembled.trust_distribution as Record<string, number>,
    };

    const logLine = JSON.stringify(logEntry) + '\n';
    appendFileSync(logPath, logLine, { mode: 0o600 });
  } catch (err) {
    console.error(`[context-broker-monitor] Failed to log assembled context: ${err}`);
  }
}

/**
 * Check for alert conditions based on security events
 *
 * Returns true if any alert-worthy patterns are detected:
 * - Multiple low-trust blocks in single context
 * - High rate of instruction detection
 * - Re-injection risks
 *
 * @param assembled - Assembled context to check
 * @returns True if alert should be raised
 */
export function checkAlertConditions(assembled: AssembledContext): boolean {
  // Alert if more than 3 low-trust blocks
  const lowTrustCount = assembled.trust_distribution['low'] || 0;
  if (lowTrustCount > 3) {
    return true;
  }

  // Alert if any re-injection risks detected
  const reinjectionEvents = assembled.security_events.filter(
    e => e.type === 'reinjection_risk'
  );
  if (reinjectionEvents.length > 0) {
    return true;
  }

  // Alert if multiple instruction detections
  const instructionEvents = assembled.security_events.filter(
    e => e.type === 'instruction_detected' || e.type === 'sanitization_applied'
  );
  if (instructionEvents.length > 2) {
    return true;
  }

  return false;
}

/**
 * Emit alert to stderr for hook monitoring
 *
 * @param message - Alert message
 * @param assembled - Context that triggered alert
 */
export function emitAlert(message: string, assembled: AssembledContext): void {
  console.error('');
  console.error('═══════════════════════════════════════════════════════════════');
  console.error('🚨 CONTEXT BROKER SECURITY ALERT');
  console.error('═══════════════════════════════════════════════════════════════');
  console.error('');
  console.error(message);
  console.error('');
  console.error('Trust Distribution:', JSON.stringify(assembled.trust_distribution));
  console.error('Security Events:', assembled.security_events.length);
  console.error('Requires Confirmation:', assembled.requires_confirmation);
  console.error('');
  console.error('Review: .claude/logs/context-broker-audit.jsonl');
  console.error('═══════════════════════════════════════════════════════════════');
  console.error('');
}

/**
 * Convenience function: Log all events and check for alerts
 *
 * Call this after assembling context in a hook.
 *
 * @param assembled - Assembled context from broker
 * @param sessionId - Current session ID
 * @param hookName - Name of hook (for tracking)
 */
export function monitorAssembledContext(
  assembled: AssembledContext,
  sessionId: string,
  hookName: string
): void {
  // Log all individual security events
  for (const event of assembled.security_events) {
    logSecurityEvent(event, sessionId, hookName);
  }

  // Log overall context summary
  logAssembledContext(assembled, sessionId, hookName);

  // Check and emit alerts if needed
  if (checkAlertConditions(assembled)) {
    emitAlert(
      `Hook "${hookName}" assembled context with suspicious patterns (session: ${sessionId})`,
      assembled
    );
  }
}
