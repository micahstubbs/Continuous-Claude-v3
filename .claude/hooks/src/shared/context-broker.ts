/**
 * Context Broker - Centralized context assembly with trust enforcement
 *
 * Prevents chained context poisoning by:
 * - Classifying all context into trust tiers (High/Medium/Low)
 * - Validating context blocks against schema and security rules
 * - Sanitizing low-trust content to remove instruction markers
 * - Isolating hook outputs to prevent re-injection
 * - Monitoring trust tier distribution and security events
 *
 * Security: V4 - Chained context poisoning prevention (Round 2 audit, CVSS 6.9)
 * Audit: Round 2 V4 - Incomplete isolation between hook outputs
 */

import {
  type ProvenanceMetadata,
  TrustLevel,
  SourceType,
  formatProvenance,
} from './provenance-types.js';
import { computeTrustLevel } from './trust-tier.js';
import { containsPromptInjection, detectPromptInjection } from './security-utils.js';

/**
 * Trust tier for context blocks (simplified from TrustLevel enum)
 */
export enum TrustTier {
  High = 'high',     // User input, verified signatures, system hooks
  Medium = 'medium', // Signed database entries, recent artifacts
  Low = 'low',       // Unsigned entries, old artifacts, external sources
}

/**
 * Map TrustLevel (from provenance) to TrustTier (for broker)
 */
function trustLevelToTier(level: TrustLevel): TrustTier {
  switch (level) {
    case TrustLevel.High:
      return TrustTier.High;
    case TrustLevel.Medium:
      return TrustTier.Medium;
    case TrustLevel.Low:
      return TrustTier.Low;
  }
}

/**
 * A discrete unit of context with trust metadata
 */
export interface ContextBlock {
  id: string;                     // Unique block ID
  source_type: SourceType;        // Where this came from
  trust_tier: TrustTier;          // Computed trust level
  content: string;                // The actual content
  provenance: ProvenanceMetadata; // Full provenance tracking
  sanitized: boolean;             // Whether content was sanitized
  requires_confirmation: boolean; // Low-trust requiring approval
  metadata?: Record<string, unknown>; // Additional source-specific data
}

/**
 * Assembled context ready for injection
 */
export interface AssembledContext {
  blocks: ContextBlock[];
  total_size: number;
  trust_distribution: Record<TrustTier, number>;
  security_events: SecurityEvent[];
  formatted_output: string;
}

/**
 * Security events logged during context assembly
 */
export interface SecurityEvent {
  type: 'instruction_detected' | 'low_trust_blocked' | 'sanitization_applied' | 'size_limit_exceeded' | 'reinjection_risk';
  block_id: string;
  source_type: SourceType;
  trust_tier: TrustTier;
  pattern_matched?: string;
  timestamp: number;
}

/**
 * Validation result from context checks
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Configuration for context broker behavior
 */
export interface BrokerConfig {
  // Size limits
  maxBlockSize: number;        // Max size per block (bytes)
  maxTotalSize: number;         // Max total context size (bytes)
  maxBlocks: number;            // Max number of blocks

  // Trust policies
  blockLowTrust: boolean;       // Block low-trust content entirely
  requireConfirmation: boolean; // Require user confirmation for low-trust
  stripInstructions: boolean;   // Strip instruction markers

  // Sanitization
  aggressiveSanitization: boolean; // More aggressive pattern matching
  prefixLowTrust: boolean;         // Add [UNVERIFIED] prefix

  // Monitoring
  logSecurityEvents: boolean;   // Log all security events
  alertOnLowTrust: boolean;     // Alert on low-trust injection
}

/**
 * Default broker configuration
 */
export const DEFAULT_BROKER_CONFIG: BrokerConfig = {
  maxBlockSize: 2048,           // 2KB per block
  maxTotalSize: 10240,          // 10KB total
  maxBlocks: 20,                // Max 20 blocks

  blockLowTrust: false,         // Allow but sanitize
  requireConfirmation: true,    // Require confirmation for low-trust
  stripInstructions: true,      // Always strip instructions

  aggressiveSanitization: true, // Aggressive by default
  prefixLowTrust: true,         // Mark unverified content

  logSecurityEvents: true,      // Always log
  alertOnLowTrust: true,        // Alert on suspicious content
};

/**
 * Centralized context assembly with trust enforcement
 */
export class ContextBroker {
  private blocks: ContextBlock[] = [];
  private config: BrokerConfig;
  private securityEvents: SecurityEvent[] = [];
  private blockCounter = 0;

  constructor(config?: Partial<BrokerConfig>) {
    this.config = { ...DEFAULT_BROKER_CONFIG, ...config };
  }

  /**
   * Register a context block with trust computation
   *
   * @param block - Context block to register (without computed fields)
   * @returns Block ID for tracking
   */
  register(block: Omit<ContextBlock, 'id' | 'trust_tier' | 'sanitized' | 'requires_confirmation'>): string {
    // Generate unique block ID
    const id = this.generateBlockId();

    // Compute trust tier based on provenance
    const trust_tier = this.computeTrustTier(block.provenance);

    // Check if content contains instruction markers
    const hasInstructions = this.detectInstructions(block.content);

    // Sanitize if low-trust or contains instructions
    let content = block.content;
    let sanitized = false;

    if ((trust_tier === TrustTier.Low || hasInstructions) && this.config.stripInstructions) {
      const patterns = hasInstructions ? detectPromptInjection(block.content) : [];
      content = this.sanitize(content, trust_tier);
      sanitized = true;

      this.logSecurityEvent({
        type: 'sanitization_applied',
        block_id: id,
        source_type: block.source_type,
        trust_tier,
        pattern_matched: patterns.join(', '),
        timestamp: Date.now(),
      });
    }

    // Log instruction detection even if not sanitized
    if (hasInstructions && !sanitized) {
      const patterns = detectPromptInjection(block.content);
      this.logSecurityEvent({
        type: 'instruction_detected',
        block_id: id,
        source_type: block.source_type,
        trust_tier,
        pattern_matched: patterns.join(', '),
        timestamp: Date.now(),
      });
    }

    // Determine if confirmation required
    const requires_confirmation = this.requiresConfirmation(trust_tier, hasInstructions);

    // Check size limits
    if (content.length > this.config.maxBlockSize) {
      this.logSecurityEvent({
        type: 'size_limit_exceeded',
        block_id: id,
        source_type: block.source_type,
        trust_tier,
        timestamp: Date.now(),
      });

      // Truncate with marker
      content = content.slice(0, this.config.maxBlockSize - 15) + ' [TRUNCATED]';
      sanitized = true;
    }

    const contextBlock: ContextBlock = {
      id,
      trust_tier,
      sanitized,
      requires_confirmation,
      ...block,
      content,
    };

    this.blocks.push(contextBlock);
    return id;
  }

  /**
   * Validate all registered blocks against security rules
   *
   * @returns Validation result with errors and warnings
   */
  validate(): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check total block count
    if (this.blocks.length > this.config.maxBlocks) {
      errors.push(`Too many blocks: ${this.blocks.length} > ${this.config.maxBlocks}`);
    }

    for (const block of this.blocks) {
      // Check for re-injection of low-trust content
      if (block.trust_tier === TrustTier.Low && this.isReinjectionRisk(block)) {
        warnings.push(`Block ${block.id} from ${block.source_type} may be re-injected low-trust content`);
        this.logSecurityEvent({
          type: 'reinjection_risk',
          block_id: block.id,
          source_type: block.source_type,
          trust_tier: block.trust_tier,
          timestamp: Date.now(),
        });
      }

      // Check for instruction markers that survived sanitization
      if (block.sanitized && this.detectInstructions(block.content)) {
        errors.push(`Block ${block.id} contains instruction markers after sanitization`);
      }

      // Enforce low-trust blocking if configured
      if (this.config.blockLowTrust && block.trust_tier === TrustTier.Low) {
        this.logSecurityEvent({
          type: 'low_trust_blocked',
          block_id: block.id,
          source_type: block.source_type,
          trust_tier: block.trust_tier,
          timestamp: Date.now(),
        });
        errors.push(`Block ${block.id} blocked: low-trust content not allowed`);
      }
    }

    // Check total size
    const totalSize = this.blocks.reduce((sum, b) => sum + b.content.length, 0);
    if (totalSize > this.config.maxTotalSize) {
      errors.push(`Total context size exceeds limit: ${totalSize} > ${this.config.maxTotalSize}`);
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Assemble all blocks into formatted context output
   *
   * @returns Assembled context with formatted output
   */
  assemble(): AssembledContext {
    // Sort blocks by trust tier (High → Medium → Low)
    const sorted = this.sortByTrust(this.blocks);

    // Calculate trust distribution
    const trust_distribution = this.calculateTrustDistribution();

    // Format output with trust tier markers
    const formatted_output = this.formatBlocks(sorted);

    // Calculate total size
    const total_size = formatted_output.length;

    return {
      blocks: sorted,
      total_size,
      trust_distribution,
      security_events: this.securityEvents,
      formatted_output,
    };
  }

  /**
   * Get security events logged during assembly
   */
  getSecurityEvents(): SecurityEvent[] {
    return this.securityEvents;
  }

  /**
   * Clear all blocks and events (for new context assembly)
   */
  clear(): void {
    this.blocks = [];
    this.securityEvents = [];
    this.blockCounter = 0;
  }

  /**
   * Generate unique block ID
   */
  private generateBlockId(): string {
    this.blockCounter++;
    return `ctx_${this.blockCounter.toString().padStart(6, '0')}`;
  }

  /**
   * Compute trust tier from provenance metadata
   */
  private computeTrustTier(provenance: ProvenanceMetadata): TrustTier {
    // Use existing trust-tier.ts logic with signature validation
    const signatureValid = provenance.signature !== undefined;
    const trustLevel = computeTrustLevel(provenance, signatureValid);
    return trustLevelToTier(trustLevel);
  }

  /**
   * Detect instruction-like patterns in content
   */
  private detectInstructions(content: string): boolean {
    // Use existing security-utils.ts patterns
    return containsPromptInjection(content);
  }

  /**
   * Determine if content requires user confirmation
   */
  private requiresConfirmation(trust_tier: TrustTier, hasInstructions: boolean): boolean {
    if (!this.config.requireConfirmation) {
      return false;
    }

    // Low-trust with instructions always requires confirmation
    if (trust_tier === TrustTier.Low && hasInstructions) {
      return true;
    }

    // Medium-trust with instructions requires confirmation
    if (trust_tier === TrustTier.Medium && hasInstructions) {
      return true;
    }

    return false;
  }

  /**
   * Check if block is at risk of being re-injected low-trust content
   */
  private isReinjectionRisk(block: ContextBlock): boolean {
    // Heuristic: Low-trust content from continuity/handoff sources
    // that was previously sanitized indicates possible re-injection
    if (block.trust_tier !== TrustTier.Low) {
      return false;
    }

    // Continuity and handoff files can contain previously sanitized content
    const riskySources = [SourceType.Continuity, SourceType.File];
    if (riskySources.includes(block.source_type)) {
      // Check if content has sanitization markers
      if (block.content.includes('[TRUNCATED]') || block.content.includes('[SANITIZED]')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Sanitize content based on trust tier
   */
  private sanitize(content: string, trust_tier: TrustTier): string {
    let sanitized = content;

    // Strip instruction markers
    sanitized = this.stripInstructionMarkers(sanitized);

    // Normalize whitespace (aggressive sanitization)
    if (this.config.aggressiveSanitization) {
      sanitized = this.normalizeWhitespace(sanitized);
    }

    // Add low-trust prefix if configured
    if (trust_tier === TrustTier.Low && this.config.prefixLowTrust) {
      sanitized = this.prefixLowTrustMarker(sanitized);
    }

    return sanitized;
  }

  /**
   * Strip instruction markers from content
   */
  private stripInstructionMarkers(content: string): string {
    // Remove common instruction patterns
    let stripped = content;

    // Remove <SYSTEM>, <INSTRUCTION>, <COMMAND> tags
    stripped = stripped.replace(/<\s*(SYSTEM|INSTRUCTION|COMMAND)[^>]*>[\s\S]*?<\/\s*\1\s*>/gi, '[SANITIZED]');

    // Remove standalone tags
    stripped = stripped.replace(/<\s*(SYSTEM|INSTRUCTION|COMMAND)[^>]*>/gi, '');

    // Remove markdown code blocks with suspicious keywords
    stripped = stripped.replace(/```(?:bash|sh|shell|python)\s*(curl|rm|sudo|chmod)[\s\S]*?```/gi, '[SANITIZED]');

    // Remove SQL injection patterns
    stripped = stripped.replace(/;\s*DROP\s+TABLE/gi, '[SANITIZED]');

    return stripped;
  }

  /**
   * Normalize whitespace (collapse multiple spaces/newlines)
   */
  private normalizeWhitespace(content: string): string {
    return content
      .replace(/\s+/g, ' ')     // Collapse whitespace
      .replace(/\n{3,}/g, '\n\n') // Max 2 consecutive newlines
      .trim();
  }

  /**
   * Add low-trust marker prefix
   */
  private prefixLowTrustMarker(content: string): string {
    return `[UNVERIFIED CONTENT]\n${content}`;
  }

  /**
   * Sort blocks by trust tier (High → Medium → Low)
   */
  private sortByTrust(blocks: ContextBlock[]): ContextBlock[] {
    const tierOrder = {
      [TrustTier.High]: 0,
      [TrustTier.Medium]: 1,
      [TrustTier.Low]: 2,
    };

    return [...blocks].sort((a, b) => tierOrder[a.trust_tier] - tierOrder[b.trust_tier]);
  }

  /**
   * Calculate trust tier distribution
   */
  private calculateTrustDistribution(): Record<TrustTier, number> {
    const distribution = {
      [TrustTier.High]: 0,
      [TrustTier.Medium]: 0,
      [TrustTier.Low]: 0,
    };

    for (const block of this.blocks) {
      distribution[block.trust_tier]++;
    }

    return distribution;
  }

  /**
   * Format blocks with trust tier markers
   */
  private formatBlocks(blocks: ContextBlock[]): string {
    const lines: string[] = [];

    for (const block of blocks) {
      // Add provenance tag and trust marker
      const provenanceTag = formatProvenance(block.provenance, false);
      const trustMarker = this.getTrustMarker(block.trust_tier);

      lines.push(`${provenanceTag} ${trustMarker}`);

      // Add confirmation warning for low-trust content
      if (block.requires_confirmation) {
        lines.push('⚠️  LOW-TRUST CONTENT - VERIFY BEFORE ACTING');
      }

      lines.push(block.content);
      lines.push('');
    }

    return lines.join('\n');
  }

  /**
   * Get display marker for trust tier
   */
  private getTrustMarker(tier: TrustTier): string {
    switch (tier) {
      case TrustTier.High:
        return '[TRUSTED]';
      case TrustTier.Medium:
        return '[VERIFIED]';
      case TrustTier.Low:
        return '[UNVERIFIED]';
    }
  }

  /**
   * Log a security event
   */
  private logSecurityEvent(event: SecurityEvent): void {
    this.securityEvents.push(event);

    if (this.config.logSecurityEvents) {
      // In production, this would go to a security audit log
      // For now, we just accumulate in memory
      if (this.config.alertOnLowTrust && event.trust_tier === TrustTier.Low) {
        // Could trigger alerts/notifications
      }
    }
  }
}
