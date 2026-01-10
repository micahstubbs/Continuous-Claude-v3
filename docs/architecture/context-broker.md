# Context Broker Architecture

**Status:** Design (V4.1)
**Security:** Round 2 Audit V4 - Chained Context Poisoning Prevention
**CVSS:** 6.9 (Medium)
**Updated:** 2026-01-10

## 1. Overview

The Context Broker is a centralized system for assembling, validating, and sanitizing context injected by hooks. It prevents chained context poisoning by enforcing trust boundaries and preventing re-injection of low-trust artifacts.

### Problem Statement

Currently, hooks inject context directly into the assistant's conversation without:
- Trust level classification
- Sanitization of instruction-like content
- Validation against re-injection attacks
- Monitoring of cross-hook context flow

This allows poisoned content (e.g., malicious instructions in memory, broadcasts, or continuity files) to:
1. Be surfaced as authoritative context
2. Influence downstream decisions
3. Get re-ingested into databases, creating amplification loops

### Solution

A centralized Context Broker that:
1. **Classifies** all context into trust tiers (High/Medium/Low)
2. **Validates** context blocks against schema and security rules
3. **Sanitizes** low-trust content to remove instruction markers
4. **Isolates** hook outputs to prevent re-injection
5. **Monitors** trust tier distribution and security events

## 2. Architecture Components

### 2.1 Core Types

```typescript
/**
 * Trust tier for context blocks
 */
export enum TrustTier {
  High = 'high',     // User input, verified signatures, system hooks
  Medium = 'medium', // Signed database entries, recent artifacts
  Low = 'low',       // Unsigned entries, old artifacts, external sources
}

/**
 * Source type for context provenance
 */
export enum SourceType {
  User = 'user',           // Direct user input
  Memory = 'memory',       // Memory database recall
  Broadcast = 'broadcast', // Agent broadcasts
  Continuity = 'continuity', // Session continuity files
  Handoff = 'handoff',     // Handoff summaries
  File = 'file',           // File system artifacts
  External = 'external',   // External sources
}

/**
 * A discrete unit of context with trust metadata
 */
export interface ContextBlock {
  id: string;                    // Unique block ID
  source_type: SourceType;       // Where this came from
  trust_tier: TrustTier;         // Computed trust level
  content: string;               // The actual content
  provenance: ProvenanceMetadata; // Full provenance tracking
  sanitized: boolean;            // Whether content was sanitized
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
  type: 'instruction_detected' | 'low_trust_blocked' | 'sanitization_applied' | 'size_limit_exceeded';
  block_id: string;
  source_type: SourceType;
  trust_tier: TrustTier;
  pattern_matched?: string;
  timestamp: number;
}
```

### 2.2 Context Broker Class

```typescript
/**
 * Centralized context assembly with trust enforcement
 */
export class ContextBroker {
  private blocks: ContextBlock[] = [];
  private config: BrokerConfig;
  private securityEvents: SecurityEvent[] = [];

  constructor(config?: Partial<BrokerConfig>) {
    this.config = { ...DEFAULT_BROKER_CONFIG, ...config };
  }

  /**
   * Register a context block with trust computation
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
    if (trust_tier === TrustTier.Low || hasInstructions) {
      content = this.sanitize(content, trust_tier);
      sanitized = true;
      this.logSecurityEvent({
        type: 'sanitization_applied',
        block_id: id,
        source_type: block.source_type,
        trust_tier,
        timestamp: Date.now(),
      });
    }

    // Determine if confirmation required
    const requires_confirmation = this.requiresConfirmation(trust_tier, hasInstructions);

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
   */
  validate(): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const block of this.blocks) {
      // Check for re-injection of low-trust content
      if (block.trust_tier === TrustTier.Low && this.isReinjectionRisk(block)) {
        warnings.push(`Block ${block.id} from ${block.source_type} may be re-injected low-trust content`);
      }

      // Check for instruction markers that survived sanitization
      if (this.detectInstructions(block.content)) {
        errors.push(`Block ${block.id} contains instruction markers after sanitization`);
      }

      // Check size limits
      if (block.content.length > this.config.maxBlockSize) {
        errors.push(`Block ${block.id} exceeds max size (${block.content.length} > ${this.config.maxBlockSize})`);
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Assemble all blocks into formatted context output
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
   * Compute trust tier from provenance metadata
   */
  private computeTrustTier(provenance: ProvenanceMetadata): TrustTier {
    // Use existing trust-tier.ts logic
    // High: User input, verified signatures, Hook source
    // Medium: Recent signed DB entries, Session/Agent sources
    // Low: Unsigned entries, old entries, External sources
    return computeTrustLevel(provenance, provenance.signature !== undefined);
  }

  /**
   * Detect instruction-like patterns in content
   */
  private detectInstructions(content: string): boolean {
    // Use existing security-utils.ts patterns
    return containsPromptInjection(content);
  }

  /**
   * Sanitize content based on trust tier
   */
  private sanitize(content: string, trust_tier: TrustTier): string {
    // For low trust: strip instruction markers, normalize formatting
    // For medium trust: only strip explicit instruction markers
    // For high trust: no sanitization (already trusted)

    if (trust_tier === TrustTier.Low) {
      // Aggressive sanitization
      content = this.stripInstructionMarkers(content);
      content = this.normalizeWhitespace(content);
      content = this.prefixLowTrustMarker(content);
    } else if (trust_tier === TrustTier.Medium) {
      // Moderate sanitization
      content = this.stripInstructionMarkers(content);
    }

    return content;
  }

  /**
   * Format blocks with trust tier markers
   */
  private formatBlocks(blocks: ContextBlock[]): string {
    const lines: string[] = [];

    for (const block of blocks) {
      // Add trust tier prefix
      const provenanceTag = formatProvenance(block.provenance, false);
      const trustMarker = this.getTrustMarker(block.trust_tier);

      lines.push(`${provenanceTag} ${trustMarker}`);
      lines.push(block.content);
      lines.push('');
    }

    return lines.join('\n');
  }

  private getTrustMarker(tier: TrustTier): string {
    switch (tier) {
      case TrustTier.High: return '[TRUSTED]';
      case TrustTier.Medium: return '[VERIFIED]';
      case TrustTier.Low: return '[UNVERIFIED]';
    }
  }
}
```

### 2.3 Configuration

```typescript
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
```

## 3. Data Flow

### 3.1 Context Registration Flow

```
Hook generates context
    ↓
ContextBroker.register({
  source_type,
  content,
  provenance
})
    ↓
Compute trust tier from provenance
    ↓
Detect instruction patterns
    ↓
Sanitize if low-trust or instructions detected
    ↓
Log security event if sanitized
    ↓
Return block ID
```

### 3.2 Context Assembly Flow

```
ContextBroker.validate()
    ↓
Check for re-injection risks
    ↓
Check for instruction markers
    ↓
Check size limits
    ↓
Return validation result
    ↓
ContextBroker.assemble()
    ↓
Sort blocks by trust tier
    ↓
Format with trust markers
    ↓
Calculate distribution metrics
    ↓
Return assembled context
```

### 3.3 Hook Integration Pattern

```typescript
// Example: memory-awareness.ts integration

// OLD (direct injection)
const claudeContext = `MEMORY MATCH: ${content}`;
console.log(JSON.stringify({ additionalContext: claudeContext }));

// NEW (broker-mediated)
import { ContextBroker } from './shared/context-broker.js';

const broker = new ContextBroker();

for (const result of results) {
  broker.register({
    source_type: SourceType.Memory,
    content: result.content,
    provenance: createProvenance({
      session_id: result.session_id,
      trust_level: TrustLevel.Medium,
      source_type: SourceType.Memory,
      content: result.content,
    }),
  });
}

const validation = broker.validate();
if (!validation.valid) {
  console.error('Context validation failed:', validation.errors);
  return;
}

const assembled = broker.assemble();
console.log(JSON.stringify({
  additionalContext: assembled.formatted_output,
  securityEvents: assembled.security_events,
}));
```

## 4. Integration Points

### 4.1 Hook Modifications Required

1. **memory-awareness.ts** (V4.3)
   - Replace direct context injection with ContextBroker
   - Tag results with SourceType.Memory
   - Apply size limits via broker

2. **pre-tool-use-broadcast.ts** (V4.4)
   - Register broadcasts through ContextBroker
   - Trust tier based on signature validation
   - Block re-injection of low-trust broadcasts

3. **session-start-continuity.ts** (V4.5)
   - Register continuity notes through broker
   - Tag as SourceType.Continuity
   - Sanitize user-supplied ledger artifacts

4. **handoff-index.ts** (V4.5)
   - Register handoff summaries through broker
   - Tag as SourceType.Handoff
   - Prevent re-ingestion of unreviewed artifacts

### 4.2 Shared Utilities Integration

The Context Broker will integrate with existing security infrastructure:

- **provenance-types.ts**: Use ProvenanceMetadata interface
- **trust-tier.ts**: Use computeTrustLevel() for tier computation
- **security-utils.ts**: Use containsPromptInjection() for detection
- **memory-limits.ts**: Use size limit utilities

## 5. Security Properties

### 5.1 Threat Mitigations

| Threat | Mitigation |
|--------|------------|
| Instruction injection via memory | Sanitization strips instruction markers before surfacing |
| Broadcast payload poisoning | Trust tier based on signature; low-trust blocked or flagged |
| Continuity file tampering | File artifacts tagged as low-trust unless signed |
| Amplification (re-storage) | Validation prevents re-injection of sanitized content |
| Context eviction via bloat | Size limits enforced per-block and total |

### 5.2 Defense in Depth Layers

1. **Input Validation**: Schema validation on all context blocks
2. **Trust Classification**: Automatic tier assignment from provenance
3. **Sanitization**: Pattern-based instruction stripping
4. **Isolation**: Prevent cross-hook re-injection
5. **Monitoring**: Log all security events for audit
6. **Confirmation**: Require approval for low-trust actions

## 6. Monitoring and Logging

### 6.1 Security Events

The broker logs the following security events:

- `instruction_detected`: Instruction markers found in content
- `low_trust_blocked`: Low-trust content rejected
- `sanitization_applied`: Content was sanitized
- `size_limit_exceeded`: Block exceeded size limits
- `reinjection_risk`: Potential re-injection detected

### 6.2 Metrics

Track the following metrics per session:

- Trust tier distribution (% High/Medium/Low)
- Sanitization rate (% blocks sanitized)
- Security event count by type
- Average block size
- Total context size

### 6.3 Audit Log Format

```jsonlines
{"event":"instruction_detected","block_id":"ctx_abc123","source":"memory","tier":"medium","pattern":"<SYSTEM>","timestamp":1704830400}
{"event":"sanitization_applied","block_id":"ctx_abc123","source":"memory","tier":"low","timestamp":1704830401}
```

## 7. Testing Strategy

### 7.1 Unit Tests (V4.2)

- Trust tier computation from various provenance states
- Instruction detection with known poisoned patterns
- Sanitization effectiveness on instruction markers
- Size limit enforcement
- Block sorting and formatting

### 7.2 Integration Tests (V4.3-V4.7)

- Memory hook with poisoned entries
- Broadcast hook with malicious payloads
- Continuity hook with tampered files
- Confirmation flow with low-trust content
- Monitoring and logging integration

### 7.3 End-to-End Tests (V4.8)

- **Chained poisoning**: Memory → Broadcast → Continuity
- **Amplification prevention**: Poisoned content not re-stored
- **Trust propagation**: Trust tiers maintained across hooks
- **Attack scenarios**: PoC from audit report

## 8. Implementation Phases

### Phase 1: Design (V4.1) - THIS DOCUMENT
- Architecture design
- Interface definitions
- Data flow diagrams
- Integration planning

### Phase 2: Core Implementation (V4.2)
- ContextBroker class
- Trust computation logic
- Sanitization rules
- Unit tests

### Phase 3: Hook Integration (V4.3-V4.5)
- Parallel implementation across hooks
- Replace direct injection with broker
- Tag source types correctly
- Validate trust tiers

### Phase 4: Security Features (V4.6-V4.7)
- User confirmation flow
- Monitoring and logging
- Alert mechanisms
- Security audit log

### Phase 5: Testing (V4.8)
- End-to-end poisoning tests
- Attack scenario reproduction
- Performance benchmarking
- Documentation

## 9. Migration Path

### 9.1 Backwards Compatibility

The Context Broker is additive - hooks can migrate incrementally:

1. Deploy broker infrastructure (V4.2)
2. Migrate one hook at a time (V4.3-V4.5)
3. Enable strict mode after all hooks migrated
4. Remove legacy direct injection code

### 9.2 Rollout Strategy

1. **Week 1**: V4.1-V4.2 (design + implementation)
2. **Week 2**: V4.3-V4.5 (parallel hook integration)
3. **Week 3**: V4.6-V4.7 (security features)
4. **Week 4**: V4.8 (testing and validation)

## 10. Future Enhancements

### 10.1 Advanced Trust Policies

- User-defined trust rules
- Dynamic trust adjustment based on behavior
- ML-based instruction detection
- Allowlist/blocklist for content patterns

### 10.2 Context Compression

- Summarization for low-priority context
- Deduplication across blocks
- Smart truncation preserving high-trust content

### 10.3 Multi-Session Correlation

- Track trust across session boundaries
- Detect persistent poisoning attempts
- Session reputation scoring

## 11. References

- **Audit Report**: Round 2 V4 - Chained Context Poisoning
- **CWE-917**: Improper Neutralization of Special Elements
- **CWE-657**: Violation of Secure Design Principles
- **CVSS v3.1**: 6.9 (AV:A/AC:H/PR:L/UI:R/S:C/C:M/I:H/A:L)
