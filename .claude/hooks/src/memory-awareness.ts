/**
 * Memory Awareness Hook (UserPromptSubmit)
 *
 * Checks if user prompt is similar to stored learnings.
 * Shows hint to BOTH user (visible) AND Claude (system context).
 *
 * Flow:
 * 1. Extract INTENT from user prompt (not just keywords)
 * 2. Semantic search using hybrid RRF (text + vector)
 * 3. If score > threshold, show visible hint with top learning preview
 * 4. Claude proactively discloses and acts on relevant memories
 */

import { readFileSync, existsSync, appendFileSync } from 'fs';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { containsPromptInjection, detectPromptInjection } from './shared/security-utils.js';
import {
  createProvenance,
  formatProvenance,
  TrustLevel,
  SourceType,
  type ProvenanceMetadata
} from './shared/provenance-types.js';
import {
  applyMemoryLimits,
  checkMemoryLimits,
  formatBytes,
  DEFAULT_MEMORY_LIMITS
} from './shared/memory-limits.js';
import { ContextBroker } from './shared/context-broker.js';
import { monitorAssembledContext } from './shared/context-broker-monitor.js';
import { verifyEntry } from './shared/crypto-signing.js';
import { getLegacyMode } from './shared/session-registry.js';

interface UserPromptSubmitInput {
  session_id: string;
  hook_event_name: string;
  prompt: string;
  cwd: string;
}

interface LearningResult {
  id: string;
  type: string;
  content: string;
  score: number;
  session_id?: string;
  created_at?: string;
}

interface LearningResultWithProvenance extends LearningResult {
  provenance: ProvenanceMetadata;
}

interface MemoryMatch {
  count: number;
  results: LearningResult[];
}

function readStdin(): string {
  return readFileSync(0, 'utf-8');
}

/**
 * Extract the INTENT from user prompt - what they're actually asking about.
 * Removes meta-language ("can you", "help me", "recall") to get core topic.
 */
function extractIntent(prompt: string): string {
  // Meta-phrases to remove (these describe HOW, not WHAT)
  const metaPhrases = [
    /^(can you|could you|would you|please|help me|i want to|i need to|let's|lets)\s+/gi,
    /^(show me|tell me|find|search for|look for|recall|remember)\s+/gi,
    /^(how do i|how can i|how to|what is|what are|where is|where are)\s+/gi,
    /\s+(for me|please|thanks|thank you)$/gi,
    /\?$/g,
  ];

  let intent = prompt.trim();

  // Strip meta-phrases iteratively
  for (const pattern of metaPhrases) {
    intent = intent.replace(pattern, '');
  }

  intent = intent.trim();

  // If we stripped too much, fall back to keyword extraction
  if (intent.length < 5) {
    return extractKeywords(prompt);
  }

  return intent;
}

/**
 * Extract meaningful keywords from prompt (fallback for very short intents).
 */
function extractKeywords(prompt: string): string {
  const stopWords = new Set([
    'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
    'should', 'may', 'might', 'must', 'can', 'to', 'of', 'in', 'for',
    'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
    'before', 'after', 'above', 'below', 'between', 'under', 'again',
    'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why',
    'how', 'all', 'each', 'few', 'more', 'most', 'other', 'some', 'such',
    'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
    's', 't', 'just', 'don', 'now', 'i', 'me', 'my', 'you', 'your', 'we', 'help', 'with',
    'our', 'they', 'them', 'their', 'it', 'its', 'this', 'that', 'these',
    'what', 'which', 'who', 'whom', 'and', 'but', 'if', 'or', 'because',
    'until', 'while', 'about', 'against', 'also', 'get', 'got', 'make',
    'want', 'need', 'look', 'see', 'use', 'like', 'know', 'think', 'take',
    'come', 'go', 'say', 'said', 'tell', 'please', 'help', 'let', 'sure',
    'recall', 'remember', 'similar', 'problems', 'issues'
  ]);

  const words = prompt
    .toLowerCase()
    .replace(/[^\w\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !stopWords.has(w));

  return [...new Set(words)].slice(0, 5).join(' ');
}

/**
 * Log security events for audit trail.
 * Writes to .claude/security-audit.log in JSON Lines format.
 */
function logSecurityEvent(projectDir: string, event: Record<string, unknown>): void {
  try {
    const logPath = join(projectDir, '.claude', 'security-audit.log');
    const logLine = JSON.stringify(event) + '\n';
    appendFileSync(logPath, logLine, { flag: 'a' });
  } catch {
    // Silent fail - don't disrupt normal operation
    // Security logging is best-effort
  }
}

/**
 * Fast memory relevance check using text search.
 * For text-only mode, we search by the most significant keyword
 * (text ILIKE looks for substring match, not multi-word).
 */
function checkMemoryRelevance(intent: string, projectDir: string): MemoryMatch | null {
  if (!intent || intent.length < 3) return null;

  const opcDir = join(projectDir, 'opc');

  // PostgreSQL full-text search handles stopwords automatically via plainto_tsquery
  // Just clean up the intent: remove paths, underscores, short words
  const searchTerm = intent
    .replace(/[_\/]/g, ' ')           // Convert underscores/slashes to spaces
    .replace(/\b\w{1,2}\b/g, '')      // Remove 1-2 char words
    .replace(/\s+/g, ' ')             // Collapse whitespace
    .trim();

  // Use text-only for fast checking (< 1s), user can run /recall for semantic
  const result = spawnSync('uv', [
    'run', 'python', 'scripts/core/recall_learnings.py',
    '--query', searchTerm,  // Single keyword for text match
    '--k', String(DEFAULT_MEMORY_LIMITS.maxResults), // V5: Enforce max results
    '--json',
    '--text-only'  // Fast text search for hints
  ], {
    encoding: 'utf-8',
    cwd: opcDir,
    env: {
      ...process.env,
      PYTHONPATH: opcDir
    },
    timeout: DEFAULT_MEMORY_LIMITS.maxExecutionMs // V5: Enforce execution timeout
  });

  if (result.status !== 0 || !result.stdout) {
    return null;
  }

  try {
    const data = JSON.parse(result.stdout);

    if (!data.results || data.results.length === 0) {
      return null;
    }

    // ts_rank returns small values (0.0001-0.1), ILIKE fallback returns 0.1
    // Any match from FTS is relevant enough to show

    // SECURITY: Filter out entries containing prompt injection patterns
    const safeResults = data.results.filter((r: any) => {
      const content = r.content || '';
      if (containsPromptInjection(content)) {
        // Log blocked entry for security audit
        const patterns = detectPromptInjection(content);
        logSecurityEvent(projectDir, {
          event: 'MEMORY_POISONING_BLOCKED',
          entryId: r.id || 'unknown',
          patterns,
          timestamp: new Date().toISOString(),
        });
        return false;  // Filter out poisoned entry
      }
      return true;
    });

    if (safeResults.length === 0) {
      return null;
    }

    // V1.9: Validate provenance for all memory results
    const rejectedCount = { missing_provenance: 0, invalid_signature: 0 };
    const validResults = safeResults.filter((r: any) => {
      // Check if provenance fields exist
      if (!r.origin_session || !r.signature || !r.created_at_ts) {
        rejectedCount.missing_provenance++;
        // R3-V2: Handle legacy entries based on mode
        const mode = getLegacyMode();
        logSecurityEvent(projectDir, {
          event: 'MEMORY_PROVENANCE_MISSING',
          entryId: r.id || 'unknown',
          mode,
          timestamp: new Date().toISOString(),
        });
        if (mode === 'reject') {
          return false; // Reject entries without provenance
        }
        return true; // Accept legacy entries in 'accept' or 'quarantine' mode
      }

      // Verify signature
      try {
        // Reconstruct signed content (must match write path format in memory-db-utils.ts)
        const dataToVerify = {
          content: r.content,
          learning_type: r.type || r.learning_type,
          session_id: r.session_id,
          origin_session: r.origin_session,
          origin_agent: r.origin_agent,
          created_at_ts: r.created_at_ts
        };

        const isValid = verifyEntry(dataToVerify, r.signature, r.origin_session);
        if (!isValid) {
          rejectedCount.invalid_signature++;
          logSecurityEvent(projectDir, {
            event: 'MEMORY_SIGNATURE_INVALID',
            entryId: r.id || 'unknown',
            origin_session: r.origin_session,
            timestamp: new Date().toISOString(),
          });
          return false; // Reject entries with invalid signatures
        }

        return true; // Accept valid entries
      } catch (err) {
        rejectedCount.invalid_signature++;
        logSecurityEvent(projectDir, {
          event: 'MEMORY_SIGNATURE_ERROR',
          entryId: r.id || 'unknown',
          error: String(err),
          timestamp: new Date().toISOString(),
        });
        return false;
      }
    });

    // Log rejection summary if any entries were rejected
    if (rejectedCount.invalid_signature > 0) {
      logSecurityEvent(projectDir, {
        event: 'MEMORY_PROVENANCE_VALIDATION',
        rejected: rejectedCount,
        accepted: validResults.length,
        timestamp: new Date().toISOString(),
      });
    }

    if (validResults.length === 0) {
      return null;
    }

    // V5: Apply memory size limits before extracting results
    const limitedResults = applyMemoryLimits(
      validResults.map((r: any) => ({ ...r, content: r.content || '' })),
      DEFAULT_MEMORY_LIMITS
    );

    // Log if results were truncated
    const limits = checkMemoryLimits(limitedResults, DEFAULT_MEMORY_LIMITS);
    if (!limits.within_limits) {
      logSecurityEvent(projectDir, {
        event: 'MEMORY_SIZE_LIMIT_ENFORCED',
        exceeded: limits.exceeded,
        total_bytes: limits.total_bytes,
        max_allowed: DEFAULT_MEMORY_LIMITS.maxTotalBytes,
        timestamp: new Date().toISOString(),
      });
    }

    // Extract structured results with better previews
    const results: LearningResult[] = limitedResults.slice(0, 3).map((r: any) => {
      const content = r.content || '';
      // Get first meaningful line up to 120 chars
      const preview = content
        .split('\n')
        .filter((l: string) => l.trim().length > 0)
        .map((l: string) => l.trim())
        .join(' ')
        .slice(0, 120);

      return {
        id: (r.id || 'unknown').slice(0, 8),
        type: r.learning_type || r.type || 'UNKNOWN',
        content: preview + (content.length > 120 ? '...' : ''),
        score: r.score || 0
      };
    });

    return {
      count: validResults.length,
      results
    };
  } catch {
    return null;
  }
}

async function main() {
  const input: UserPromptSubmitInput = JSON.parse(readStdin());
  const projectDir = process.env.CLAUDE_PROJECT_DIR || input.cwd;

  // Skip for subagents - they don't need memory recall (saves tokens)
  if (process.env.CLAUDE_AGENT_ID) {
    return;
  }

  // Skip very short prompts (greetings, commands)
  if (input.prompt.length < 15) {
    return;
  }

  // Skip if prompt is just a slash command
  if (input.prompt.trim().startsWith('/')) {
    return;
  }

  // Extract intent (semantic query, not just keywords)
  const intent = extractIntent(input.prompt);

  // Skip if no meaningful intent
  if (intent.length < 3) {
    return;
  }

  // Check memory relevance using semantic search
  const match = checkMemoryRelevance(intent, projectDir);

  if (match) {
    // V4.3: Use context broker for trust-enforced assembly
    const sessionId = input.session_id || 'unknown';
    const broker = new ContextBroker();

    // Register each memory result as a context block
    for (const r of match.results) {
      // Create provenance metadata for this memory entry
      const provenance = createProvenance({
        session_id: r.session_id || sessionId, // Original session if available
        agent_id: null, // Memory recall doesn't have agent context
        trust_level: TrustLevel.Medium, // Database source, unsigned
        source_type: SourceType.Memory,
        content: r.content,
        // No signature available from recall query (read path V1.9 will validate)
      });

      // Format memory result with type and ID
      const formattedContent = `[${r.type}] ${r.content} (id: ${r.id})`;

      broker.register({
        source_type: SourceType.Memory,
        content: formattedContent,
        provenance,
        metadata: {
          memory_id: r.id,
          memory_type: r.type,
          score: r.score,
        },
      });
    }

    // Validate registered blocks
    const validation = broker.validate();
    if (!validation.valid) {
      // Log validation errors but continue with warnings
      logSecurityEvent(projectDir, {
        event: 'MEMORY_CONTEXT_VALIDATION_FAILED',
        errors: validation.errors,
        warnings: validation.warnings,
        timestamp: new Date().toISOString(),
      });
    }

    // Assemble context with trust markers
    const assembled = broker.assemble();

    // V4.7: Monitor and log security events
    monitorAssembledContext(assembled, sessionId, 'memory-awareness');

    // Build output with trust-aware context
    const claudeContext = `MEMORY MATCH (${match.count} results) for "${intent}":\n\n${assembled.formatted_output}\n\nUse /recall "${intent}" for full content. Disclose if helpful.`;

    // Include security events in output for monitoring
    const output: any = {
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: claudeContext
      }
    };

    // Attach security events if any were logged
    if (assembled.security_events.length > 0) {
      output.securityEvents = assembled.security_events;
    }

    console.log(JSON.stringify(output));
  }
}

main().catch(() => {
  // Silent fail - don't block user prompts
});
