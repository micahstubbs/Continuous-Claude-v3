/**
 * Agent Definition Validator
 *
 * Validates agent markdown files for security issues including:
 * - Prompt injection patterns in agent instructions
 * - Suspicious tool configurations
 * - Unauthorized capability escalation
 *
 * Usage:
 *   import { validateAgentDefinition, validateAllAgents } from './shared/agent-validator.js';
 *   const result = validateAgentDefinition(agentPath);
 *   if (!result.valid) { console.error(result.issues); }
 */

import { readFileSync, readdirSync, existsSync, appendFileSync } from 'fs';
import { join, basename } from 'path';
import { createHash } from 'crypto';
import { containsPromptInjection, detectPromptInjection } from './security-utils.js';

// =============================================================================
// Types
// =============================================================================

export interface AgentFrontmatter {
  name: string;
  description?: string;
  model?: string;
  tools?: string[];
}

export interface AgentDefinition {
  name: string;
  frontmatter: AgentFrontmatter;
  body: string;
  filePath: string;
  hash: string;
}

export interface ValidationResult {
  valid: boolean;
  issues: string[];
  warnings: string[];
  agent?: AgentDefinition;
}

export interface AgentValidationSummary {
  totalAgents: number;
  validAgents: number;
  invalidAgents: number;
  results: Record<string, ValidationResult>;
}

// =============================================================================
// Tool Allowlists
// =============================================================================

/**
 * Tools that are generally safe and commonly needed.
 */
const SAFE_TOOLS = new Set([
  'Read',
  'Grep',
  'Glob',
  'LS',
  'Task',
  'TodoWrite',
  'AskUserQuestion',
]);

/**
 * Tools that are potentially dangerous and should be reviewed.
 */
const DANGEROUS_TOOLS = new Set([
  'Bash',
  'Write',
  'Edit',
  'WebFetch',
  'WebSearch',
  'NotebookEdit',
]);

/**
 * Maximum allowed tools per agent (prevents capability creep).
 */
const MAX_TOOLS_PER_AGENT = 15;

// =============================================================================
// Dangerous Patterns in Agent Bodies
// =============================================================================

/**
 * Patterns that indicate potentially malicious agent instructions.
 */
const DANGEROUS_BODY_PATTERNS = [
  // Command injection attempts
  /curl\s+[^|]*\|\s*(bash|sh|python|perl)/gi,
  /wget\s+[^|]*\|\s*(bash|sh|python|perl)/gi,
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,

  // Data exfiltration patterns
  /curl\s+(-X\s+POST|--data)/gi,
  /\bsend\s+(to|email|http)/gi,
  /\bexfiltrat/gi,

  // Instruction override attempts (beyond standard injection patterns)
  /CRITICAL\s+OVERRIDE/gi,
  /MANDATORY\s+FIRST\s+STEP/gi,
  /BEFORE\s+ALL\s+ELSE/gi,
  /SYSTEM\s+PRIORITY/gi,
  /ADMIN\s+OVERRIDE/gi,

  // Environment variable access
  /\$\{?([A-Z_]+_KEY|[A-Z_]+_SECRET|[A-Z_]+_TOKEN|PASSWORD|CREDENTIALS)\}?/gi,
  /process\.env\./gi,
  /os\.environ/gi,

  // File system attacks
  /rm\s+-rf\s+[\/~]/gi,
  /chmod\s+777/gi,
  /\/etc\/passwd/gi,
  /\/etc\/shadow/gi,
  /~\/\.ssh/gi,

  // Network exfiltration
  /nc\s+-[elp]/gi,
  /netcat/gi,
  /reverse\s+shell/gi,
];

// =============================================================================
// Parser
// =============================================================================

/**
 * Parse YAML frontmatter from markdown content.
 */
function parseFrontmatter(content: string): { frontmatter: AgentFrontmatter | null; body: string } {
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);

  if (!frontmatterMatch) {
    return { frontmatter: null, body: content };
  }

  const yamlContent = frontmatterMatch[1];
  const body = frontmatterMatch[2];

  // Simple YAML parsing for known fields (avoid full YAML parser for security)
  const frontmatter: AgentFrontmatter = { name: '' };

  const nameMatch = yamlContent.match(/^name:\s*(.+)$/m);
  if (nameMatch) frontmatter.name = nameMatch[1].trim();

  const descMatch = yamlContent.match(/^description:\s*(.+)$/m);
  if (descMatch) frontmatter.description = descMatch[1].trim();

  const modelMatch = yamlContent.match(/^model:\s*(.+)$/m);
  if (modelMatch) frontmatter.model = modelMatch[1].trim();

  const toolsMatch = yamlContent.match(/^tools:\s*\[([^\]]+)\]$/m);
  if (toolsMatch) {
    frontmatter.tools = toolsMatch[1]
      .split(',')
      .map(t => t.trim())
      .filter(t => t.length > 0);
  }

  return { frontmatter, body };
}

// =============================================================================
// Validation Functions
// =============================================================================

/**
 * Validate a single agent definition file.
 */
export function validateAgentDefinition(filePath: string): ValidationResult {
  const issues: string[] = [];
  const warnings: string[] = [];

  // Check file exists
  if (!existsSync(filePath)) {
    return {
      valid: false,
      issues: [`Agent file not found: ${filePath}`],
      warnings: [],
    };
  }

  // Read and parse
  let content: string;
  try {
    content = readFileSync(filePath, 'utf-8');
  } catch (err) {
    return {
      valid: false,
      issues: [`Failed to read agent file: ${err}`],
      warnings: [],
    };
  }

  const { frontmatter, body } = parseFrontmatter(content);

  if (!frontmatter || !frontmatter.name) {
    issues.push('Missing or invalid frontmatter (name required)');
  }

  const agentName = frontmatter?.name || basename(filePath, '.md');

  // Calculate content hash
  const hash = createHash('sha256').update(content).digest('hex').slice(0, 16);

  // Check for prompt injection in body
  if (containsPromptInjection(body)) {
    const patterns = detectPromptInjection(body);
    issues.push(`Prompt injection patterns detected: ${patterns.slice(0, 3).join(', ')}`);
  }

  // Check for dangerous patterns in body
  for (const pattern of DANGEROUS_BODY_PATTERNS) {
    if (pattern.test(body)) {
      issues.push(`Dangerous pattern detected: ${pattern.source}`);
    }
  }

  // Validate tools
  if (frontmatter?.tools) {
    // Check tool count
    if (frontmatter.tools.length > MAX_TOOLS_PER_AGENT) {
      warnings.push(`Agent has ${frontmatter.tools.length} tools (max recommended: ${MAX_TOOLS_PER_AGENT})`);
    }

    // Check for dangerous tools
    const dangerousUsed = frontmatter.tools.filter(t => DANGEROUS_TOOLS.has(t));
    if (dangerousUsed.length > 0) {
      warnings.push(`Agent uses potentially dangerous tools: ${dangerousUsed.join(', ')}`);
    }

    // Check for unknown tools (could be typos or injection attempts)
    const knownTools = new Set([...SAFE_TOOLS, ...DANGEROUS_TOOLS]);
    const unknownTools = frontmatter.tools.filter(t => !knownTools.has(t));
    if (unknownTools.length > 0) {
      warnings.push(`Agent references unknown tools: ${unknownTools.join(', ')}`);
    }
  }

  // Check for hidden content (HTML comments that could contain instructions)
  const htmlComments = body.match(/<!--[\s\S]*?-->/g);
  if (htmlComments && htmlComments.length > 0) {
    // Check if comments contain suspicious content
    for (const comment of htmlComments) {
      if (containsPromptInjection(comment)) {
        issues.push('HTML comment contains potential injection payload');
        break;
      }
    }
  }

  // Check for base64 encoded content (potential obfuscation)
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g;
  const base64Matches = body.match(base64Pattern);
  if (base64Matches && base64Matches.length > 2) {
    warnings.push('Agent contains multiple base64-like strings (potential obfuscation)');
  }

  const agent: AgentDefinition = {
    name: agentName,
    frontmatter: frontmatter || { name: agentName },
    body,
    filePath,
    hash,
  };

  return {
    valid: issues.length === 0,
    issues,
    warnings,
    agent,
  };
}

/**
 * Validate all agents in the .claude/agents directory.
 */
export function validateAllAgents(projectDir: string): AgentValidationSummary {
  const agentsDir = join(projectDir, '.claude', 'agents');
  const results: Record<string, ValidationResult> = {};

  if (!existsSync(agentsDir)) {
    return {
      totalAgents: 0,
      validAgents: 0,
      invalidAgents: 0,
      results: {},
    };
  }

  let validCount = 0;
  let invalidCount = 0;

  const files = readdirSync(agentsDir).filter(f => f.endsWith('.md'));

  for (const file of files) {
    const filePath = join(agentsDir, file);
    const result = validateAgentDefinition(filePath);
    results[file] = result;

    if (result.valid) {
      validCount++;
    } else {
      invalidCount++;
    }
  }

  return {
    totalAgents: files.length,
    validAgents: validCount,
    invalidAgents: invalidCount,
    results,
  };
}

/**
 * Log agent validation results to security audit log.
 */
export function logAgentValidation(projectDir: string, summary: AgentValidationSummary): void {
  try {
    const logPath = join(projectDir, '.claude', 'security-audit.log');
    const event = {
      event: 'AGENT_VALIDATION',
      timestamp: new Date().toISOString(),
      totalAgents: summary.totalAgents,
      validAgents: summary.validAgents,
      invalidAgents: summary.invalidAgents,
      issues: Object.entries(summary.results)
        .filter(([_, r]) => !r.valid)
        .map(([name, r]) => ({ agent: name, issues: r.issues })),
    };
    appendFileSync(logPath, JSON.stringify(event) + '\n', { flag: 'a' });
  } catch {
    // Silent fail
  }
}

// =============================================================================
// Hash Management (for integrity verification)
// =============================================================================

export interface AgentHashes {
  version: string;
  generated: string;
  agents: Record<string, string>;
}

/**
 * Generate hash file for current agent definitions.
 */
export function generateAgentHashes(projectDir: string): AgentHashes {
  const summary = validateAllAgents(projectDir);
  const agents: Record<string, string> = {};

  for (const [name, result] of Object.entries(summary.results)) {
    if (result.agent) {
      agents[name] = result.agent.hash;
    }
  }

  return {
    version: '1.0.0',
    generated: new Date().toISOString(),
    agents,
  };
}

/**
 * Verify agents against known hashes.
 */
export function verifyAgentHashes(
  projectDir: string,
  knownHashes: AgentHashes
): { verified: string[]; modified: string[]; new: string[]; missing: string[] } {
  const current = generateAgentHashes(projectDir);

  const verified: string[] = [];
  const modified: string[] = [];
  const newAgents: string[] = [];
  const missing: string[] = [];

  // Check current agents against known
  for (const [name, hash] of Object.entries(current.agents)) {
    if (knownHashes.agents[name]) {
      if (knownHashes.agents[name] === hash) {
        verified.push(name);
      } else {
        modified.push(name);
      }
    } else {
      newAgents.push(name);
    }
  }

  // Check for missing agents
  for (const name of Object.keys(knownHashes.agents)) {
    if (!current.agents[name]) {
      missing.push(name);
    }
  }

  return { verified, modified, new: newAgents, missing };
}

export default {
  validateAgentDefinition,
  validateAllAgents,
  logAgentValidation,
  generateAgentHashes,
  verifyAgentHashes,
};
