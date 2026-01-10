/**
 * Session Start Agent Validation Hook
 *
 * Validates all agent definitions in .claude/agents/ at session start.
 * Logs warnings for any agents with security issues.
 * Does NOT block session start - just warns.
 *
 * Security benefits:
 * - Detects prompt injection in agent definitions
 * - Identifies suspicious tool configurations
 * - Logs validation results for audit trail
 */

import { readFileSync } from 'fs';
import {
  validateAllAgents,
  logAgentValidation,
  type AgentValidationSummary,
} from './shared/agent-validator.js';

interface SessionStartInput {
  session_id: string;
  hook_event_name: string;
  cwd: string;
}

function readStdin(): string {
  return readFileSync(0, 'utf-8');
}

async function main() {
  const input: SessionStartInput = JSON.parse(readStdin());
  const projectDir = process.env.CLAUDE_PROJECT_DIR || input.cwd;

  // Skip for subagents to avoid redundant validation
  if (process.env.CLAUDE_AGENT_ID) {
    return;
  }

  // Validate all agents
  const summary: AgentValidationSummary = validateAllAgents(projectDir);

  // Log results to security audit log
  logAgentValidation(projectDir, summary);

  // Only output if there are issues
  if (summary.invalidAgents > 0) {
    const invalidList = Object.entries(summary.results)
      .filter(([_, r]) => !r.valid)
      .map(([name, r]) => `  • ${name}: ${r.issues.slice(0, 2).join('; ')}`)
      .join('\n');

    const warningOutput = [
      '⚠️ AGENT SECURITY WARNING',
      `Validated ${summary.totalAgents} agents: ${summary.invalidAgents} have issues`,
      '',
      'Agents with security issues:',
      invalidList,
      '',
      'Review .claude/security-audit.log for details.',
      'Consider reviewing/removing problematic agents.',
    ].join('\n');

    console.log(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: warningOutput,
      }
    }));
  } else if (summary.totalAgents > 0) {
    // Also report warnings (non-blocking issues)
    const warnings = Object.entries(summary.results)
      .filter(([_, r]) => r.warnings.length > 0)
      .flatMap(([name, r]) => r.warnings.map(w => `${name}: ${w}`));

    if (warnings.length > 0) {
      const warningOutput = [
        '📋 Agent Security Check',
        `${summary.totalAgents} agents validated, ${warnings.length} warnings`,
        '',
        'Warnings (non-blocking):',
        ...warnings.slice(0, 5).map(w => `  • ${w}`),
        warnings.length > 5 ? `  ... and ${warnings.length - 5} more` : '',
      ].filter(Boolean).join('\n');

      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'SessionStart',
          additionalContext: warningOutput,
        }
      }));
    }
  }
}

main().catch(() => {
  // Silent fail - don't block session start
});
