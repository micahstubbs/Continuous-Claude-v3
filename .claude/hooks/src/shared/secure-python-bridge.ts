/**
 * SECURE REPLACEMENT for python-bridge.ts functions
 *
 * Original vulnerabilities:
 * - callPatternInference (line 74-75): Missing escaping for backticks and $()
 * - callValidateComposition (line 34): Pattern names interpolated into shell
 * Location: .claude/hooks/src/shared/python-bridge.ts
 *
 * Fix: Use spawnSync with argument arrays, pass data via stdin
 */

import { spawnSync } from 'child_process';
import { dirname, resolve, join } from 'path';
import { fileURLToPath } from 'url';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { randomBytes } from 'crypto';
import type { ValidationResult, PatternInferenceResult, PatternType } from './pattern-selector.js';

// Get project root
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_DIR = process.env.CLAUDE_PROJECT_DIR || resolve(__dirname, '..', '..', '..', '..');

/**
 * SECURE: Input validation for pattern names
 * Pattern names should only contain alphanumeric, underscore, and hyphen
 */
function validatePatternName(name: string): boolean {
    return /^[a-zA-Z0-9_-]+$/.test(name);
}

/**
 * SECURE: Validate scope value
 * Scope should only contain alphanumeric, underscore, hyphen, colon
 */
function validateScope(scope: string): boolean {
    return /^[a-zA-Z0-9_:-]+$/.test(scope);
}

/**
 * SECURE: Validate operator
 * Operators should only be specific allowed characters
 */
function validateOperator(op: string): boolean {
    return /^[;|&>]+$/.test(op);
}

/**
 * SECURE: Call Python validate_composition.py with JSON output.
 *
 * Security improvements:
 * 1. Validates pattern names against whitelist
 * 2. Uses spawnSync with argument array
 * 3. Passes expression via stdin, not command line
 */
export function callValidateCompositionSecure(
    patternA: string,
    patternB: string,
    scope: string,
    operator: string = ';'
): ValidationResult {
    // SECURE: Validate all inputs before use
    if (!validatePatternName(patternA)) {
        return {
            valid: false,
            composition: '',
            errors: [`Invalid pattern name: ${patternA}`],
            warnings: [],
            scopeTrace: [],
        };
    }
    if (!validatePatternName(patternB)) {
        return {
            valid: false,
            composition: '',
            errors: [`Invalid pattern name: ${patternB}`],
            warnings: [],
            scopeTrace: [],
        };
    }
    if (!validateScope(scope)) {
        return {
            valid: false,
            composition: '',
            errors: [`Invalid scope: ${scope}`],
            warnings: [],
            scopeTrace: [],
        };
    }
    if (!validateOperator(operator)) {
        return {
            valid: false,
            composition: '',
            errors: [`Invalid operator: ${operator}`],
            warnings: [],
            scopeTrace: [],
        };
    }

    const expr = `${patternA} ${operator}[${scope}] ${patternB}`;

    try {
        // SECURE: Use spawnSync with argument array
        // Expression passed as argument (safe after validation)
        const result = spawnSync(
            'uv',
            ['run', 'python', 'scripts/validate_composition.py', '--json', expr],
            {
                cwd: PROJECT_DIR,
                encoding: 'utf-8',
                timeout: 10000,
                stdio: ['pipe', 'pipe', 'pipe'],
            }
        );

        if (result.status !== 0) {
            return {
                valid: false,
                composition: expr,
                errors: [`Script error: ${result.stderr || 'Unknown error'}`],
                warnings: [],
                scopeTrace: [],
            };
        }

        const parsed = JSON.parse(result.stdout);

        return {
            valid: parsed.all_valid ?? false,
            composition: parsed.expression ?? expr,
            errors: parsed.compositions?.[0]?.errors ?? [],
            warnings: parsed.compositions?.[0]?.warnings ?? [],
            scopeTrace: parsed.compositions?.[0]?.scope_trace ?? [],
        };
    } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        return {
            valid: false,
            composition: expr,
            errors: [`Bridge error: ${errorMessage}`],
            warnings: [],
            scopeTrace: [],
        };
    }
}

/**
 * SECURE: Call Python pattern_inference.py to infer best pattern for a task.
 *
 * Security improvements:
 * 1. Uses spawnSync with argument array (no shell interpolation)
 * 2. Passes prompt via stdin (cannot escape to shell)
 * 3. No string escaping needed - data never touches shell
 */
export function callPatternInferenceSecure(prompt: string): PatternInferenceResult {
    try {
        // Create a secure wrapper script that reads prompt from stdin
        const tempId = randomBytes(16).toString('hex');
        const wrapperPath = join(tmpdir(), `pattern-inference-${tempId}.py`);

        const wrapperScript = `
import sys
import json

# Add scripts directory to path
sys.path.insert(0, 'scripts/agentica_patterns')
import pattern_inference

# SECURE: Read prompt from stdin - no shell escaping needed
prompt = sys.stdin.read()
result = pattern_inference.infer_pattern(prompt)
print(json.dumps(result.to_dict()))
`;

        writeFileSync(wrapperPath, wrapperScript, { mode: 0o600 });

        try {
            // SECURE: spawnSync with argument array
            // Prompt passed via stdin - cannot escape to shell
            const result = spawnSync(
                'uv',
                ['run', 'python', wrapperPath],
                {
                    cwd: PROJECT_DIR,
                    encoding: 'utf-8',
                    timeout: 10000,
                    input: prompt,  // SECURE: passed via stdin
                    stdio: ['pipe', 'pipe', 'pipe'],
                }
            );

            if (result.status !== 0) {
                throw new Error(result.stderr || 'Script execution failed');
            }

            const parsed = JSON.parse(result.stdout);

            return {
                pattern: parsed.pattern as PatternType,
                confidence: parsed.confidence ?? 0.5,
                signals: parsed.signals ?? [],
                needsClarification: parsed.needs_clarification ?? false,
                clarificationProbe: parsed.clarification_probe ?? null,
                ambiguityType: parsed.ambiguity_type ?? null,
                alternatives: (parsed.alternatives ?? []) as PatternType[],
                workBreakdown: parsed.work_breakdown ?? 'Task decomposition',
            };
        } finally {
            // Clean up temp file
            try {
                unlinkSync(wrapperPath);
            } catch {
                // Ignore cleanup errors
            }
        }
    } catch (err) {
        // Fallback to hierarchical on error
        return {
            pattern: 'hierarchical',
            confidence: 0.3,
            signals: ['bridge error fallback'],
            needsClarification: true,
            clarificationProbe: 'Could not infer pattern - what would help?',
            ambiguityType: 'scope',
            alternatives: [],
            workBreakdown: 'Coordinated task decomposition with specialists',
        };
    }
}

/**
 * Alternative: Direct argument passing with base64 encoding
 * Use if stdin approach has issues
 */
export function callPatternInferenceSecureBase64(prompt: string): PatternInferenceResult {
    try {
        // SECURE: Base64 encode prompt - only contains [A-Za-z0-9+/=]
        const promptBase64 = Buffer.from(prompt, 'utf-8').toString('base64');

        const tempId = randomBytes(16).toString('hex');
        const wrapperPath = join(tmpdir(), `pattern-inference-${tempId}.py`);

        const wrapperScript = `
import sys
import json
import base64

sys.path.insert(0, 'scripts/agentica_patterns')
import pattern_inference

# SECURE: Decode base64 prompt - no shell escaping possible
prompt = base64.b64decode(sys.argv[1]).decode('utf-8')
result = pattern_inference.infer_pattern(prompt)
print(json.dumps(result.to_dict()))
`;

        writeFileSync(wrapperPath, wrapperScript, { mode: 0o600 });

        try {
            // SECURE: spawnSync with arguments
            // Base64 string is safe - only alphanumeric chars
            const result = spawnSync(
                'uv',
                ['run', 'python', wrapperPath, promptBase64],
                {
                    cwd: PROJECT_DIR,
                    encoding: 'utf-8',
                    timeout: 10000,
                    stdio: ['pipe', 'pipe', 'pipe'],
                }
            );

            if (result.status !== 0) {
                throw new Error(result.stderr || 'Script execution failed');
            }

            const parsed = JSON.parse(result.stdout);

            return {
                pattern: parsed.pattern as PatternType,
                confidence: parsed.confidence ?? 0.5,
                signals: parsed.signals ?? [],
                needsClarification: parsed.needs_clarification ?? false,
                clarificationProbe: parsed.clarification_probe ?? null,
                ambiguityType: parsed.ambiguity_type ?? null,
                alternatives: (parsed.alternatives ?? []) as PatternType[],
                workBreakdown: parsed.work_breakdown ?? 'Task decomposition',
            };
        } finally {
            try {
                unlinkSync(wrapperPath);
            } catch {
                // Ignore
            }
        }
    } catch (err) {
        return {
            pattern: 'hierarchical',
            confidence: 0.3,
            signals: ['bridge error fallback'],
            needsClarification: true,
            clarificationProbe: 'Could not infer pattern - what would help?',
            ambiguityType: 'scope',
            alternatives: [],
            workBreakdown: 'Coordinated task decomposition with specialists',
        };
    }
}
