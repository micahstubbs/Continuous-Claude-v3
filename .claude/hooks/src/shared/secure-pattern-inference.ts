/**
 * SECURE REPLACEMENT for runPatternInference function
 *
 * Original vulnerability: Command injection via triple-quote bypass
 * Location: .claude/hooks/src/skill-activation-prompt.ts:85-128
 *
 * Fix: Use spawnSync with stdin for user input instead of shell interpolation
 */

import { spawnSync } from 'child_process';
import { join } from 'path';
import { existsSync, writeFileSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import { randomBytes } from 'crypto';

// Pattern inference result from Python module
interface PatternInference {
    pattern: string;
    confidence: number;
    signals: string[];
    needs_clarification: boolean;
    clarification_probe: string | null;
    ambiguity_type: string | null;
    alternatives: string[];
    work_breakdown: string;
    work_breakdown_detailed: string;
}

/**
 * SECURE: Run pattern inference using the Python module.
 * Returns null if inference fails or module not available.
 *
 * Security improvements:
 * 1. Uses spawnSync with argument array (no shell interpolation)
 * 2. Passes prompt via stdin (cannot escape to shell)
 * 3. Uses temporary file with secure random name for script
 * 4. Validates script path exists before execution
 */
export function runPatternInferenceSecure(prompt: string, projectDir: string): PatternInference | null {
    try {
        const scriptPath = join(projectDir, 'scripts', 'agentica_patterns', 'pattern_inference.py');
        if (!existsSync(scriptPath)) {
            return null;
        }

        // Validate scriptPath is within projectDir (path traversal protection)
        const resolvedScript = require('path').resolve(scriptPath);
        const resolvedProject = require('path').resolve(projectDir);
        if (!resolvedScript.startsWith(resolvedProject)) {
            console.error('Security: Script path outside project directory');
            return null;
        }

        // Create a secure temporary Python wrapper script
        // This avoids any shell interpolation of user input
        const tempId = randomBytes(16).toString('hex');
        const wrapperPath = join(tmpdir(), `pattern-inference-${tempId}.py`);

        const wrapperScript = `
import sys
import json
import importlib.util

# Read prompt from stdin - SECURE: no shell escaping needed
prompt = sys.stdin.read()

# Direct import bypassing __init__.py
spec = importlib.util.spec_from_file_location(
    'pattern_inference',
    sys.argv[1]  # Script path passed as argument
)
pattern_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pattern_mod)

result = pattern_mod.infer_pattern(prompt)
output = result.to_dict()
output['work_breakdown_detailed'] = pattern_mod.generate_work_breakdown(result)
print(json.dumps(output))
`;

        writeFileSync(wrapperPath, wrapperScript, { mode: 0o600 });

        try {
            // SECURE: Use spawnSync with argument array
            // - No shell=true, no template string interpolation
            // - User input passed via stdin, not command line
            const result = spawnSync('uv', ['run', 'python', wrapperPath, scriptPath], {
                cwd: projectDir,
                encoding: 'utf-8',
                timeout: 5000,  // 5 second timeout
                input: prompt,  // SECURE: prompt passed via stdin
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            if (result.status !== 0) {
                return null;
            }

            return JSON.parse(result.stdout.trim()) as PatternInference;
        } finally {
            // Clean up temporary wrapper script
            try {
                unlinkSync(wrapperPath);
            } catch {
                // Ignore cleanup errors
            }
        }
    } catch (err) {
        // Pattern inference is optional - fail silently
        return null;
    }
}

/**
 * Alternative SECURE implementation using base64 encoding
 * Use this if stdin approach causes issues with the Python script
 */
export function runPatternInferenceSecureBase64(prompt: string, projectDir: string): PatternInference | null {
    try {
        const scriptPath = join(projectDir, 'scripts', 'agentica_patterns', 'pattern_inference.py');
        if (!existsSync(scriptPath)) {
            return null;
        }

        // Validate scriptPath is within projectDir
        const resolvedScript = require('path').resolve(scriptPath);
        const resolvedProject = require('path').resolve(projectDir);
        if (!resolvedScript.startsWith(resolvedProject)) {
            return null;
        }

        // SECURE: Base64 encode the prompt to avoid any escaping issues
        const promptBase64 = Buffer.from(prompt, 'utf-8').toString('base64');

        const tempId = randomBytes(16).toString('hex');
        const wrapperPath = join(tmpdir(), `pattern-inference-${tempId}.py`);

        const wrapperScript = `
import sys
import json
import base64
import importlib.util

# SECURE: Decode base64 prompt - no shell escaping possible
prompt = base64.b64decode(sys.argv[2]).decode('utf-8')

spec = importlib.util.spec_from_file_location(
    'pattern_inference',
    sys.argv[1]
)
pattern_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pattern_mod)

result = pattern_mod.infer_pattern(prompt)
output = result.to_dict()
output['work_breakdown_detailed'] = pattern_mod.generate_work_breakdown(result)
print(json.dumps(output))
`;

        writeFileSync(wrapperPath, wrapperScript, { mode: 0o600 });

        try {
            // SECURE: spawnSync with arguments array
            // promptBase64 is safe - only contains [A-Za-z0-9+/=]
            const result = spawnSync('uv', ['run', 'python', wrapperPath, scriptPath, promptBase64], {
                cwd: projectDir,
                encoding: 'utf-8',
                timeout: 5000,
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            if (result.status !== 0) {
                return null;
            }

            return JSON.parse(result.stdout.trim()) as PatternInference;
        } finally {
            try {
                unlinkSync(wrapperPath);
            } catch {
                // Ignore cleanup errors
            }
        }
    } catch (err) {
        return null;
    }
}
