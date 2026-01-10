/**
 * SECURE REPLACEMENT for ripgrepFallback function
 *
 * Original vulnerability: Command injection via incomplete pattern escaping
 * Location: .claude/hooks/src/smart-search-router.ts:96-114
 *
 * Original code only escaped double quotes and dollar signs, missing:
 * - Backticks: `command`
 * - Command substitution: $(command)
 * - Newlines that could break quoting
 *
 * Fix: Use spawnSync with argument array - no escaping needed
 */

import { spawnSync } from 'child_process';
import { resolve } from 'path';
import { existsSync } from 'fs';

interface TLDRSearchResult {
    file: string;
    line: number;
    content: string;
}

/**
 * SECURE: Ripgrep fallback for when daemon is unavailable.
 *
 * Security improvements:
 * 1. Uses spawnSync with argument array (no shell interpolation)
 * 2. No pattern escaping needed - data never touches shell
 * 3. Validates projectDir exists and is absolute path
 * 4. Limits output to prevent DoS
 */
export function ripgrepFallbackSecure(pattern: string, projectDir: string): TLDRSearchResult[] {
    try {
        // Validate projectDir is an existing absolute path
        const resolvedDir = resolve(projectDir);
        if (!existsSync(resolvedDir)) {
            return [];
        }

        // SECURE: spawnSync with argument array
        // Pattern is passed as an argument, not interpolated into shell command
        const result = spawnSync('rg', [
            pattern,           // SECURE: passed as argument, not shell-interpolated
            resolvedDir,       // Validated path
            '--type', 'py',
            '--line-number',
            '--max-count', '10',
            '--no-heading',    // Easier to parse
            '--color', 'never' // No ANSI codes in output
        ], {
            encoding: 'utf-8',
            timeout: 3000,
            stdio: ['pipe', 'pipe', 'pipe'],  // Capture stderr too
        });

        // Exit code 1 means no matches (not an error for rg)
        if (result.status !== 0 && result.status !== 1) {
            return [];
        }

        if (!result.stdout) {
            return [];
        }

        // Parse ripgrep output: file:line:content
        return result.stdout
            .trim()
            .split('\n')
            .filter(l => l)
            .slice(0, 10)
            .map(line => {
                const match = line.match(/^([^:]+):(\d+):(.*)$/);
                if (match) {
                    return {
                        file: match[1],
                        line: parseInt(match[2], 10),
                        content: match[3]
                    };
                }
                return { file: line, line: 0, content: '' };
            });
    } catch {
        return [];
    }
}

/**
 * SECURE: Generic grep-like search using ripgrep
 * Allows specifying file types and other options safely
 */
export function secureRipgrepSearch(
    pattern: string,
    searchPath: string,
    options: {
        fileType?: string;
        maxResults?: number;
        caseSensitive?: boolean;
        wholeWord?: boolean;
        timeout?: number;
    } = {}
): TLDRSearchResult[] {
    try {
        const resolvedPath = resolve(searchPath);
        if (!existsSync(resolvedPath)) {
            return [];
        }

        // Build argument array safely
        const args: string[] = [pattern, resolvedPath];

        if (options.fileType) {
            // Validate file type is alphanumeric
            if (/^[a-zA-Z0-9]+$/.test(options.fileType)) {
                args.push('--type', options.fileType);
            }
        }

        const maxResults = Math.min(options.maxResults || 10, 100);
        args.push('--max-count', String(maxResults));
        args.push('--line-number');
        args.push('--no-heading');
        args.push('--color', 'never');

        if (options.caseSensitive === false) {
            args.push('--ignore-case');
        }

        if (options.wholeWord) {
            args.push('--word-regexp');
        }

        const result = spawnSync('rg', args, {
            encoding: 'utf-8',
            timeout: options.timeout || 5000,
            stdio: ['pipe', 'pipe', 'pipe'],
        });

        if (result.status !== 0 && result.status !== 1) {
            return [];
        }

        if (!result.stdout) {
            return [];
        }

        return result.stdout
            .trim()
            .split('\n')
            .filter(l => l)
            .slice(0, maxResults)
            .map(line => {
                const match = line.match(/^([^:]+):(\d+):(.*)$/);
                if (match) {
                    return {
                        file: match[1],
                        line: parseInt(match[2], 10),
                        content: match[3]
                    };
                }
                return { file: line, line: 0, content: '' };
            });
    } catch {
        return [];
    }
}
