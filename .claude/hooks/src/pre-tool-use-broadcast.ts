#!/usr/bin/env node
import { readFileSync, existsSync } from 'fs';
import { spawnSync } from 'child_process';
import { join } from 'path';
import { containsPromptInjection, sanitizeContent } from './shared/security-utils';
import {
  createProvenance,
  formatProvenance,
  TrustLevel,
  SourceType,
  type ProvenanceMetadata
} from './shared/provenance-types.js';
import { ContextBroker } from './shared/context-broker.js';
import { monitorAssembledContext } from './shared/context-broker-monitor.js';
import { verifyEntry } from './shared/crypto-signing.js';
import { validateSession } from './shared/session-registry.js';
import { logSecurityEvent, logError } from './shared/error-sanitizer.js';

interface PreToolUseInput {
    session_id: string;
    tool_name: string;
    tool_input: Record<string, unknown>;
}

interface HookOutput {
    result: 'continue' | 'block';
    message?: string;
}

// Safe ID pattern: alphanumeric with hyphens/underscores, 1-64 chars
// Blocks shell metacharacters, newlines, quotes, etc.
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

// Valid broadcast types (whitelist)
const VALID_BROADCAST_TYPES = ['started', 'done', 'progress', 'error', 'handoff', 'claim'];

/**
 * Sanitizes a broadcast payload to prevent injection attacks.
 * Returns a sanitized version of the payload or a safe placeholder.
 */
function sanitizeBroadcastPayload(payload: unknown): string {
    const jsonStr = JSON.stringify(payload);

    // Check for prompt injection patterns
    if (containsPromptInjection(jsonStr)) {
        // Log security event (but don't block - just sanitize)
        logSecurityEvent('INJECTION_DETECTED', 'pre-tool-use-broadcast', 'Broadcast payload contained suspicious content');
        return JSON.stringify({ sanitized: true, reason: 'potential_injection' });
    }

    // Limit payload size to prevent context flooding
    if (jsonStr.length > 1000) {
        return JSON.stringify({ truncated: true, preview: jsonStr.slice(0, 200) });
    }

    return jsonStr;
}

async function main() {
    const input = readFileSync(0, 'utf-8');
    // Parse input but don't assign to unused variable
    JSON.parse(input) as PreToolUseInput;

    // Check if we're in an agentica swarm
    const swarmId = process.env.SWARM_ID;
    if (!swarmId) {
        // Not in a swarm, continue normally
        console.log(JSON.stringify({ result: 'continue' }));
        return;
    }

    // Validate SWARM_ID format to prevent injection
    if (!SAFE_ID_PATTERN.test(swarmId)) {
        console.log(JSON.stringify({ result: 'continue' }));
        return;
    }

    const agentId = process.env.AGENT_ID || 'unknown';
    // Validate AGENT_ID format if provided
    if (agentId !== 'unknown' && !SAFE_ID_PATTERN.test(agentId)) {
        console.log(JSON.stringify({ result: 'continue' }));
        return;
    }

    // Query broadcasts table for this swarm
    const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
    const dbPath = join(projectDir, '.claude', 'cache',
                        'agentica-coordination', 'coordination.db');

    if (!existsSync(dbPath)) {
        console.log(JSON.stringify({ result: 'continue' }));
        return;
    }

    try {
        // Use Python to query SQLite with spawnSync for safety (no shell interpolation)
        const query = `
import sqlite3
import json
import sys

db_path = sys.argv[1]
swarm_id = sys.argv[2]
agent_id = sys.argv[3]

conn = sqlite3.connect(db_path)
# Set busy_timeout to prevent indefinite blocking (Finding 3: STARVATION_FINDINGS.md)
conn.execute("PRAGMA busy_timeout = 5000")
conn.execute("PRAGMA journal_mode = WAL")
conn.row_factory = sqlite3.Row
cursor = conn.execute('''
    SELECT sender_agent, broadcast_type, payload, created_at,
           origin_session, origin_agent, signature, timestamp
    FROM broadcasts
    WHERE swarm_id = ? AND sender_agent != ?
    ORDER BY created_at DESC
    LIMIT 10
''', (swarm_id, agent_id))

broadcasts = []
for row in cursor.fetchall():
    broadcasts.append({
        'sender': row['sender_agent'],
        'type': row['broadcast_type'],
        'payload': json.loads(row['payload']),
        'time': row['created_at'],
        'origin_session': row['origin_session'],
        'origin_agent': row['origin_agent'],
        'signature': row['signature'],
        'timestamp': row['timestamp']
    })

print(json.dumps(broadcasts))
`;

        // Use spawnSync with argument array to prevent command injection
        const result = spawnSync('python3', ['-c', query, dbPath, swarmId, agentId], {
            encoding: 'utf-8',
            maxBuffer: 1024 * 1024
        });

        if (result.status !== 0) {
            console.log(JSON.stringify({ result: 'continue' }));
            return;
        }

        const broadcasts = JSON.parse(result.stdout.trim() || '[]');

        // V1.8: Validate provenance for all broadcasts
        const validBroadcasts: any[] = [];
        const rejectedCount = { missing_provenance: 0, invalid_signature: 0, inactive_session: 0 };

        for (const b of broadcasts) {
            // Check if provenance fields exist
            if (!b.origin_session || !b.signature || !b.timestamp) {
                rejectedCount.missing_provenance++;
                logSecurityEvent('PROVENANCE_MISSING', 'pre-tool-use-broadcast', 'Broadcast missing provenance fields');
                continue;
            }

            // Verify origin_session is active
            const sessionValidation = validateSession(b.origin_session);
            if (!sessionValidation.valid) {
                rejectedCount.inactive_session++;
                logSecurityEvent('SESSION_INACTIVE', 'pre-tool-use-broadcast', 'Broadcast from inactive session');
                continue;
            }

            // Verify signature
            try {
                // Reconstruct signed content (must match write path format in db-utils.ts)
                const dataToVerify = {
                    swarm_id: swarmId,
                    sender_agent: b.sender,
                    broadcast_type: b.type,
                    payload: typeof b.payload === 'string' ? b.payload : JSON.stringify(b.payload),
                    timestamp: b.timestamp,
                    origin_session: b.origin_session,
                    origin_agent: b.origin_agent
                };

                const isValid = verifyEntry(dataToVerify, b.signature, b.origin_session);
                if (!isValid) {
                    rejectedCount.invalid_signature++;
                    logSecurityEvent('SIGNATURE_INVALID', 'pre-tool-use-broadcast', 'Broadcast signature verification failed');
                    continue;
                }

                // Broadcast is valid
                validBroadcasts.push(b);
            } catch (err) {
                rejectedCount.invalid_signature++;
                logSecurityEvent('VERIFICATION_FAILED', 'pre-tool-use-broadcast', 'Broadcast signature verification error');
                continue;
            }
        }

        // Log rejection summary if any broadcasts were rejected
        if (Object.values(rejectedCount).some(c => c > 0)) {
            logSecurityEvent('TRUST_VIOLATION', 'pre-tool-use-broadcast', 'Broadcast validation completed with rejections', {
                missing_provenance: rejectedCount.missing_provenance,
                invalid_signature: rejectedCount.invalid_signature,
                inactive_session: rejectedCount.inactive_session,
                accepted: validBroadcasts.length
            });
        }

        if (validBroadcasts.length > 0) {
            // V4.4: Use context broker for trust-enforced assembly
            const sessionId = input.session_id || 'unknown';
            const broker = new ContextBroker();

            // Register each valid broadcast as a context block
            for (const b of validBroadcasts) {
                // Validate sender matches safe pattern
                const sender = SAFE_ID_PATTERN.test(b.sender) ? b.sender : '[invalid-sender]';

                // Validate type against whitelist
                const type = VALID_BROADCAST_TYPES.includes(b.type?.toLowerCase())
                    ? b.type.toUpperCase()
                    : 'UNKNOWN';

                // Sanitize payload to prevent injection
                const safePayload = sanitizeBroadcastPayload(b.payload);

                // Create provenance metadata for this broadcast
                const provenance = createProvenance({
                    session_id: sessionId, // Current session receiving the broadcast
                    agent_id: b.sender, // Sender is the origin agent
                    trust_level: TrustLevel.Medium, // Database source, unsigned
                    source_type: SourceType.Broadcast,
                    content: safePayload,
                    // No signature available from query (V1.8 read path will validate)
                });

                // Format broadcast with type and sender
                const formattedContent = `[${type}] from ${sender}:\n  ${safePayload}`;

                broker.register({
                    source_type: SourceType.Broadcast,
                    content: formattedContent,
                    provenance,
                    metadata: {
                        sender_agent: b.sender,
                        broadcast_type: b.type,
                        created_at: b.time,
                    },
                });
            }

            // Validate registered blocks
            const validation = broker.validate();
            if (!validation.valid) {
                // Log validation errors - broadcasts may be poisoned
                logSecurityEvent('TRUST_VIOLATION', 'pre-tool-use-broadcast', 'Context broker validation failed');
            }

            // Assemble context with trust markers
            const assembled = broker.assemble();

            // V4.7: Monitor and log security events
            monitorAssembledContext(assembled, sessionId, 'pre-tool-use-broadcast');

            // Build output with trust-aware context
            const contextMessage = `\n--- SWARM BROADCASTS ---\n${assembled.formatted_output}------------------------\n`;

            const output: any = {
                result: 'continue',
                message: contextMessage
            };

            // Attach security events if any were logged
            if (assembled.security_events.length > 0) {
                output.securityEvents = assembled.security_events;
            }

            console.log(JSON.stringify(output));
        } else {
            console.log(JSON.stringify({ result: 'continue' }));
        }
    } catch (err) {
        // On error, continue without broadcasts
        logError('pre-tool-use-broadcast', err);
        console.log(JSON.stringify({ result: 'continue' }));
    }
}

main().catch(err => {
    logError('pre-tool-use-broadcast', err);
    console.log(JSON.stringify({ result: 'continue' }));
});
