/**
 * Cryptographic Signing Infrastructure
 *
 * Provides HMAC-SHA256 signing and verification for database entries to prevent
 * tampering and impersonation attacks.
 *
 * Security: CWE-345 (Insufficient Verification of Data Authenticity) mitigation
 * Audit: Round 2 V1 - Unauthenticated coordination/memory stores
 * Audit: Round 3 V1 - Persist session keys (CVSS 8.2)
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync } from 'fs';
import { dirname, join } from 'path';

// ============================================================================
// Key Persistence (R3-V1)
// ============================================================================

/**
 * Session key storage
 * Keys are persisted to file and loaded on startup
 */
const sessionKeys = new Map<string, Buffer>();

/**
 * Key file path - defaults to .claude/cache/session-keys.json
 * Can be overridden for testing via setKeyFilePath()
 */
let keyFilePath: string | null = null;

/**
 * Whether key persistence is initialized
 */
let keyPersistenceInitialized = false;

/**
 * Get the key file path, computing it lazily if needed
 */
function getKeyFilePath(): string {
    if (keyFilePath) {
        return keyFilePath;
    }
    const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
    return join(projectDir, '.claude', 'cache', 'session-keys.json');
}

/**
 * Set the key file path (for testing or configuration)
 * @param path - Absolute path to the key file
 */
export function setKeyFilePath(path: string | null): void {
    keyFilePath = path;
    keyPersistenceInitialized = false;
}

/**
 * Load session keys from persistent storage
 * Called automatically on first access; can be called explicitly to re-initialize
 *
 * R3-V1: Fail closed - if file exists but is corrupted, do not accept any keys
 *
 * @returns true if keys were loaded successfully, false if no file or error
 */
export function loadSessionKeys(): boolean {
    const filePath = getKeyFilePath();

    if (!existsSync(filePath)) {
        keyPersistenceInitialized = true;
        return false;
    }

    try {
        const data = readFileSync(filePath, 'utf8');
        const parsed = JSON.parse(data);

        // Validate structure
        if (!parsed || typeof parsed !== 'object' || !parsed.keys || typeof parsed.keys !== 'object') {
            // Corrupted file - fail closed, do not load any keys
            console.error('[crypto-signing] Key file corrupted: invalid structure');
            keyPersistenceInitialized = true;
            return false;
        }

        // Load keys
        for (const [sessionId, keyB64] of Object.entries(parsed.keys)) {
            if (typeof keyB64 === 'string') {
                try {
                    const key = Buffer.from(keyB64, 'base64');
                    // Validate key length (32 bytes expected)
                    if (key.length === 32) {
                        sessionKeys.set(sessionId, key);
                    }
                } catch {
                    // Skip invalid key entry
                }
            }
        }

        keyPersistenceInitialized = true;
        return sessionKeys.size > 0;
    } catch (err) {
        // File exists but cannot be read/parsed - fail closed
        console.error('[crypto-signing] Failed to load keys:', err instanceof Error ? err.message : 'unknown error');
        keyPersistenceInitialized = true;
        return false;
    }
}

/**
 * Persist session keys to storage
 * Sets file permissions to 0600 (owner read/write only)
 *
 * @returns true if keys were persisted successfully
 */
function persistSessionKeys(): boolean {
    const filePath = getKeyFilePath();

    try {
        // Ensure directory exists
        const dir = dirname(filePath);
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true, mode: 0o700 });
        }

        // Build key object
        const keys: Record<string, string> = {};
        for (const [sessionId, key] of sessionKeys.entries()) {
            keys[sessionId] = key.toString('base64');
        }

        const data = JSON.stringify({
            version: 1,
            created_at: new Date().toISOString(),
            keys,
        }, null, 2);

        // Write with restrictive permissions
        writeFileSync(filePath, data, { encoding: 'utf8', mode: 0o600 });

        // Ensure permissions are set (in case file existed with different perms)
        chmodSync(filePath, 0o600);

        return true;
    } catch (err) {
        console.error('[crypto-signing] Failed to persist keys:', err instanceof Error ? err.message : 'unknown error');
        return false;
    }
}

/**
 * Ensure key persistence is initialized (lazy loading)
 */
function ensureKeyPersistenceInitialized(): void {
    if (!keyPersistenceInitialized) {
        loadSessionKeys();
    }
}

/**
 * Generate a new session key for HMAC signing
 *
 * @param sessionId - Unique session identifier
 * @returns The generated key in base64 format
 */
export function generateSessionKey(sessionId: string): string {
    ensureKeyPersistenceInitialized();

    // Generate cryptographically secure 32-byte key
    const key = randomBytes(32);
    sessionKeys.set(sessionId, key);

    // Persist to storage
    persistSessionKeys();

    return key.toString('base64');
}

/**
 * Get an existing session key
 *
 * @param sessionId - Session identifier
 * @returns The session key buffer, or null if not found
 */
function getSessionKey(sessionId: string): Buffer | null {
    ensureKeyPersistenceInitialized();
    return sessionKeys.get(sessionId) || null;
}

/**
 * Sign data using HMAC-SHA256
 *
 * @param data - Data to sign (will be JSON stringified if object)
 * @param sessionId - Session identifier whose key will be used
 * @returns HMAC signature in base64 format
 * @throws Error if session key not found
 */
export function signEntry(data: unknown, sessionId: string): string {
    const key = getSessionKey(sessionId);
    if (!key) {
        throw new Error(`Session key not found for session: ${sessionId}`);
    }

    // Normalize data to string
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

    // Create HMAC-SHA256 signature
    const hmac = createHmac('sha256', key);
    hmac.update(dataStr, 'utf8');
    return hmac.digest('base64');
}

/**
 * Verify HMAC signature for data
 *
 * @param data - Data to verify (will be JSON stringified if object)
 * @param signature - Expected HMAC signature in base64
 * @param sessionId - Session identifier whose key will be used
 * @returns true if signature is valid, false otherwise
 */
export function verifyEntry(data: unknown, signature: string, sessionId: string): boolean {
    try {
        const key = getSessionKey(sessionId);
        if (!key) {
            return false;
        }

        // Normalize data to string
        const dataStr = typeof data === 'string' ? data : JSON.stringify(data);

        // Compute expected signature
        const hmac = createHmac('sha256', key);
        hmac.update(dataStr, 'utf8');
        const expectedSig = hmac.digest();

        // Parse provided signature
        const providedSig = Buffer.from(signature, 'base64');

        // Timing-safe comparison to prevent timing attacks
        if (expectedSig.length !== providedSig.length) {
            return false;
        }

        return timingSafeEqual(expectedSig, providedSig);
    } catch (err) {
        // Any error during verification (invalid base64, etc.) = invalid signature
        return false;
    }
}

/**
 * Sign database entry with metadata
 *
 * @param entry - Database entry object
 * @param sessionId - Session identifier
 * @returns Entry with added signature field
 */
export function signDatabaseEntry<T extends Record<string, unknown>>(
    entry: T,
    sessionId: string
): T & { signature: string } {
    // Create canonical representation for signing (exclude signature field)
    const { signature: _, ...dataToSign } = entry as T & { signature?: string };
    const sig = signEntry(dataToSign, sessionId);

    return {
        ...entry,
        signature: sig,
    };
}

/**
 * Verify database entry signature
 *
 * @param entry - Database entry with signature field
 * @param sessionId - Session identifier
 * @returns true if signature is valid, false otherwise
 */
export function verifyDatabaseEntry<T extends Record<string, unknown>>(
    entry: T & { signature?: string },
    sessionId: string
): boolean {
    if (!entry.signature) {
        return false;
    }

    const { signature, ...dataToVerify } = entry;
    return verifyEntry(dataToVerify, signature, sessionId);
}

/**
 * Revoke a session key (cleanup on session end)
 *
 * @param sessionId - Session identifier
 */
export function revokeSessionKey(sessionId: string): void {
    ensureKeyPersistenceInitialized();
    sessionKeys.delete(sessionId);
    persistSessionKeys();
}

/**
 * List all active session IDs (for debugging/monitoring)
 *
 * @returns Array of active session IDs
 */
export function getActiveSessions(): string[] {
    ensureKeyPersistenceInitialized();
    return Array.from(sessionKeys.keys());
}

// ============================================================================
// V3.7: Provenance Signing
// ============================================================================

/**
 * Provenance metadata structure (imported type reference)
 * Actual type is defined in provenance-types.ts to avoid circular dependencies
 */
interface ProvenanceForSigning {
    session_id: string;
    agent_id: string | null;
    timestamp: number;
    trust_level: string;
    source_type: string;
    content_hash: string;
    signature?: string;
    metadata?: Record<string, unknown>;
}

/**
 * Sign provenance metadata with content hash
 *
 * V3.7: Signs the provenance fields + content_hash to ensure integrity
 * of the entire context item. Uses the session key from the origin session.
 *
 * @param provenance - Provenance metadata to sign (without signature field)
 * @returns HMAC signature in base64 format
 * @throws Error if session key not found
 */
export function signProvenance(provenance: ProvenanceForSigning): string {
    const sessionId = provenance.session_id;

    // Extract canonical fields for signing (exclude signature itself)
    const { signature: _, metadata: __, ...coreFields } = provenance;

    // Create a deterministic string for signing
    const dataToSign = {
        session_id: coreFields.session_id,
        agent_id: coreFields.agent_id,
        timestamp: coreFields.timestamp,
        trust_level: coreFields.trust_level,
        source_type: coreFields.source_type,
        content_hash: coreFields.content_hash,
    };

    return signEntry(dataToSign, sessionId);
}

/**
 * Verify provenance metadata signature
 *
 * V3.7: Verifies that provenance + content_hash hasn't been tampered with.
 *
 * @param provenance - Provenance metadata with signature
 * @returns true if signature is valid, false otherwise
 */
export function verifyProvenance(provenance: ProvenanceForSigning): boolean {
    if (!provenance.signature) {
        return false;
    }

    const sessionId = provenance.session_id;

    // Extract canonical fields for verification (same order as signing)
    const dataToVerify = {
        session_id: provenance.session_id,
        agent_id: provenance.agent_id,
        timestamp: provenance.timestamp,
        trust_level: provenance.trust_level,
        source_type: provenance.source_type,
        content_hash: provenance.content_hash,
    };

    return verifyEntry(dataToVerify, provenance.signature, sessionId);
}

/**
 * Add signature to provenance metadata
 *
 * V3.7: Convenience function that creates a signed copy of provenance.
 *
 * @param provenance - Provenance metadata without signature
 * @returns Copy of provenance with signature field added
 */
export function signedProvenance<T extends ProvenanceForSigning>(
    provenance: T
): T & { signature: string } {
    const signature = signProvenance(provenance);
    return {
        ...provenance,
        signature,
    };
}
