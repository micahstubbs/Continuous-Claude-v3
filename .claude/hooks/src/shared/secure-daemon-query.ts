/**
 * SECURE REPLACEMENT for queryDaemonSync function
 *
 * Original vulnerabilities:
 * - Line 415: Command injection via unescaped JSON in `echo '${input}' | nc -U`
 * - Line 401: Command injection via incomplete escaping in PowerShell
 * Location: .claude/hooks/src/daemon-client.ts:370-431
 *
 * Fix: Use Node.js native net module for socket communication
 * This completely eliminates shell command execution with user input.
 */

import * as net from 'net';
import { existsSync } from 'fs';

interface DaemonQuery {
    cmd: string;
    [key: string]: any;
}

interface DaemonResponse {
    status: string;
    indexing?: boolean;
    message?: string;
    error?: string;
    [key: string]: any;
}

interface ConnectionInfo {
    type: 'unix' | 'tcp';
    path?: string;      // Unix socket path
    host?: string;      // TCP host
    port?: number;      // TCP port
}

const QUERY_TIMEOUT = 5000; // 5 second timeout

/**
 * SECURE: Query daemon using native Node.js net module
 *
 * Security improvements:
 * 1. No shell execution - direct socket communication
 * 2. No command interpolation risks
 * 3. JSON serialization is handled safely by native methods
 * 4. Validates socket path exists before connecting
 */
export function queryDaemonSyncSecure(
    query: DaemonQuery,
    connInfo: ConnectionInfo
): DaemonResponse {
    return new Promise<DaemonResponse>((resolve) => {
        const timeout = setTimeout(() => {
            resolve({ status: 'error', error: 'timeout' });
        }, QUERY_TIMEOUT);

        try {
            const input = JSON.stringify(query);
            let socket: net.Socket;

            if (connInfo.type === 'unix') {
                // Validate socket path exists
                if (!connInfo.path || !existsSync(connInfo.path)) {
                    clearTimeout(timeout);
                    resolve({ status: 'unavailable', error: 'Socket not found' });
                    return;
                }

                // SECURE: Connect directly to Unix socket
                socket = net.createConnection({ path: connInfo.path });
            } else {
                // TCP connection
                if (!connInfo.host || !connInfo.port) {
                    clearTimeout(timeout);
                    resolve({ status: 'unavailable', error: 'Invalid TCP config' });
                    return;
                }

                // SECURE: Connect directly to TCP socket
                socket = net.createConnection({
                    host: connInfo.host,
                    port: connInfo.port,
                });
            }

            let responseData = '';

            socket.on('connect', () => {
                // SECURE: Write JSON directly to socket - no shell escaping needed
                socket.write(input + '\n');
            });

            socket.on('data', (data) => {
                responseData += data.toString();
                // Check for complete JSON response (ends with newline)
                if (responseData.includes('\n')) {
                    clearTimeout(timeout);
                    socket.end();
                    try {
                        resolve(JSON.parse(responseData.trim()));
                    } catch {
                        resolve({ status: 'error', error: 'Invalid JSON response' });
                    }
                }
            });

            socket.on('error', (err: NodeJS.ErrnoException) => {
                clearTimeout(timeout);
                if (err.code === 'ECONNREFUSED' || err.code === 'ENOENT') {
                    resolve({ status: 'unavailable', error: 'Daemon not running' });
                } else {
                    resolve({ status: 'error', error: err.message || 'Socket error' });
                }
            });

            socket.on('timeout', () => {
                clearTimeout(timeout);
                socket.destroy();
                resolve({ status: 'error', error: 'timeout' });
            });

            socket.setTimeout(QUERY_TIMEOUT);

        } catch (err: any) {
            clearTimeout(timeout);
            resolve({ status: 'error', error: err.message || 'Unknown error' });
        }
    }) as unknown as DaemonResponse;
}

/**
 * Synchronous wrapper using Node.js synchronous socket operations
 * For use in contexts where async is not available
 *
 * Note: This uses a child process but passes data via stdin/stdout,
 * NOT via shell command interpolation.
 */
import { spawnSync } from 'child_process';

export function queryDaemonSyncSecureSync(
    query: DaemonQuery,
    connInfo: ConnectionInfo
): DaemonResponse {
    try {
        const input = JSON.stringify(query);

        if (connInfo.type === 'unix') {
            if (!connInfo.path || !existsSync(connInfo.path)) {
                return { status: 'unavailable', error: 'Socket not found' };
            }

            // SECURE: Use socat with stdin input instead of echo
            // Data passed via stdin cannot escape to shell
            const result = spawnSync('socat', ['-', `UNIX-CONNECT:${connInfo.path}`], {
                input: input + '\n',
                encoding: 'utf-8',
                timeout: QUERY_TIMEOUT,
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            if (result.status !== 0 || result.error) {
                return { status: 'unavailable', error: 'Connection failed' };
            }

            return JSON.parse(result.stdout.trim());

        } else {
            // TCP: Use socat for TCP connection
            if (!connInfo.host || !connInfo.port) {
                return { status: 'unavailable', error: 'Invalid TCP config' };
            }

            const result = spawnSync('socat', ['-', `TCP:${connInfo.host}:${connInfo.port}`], {
                input: input + '\n',
                encoding: 'utf-8',
                timeout: QUERY_TIMEOUT,
                stdio: ['pipe', 'pipe', 'pipe'],
            });

            if (result.status !== 0 || result.error) {
                return { status: 'unavailable', error: 'Connection failed' };
            }

            return JSON.parse(result.stdout.trim());
        }

    } catch (err: any) {
        if (err.message?.includes('ECONNREFUSED') || err.message?.includes('ENOENT')) {
            return { status: 'unavailable', error: 'Daemon not running' };
        }
        return { status: 'error', error: err.message || 'Unknown error' };
    }
}

/**
 * Alternative: Use netcat with stdin input (if socat not available)
 * SECURE: Data passed via stdin, not shell interpolation
 */
export function queryDaemonSyncSecureNc(
    query: DaemonQuery,
    connInfo: ConnectionInfo
): DaemonResponse {
    try {
        if (connInfo.type !== 'unix' || !connInfo.path) {
            return { status: 'error', error: 'Only Unix sockets supported with nc' };
        }

        if (!existsSync(connInfo.path)) {
            return { status: 'unavailable', error: 'Socket not found' };
        }

        const input = JSON.stringify(query);

        // SECURE: Use spawnSync with stdin input
        // The JSON data is passed via stdin pipe, not interpolated into command
        const result = spawnSync('nc', ['-U', connInfo.path], {
            input: input + '\n',  // SECURE: passed via stdin
            encoding: 'utf-8',
            timeout: QUERY_TIMEOUT,
            stdio: ['pipe', 'pipe', 'pipe'],
        });

        if (result.status !== 0 || result.error) {
            return { status: 'unavailable', error: 'Connection failed' };
        }

        return JSON.parse(result.stdout.trim());

    } catch (err: any) {
        return { status: 'error', error: err.message || 'Unknown error' };
    }
}
