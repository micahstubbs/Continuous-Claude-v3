/**
 * Tests for Secure Path Validator
 *
 * Tests path traversal prevention (F3 vulnerability, CVSS 6.5)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, writeFileSync, symlinkSync, unlinkSync, rmdirSync, existsSync } from 'fs';
import { join, resolve } from 'path';
import {
  validateFilePath,
  validateTLDRPath,
  sanitizeFilePath,
  MAX_PATH_LENGTH,
} from '../shared/secure-path-validator.js';

// Test fixtures directory
const TEST_DIR = '/tmp/secure-path-test-' + Date.now();
const NESTED_DIR = join(TEST_DIR, 'nested', 'deep');
const TEST_FILE = join(TEST_DIR, 'test.txt');
const NESTED_FILE = join(NESTED_DIR, 'file.py');
const SYMLINK_INTERNAL = join(TEST_DIR, 'link-internal');
const SYMLINK_EXTERNAL = join(TEST_DIR, 'link-external');

describe('Secure Path Validator', () => {
  beforeAll(() => {
    // Create test directory structure
    mkdirSync(NESTED_DIR, { recursive: true });
    writeFileSync(TEST_FILE, 'test content');
    writeFileSync(NESTED_FILE, 'nested content');

    // Create symlinks
    symlinkSync(NESTED_FILE, SYMLINK_INTERNAL);
    symlinkSync('/etc/passwd', SYMLINK_EXTERNAL);
  });

  afterAll(() => {
    // Cleanup
    try {
      unlinkSync(SYMLINK_INTERNAL);
      unlinkSync(SYMLINK_EXTERNAL);
      unlinkSync(TEST_FILE);
      unlinkSync(NESTED_FILE);
      rmdirSync(join(NESTED_DIR));
      rmdirSync(join(TEST_DIR, 'nested'));
      rmdirSync(TEST_DIR);
    } catch {
      // Ignore cleanup errors
    }
  });

  // ===========================================================================
  // Basic Validation
  // ===========================================================================

  describe('Basic Validation', () => {
    it('should accept valid paths within baseDir', () => {
      const result = validateFilePath(TEST_FILE, { baseDir: TEST_DIR });
      expect(result.valid).toBe(true);
      expect(result.resolvedPath).toBe(resolve(TEST_FILE));
    });

    it('should accept relative paths within baseDir', () => {
      const result = validateFilePath('test.txt', { baseDir: TEST_DIR });
      expect(result.valid).toBe(true);
      expect(result.relativePath).toBe('test.txt');
    });

    it('should accept nested paths within baseDir', () => {
      const result = validateFilePath(NESTED_FILE, { baseDir: TEST_DIR });
      expect(result.valid).toBe(true);
      expect(result.relativePath).toBe('nested/deep/file.py');
    });

    it('should reject empty paths', () => {
      const result = validateFilePath('', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('required');
    });

    it('should reject null/undefined paths', () => {
      const result = validateFilePath(null as any, { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('required');
    });

    it('should reject non-existent files when mustExist is true', () => {
      const result = validateFilePath('/nonexistent/path.txt', {
        baseDir: TEST_DIR,
        mustExist: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('does not exist');
    });
  });

  // ===========================================================================
  // Path Traversal Prevention
  // ===========================================================================

  describe('Path Traversal Prevention', () => {
    it('should reject ../ sequences', () => {
      const result = validateFilePath('../../../etc/passwd', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('traversal');
    });

    it('should reject ../ in the middle of path', () => {
      const result = validateFilePath('nested/../../../etc/passwd', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('traversal');
    });

    it('should reject standalone ..', () => {
      const result = validateFilePath('..', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('traversal');
    });

    it('should reject trailing /..', () => {
      const result = validateFilePath('nested/deep/..', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('traversal');
    });

    it('should reject URL-encoded path traversal (%2e%2e)', () => {
      const result = validateFilePath('%2e%2e/%2e%2e/etc/passwd', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Encoded path traversal');
    });

    it('should reject double URL-encoded traversal (%252e%252e)', () => {
      const result = validateFilePath('%252e%252e/etc/passwd', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Encoded path traversal');
    });

    it('should reject absolute paths outside baseDir', () => {
      const result = validateFilePath('/etc/passwd', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('outside allowed directory');
    });
  });

  // ===========================================================================
  // Null Byte and Control Character Prevention
  // ===========================================================================

  describe('Null Byte and Control Character Prevention', () => {
    it('should reject paths with null bytes', () => {
      const result = validateFilePath('test.txt\x00.jpg', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Null byte');
    });

    it('should reject paths with control characters', () => {
      const result = validateFilePath('test\x1f.txt', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Control characters');
    });

    it('should reject paths with Unicode line separators (NEL)', () => {
      const result = validateFilePath('test\u0085.txt', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Unicode line separators');
    });

    it('should reject paths with Unicode line separator (LS)', () => {
      const result = validateFilePath('test\u2028.txt', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Unicode line separators');
    });

    it('should reject paths with Unicode paragraph separator (PS)', () => {
      const result = validateFilePath('test\u2029.txt', { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Unicode line separators');
    });
  });

  // ===========================================================================
  // Symlink Handling
  // ===========================================================================

  describe('Symlink Handling', () => {
    it('should allow symlinks pointing within baseDir', () => {
      const result = validateFilePath(SYMLINK_INTERNAL, {
        baseDir: TEST_DIR,
        allowSymlinks: true,
      });
      expect(result.valid).toBe(true);
      expect(result.isSymlink).toBe(true);
      expect(result.resolvedPath).toBe(resolve(NESTED_FILE));
    });

    it('should reject symlinks pointing outside baseDir', () => {
      const result = validateFilePath(SYMLINK_EXTERNAL, {
        baseDir: TEST_DIR,
        allowSymlinks: true,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('outside allowed directory');
    });

    it('should reject symlinks when allowSymlinks is false', () => {
      const result = validateFilePath(SYMLINK_INTERNAL, {
        baseDir: TEST_DIR,
        allowSymlinks: false,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Symlinks not allowed');
    });
  });

  // ===========================================================================
  // Allowed Paths
  // ===========================================================================

  describe('Allowed Paths', () => {
    it('should allow paths in explicitly allowed directories', () => {
      const result = validateFilePath('/tmp/other-dir/file.txt', {
        baseDir: TEST_DIR,
        allowedPaths: ['/tmp/other-dir'],
        mustExist: false,
      });
      // Note: file doesn't exist but mustExist is false
      expect(result.valid).toBe(true);
    });

    it('should reject paths not in any allowed directory', () => {
      const result = validateFilePath('/home/user/secret.txt', {
        baseDir: TEST_DIR,
        allowedPaths: ['/tmp/other-dir'],
        mustExist: false,
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('outside allowed directory');
    });
  });

  // ===========================================================================
  // Length Limits
  // ===========================================================================

  describe('Length Limits', () => {
    it('should reject paths exceeding MAX_PATH_LENGTH', () => {
      const longPath = 'a'.repeat(MAX_PATH_LENGTH + 1);
      const result = validateFilePath(longPath, { baseDir: TEST_DIR });
      expect(result.valid).toBe(false);
      expect(result.error).toContain('maximum length');
    });

    it('should accept paths at MAX_PATH_LENGTH', () => {
      // Create a path exactly at the limit (needs to be valid path structure)
      const basePath = join(TEST_DIR, 'x'.repeat(MAX_PATH_LENGTH - TEST_DIR.length - 2));
      const result = validateFilePath(basePath.substring(0, MAX_PATH_LENGTH), {
        baseDir: TEST_DIR,
        mustExist: false,
      });
      expect(result.valid).toBe(true);
    });
  });

  // ===========================================================================
  // validateTLDRPath
  // ===========================================================================

  describe('validateTLDRPath', () => {
    const originalEnv = process.env.CLAUDE_PROJECT_DIR;

    beforeAll(() => {
      process.env.CLAUDE_PROJECT_DIR = TEST_DIR;
    });

    afterAll(() => {
      if (originalEnv) {
        process.env.CLAUDE_PROJECT_DIR = originalEnv;
      } else {
        delete process.env.CLAUDE_PROJECT_DIR;
      }
    });

    it('should validate paths within CLAUDE_PROJECT_DIR', () => {
      const result = validateTLDRPath(TEST_FILE);
      expect(result.valid).toBe(true);
    });

    it('should reject paths outside CLAUDE_PROJECT_DIR', () => {
      const result = validateTLDRPath('/etc/passwd');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('outside allowed directory');
    });

    it('should require CLAUDE_PROJECT_DIR to be set', () => {
      const saved = process.env.CLAUDE_PROJECT_DIR;
      delete process.env.CLAUDE_PROJECT_DIR;

      const result = validateTLDRPath('/some/path');
      expect(result.valid).toBe(false);
      expect(result.error).toContain('CLAUDE_PROJECT_DIR not set');

      process.env.CLAUDE_PROJECT_DIR = saved;
    });

    it('should require file to exist', () => {
      const result = validateTLDRPath(join(TEST_DIR, 'nonexistent.txt'));
      expect(result.valid).toBe(false);
      expect(result.error).toContain('does not exist');
    });
  });

  // ===========================================================================
  // sanitizeFilePath
  // ===========================================================================

  describe('sanitizeFilePath', () => {
    it('should remove null bytes', () => {
      const sanitized = sanitizeFilePath('test\x00.txt');
      expect(sanitized).toBe('test.txt');
    });

    it('should remove control characters', () => {
      const sanitized = sanitizeFilePath('test\x1f\x7f.txt');
      expect(sanitized).toBe('test.txt');
    });

    it('should remove path traversal sequences', () => {
      const sanitized = sanitizeFilePath('../../../etc/passwd');
      expect(sanitized).toBe('etc/passwd');
    });

    it('should normalize multiple slashes', () => {
      const sanitized = sanitizeFilePath('path///to////file.txt');
      expect(sanitized).toBe('path/to/file.txt');
    });

    it('should return empty string for null/undefined', () => {
      expect(sanitizeFilePath(null as any)).toBe('');
      expect(sanitizeFilePath(undefined as any)).toBe('');
    });

    it('should remove Unicode line separators', () => {
      const sanitized = sanitizeFilePath('test\u0085\u2028\u2029.txt');
      expect(sanitized).toBe('test.txt');
    });
  });

  // ===========================================================================
  // Edge Cases
  // ===========================================================================

  describe('Edge Cases', () => {
    it('should handle paths with spaces', () => {
      const pathWithSpaces = join(TEST_DIR, 'path with spaces', 'file.txt');
      const result = validateFilePath(pathWithSpaces, {
        baseDir: TEST_DIR,
        mustExist: false,
      });
      expect(result.valid).toBe(true);
    });

    it('should handle paths with special characters', () => {
      const specialPath = join(TEST_DIR, 'file-name_with.special$chars.txt');
      const result = validateFilePath(specialPath, {
        baseDir: TEST_DIR,
        mustExist: false,
      });
      expect(result.valid).toBe(true);
    });

    it('should handle Unicode file names', () => {
      const unicodePath = join(TEST_DIR, '文件.txt');
      const result = validateFilePath(unicodePath, {
        baseDir: TEST_DIR,
        mustExist: false,
      });
      expect(result.valid).toBe(true);
    });

    it('should handle . (current directory)', () => {
      const result = validateFilePath('.', { baseDir: TEST_DIR });
      expect(result.valid).toBe(true);
      expect(result.resolvedPath).toBe(resolve(TEST_DIR));
    });

    it('should handle empty baseDir (uses cwd)', () => {
      const originalCwd = process.cwd();
      try {
        process.chdir(TEST_DIR);
        const result = validateFilePath('test.txt', { baseDir: '' });
        expect(result.valid).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
