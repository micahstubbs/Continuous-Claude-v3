"""
Tests for secure_file_discovery.py

Tests the symlink rejection and path escape prevention for JSONL file discovery.
These tests verify the F2 vulnerability mitigation (CVSS 6.1).
"""

import os
import stat
import tempfile
import time
from pathlib import Path
from unittest import TestCase, skipIf
import unittest

# Add parent path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts" / "core"))

from secure_file_discovery import (
    is_safe_path,
    validate_jsonl_file,
    secure_glob_jsonl,
    find_session_jsonl,
    find_recent_jsonl,
)


class TestIsSafePath(TestCase):
    """Tests for is_safe_path function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_within_base_is_safe(self):
        """File within base directory should be safe."""
        test_file = self.base_dir / "test.jsonl"
        test_file.touch()
        self.assertTrue(is_safe_path(test_file, self.base_dir))

    def test_file_in_subdirectory_is_safe(self):
        """File in subdirectory of base should be safe."""
        subdir = self.base_dir / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.jsonl"
        test_file.touch()
        self.assertTrue(is_safe_path(test_file, self.base_dir))

    def test_file_outside_base_is_unsafe(self):
        """File outside base directory should be unsafe."""
        outside_dir = Path(self.temp_dir) / "outside"
        outside_dir.mkdir()
        test_file = outside_dir / "test.jsonl"
        test_file.touch()
        self.assertFalse(is_safe_path(test_file, self.base_dir))

    def test_traversal_path_is_unsafe(self):
        """Path with traversal components should be unsafe after resolution."""
        # Create file outside base
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.touch()

        # Try to access via traversal from inside base
        traversal_path = self.base_dir / ".." / "secret.jsonl"
        self.assertFalse(is_safe_path(traversal_path, self.base_dir))

    def test_symlink_to_outside_is_unsafe(self):
        """Symlink pointing outside base directory should be unsafe."""
        # Create file outside base
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.write_text('{"secret": true}')

        # Create symlink inside base pointing to outside file
        symlink = self.base_dir / "link.jsonl"
        symlink.symlink_to(outside_file)

        # Symlink resolves to outside - should be unsafe
        self.assertFalse(is_safe_path(symlink, self.base_dir))

    def test_symlink_within_base_is_safe(self):
        """Symlink pointing within base directory should be safe."""
        # Create real file inside base
        real_file = self.base_dir / "real.jsonl"
        real_file.write_text('{"data": true}')

        # Create symlink inside base pointing to real file
        symlink = self.base_dir / "link.jsonl"
        symlink.symlink_to(real_file)

        # Symlink resolves to inside - path itself is safe
        # (but symlinks may still be rejected by reject_symlinks option)
        self.assertTrue(is_safe_path(symlink, self.base_dir))


class TestValidateJsonlFile(TestCase):
    """Tests for validate_jsonl_file function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_valid_jsonl_file_passes(self):
        """Valid JSONL file should pass validation."""
        test_file = self.base_dir / "test.jsonl"
        test_file.write_text('{"valid": true}')
        self.assertTrue(validate_jsonl_file(test_file, self.base_dir))

    def test_symlink_rejected_by_default(self):
        """Symlinks should be rejected by default."""
        real_file = self.base_dir / "real.jsonl"
        real_file.write_text('{"data": true}')

        symlink = self.base_dir / "link.jsonl"
        symlink.symlink_to(real_file)

        self.assertFalse(validate_jsonl_file(symlink, self.base_dir))

    def test_symlink_allowed_when_configured(self):
        """Symlinks within base should be allowed when reject_symlinks=False."""
        real_file = self.base_dir / "real.jsonl"
        real_file.write_text('{"data": true}')

        symlink = self.base_dir / "link.jsonl"
        symlink.symlink_to(real_file)

        self.assertTrue(validate_jsonl_file(symlink, self.base_dir, reject_symlinks=False))

    def test_symlink_to_outside_rejected_even_when_symlinks_allowed(self):
        """Symlink to outside should fail even when reject_symlinks=False."""
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.write_text('{"secret": true}')

        symlink = self.base_dir / "escape.jsonl"
        symlink.symlink_to(outside_file)

        # Even with reject_symlinks=False, path escape should be detected
        self.assertFalse(validate_jsonl_file(symlink, self.base_dir, reject_symlinks=False))

    def test_wrong_extension_rejected(self):
        """File with wrong extension should be rejected."""
        test_file = self.base_dir / "test.json"  # .json not .jsonl
        test_file.write_text('{}')
        self.assertFalse(validate_jsonl_file(test_file, self.base_dir))

    def test_directory_rejected(self):
        """Directories should be rejected."""
        test_dir = self.base_dir / "notafile.jsonl"
        test_dir.mkdir()
        self.assertFalse(validate_jsonl_file(test_dir, self.base_dir))

    def test_nonexistent_file_rejected(self):
        """Nonexistent files should be rejected."""
        test_file = self.base_dir / "missing.jsonl"
        self.assertFalse(validate_jsonl_file(test_file, self.base_dir))

    def test_file_outside_base_rejected(self):
        """File outside base directory should be rejected."""
        outside_dir = Path(self.temp_dir) / "outside"
        outside_dir.mkdir()
        test_file = outside_dir / "test.jsonl"
        test_file.write_text('{}')
        self.assertFalse(validate_jsonl_file(test_file, self.base_dir))


class TestSecureGlobJsonl(TestCase):
    """Tests for secure_glob_jsonl function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_finds_valid_jsonl_files(self):
        """Should find valid JSONL files in subdirectories."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        file1 = subdir / "session1.jsonl"
        file1.write_text('{}')
        file2 = subdir / "session2.jsonl"
        file2.write_text('{}')

        results = list(secure_glob_jsonl(self.base_dir))
        self.assertEqual(len(results), 2)
        self.assertIn(file1, results)
        self.assertIn(file2, results)

    def test_excludes_symlinks(self):
        """Should exclude symlinked JSONL files."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        real_file = subdir / "real.jsonl"
        real_file.write_text('{}')
        symlink = subdir / "link.jsonl"
        symlink.symlink_to(real_file)

        results = list(secure_glob_jsonl(self.base_dir))
        self.assertEqual(len(results), 1)
        self.assertIn(real_file, results)
        self.assertNotIn(symlink, results)

    def test_excludes_path_escapes(self):
        """Should exclude files that resolve outside base."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()

        # Create file outside base
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.write_text('{"secret": true}')

        # Create symlink inside base pointing to outside
        escape_link = subdir / "escape.jsonl"
        escape_link.symlink_to(outside_file)

        # Create valid file for comparison
        valid_file = subdir / "valid.jsonl"
        valid_file.write_text('{}')

        results = list(secure_glob_jsonl(self.base_dir))
        self.assertEqual(len(results), 1)
        self.assertIn(valid_file, results)

    def test_sorts_by_mtime(self):
        """Should sort by mtime when sort_key provided."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()

        # Create files with different mtimes
        old_file = subdir / "old.jsonl"
        old_file.write_text('{}')
        time.sleep(0.1)
        new_file = subdir / "new.jsonl"
        new_file.write_text('{}')

        results = list(secure_glob_jsonl(
            self.base_dir,
            sort_key=lambda x: x.stat().st_mtime,
            reverse=True
        ))

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], new_file)  # Most recent first
        self.assertEqual(results[1], old_file)


class TestFindSessionJsonl(TestCase):
    """Tests for find_session_jsonl function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_finds_exact_stem_match(self):
        """Should find file with exact stem match."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        session_file = subdir / "abc123-def456.jsonl"
        session_file.write_text('{}')

        result = find_session_jsonl(self.base_dir, "abc123-def456", match_mode="exact_stem")
        self.assertEqual(result, session_file)

    def test_finds_contains_match(self):
        """Should find file with substring match in legacy mode."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        session_file = subdir / "session-abc123-data.jsonl"
        session_file.write_text('{}')

        result = find_session_jsonl(self.base_dir, "abc123", match_mode="contains")
        self.assertEqual(result, session_file)

    def test_rejects_invalid_session_id(self):
        """Should reject session IDs with invalid characters."""
        result = find_session_jsonl(self.base_dir, "../../../etc/passwd")
        self.assertIsNone(result)

    def test_rejects_empty_session_id(self):
        """Should reject empty session ID."""
        result = find_session_jsonl(self.base_dir, "")
        self.assertIsNone(result)

    def test_ignores_symlinks(self):
        """Should not return symlinked files."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        real_file = subdir / "other.jsonl"
        real_file.write_text('{}')
        symlink = subdir / "abc123.jsonl"
        symlink.symlink_to(real_file)

        result = find_session_jsonl(self.base_dir, "abc123", match_mode="exact_stem")
        self.assertIsNone(result)


class TestFindRecentJsonl(TestCase):
    """Tests for find_recent_jsonl function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_finds_recent_file(self):
        """Should find file within age threshold."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        recent_file = subdir / "recent.jsonl"
        recent_file.write_text('{}')

        result = find_recent_jsonl(self.base_dir, max_age_seconds=60)
        self.assertEqual(result, recent_file)

    def test_ignores_old_files(self):
        """Should ignore files older than threshold."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        old_file = subdir / "old.jsonl"
        old_file.write_text('{}')

        # Set mtime to 2 hours ago
        old_time = time.time() - 7200
        os.utime(old_file, (old_time, old_time))

        result = find_recent_jsonl(self.base_dir, max_age_seconds=60)
        self.assertIsNone(result)

    def test_filters_by_session_id(self):
        """Should filter by session ID when provided."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()
        match_file = subdir / "abc123.jsonl"
        match_file.write_text('{}')
        other_file = subdir / "other.jsonl"
        other_file.write_text('{}')

        result = find_recent_jsonl(
            self.base_dir,
            max_age_seconds=60,
            session_id="abc123",
            match_mode="exact_stem"
        )
        self.assertEqual(result, match_file)

    def test_ignores_symlinks(self):
        """Should not return symlinked files."""
        subdir = self.base_dir / "project1"
        subdir.mkdir()

        # Create outside file
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.write_text('{}')

        # Create symlink inside base
        symlink = subdir / "link.jsonl"
        symlink.symlink_to(outside_file)

        result = find_recent_jsonl(self.base_dir, max_age_seconds=60)
        self.assertIsNone(result)


class TestPathTraversalAttacks(TestCase):
    """
    Security tests for path traversal attack vectors.

    These tests verify the F2 vulnerability (CVSS 6.1) is properly mitigated.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir) / "base"
        self.base_dir.mkdir()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dotdot_traversal_blocked(self):
        """../sequences should be blocked."""
        attack_path = self.base_dir / ".." / "secret.jsonl"
        self.assertFalse(is_safe_path(attack_path, self.base_dir))

    def test_symlink_to_sensitive_file_blocked(self):
        """Symlink to /etc/passwd should be blocked."""
        subdir = self.base_dir / "project"
        subdir.mkdir()
        evil_link = subdir / "evil.jsonl"

        # Try to create symlink to sensitive file
        try:
            evil_link.symlink_to("/etc/passwd")
        except (OSError, PermissionError):
            self.skipTest("Cannot create symlink")

        # Should be rejected by validation
        self.assertFalse(validate_jsonl_file(evil_link, self.base_dir))

    def test_symlink_chain_escape_blocked(self):
        """Symlink chain escaping base should be blocked."""
        subdir = self.base_dir / "project"
        subdir.mkdir()

        # Create outside directory
        outside_dir = Path(self.temp_dir) / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.jsonl"
        secret_file.write_text('{"secret": true}')

        # Create symlink to outside directory
        link_to_outside = subdir / "escape"
        link_to_outside.symlink_to(outside_dir)

        # Try to access secret file through symlink
        escaped_path = link_to_outside / "secret.jsonl"

        # Should be blocked
        self.assertFalse(is_safe_path(escaped_path, self.base_dir))

    def test_multiple_symlink_hops_blocked(self):
        """Multiple symlink hops escaping base should be blocked."""
        subdir = self.base_dir / "project"
        subdir.mkdir()

        # Create outside file
        outside_file = Path(self.temp_dir) / "secret.jsonl"
        outside_file.write_text('{}')

        # Create chain: link1 -> link2 -> outside_file
        link2 = Path(self.temp_dir) / "link2"
        link2.symlink_to(outside_file)

        link1 = subdir / "link1.jsonl"
        link1.symlink_to(link2)

        # Should be blocked at validation
        self.assertFalse(validate_jsonl_file(link1, self.base_dir))

    def test_absolute_path_escape_blocked(self):
        """Absolute paths outside base should be blocked."""
        outside_file = Path("/tmp/test-secret.jsonl")
        try:
            outside_file.write_text('{}')
            self.assertFalse(validate_jsonl_file(outside_file, self.base_dir))
        finally:
            if outside_file.exists():
                outside_file.unlink()


if __name__ == "__main__":
    unittest.main(verbosity=2)
