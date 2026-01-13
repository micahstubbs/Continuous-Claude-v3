"""
SECURE REPLACEMENT for JSONL file discovery

Original vulnerability: Symlink/path escape in glob-based JSONL discovery
Location: opc/scripts/core/memory_daemon.py:231-242
CVSS 3.1: 6.1 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

Original code accepted any *.jsonl including symlinks, allowing path
redirection to arbitrary files.

Fix: Validate files are real files within the expected directory, reject
symlinks, and verify resolved paths stay within bounds.
"""

import re
from pathlib import Path
from typing import Iterator, Optional, Callable
import os


class FileValidationError(Exception):
    """Raised when file validation fails."""
    pass


def is_safe_path(file_path: Path, base_dir: Path) -> bool:
    """
    Check if a file path is safely within the base directory.

    Args:
        file_path: Path to validate
        base_dir: Base directory that file must be within

    Returns:
        True if file is safely within base_dir, False otherwise
    """
    try:
        # Resolve both paths to their real locations
        resolved_file = file_path.resolve()
        resolved_base = base_dir.resolve()

        # Check if file is within base directory
        # Use os.path.commonpath to properly handle path boundaries
        try:
            common = Path(os.path.commonpath([str(resolved_file), str(resolved_base)]))
            return common == resolved_base
        except ValueError:
            # Paths on different drives (Windows) or invalid
            return False
    except (OSError, RuntimeError):
        # Path resolution failed (broken symlink, permission denied, etc.)
        return False


def validate_jsonl_file(
    file_path: Path,
    base_dir: Path,
    reject_symlinks: bool = True,
    require_extension: str = ".jsonl",
) -> bool:
    """
    Validate that a JSONL file is safe to process.

    Security checks:
    1. File must exist
    2. File must be a regular file (not directory, device, etc.)
    3. File must not be a symlink (if reject_symlinks=True)
    4. Resolved path must be within base_dir
    5. File must have expected extension

    Args:
        file_path: Path to the file to validate
        base_dir: Base directory the file must be within
        reject_symlinks: If True, reject symbolic links
        require_extension: Required file extension (default: .jsonl)

    Returns:
        True if file passes all security checks
    """
    try:
        # Check if path exists without following symlinks
        if not file_path.exists():
            return False

        # Reject symlinks if configured
        is_symlink = file_path.is_symlink()
        if reject_symlinks and is_symlink:
            return False

        # Must be a regular file
        # If symlinks are allowed and this is a symlink, check the target (stat)
        # Otherwise check the file itself (lstat)
        import stat as stat_module
        if is_symlink and not reject_symlinks:
            # Follow symlink to check target
            stat_info = file_path.stat()
        else:
            # Check file directly
            stat_info = file_path.lstat()

        if not stat_module.S_ISREG(stat_info.st_mode):
            return False

        # Validate extension
        if require_extension and not file_path.name.endswith(require_extension):
            return False

        # Validate path is within base directory
        if not is_safe_path(file_path, base_dir):
            return False

        return True
    except (OSError, RuntimeError):
        return False


def secure_glob_jsonl(
    base_dir: Path,
    pattern: str = "*/*.jsonl",
    reject_symlinks: bool = True,
    sort_key: Optional[Callable[[Path], any]] = None,
    reverse: bool = False,
) -> Iterator[Path]:
    """
    Securely glob for JSONL files within a directory.

    This is a secure replacement for:
        sorted(base_dir.glob("*/*.jsonl"), key=lambda x: x.stat().st_mtime, reverse=True)

    Security improvements:
    1. Rejects symlinks by default
    2. Validates all paths are within base_dir
    3. Verifies files are regular files
    4. Uses safe stat operations

    Args:
        base_dir: Base directory to search within
        pattern: Glob pattern (default: "*/*.jsonl")
        reject_symlinks: If True, skip symbolic links
        sort_key: Optional sort key function (receives Path, returns sortable value)
        reverse: If True, reverse sort order

    Yields:
        Path objects for valid JSONL files

    Example:
        # Secure replacement for time-sorted glob
        for f in secure_glob_jsonl(
            jsonl_dir,
            sort_key=lambda x: x.stat().st_mtime,
            reverse=True
        ):
            ...
    """
    if not base_dir.exists() or not base_dir.is_dir():
        return

    # Collect valid files
    valid_files = []

    try:
        for file_path in base_dir.glob(pattern):
            if validate_jsonl_file(file_path, base_dir, reject_symlinks):
                valid_files.append(file_path)
    except (OSError, RuntimeError):
        # Glob failed (permission denied, etc.)
        return

    # Sort if requested
    if sort_key is not None:
        try:
            valid_files.sort(key=sort_key, reverse=reverse)
        except (OSError, RuntimeError):
            # Sort failed (file disappeared, permission denied)
            # Return unsorted rather than fail
            pass
    elif reverse:
        valid_files.reverse()

    yield from valid_files


def find_session_jsonl(
    base_dir: Path,
    session_id: str,
    match_mode: str = "exact_stem",
) -> Optional[Path]:
    """
    Find a JSONL file for a specific session ID.

    Secure replacement for session-based JSONL lookup that:
    1. Rejects symlinks
    2. Validates paths stay within base_dir
    3. Uses secure matching modes

    Args:
        base_dir: Base directory to search
        session_id: Session ID to find
        match_mode: How to match session ID:
            - "exact_stem": File stem must equal session_id (most secure)
            - "stem_prefix": File stem must start with session_id
            - "contains": session_id must be in filename (least secure, legacy)

    Returns:
        Path to matching JSONL file, or None if not found

    Security Notes:
        - "exact_stem" is most secure but may not work with all naming conventions
        - "contains" is vulnerable to collision attacks with crafted filenames
    """
    # Validate session_id format (basic UUID-like check)
    # UUIDs are 36 chars: 8-4-4-4-12 with hyphens
    # Short UUIDs might be 8-12 chars
    if not session_id or not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
        return None

    # Get files sorted by mtime (most recent first)
    for f in secure_glob_jsonl(
        base_dir,
        pattern="*/*.jsonl",
        reject_symlinks=True,
        sort_key=lambda x: x.stat().st_mtime,
        reverse=True,
    ):
        matched = False

        if match_mode == "exact_stem":
            matched = f.stem == session_id
        elif match_mode == "stem_prefix":
            matched = f.stem.startswith(session_id)
        elif match_mode == "contains":
            # Legacy mode - less secure but compatible
            matched = session_id in f.name
        else:
            raise ValueError(f"Unknown match_mode: {match_mode}")

        if matched:
            return f

    return None


def find_recent_jsonl(
    base_dir: Path,
    max_age_seconds: float = 600,  # 10 minutes default
    session_id: Optional[str] = None,
    match_mode: str = "contains",
) -> Optional[Path]:
    """
    Find the most recent JSONL file within an age threshold.

    This is a secure replacement for the mtime-based fallback:
        for f in sorted(jsonl_dir.glob("*/*.jsonl"),
                        key=lambda x: x.stat().st_mtime, reverse=True):
            if session_id in f.name or f.stem == session_id:
                jsonl_path = f
                break

    Args:
        base_dir: Base directory to search
        max_age_seconds: Maximum file age in seconds (default: 600 = 10 minutes)
        session_id: Optional session ID to match
        match_mode: How to match session ID (see find_session_jsonl)

    Returns:
        Path to matching JSONL file, or None if not found
    """
    import time

    now = time.time()

    for f in secure_glob_jsonl(
        base_dir,
        pattern="*/*.jsonl",
        reject_symlinks=True,
        sort_key=lambda x: x.stat().st_mtime,
        reverse=True,
    ):
        try:
            mtime = f.stat().st_mtime
            age = now - mtime

            # Skip files older than threshold
            if age > max_age_seconds:
                continue

            # If session_id specified, check for match
            if session_id:
                matched = False
                if match_mode == "exact_stem":
                    matched = f.stem == session_id
                elif match_mode == "stem_prefix":
                    matched = f.stem.startswith(session_id)
                elif match_mode == "contains":
                    matched = session_id in f.name or f.stem == session_id

                if matched:
                    return f
            else:
                # No session_id filter, return most recent
                return f

        except (OSError, RuntimeError):
            # File disappeared or permission denied
            continue

    return None
