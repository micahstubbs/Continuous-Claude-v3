#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Auto-handoff stop hook - blocks stop if context is high.

SECURITY NOTES (F1/F2/F4 mitigations):
- Uses O_NOFOLLOW to reject symlink attacks
- Sanitizes filenames with pattern matching
- Validates files are regular files before reading
"""
import json
import sys
import os
import re
import tempfile
import stat

def sanitize_session_id(session_id: str) -> str:
    """Sanitize session ID to prevent path injection (F4)."""
    if not session_id:
        return ""
    # Keep only alphanumeric, underscore, hyphen
    sanitized = re.sub(r'[^A-Za-z0-9_-]', '', session_id)
    return sanitized[:64]  # Limit length

def safe_read_file(filepath: str) -> str | None:
    """Safely read a file with symlink protection (F1)."""
    try:
        # O_NOFOLLOW causes open to fail if path is a symlink
        fd = os.open(filepath, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            # Verify it's a regular file
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return None
            # Read content
            with os.fdopen(fd, 'r') as f:
                fd = -1  # fd ownership transferred
                return f.read()
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError:
        return None

def find_context_file(tmp_dir: str) -> str | None:
    """
    Find context percentage file securely (F2).

    Instead of glob, we check for expected session-based filename pattern.
    """
    session_id = os.environ.get('CLAUDE_SESSION_ID', '')
    if session_id:
        safe_id = sanitize_session_id(session_id)
        if safe_id:
            candidate = os.path.join(tmp_dir, f'claude-context-pct-{safe_id}.txt')
            if os.path.exists(candidate) and not os.path.islink(candidate):
                return candidate

    # Fallback: look for any context file but validate it carefully
    try:
        for entry in os.listdir(tmp_dir):
            if entry.startswith('claude-context-pct-') and entry.endswith('.txt'):
                # Validate filename pattern
                if not re.match(r'^claude-context-pct-[A-Za-z0-9_-]+\.txt$', entry):
                    continue
                filepath = os.path.join(tmp_dir, entry)
                # Skip symlinks
                if os.path.islink(filepath):
                    continue
                # Verify it's a regular file
                try:
                    st = os.stat(filepath)
                    if stat.S_ISREG(st.st_mode):
                        return filepath
                except OSError:
                    continue
    except OSError:
        pass
    return None

def main():
    data = json.load(sys.stdin)
    if data.get('stop_hook_active'):
        print('{}')
        sys.exit(0)

    tmp_dir = tempfile.gettempdir()
    ctx_file = find_context_file(tmp_dir)

    if ctx_file:
        content = safe_read_file(ctx_file)
        if content:
            try:
                pct = int(content.strip())
                if pct >= 85:
                    print(json.dumps({
                        "decision": "block",
                        "reason": f"Context at {pct}%. Run: /create_handoff"
                    }))
                    sys.exit(0)
            except ValueError:
                pass

    print('{}')

if __name__ == '__main__':
    main()
