"""
Secure SQLite Connection Utilities

Provides secure SQLite connections with:
- 5000ms busy timeout to prevent lock contention errors
- WAL mode for better concurrent access
- Proper connection cleanup

Usage:
    from sqlite_utils import get_secure_connection

    conn = get_secure_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM table")
        # ... use results
    finally:
        conn.close()

Or with context manager:
    with get_secure_connection(db_path) as conn:
        cursor = conn.execute("SELECT * FROM table")
        # auto-closed on exit
"""

import sqlite3
from pathlib import Path
from typing import Optional
import os


# Default settings for concurrent access
DEFAULT_BUSY_TIMEOUT_MS = 5000  # 5 seconds
DEFAULT_JOURNAL_MODE = "WAL"


class SecureSQLiteConnection:
    """
    Context manager for secure SQLite connections.

    Automatically:
    - Sets busy_timeout to prevent SQLITE_BUSY errors
    - Enables WAL mode for better concurrent read/write
    - Creates parent directories if needed
    - Cleans up connection on exit
    """

    def __init__(
        self,
        db_path: str,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        journal_mode: str = DEFAULT_JOURNAL_MODE,
        create_dir: bool = True
    ):
        self.db_path = db_path
        self.busy_timeout_ms = busy_timeout_ms
        self.journal_mode = journal_mode
        self.create_dir = create_dir
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self) -> sqlite3.Connection:
        self.conn = get_secure_connection(
            self.db_path,
            busy_timeout_ms=self.busy_timeout_ms,
            journal_mode=self.journal_mode,
            create_dir=self.create_dir
        )
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
            self.conn = None
        return False  # Don't suppress exceptions


def get_secure_connection(
    db_path: str,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    journal_mode: str = DEFAULT_JOURNAL_MODE,
    create_dir: bool = True,
    row_factory: Optional[type] = None
) -> sqlite3.Connection:
    """
    Create a secure SQLite connection with proper concurrency settings.

    Args:
        db_path: Path to SQLite database file
        busy_timeout_ms: Milliseconds to wait on locks (default 5000)
        journal_mode: SQLite journal mode (default WAL for concurrency)
        create_dir: Create parent directory if it doesn't exist
        row_factory: Optional row factory (e.g., sqlite3.Row)

    Returns:
        sqlite3.Connection with security settings applied

    Example:
        conn = get_secure_connection("/path/to/db.sqlite")
        conn.execute("SELECT * FROM table")
        conn.close()
    """
    # Create parent directory if needed
    if create_dir:
        db_dir = Path(db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    # Create connection
    conn = sqlite3.connect(db_path)

    # Apply security settings
    conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
    conn.execute(f"PRAGMA journal_mode = {journal_mode}")

    # Set row factory if provided
    if row_factory:
        conn.row_factory = row_factory

    return conn


def init_database_wal(db_path: str) -> bool:
    """
    Initialize a database with WAL mode.

    Call this once when creating a new database to ensure
    WAL mode is set before any other connections open it.

    Args:
        db_path: Path to SQLite database file

    Returns:
        True if WAL mode was successfully set
    """
    try:
        conn = get_secure_connection(db_path)
        result = conn.execute("PRAGMA journal_mode").fetchone()
        conn.close()
        return result and result[0].upper() == "WAL"
    except Exception:
        return False


def retry_on_busy(
    func,
    max_retries: int = 3,
    base_delay_ms: int = 100
):
    """
    Decorator/wrapper for retrying operations that may hit SQLITE_BUSY.

    Uses exponential backoff: 100ms, 200ms, 400ms, etc.

    Args:
        func: Function that may raise sqlite3.OperationalError
        max_retries: Maximum retry attempts
        base_delay_ms: Initial delay in milliseconds

    Returns:
        Result of func() if successful

    Raises:
        Last exception if all retries fail
    """
    import time

    last_error = None
    for attempt in range(max_retries):
        try:
            return func()
        except sqlite3.OperationalError as e:
            if "database is locked" not in str(e).lower():
                raise  # Re-raise non-lock errors immediately

            last_error = e
            delay_s = (base_delay_ms * (2 ** attempt)) / 1000
            time.sleep(delay_s)

    raise last_error


# Convenience function matching the db-utils.ts pattern
def with_secure_connection(db_path: str, row_factory=None):
    """
    Create a context manager for secure SQLite connections.

    Usage:
        with with_secure_connection("/path/to/db.sqlite") as conn:
            cursor = conn.execute("SELECT * FROM table")
    """
    return SecureSQLiteConnection(
        db_path,
        create_dir=True
    )


if __name__ == "__main__":
    # Test the module
    import tempfile
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = os.path.join(tmpdir, "test.db")

        # Test context manager
        with SecureSQLiteConnection(test_db) as conn:
            conn.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO test (value) VALUES (?)", ("hello",))
            conn.commit()

            result = conn.execute("SELECT value FROM test").fetchone()
            assert result[0] == "hello", "Value mismatch"

            # Verify WAL mode is set
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            assert journal_mode.upper() == "WAL", f"Expected WAL, got {journal_mode}"

        print("All tests passed!")
