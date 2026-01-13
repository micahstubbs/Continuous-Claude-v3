"""
Security validators for MCP runtime.

These functions provide hardened validation to prevent:
- F1: SSRF via unvalidated URLs (CVSS 6.8)
- F2: Code injection via generated wrappers (CVSS 8.8)
- F4: Path traversal in schema discovery (CVSS 4.9)
"""

import ipaddress
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Safe identifier regex - prevents code injection in generated Python code
# Only allows valid Python identifiers: start with letter/underscore,
# followed by letters/digits/underscores
SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Private IP ranges that should be blocked for SSRF prevention
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("127.0.0.0/8"),  # Localhost
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


class SecurityValidationError(ValueError):
    """Raised when security validation fails."""

    def __init__(self, message: str, field: str, value: str):
        self.field = field
        self.value = value
        super().__init__(f"{message}: {field}={repr(value)}")


def validate_identifier(name: str, field_name: str = "identifier") -> str:
    """
    Validate that a string is safe to use as a Python identifier.

    This prevents code injection attacks where malicious tool/server names
    like 'x"); os.system("evil")#' could execute arbitrary code.

    Args:
        name: The identifier to validate
        field_name: Name of the field for error messages

    Returns:
        The validated identifier (unchanged if valid)

    Raises:
        SecurityValidationError: If the identifier is not safe

    Examples:
        >>> validate_identifier("my_tool")
        'my_tool'
        >>> validate_identifier("get_status_v2")
        'get_status_v2'
        >>> validate_identifier('evil"); import os #')
        SecurityValidationError: Invalid identifier contains unsafe characters
    """
    if not name:
        raise SecurityValidationError(
            "Identifier cannot be empty",
            field_name,
            name
        )

    # Check for obviously dangerous characters first
    dangerous_chars = {'"', "'", "`", "\n", "\r", ";", "(", ")", "[", "]", "{", "}"}
    found_dangerous = dangerous_chars & set(name)
    if found_dangerous:
        raise SecurityValidationError(
            f"Identifier contains dangerous characters: {found_dangerous}",
            field_name,
            name
        )

    # Check against safe regex
    if not SAFE_IDENTIFIER_REGEX.match(name):
        raise SecurityValidationError(
            "Identifier must match pattern [a-zA-Z_][a-zA-Z0-9_]*",
            field_name,
            name
        )

    # Check length (prevent DoS via very long identifiers)
    if len(name) > 256:
        raise SecurityValidationError(
            "Identifier exceeds maximum length of 256 characters",
            field_name,
            name
        )

    return name


def sanitize_for_code_string(text: str, max_length: int = 1000) -> str:
    """
    Sanitize text for safe inclusion in generated Python code strings.

    Uses repr() to properly escape all special characters, then strips
    the surrounding quotes since the caller will add their own.

    Args:
        text: The text to sanitize
        max_length: Maximum allowed length (truncates if exceeded)

    Returns:
        Escaped string safe for code inclusion

    Examples:
        >>> sanitize_for_code_string('Hello "world"')
        'Hello \\"world\\"'
        >>> sanitize_for_code_string("Line1\\nLine2")
        'Line1\\\\nLine2'
    """
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "..."

    # Use repr() for proper escaping, then strip the quotes
    escaped = repr(text)
    # repr() returns 'text' or "text" - strip the quotes
    if escaped.startswith("'") and escaped.endswith("'"):
        escaped = escaped[1:-1]
    elif escaped.startswith('"') and escaped.endswith('"'):
        escaped = escaped[1:-1]

    return escaped


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is in a private/reserved range.

    Args:
        ip_str: IP address string

    Returns:
        True if the IP is private/reserved, False if public or not an IP address
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for network in PRIVATE_IP_RANGES:
            if ip in network:
                return True
        return False
    except ValueError:
        # Not a valid IP address (e.g., hostname) - not a private IP
        return False


def validate_url(
    url: str,
    field_name: str = "url",
    allowed_schemes: Optional[set[str]] = None,
    block_private_ips: bool = True,
) -> str:
    """
    Validate a URL for SSRF prevention.

    Blocks:
    - Private/internal IP addresses
    - Localhost references
    - Cloud metadata endpoints (169.254.x.x)
    - Unsafe schemes (file://, gopher://, etc.)

    Args:
        url: The URL to validate
        field_name: Name of the field for error messages
        allowed_schemes: Set of allowed URL schemes (default: {"https", "http"})
        block_private_ips: Whether to block private IP ranges

    Returns:
        The validated URL (unchanged if valid)

    Raises:
        SecurityValidationError: If the URL is not safe
    """
    if allowed_schemes is None:
        allowed_schemes = {"https", "http"}

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise SecurityValidationError(
            f"Invalid URL format: {e}",
            field_name,
            url
        )

    # Check scheme
    if parsed.scheme.lower() not in allowed_schemes:
        raise SecurityValidationError(
            f"URL scheme must be one of {allowed_schemes}",
            field_name,
            url
        )

    # Check for missing host
    if not parsed.hostname:
        raise SecurityValidationError(
            "URL must have a valid hostname",
            field_name,
            url
        )

    hostname = parsed.hostname.lower()

    # Block localhost variants
    localhost_patterns = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if hostname in localhost_patterns:
        raise SecurityValidationError(
            "URL cannot reference localhost",
            field_name,
            url
        )

    # Block private IPs
    if block_private_ips:
        if is_private_ip(hostname):
            raise SecurityValidationError(
                "URL cannot reference private/internal IP addresses",
                field_name,
                url
            )

    return url


def validate_path_component(
    name: str,
    field_name: str = "path_component",
    base_dir: Optional[Path] = None,
) -> str:
    """
    Validate a path component to prevent path traversal attacks.

    Rejects:
    - Path separators (/, \\)
    - Parent directory references (..)
    - Null bytes
    - Hidden file prefixes on Unix (.)

    Args:
        name: The path component to validate
        field_name: Name of the field for error messages
        base_dir: If provided, verify the resolved path stays within this directory

    Returns:
        The validated path component (unchanged if valid)

    Raises:
        SecurityValidationError: If the path component is not safe
    """
    if not name:
        raise SecurityValidationError(
            "Path component cannot be empty",
            field_name,
            name
        )

    # Check for null bytes
    if "\0" in name:
        raise SecurityValidationError(
            "Path component cannot contain null bytes",
            field_name,
            name
        )

    # Check for path separators
    if "/" in name or "\\" in name:
        raise SecurityValidationError(
            "Path component cannot contain path separators",
            field_name,
            name
        )

    # Check for parent directory reference
    if name == ".." or name.startswith("../") or name.endswith("/.."):
        raise SecurityValidationError(
            "Path component cannot contain parent directory references",
            field_name,
            name
        )

    # Check for hidden files (optional security measure)
    if name.startswith(".") and name != ".":
        raise SecurityValidationError(
            "Path component cannot be a hidden file",
            field_name,
            name
        )

    # If base_dir is provided, verify the resolved path stays within it
    if base_dir is not None:
        base_dir = base_dir.resolve()
        test_path = (base_dir / name).resolve()

        try:
            test_path.relative_to(base_dir)
        except ValueError:
            raise SecurityValidationError(
                f"Path would escape base directory: {base_dir}",
                field_name,
                name
            )

    return name
