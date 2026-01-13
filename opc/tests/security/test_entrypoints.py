"""
Tests for entry point validation.

These tests verify that all pyproject.toml entry points resolve to existing modules,
preventing the security vulnerabilities identified in issue #65:
- F1: Orphaned entry points enable import-path hijack (CVSS 7.7)
- F2: Dead CLI references enable binary takeover (CVSS 7.3)

Regression test for beads issue vv1 (27e8296).
"""

import tomllib
import unittest
from pathlib import Path


class TestEntryPoints(unittest.TestCase):
    """Tests that all pyproject.toml entry points resolve to existing modules."""

    @classmethod
    def setUpClass(cls):
        """Load pyproject.toml once for all tests."""
        # Find pyproject.toml relative to this file
        cls.repo_root = Path(__file__).parent.parent.parent  # opc/
        cls.pyproject_path = cls.repo_root / "pyproject.toml"

        if not cls.pyproject_path.exists():
            raise FileNotFoundError(f"pyproject.toml not found at {cls.pyproject_path}")

        with open(cls.pyproject_path, "rb") as f:
            cls.pyproject = tomllib.load(f)

    def test_all_script_entrypoints_resolvable(self):
        """All [project.scripts] entry points must resolve to existing modules.

        This prevents orphaned entry points that could be exploited via:
        - F1: Import-path hijack (attacker creates scripts/opc_cli.py)
        - ModuleNotFoundError at runtime (poor user experience)
        """
        scripts = self.pyproject.get("project", {}).get("scripts", {})

        unresolvable = []
        for name, entrypoint in scripts.items():
            # Entry point format: "module.path:function"
            if ":" in entrypoint:
                module_path = entrypoint.split(":")[0]
            else:
                module_path = entrypoint

            # Convert module path to file path
            # e.g., "runtime.harness" -> "runtime/harness.py" or "src/runtime/harness.py"
            rel_path = module_path.replace(".", "/") + ".py"

            # Check standard locations: direct, src/, and package directories
            possible_paths = [
                self.repo_root / rel_path,
                self.repo_root / "src" / rel_path,
            ]

            # Also check if it's a package with __init__.py
            pkg_path = module_path.replace(".", "/")
            possible_paths.extend([
                self.repo_root / pkg_path / "__init__.py",
                self.repo_root / "src" / pkg_path / "__init__.py",
            ])

            found = any(p.exists() for p in possible_paths)
            if not found:
                unresolvable.append(f"{name} -> {module_path}")

        if unresolvable:
            self.fail(
                f"Orphaned entry points detected (security risk - F1/F2):\n"
                f"  {chr(10).join('  ' + e for e in unresolvable)}\n"
                f"Either add the missing module or remove the entry point."
            )

    def test_no_orphaned_opc_entrypoint(self):
        """Specific regression test: 'opc' entry point must not exist.

        The opc CLI was archived but its entry point was left behind,
        creating an import-path hijack vulnerability (beads issue vv1).
        """
        scripts = self.pyproject.get("project", {}).get("scripts", {})

        self.assertNotIn(
            "opc",
            scripts,
            "Orphaned 'opc' entry point detected - security vulnerability F1"
        )

    def test_entrypoints_have_valid_format(self):
        """Entry points must be in valid format: 'module.path:function'."""
        scripts = self.pyproject.get("project", {}).get("scripts", {})

        invalid = []
        for name, entrypoint in scripts.items():
            # Must contain exactly one colon and have parts on both sides
            if ":" not in entrypoint:
                invalid.append(f"{name}: missing ':function' suffix")
            elif entrypoint.count(":") > 1:
                invalid.append(f"{name}: multiple ':' characters")
            else:
                module_path, func = entrypoint.split(":")
                if not module_path:
                    invalid.append(f"{name}: empty module path")
                if not func:
                    invalid.append(f"{name}: empty function name")
                if not func.isidentifier():
                    invalid.append(f"{name}: invalid function name '{func}'")

        if invalid:
            self.fail(
                f"Invalid entry point format(s):\n"
                f"  {chr(10).join('  ' + e for e in invalid)}"
            )


if __name__ == "__main__":
    unittest.main()
