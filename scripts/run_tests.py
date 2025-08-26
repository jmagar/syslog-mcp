#!/usr/bin/env python3
"""
Comprehensive test runner for syslog-mcp with different test modes.

This script provides various testing modes:
- Unit tests only (fast, no external dependencies)
- Integration tests (requires Elasticsearch via testcontainers)
- Full test suite (all tests)
- Performance tests
- Security tests
- Coverage analysis
- Mutation testing

Usage:
    python scripts/run_tests.py --mode unit
    python scripts/run_tests.py --mode integration
    python scripts/run_tests.py --mode all --coverage
    python scripts/run_tests.py --mode performance
"""

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


class TestRunner:
    """Comprehensive test runner for syslog-mcp."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.test_dir = project_root / "tests"
        
    def run_command(self, cmd: List[str], capture_output: bool = False) -> subprocess.CompletedProcess:
        """Run a command and handle output."""
        print(f"🔧 Running: {' '.join(cmd)}")
        
        if capture_output:
            return subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
        else:
            return subprocess.run(cmd, cwd=self.project_root)
    
    def run_unit_tests(self, coverage: bool = False, verbose: bool = False) -> bool:
        """Run unit tests only (fast, minimal dependencies)."""
        print("🚀 Running unit tests...")
        
        cmd = ["uv", "run", "pytest"]
        
        # Test selection
        cmd.extend(["-m", "unit"])
        
        # Coverage options
        if coverage:
            cmd.extend([
                "--cov=syslog_mcp", 
                "--cov-report=term-missing", 
                "--cov-report=html"
            ])
        
        # Verbosity
        if verbose:
            cmd.append("-v")
        
        # Additional options
        cmd.extend([
            "--tb=short",
            "--durations=10",
            "tests/"
        ])
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_integration_tests(self, verbose: bool = False) -> bool:
        """Run integration tests (requires Elasticsearch)."""
        print("🐳 Running integration tests with real Elasticsearch...")
        
        # Check Docker availability
        docker_check = self.run_command(["docker", "--version"], capture_output=True)
        if docker_check.returncode != 0:
            print("❌ Docker is not available. Skipping integration tests.")
            return False
        
        cmd = ["uv", "run", "pytest"]
        
        # Test selection
        cmd.extend(["-m", "integration"])
        
        # Integration test specific options
        cmd.extend([
            "--tb=long",  # More detailed tracebacks for integration issues
            "--durations=20",  # Show slow tests
            "-x",  # Stop on first failure (integration tests are slow)
        ])
        
        if verbose:
            cmd.extend(["-v", "-s"])  # Also show print statements
        
        cmd.append("tests/integration/")
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_error_handling_tests(self, verbose: bool = False) -> bool:
        """Run error handling and edge case tests."""
        print("🛡️  Running error handling and edge case tests...")
        
        cmd = ["uv", "run", "pytest"]
        cmd.extend(["-m", "error_handling"])
        
        if verbose:
            cmd.append("-v")
        
        cmd.extend([
            "--tb=short",
            "tests/test_error_handling.py"
        ])
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_security_tests(self, verbose: bool = False) -> bool:
        """Run security-focused tests."""
        print("🔒 Running security tests...")
        
        cmd = ["uv", "run", "pytest"]
        cmd.extend(["-m", "security"])
        
        if verbose:
            cmd.append("-v")
        
        cmd.extend([
            "--tb=short",
            "tests/"
        ])
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_performance_tests(self, verbose: bool = False) -> bool:
        """Run performance benchmark tests."""
        print("⚡ Running performance tests...")
        
        cmd = ["uv", "run", "pytest"]
        cmd.extend(["-m", "performance"])
        
        # Performance test specific options
        cmd.extend([
            "--benchmark-only",  # Only run benchmarks
            "--benchmark-autosave",  # Save results
            "--benchmark-compare-fail=min:5%",  # Fail if performance degrades
        ])
        
        if verbose:
            cmd.append("-v")
        
        cmd.append("tests/")
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_all_tests(self, coverage: bool = False, verbose: bool = False) -> bool:
        """Run all tests (unit + integration + error handling)."""
        print("🎯 Running comprehensive test suite...")
        
        cmd = ["uv", "run", "pytest"]
        
        # Coverage options
        if coverage:
            cmd.extend([
                "--cov=syslog_mcp",
                "--cov-report=term-missing", 
                "--cov-report=html",
                "--cov-report=xml"
            ])
        
        # Verbosity
        if verbose:
            cmd.append("-v")
        
        # Additional options
        cmd.extend([
            "--tb=short",
            "--durations=20",
            "--maxfail=5",  # Stop after 5 failures
            "tests/"
        ])
        
        result = self.run_command(cmd)
        return result.returncode == 0
    
    def run_mutation_tests(self) -> bool:
        """Run mutation tests to verify test quality."""
        print("🧬 Running mutation tests...")
        
        cmd = ["uv", "run", "mutmut", "run"]
        result = self.run_command(cmd)
        
        if result.returncode == 0:
            # Show results
            show_cmd = ["uv", "run", "mutmut", "results"]
            self.run_command(show_cmd)
        
        return result.returncode == 0
    
    def check_test_environment(self) -> bool:
        """Check if test environment is properly set up."""
        print("🔍 Checking test environment...")
        
        issues = []
        
        # Check Python version
        if sys.version_info < (3, 11):
            issues.append("Python 3.11+ is required")
        
        # Check if uv is available
        uv_check = self.run_command(["uv", "--version"], capture_output=True)
        if uv_check.returncode != 0:
            issues.append("uv is not installed or not in PATH")
        
        # Check if dependencies are installed
        deps_check = self.run_command(["uv", "run", "python", "-c", "import pytest, faker, testcontainers"], capture_output=True)
        if deps_check.returncode != 0:
            issues.append("Test dependencies not installed. Run: uv sync --dev")
        
        # Check Docker for integration tests
        docker_check = self.run_command(["docker", "--version"], capture_output=True)
        if docker_check.returncode != 0:
            print("⚠️  Docker not available - integration tests will be skipped")
        
        if issues:
            print("❌ Test environment issues:")
            for issue in issues:
                print(f"   - {issue}")
            return False
        
        print("✅ Test environment is ready")
        return True
    
    def generate_test_report(self) -> None:
        """Generate a comprehensive test report."""
        print("📊 Generating test report...")
        
        # Generate HTML coverage report if available
        coverage_dir = self.project_root / ".cache" / "coverage" / "htmlcov"
        if coverage_dir.exists():
            print(f"📈 Coverage report available at: file://{coverage_dir}/index.html")
        
        # Show pytest cache info
        cache_dir = self.project_root / ".cache" / "pytest"
        if cache_dir.exists():
            print(f"🗂️  Pytest cache: {cache_dir}")
    
    def clean_test_artifacts(self) -> None:
        """Clean up test artifacts and caches."""
        print("🧹 Cleaning test artifacts...")
        
        artifacts = [
            ".cache/pytest",
            ".cache/coverage", 
            ".cache/mypy",
            ".cache/ruff",
            "htmlcov/",
            ".coverage*",
            "coverage.xml",
            ".mutmut-cache",
        ]
        
        for artifact in artifacts:
            artifact_path = self.project_root / artifact
            if artifact_path.exists():
                if artifact_path.is_dir():
                    import shutil
                    shutil.rmtree(artifact_path)
                    print(f"   Removed directory: {artifact}")
                else:
                    artifact_path.unlink()
                    print(f"   Removed file: {artifact}")
    
    def lint_and_typecheck(self) -> bool:
        """Run linting and type checking before tests."""
        print("📋 Running linting and type checking...")
        
        success = True
        
        # Run ruff
        print("   Running ruff...")
        ruff_result = self.run_command(["uv", "run", "ruff", "check", "syslog_mcp/"])
        if ruff_result.returncode != 0:
            success = False
        
        # Run mypy
        print("   Running mypy...")
        mypy_result = self.run_command(["uv", "run", "mypy", "syslog_mcp/"])
        if mypy_result.returncode != 0:
            success = False
        
        return success


def main():
    """Main entry point for test runner."""
    parser = argparse.ArgumentParser(description="Comprehensive test runner for syslog-mcp")
    
    parser.add_argument(
        "--mode",
        choices=["unit", "integration", "error", "security", "performance", "all", "mutation"],
        default="unit",
        help="Test mode to run (default: unit)"
    )
    
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="Include coverage analysis"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true", 
        help="Verbose output"
    )
    
    parser.add_argument(
        "--lint",
        action="store_true",
        help="Run linting and type checking before tests"
    )
    
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean test artifacts before running"
    )
    
    parser.add_argument(
        "--skip-env-check",
        action="store_true",
        help="Skip test environment check"
    )
    
    args = parser.parse_args()
    
    # Setup
    project_root = Path(__file__).parent.parent
    runner = TestRunner(project_root)
    
    # Environment check
    if not args.skip_env_check:
        if not runner.check_test_environment():
            print("❌ Environment check failed. Use --skip-env-check to bypass.")
            return 1
    
    # Clean artifacts if requested
    if args.clean:
        runner.clean_test_artifacts()
    
    # Linting and type checking
    if args.lint:
        if not runner.lint_and_typecheck():
            print("❌ Linting or type checking failed")
            return 1
    
    # Run tests based on mode
    start_time = time.time()
    success = False
    
    try:
        if args.mode == "unit":
            success = runner.run_unit_tests(coverage=args.coverage, verbose=args.verbose)
        
        elif args.mode == "integration":
            success = runner.run_integration_tests(verbose=args.verbose)
        
        elif args.mode == "error":
            success = runner.run_error_handling_tests(verbose=args.verbose)
        
        elif args.mode == "security":
            success = runner.run_security_tests(verbose=args.verbose)
        
        elif args.mode == "performance":
            success = runner.run_performance_tests(verbose=args.verbose)
        
        elif args.mode == "all":
            success = runner.run_all_tests(coverage=args.coverage, verbose=args.verbose)
        
        elif args.mode == "mutation":
            success = runner.run_mutation_tests()
        
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        return 130
    
    except Exception as e:
        print(f"❌ Test runner error: {e}")
        return 1
    
    # Results
    end_time = time.time()
    duration = end_time - start_time
    
    if success:
        print(f"\n✅ All tests passed! ({duration:.2f}s)")
        runner.generate_test_report()
        return 0
    else:
        print(f"\n❌ Some tests failed! ({duration:.2f}s)")
        return 1


if __name__ == "__main__":
    sys.exit(main())