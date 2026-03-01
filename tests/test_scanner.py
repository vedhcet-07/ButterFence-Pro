"""Tests for repo scanner."""
import pytest
from pathlib import Path
from butterfence.scanner import scan_repo, ScanResult, ScanFinding, _is_binary

class TestScanner:
    def test_empty_directory(self, tmp_path):
        result = scan_repo(tmp_path)
        assert isinstance(result, ScanResult)
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_detects_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=value\n")
        result = scan_repo(tmp_path)
        env_findings = [f for f in result.findings if "Environment" in f.rule or ".env" in f.matched_text]
        assert len(env_findings) >= 1

    def test_detects_aws_key(self, tmp_path):
        code = tmp_path / "config.py"
        code.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = scan_repo(tmp_path)
        aws_findings = [f for f in result.findings if "AWS" in f.rule]
        assert len(aws_findings) >= 1

    def test_detects_private_key(self, tmp_path):
        key_file = tmp_path / "server.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----\n")
        result = scan_repo(tmp_path)
        key_findings = [f for f in result.findings if "Private" in f.rule or "PEM" in f.rule]
        assert len(key_findings) >= 1

    def test_skips_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        secret = git_dir / "config"
        secret.write_text("AKIAIOSFODNN7EXAMPLE\n")
        result = scan_repo(tmp_path)
        # Should not find the secret inside .git/
        git_findings = [f for f in result.findings if ".git/" in f.file]
        assert len(git_findings) == 0

    def test_skips_binary_files(self, tmp_path):
        binary = tmp_path / "image.png"
        binary.write_bytes(b"\x89PNG\x00\x00binary content")
        result = scan_repo(tmp_path)
        assert result.files_skipped >= 1

    def test_skips_large_files(self, tmp_path):
        large = tmp_path / "big.txt"
        large.write_bytes(b"x" * (2 * 1024 * 1024))
        result = scan_repo(tmp_path)
        assert result.files_skipped >= 1

    def test_respects_gitignore(self, tmp_path):
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("secret.txt\n")
        secret = tmp_path / "secret.txt"
        secret.write_text("AKIAIOSFODNN7EXAMPLE\n")
        result = scan_repo(tmp_path)
        secret_findings = [f for f in result.findings if f.file == "secret.txt"]
        assert len(secret_findings) == 0

    def test_clean_repo(self, tmp_path):
        safe = tmp_path / "main.py"
        safe.write_text("print('hello world')\n")
        result = scan_repo(tmp_path)
        assert result.files_scanned >= 1
        # Should have no critical/high findings from secret patterns
        secret_findings = [f for f in result.findings if f.severity in ("critical", "high")]
        assert len(secret_findings) == 0

    def test_scan_result_fields(self, tmp_path):
        (tmp_path / "test.py").write_text("print('hi')\n")
        result = scan_repo(tmp_path)
        assert hasattr(result, "findings")
        assert hasattr(result, "files_scanned")
        assert hasattr(result, "files_skipped")

    def test_is_binary(self, tmp_path):
        text = tmp_path / "text.txt"
        text.write_text("hello")
        assert _is_binary(text) is False

        binary = tmp_path / "bin.dat"
        binary.write_bytes(b"hello\x00world")
        assert _is_binary(binary) is True

    def test_entropy_detection(self, tmp_path):
        code = tmp_path / "config.py"
        # High entropy string that looks like a secret
        code.write_text('token = "aB3dE5fG7hI9jK1LmN3oP5qR7sT9uV1WxY3zA5bC7dE9fG"\n')
        result = scan_repo(tmp_path, entropy_threshold=3.5)
        entropy_findings = [f for f in result.findings if "entropy" in f.rule.lower()]
        assert len(entropy_findings) >= 1

    def test_finding_has_suggestion(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("SECRET=value\n")
        result = scan_repo(tmp_path)
        for f in result.findings:
            # All findings should have suggestions
            assert isinstance(f.suggestion, str)
