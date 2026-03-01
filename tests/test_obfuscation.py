"""Tests for obfuscation detection."""
import pytest
from butterfence.obfuscation import (
    detect_base64_commands,
    detect_hex_escaping,
    detect_variable_indirection,
    detect_backtick_substitution,
    detect_obfuscation,
)


class TestBase64Detection:
    def test_detects_base64_pipe(self):
        text = "echo cm0gLXJmIC8= | base64 -d | sh"
        findings = detect_base64_commands(text)
        assert len(findings) >= 1
        assert findings[0].technique == "base64"
        assert "rm" in findings[0].decoded_text

    def test_detects_base64_decode_flag(self):
        text = "echo cm0gLXJmIC8= | base64 --decode | bash"
        findings = detect_base64_commands(text)
        assert len(findings) >= 1

    def test_no_false_positive(self):
        text = "echo hello world"
        findings = detect_base64_commands(text)
        assert len(findings) == 0


class TestHexEscaping:
    def test_detects_hex_sequence(self):
        text = r"\x72\x6d\x20\x2d\x72\x66"
        findings = detect_hex_escaping(text)
        assert len(findings) >= 1
        assert findings[0].technique == "hex_escape"
        assert "rm" in findings[0].decoded_text

    def test_no_single_hex(self):
        text = r"\x41"
        findings = detect_hex_escaping(text)
        assert len(findings) == 0  # Need 2+ sequences


class TestVariableIndirection:
    def test_detects_variable_usage(self):
        text = "cmd=rm; $cmd -rf /"
        findings = detect_variable_indirection(text)
        assert len(findings) >= 1
        assert findings[0].decoded_text == "rm"

    def test_no_false_positive(self):
        text = "echo hello world"
        findings = detect_variable_indirection(text)
        assert len(findings) == 0


class TestBacktickSubstitution:
    def test_detects_backticks(self):
        text = "`cat /etc/passwd`"
        findings = detect_backtick_substitution(text)
        assert len(findings) >= 1
        assert findings[0].decoded_text == "cat /etc/passwd"


class TestDetectObfuscation:
    def test_combines_all_detectors(self):
        text = "echo cm0= | base64 -d; cmd=ls; `whoami`"
        findings = detect_obfuscation(text)
        # Should find base64, variable, and backtick
        techniques = {f.technique for f in findings}
        assert "base64" in techniques
        assert "backtick_substitution" in techniques
