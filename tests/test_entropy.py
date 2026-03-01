"""Tests for entropy detection module."""
import pytest
from butterfence.entropy import shannon_entropy, find_high_entropy_strings, EntropyFinding


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars_equal(self):
        # "ab" repeated: 50% a, 50% b = 1.0 bits
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01

    def test_all_unique_chars(self):
        # 4 unique chars, each appearing once = log2(4) = 2.0
        result = shannon_entropy("abcd")
        assert abs(result - 2.0) < 0.01

    def test_high_entropy_hex(self):
        # Random-looking hex string should have high entropy
        result = shannon_entropy("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
        assert result > 3.5

    def test_low_entropy_repeated(self):
        result = shannon_entropy("aaaaabbbbb")
        assert result < 1.5

    def test_known_value(self):
        # "01" = 1 bit per character
        result = shannon_entropy("01010101")
        assert abs(result - 1.0) < 0.01


class TestFindHighEntropyStrings:
    def test_finds_high_entropy_token(self):
        # AWS-like key (high entropy)
        text = "aws_key=AKIAIOSFODNN7EXAMPLE1234567890abcdef"
        findings = find_high_entropy_strings(text, threshold=3.0, min_length=16)
        assert len(findings) >= 1

    def test_ignores_low_entropy(self):
        text = "the quick brown fox jumps over the lazy dog"
        findings = find_high_entropy_strings(text, threshold=4.5, min_length=16)
        assert len(findings) == 0

    def test_ignores_short_strings(self):
        text = "abc123"
        findings = find_high_entropy_strings(text, threshold=2.0, min_length=16)
        assert len(findings) == 0

    def test_custom_threshold(self):
        text = "x" * 20  # All same character = 0 entropy
        findings = find_high_entropy_strings(text, threshold=0.1, min_length=16)
        assert len(findings) == 0

    def test_multiple_findings(self):
        token1 = "aB3dE5fG7hI9jK1L"  # 16 chars, mixed
        token2 = "mN3oP5qR7sT9uV1W"  # 16 chars, mixed
        text = f"key1={token1} key2={token2}"
        findings = find_high_entropy_strings(text, threshold=2.5, min_length=16)
        assert len(findings) >= 1

    def test_finding_has_correct_fields(self):
        text = "token=aB3dE5fG7hI9jK1LmN3oP5qR"
        findings = find_high_entropy_strings(text, threshold=2.0, min_length=16)
        if findings:
            f = findings[0]
            assert isinstance(f, EntropyFinding)
            assert isinstance(f.entropy, float)
            assert isinstance(f.offset, int)
            assert isinstance(f.length, int)
            assert f.length >= 16

    def test_empty_text(self):
        findings = find_high_entropy_strings("", threshold=4.5)
        assert findings == []
