"""Tests for command normalizer."""
import pytest
from butterfence.normalizer import normalize_command, split_commands


class TestNormalizeCommand:
    def test_collapse_whitespace(self):
        assert normalize_command("rm  -rf  /") == "rm -rf /"

    def test_strip_edges(self):
        assert normalize_command("  ls -la  ") == "ls -la"

    def test_tabs_to_spaces(self):
        assert normalize_command("rm\t-rf\t/") == "rm -rf /"

    def test_newlines_to_spaces(self):
        assert normalize_command("echo\nhello") == "echo hello"

    def test_already_normalized(self):
        assert normalize_command("git status") == "git status"

    def test_empty_string(self):
        assert normalize_command("") == ""


class TestSplitCommands:
    def test_semicolon(self):
        result = split_commands("echo hello; echo world")
        assert result == ["echo hello", "echo world"]

    def test_and_operator(self):
        result = split_commands("cd /tmp && ls")
        assert result == ["cd /tmp", "ls"]

    def test_or_operator(self):
        result = split_commands("test -f foo || echo missing")
        assert result == ["test -f foo", "echo missing"]

    def test_pipe(self):
        result = split_commands("cat file | grep pattern")
        assert result == ["cat file", "grep pattern"]

    def test_quoted_semicolon(self):
        result = split_commands('echo "hello; world"')
        assert len(result) == 1
        assert "hello; world" in result[0]

    def test_single_command(self):
        result = split_commands("ls -la")
        assert result == ["ls -la"]

    def test_empty_string(self):
        result = split_commands("")
        assert result == []

    def test_multiple_pipes(self):
        result = split_commands("cat file | grep foo | wc -l")
        assert len(result) == 3

    def test_mixed_operators(self):
        result = split_commands("a; b && c || d")
        assert len(result) == 4
