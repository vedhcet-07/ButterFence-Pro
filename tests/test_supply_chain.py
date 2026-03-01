"""Tests for the supply chain attack scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from butterfence.supply_chain import (
    SupplyChainFinding,
    SupplyChainResult,
    _levenshtein,
    _load_known_packages,
    _parse_gemfile,
    _parse_go_mod,
    _parse_package_json,
    _parse_requirements_txt,
    check_typosquatting,
    scan_supply_chain,
    KNOWN_MALICIOUS,
)


# ---------------------------------------------------------------------------
# A. Levenshtein distance
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical(self) -> None:
        assert _levenshtein("hello", "hello") == 0

    def test_one_char_diff(self) -> None:
        assert _levenshtein("requests", "requsets") == 2
        assert _levenshtein("requests", "reqeusts") == 2

    def test_insertion(self) -> None:
        assert _levenshtein("flask", "flaask") == 1

    def test_deletion(self) -> None:
        assert _levenshtein("numpy", "nupy") == 1

    def test_substitution(self) -> None:
        assert _levenshtein("pandas", "pandaz") == 1

    def test_empty_strings(self) -> None:
        assert _levenshtein("", "") == 0
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "xyz") == 3

    def test_completely_different(self) -> None:
        assert _levenshtein("abc", "xyz") == 3


# ---------------------------------------------------------------------------
# B. Parsers
# ---------------------------------------------------------------------------

class TestParseRequirementsTxt:
    def test_basic_parsing(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28\nflask>=2.0\nnumpy\n", encoding="utf-8")
        result = _parse_requirements_txt(req_file)
        names = [name for name, _ in result]
        assert "requests" in names
        assert "flask" in names
        assert "numpy" in names

    def test_skips_comments_and_flags(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\n-r base.txt\nrequests\n\n", encoding="utf-8")
        result = _parse_requirements_txt(req_file)
        assert len(result) == 1
        assert result[0][0] == "requests"

    def test_handles_extras(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests[socks]>=2.0\n", encoding="utf-8")
        result = _parse_requirements_txt(req_file)
        assert result[0][0] == "requests"


class TestParsePackageJson:
    def test_parses_all_dep_types(self, tmp_path: Path) -> None:
        pkg = {
            "dependencies": {"express": "^4.0", "lodash": "^4.17"},
            "devDependencies": {"jest": "^29.0"},
        }
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps(pkg), encoding="utf-8")
        result = _parse_package_json(pkg_file)
        names = [name for name, _ in result]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

    def test_handles_empty_json(self, tmp_path: Path) -> None:
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text("{}", encoding="utf-8")
        result = _parse_package_json(pkg_file)
        assert result == []


class TestParseGoMod:
    def test_parses_require_block(self, tmp_path: Path) -> None:
        go_mod = tmp_path / "go.mod"
        go_mod.write_text(
            "module example.com/myapp\n\n"
            "go 1.21\n\n"
            "require (\n"
            "\tgithub.com/gin-gonic/gin v1.9.1\n"
            "\tgithub.com/go-sql-driver/mysql v1.7.1\n"
            ")\n",
            encoding="utf-8",
        )
        result = _parse_go_mod(go_mod)
        names = [name for name, _ in result]
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/go-sql-driver/mysql" in names


class TestParseGemfile:
    def test_parses_gems(self, tmp_path: Path) -> None:
        gemfile = tmp_path / "Gemfile"
        gemfile.write_text(
            'source "https://rubygems.org"\n\n'
            'gem "rails", "~> 7.0"\n'
            "gem 'puma'\n",
            encoding="utf-8",
        )
        result = _parse_gemfile(gemfile)
        names = [name for name, _ in result]
        assert "rails" in names
        assert "puma" in names


# ---------------------------------------------------------------------------
# C. Typosquatting detection
# ---------------------------------------------------------------------------

class TestCheckTyposquatting:
    def test_exact_match_is_safe(self) -> None:
        known = {"requests", "flask", "numpy"}
        is_sus, match = check_typosquatting("requests", known)
        assert is_sus is False

    def test_detects_typosquat(self) -> None:
        known = {"requests", "flask", "numpy"}
        is_sus, match = check_typosquatting("requets", known)
        assert is_sus is True
        assert match == "requests"

    def test_detects_known_malicious(self) -> None:
        known = {"lodash"}
        is_sus, _ = check_typosquatting("crossenv", known)
        assert is_sus is True

    def test_no_match_for_unique_name(self) -> None:
        known = {"requests", "flask"}
        is_sus, match = check_typosquatting("my-unique-internal-pkg-xyz", known)
        assert is_sus is False

    def test_close_distance_detected(self) -> None:
        known = {"numpy"}
        is_sus, match = check_typosquatting("numpi", known)
        assert is_sus is True
        assert match == "numpy"


# ---------------------------------------------------------------------------
# D. Known packages loader
# ---------------------------------------------------------------------------

class TestLoadKnownPackages:
    def test_loads_from_json_file(self, tmp_path: Path) -> None:
        data = {"pypi": ["requests", "flask"], "npm": ["express", "lodash"]}
        pkg_file = tmp_path / "known_packages.json"
        pkg_file.write_text(json.dumps(data), encoding="utf-8")
        result = _load_known_packages(tmp_path)
        assert "requests" in result
        assert "flask" in result
        assert "express" in result

    def test_falls_back_to_builtin(self) -> None:
        result = _load_known_packages(Path("/nonexistent/path"))
        assert len(result) > 0
        assert "requests" in result


# ---------------------------------------------------------------------------
# E. Full supply chain scan integration
# ---------------------------------------------------------------------------

class TestScanSupplyChain:
    def test_detects_known_malicious_in_requirements(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\ncrossenv\nflask\n", encoding="utf-8")
        result = scan_supply_chain(tmp_path)
        assert result.files_scanned == 1
        assert result.malicious_found >= 1
        malicious = [f for f in result.findings if f.severity == "critical"]
        assert any("crossenv" in f.package for f in malicious)

    def test_detects_typosquat_in_requirements(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requets\nnumpy\n", encoding="utf-8")
        result = scan_supply_chain(tmp_path)
        typosquats = [f for f in result.findings if "typosquat" in f.reason.lower() or "Possible" in f.reason]
        assert len(typosquats) >= 1
        assert typosquats[0].safe_alternative == "requests"

    def test_clean_project_has_no_findings(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\nnumpy\n", encoding="utf-8")
        result = scan_supply_chain(tmp_path)
        assert result.total_issues == 0

    def test_scans_package_json(self, tmp_path: Path) -> None:
        pkg = {"dependencies": {"expresss": "^4.0", "lodash": "^4.17"}}
        pkg_file = tmp_path / "package.json"
        pkg_file.write_text(json.dumps(pkg), encoding="utf-8")
        result = scan_supply_chain(tmp_path)
        assert result.files_scanned >= 1
        # "expresss" is a known malicious package
        suspicious = [f for f in result.findings if "expresss" in f.package]
        assert len(suspicious) >= 1

    def test_no_dep_files_returns_empty(self, tmp_path: Path) -> None:
        result = scan_supply_chain(tmp_path)
        assert result.files_scanned == 0
        assert result.total_issues == 0

    def test_result_properties(self) -> None:
        r = SupplyChainResult()
        assert r.total_issues == 0
        assert r.has_critical is False

        r.findings.append(SupplyChainFinding(
            package="bad", source_file="requirements.txt",
            severity="critical", reason="test",
        ))
        assert r.total_issues == 1
        assert r.has_critical is True


# ---------------------------------------------------------------------------
# F. Known malicious database
# ---------------------------------------------------------------------------

class TestKnownMalicious:
    def test_contains_pypi_entries(self) -> None:
        assert "crossenv" in KNOWN_MALICIOUS
        assert "setup-tools" in KNOWN_MALICIOUS

    def test_entries_have_required_fields(self) -> None:
        for name, info in KNOWN_MALICIOUS.items():
            assert "reason" in info, f"{name} missing reason"
            assert "safe" in info, f"{name} missing safe alternative"
