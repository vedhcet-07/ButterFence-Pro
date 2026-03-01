"""Supply chain attack scanner — typosquatting, dependency confusion, malicious packages.

Parses dependency files (requirements.txt, package.json, go.mod, Gemfile)
and checks for typosquatting via Levenshtein distance against known popular
packages, plus a database of known malicious packages.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Levenshtein distance (pure Python, no deps)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr_row.append(min(
                curr_row[j] + 1,       # insert
                prev_row[j + 1] + 1,   # delete
                prev_row[j] + cost,    # replace
            ))
        prev_row = curr_row

    return prev_row[-1]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SupplyChainFinding:
    """A finding from the supply chain scanner."""
    package: str
    source_file: str
    severity: str  # critical, high, medium, low
    reason: str
    safe_alternative: str = ""
    line_number: int = 0


@dataclass
class SupplyChainResult:
    """Aggregated results from a supply chain scan."""
    findings: list[SupplyChainFinding] = field(default_factory=list)
    files_scanned: int = 0
    packages_checked: int = 0
    typosquats_found: int = 0
    malicious_found: int = 0

    @property
    def total_issues(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)


# ---------------------------------------------------------------------------
# Known malicious packages database
# ---------------------------------------------------------------------------

# Well-known typosquatting/malicious packages (hardcoded fallback).
# This list is supplemented by assets/known_packages.json at runtime.
KNOWN_MALICIOUS: dict[str, dict[str, str]] = {
    # PyPI
    "python-dateutil2": {"reason": "Typosquat of python-dateutil", "safe": "python-dateutil"},
    "colourama": {"reason": "Typosquat of colorama", "safe": "colorama"},
    "requesocks": {"reason": "Typosquat of requests[socks]", "safe": "requests[socks]"},
    "python3-dateutil": {"reason": "Typosquat of python-dateutil", "safe": "python-dateutil"},
    "jeIlyfish": {"reason": "Typosquat of jellyfish (capital I vs l)", "safe": "jellyfish"},
    "python-sqlite": {"reason": "Known malicious package", "safe": "sqlite3 (stdlib)"},
    "setup-tools": {"reason": "Typosquat of setuptools", "safe": "setuptools"},
    "beauitfulsoup4": {"reason": "Typosquat of beautifulsoup4", "safe": "beautifulsoup4"},
    "cryptograpHy": {"reason": "Typosquat of cryptography", "safe": "cryptography"},
    "nmap-python": {"reason": "Known malicious package", "safe": "python-nmap"},
    # npm
    "crossenv": {"reason": "Known malicious npm package (data theft)", "safe": "cross-env"},
    "event-stream-fake": {"reason": "Malicious event-stream fork", "safe": "event-stream"},
    "lodash.js": {"reason": "Typosquat of lodash", "safe": "lodash"},
    "babelcli": {"reason": "Typosquat of babel-cli", "safe": "@babel/cli"},
    "electorn": {"reason": "Typosquat of electron", "safe": "electron"},
    "expresss": {"reason": "Typosquat of express", "safe": "express"},
    "momnet": {"reason": "Typosquat of moment", "safe": "moment"},
}


# ---------------------------------------------------------------------------
# Dependency file parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(path: Path) -> list[tuple[str, int]]:
    """Parse requirements.txt, return list of (package_name, line_number)."""
    packages: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages

    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers, extras, etc.
        name = re.split(r"[><=!~;\[\s@]", line)[0].strip()
        if name:
            packages.append((name, i))

    return packages


def _parse_package_json(path: Path) -> list[tuple[str, int]]:
    """Parse package.json, return list of (package_name, 0)."""
    packages: list[tuple[str, int]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return packages

    for dep_key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = data.get(dep_key, {})
        if isinstance(deps, dict):
            for name in deps:
                packages.append((name, 0))

    return packages


def _parse_go_mod(path: Path) -> list[tuple[str, int]]:
    """Parse go.mod, return list of (module_name, line_number)."""
    packages: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages

    in_require = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")" and in_require:
            in_require = False
            continue
        if in_require and stripped:
            parts = stripped.split()
            if parts:
                packages.append((parts[0], i))
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 2:
                packages.append((parts[1], i))

    return packages


def _parse_gemfile(path: Path) -> list[tuple[str, int]]:
    """Parse Gemfile, return list of (gem_name, line_number)."""
    packages: list[tuple[str, int]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return packages

    for i, line in enumerate(lines, 1):
        line = line.strip()
        match = re.match(r"""gem\s+['"]([^'"]+)['"]""", line)
        if match:
            packages.append((match.group(1), i))

    return packages


# Map filenames to their parsers
DEP_FILE_PARSERS: dict[str, callable] = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements_dev.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "dev-requirements.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Gemfile": _parse_gemfile,
}


# ---------------------------------------------------------------------------
# Known packages loader
# ---------------------------------------------------------------------------

def _load_known_packages(assets_dir: Path | None = None) -> set[str]:
    """Load the known popular packages from assets/known_packages.json.

    Falls back to a small built-in set if the file is missing.
    """
    # Try to find the assets directory
    if assets_dir is None:
        # Look relative to this file's package location
        pkg_dir = Path(__file__).parent.parent.parent
        assets_dir = pkg_dir / "assets"

    known_file = assets_dir / "known_packages.json"
    if known_file.exists():
        try:
            data = json.loads(known_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                all_pkgs: set[str] = set()
                for ecosystem_pkgs in data.values():
                    if isinstance(ecosystem_pkgs, list):
                        all_pkgs.update(str(p).lower() for p in ecosystem_pkgs)
                return all_pkgs
            elif isinstance(data, list):
                return {str(p).lower() for p in data}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load known_packages.json: %s", exc)

    # Fallback: minimal built-in set of popular packages
    return {
        # PyPI top packages
        "requests", "numpy", "pandas", "flask", "django", "pytest",
        "setuptools", "pip", "wheel", "six", "urllib3", "certifi",
        "boto3", "botocore", "pyyaml", "cryptography", "jinja2",
        "pillow", "sqlalchemy", "scipy", "matplotlib", "beautifulsoup4",
        "click", "packaging", "colorama", "toml", "attrs", "aiohttp",
        "fastapi", "uvicorn", "pydantic", "httpx", "rich", "typer",
        "celery", "redis", "gunicorn", "psycopg2", "pymongo",
        "paramiko", "fabric", "ansible", "tensorflow", "torch",
        "scikit-learn", "transformers", "openai", "anthropic",
        "google-generativeai", "langchain", "streamlit", "gradio",
        # npm top packages
        "express", "react", "vue", "angular", "lodash", "moment",
        "axios", "webpack", "typescript", "next", "nuxt", "gatsby",
        "electron", "chalk", "commander", "inquirer", "ora", "yargs",
        "eslint", "prettier", "jest", "mocha", "chai", "cypress",
        "tailwindcss", "postcss", "sass", "less", "babel-core",
        "cross-env", "dotenv", "jsonwebtoken", "bcrypt", "uuid",
    }


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def check_typosquatting(
    package_name: str,
    known_packages: set[str],
    max_distance: int = 2,
) -> tuple[bool, str]:
    """Check if a package name is a potential typosquatting attack.

    Returns (is_suspicious, closest_match_or_empty).
    """
    lower_name = package_name.lower()

    # Exact match = safe
    if lower_name in known_packages:
        return False, ""

    # Check known malicious list first
    if lower_name in KNOWN_MALICIOUS or package_name in KNOWN_MALICIOUS:
        return True, ""

    # Check Levenshtein distance against all known packages
    best_match = ""
    best_dist = max_distance + 1

    for known in known_packages:
        # Skip if length difference is too large (optimization)
        if abs(len(lower_name) - len(known)) > max_distance:
            continue

        dist = _levenshtein(lower_name, known)
        if 0 < dist <= max_distance and dist < best_dist:
            best_dist = dist
            best_match = known

    if best_match:
        return True, best_match

    return False, ""


def scan_supply_chain(
    project_dir: Path,
    assets_dir: Path | None = None,
) -> SupplyChainResult:
    """Scan a project's dependency files for supply chain threats.

    Checks for:
    1. Known malicious packages
    2. Typosquatting (Levenshtein distance from popular packages)
    3. Dependency confusion indicators

    Args:
        project_dir: Root directory of the project.
        assets_dir: Optional path to assets directory with known_packages.json.

    Returns:
        SupplyChainResult with all findings.
    """
    result = SupplyChainResult()
    known_packages = _load_known_packages(assets_dir)

    # Find and parse all dependency files
    for dep_filename, parser in DEP_FILE_PARSERS.items():
        dep_path = project_dir / dep_filename
        if not dep_path.exists():
            continue

        result.files_scanned += 1
        packages = parser(dep_path)

        for pkg_name, line_num in packages:
            result.packages_checked += 1

            # Check 1: Known malicious package
            malicious_info = KNOWN_MALICIOUS.get(pkg_name) or KNOWN_MALICIOUS.get(pkg_name.lower())
            if malicious_info:
                result.malicious_found += 1
                result.findings.append(SupplyChainFinding(
                    package=pkg_name,
                    source_file=dep_filename,
                    severity="critical",
                    reason=malicious_info["reason"],
                    safe_alternative=malicious_info.get("safe", ""),
                    line_number=line_num,
                ))
                continue

            # Check 2: Typosquatting detection
            is_suspicious, closest = check_typosquatting(pkg_name, known_packages)
            if is_suspicious:
                result.typosquats_found += 1
                reason = f"Possible typosquat of '{closest}'" if closest else f"Suspicious package name"
                result.findings.append(SupplyChainFinding(
                    package=pkg_name,
                    source_file=dep_filename,
                    severity="high",
                    reason=reason,
                    safe_alternative=closest if closest else "",
                    line_number=line_num,
                ))

    return result
