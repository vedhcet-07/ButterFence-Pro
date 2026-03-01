"""Proactive repo secret scanner — `butterfence scan`."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from butterfence.entropy import find_high_entropy_strings

# Secret patterns — regex, name, severity
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
    (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S+", "AWS Secret Key", "critical"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Token", "critical"),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token", "critical"),
    (r"ghs_[0-9a-zA-Z]{36}", "GitHub Server Token", "critical"),
    (r"github_pat_[0-9a-zA-Z_]{22,}", "GitHub Fine-grained Token", "critical"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack Token", "critical"),
    (r"sk-[0-9a-zA-Z]{20,}", "OpenAI API Key", "critical"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key", "high"),
    (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "Private Key", "critical"),
    (r"-----BEGIN\s+(?:DSA\s+)?PRIVATE\s+KEY-----", "DSA Private Key", "critical"),
    (r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----", "EC Private Key", "critical"),
    (r"AZURE_[A-Z_]*(SECRET|KEY|TOKEN)\s*[=:]\s*\S+", "Azure Secret", "critical"),
    (r"GOOGLE_APPLICATION_CREDENTIALS\s*[=:]\s*\S+", "GCP Credentials", "critical"),
    (r"(?:mongodb\+srv|mongodb)://[^\s]+", "MongoDB Connection String", "high"),
    (r"postgres://[^\s]+", "PostgreSQL Connection String", "high"),
    (r"mysql://[^\s]+", "MySQL Connection String", "high"),
]

# Dangerous file patterns
DANGEROUS_FILES: list[tuple[str, str, str]] = [
    (r"\.env$", "Environment file", "high"),
    (r"\.env\.\w+$", "Environment file (variant)", "high"),
    (r"\.pem$", "PEM certificate/key", "high"),
    (r"\.key$", "Key file", "high"),
    (r"id_rsa$", "SSH private key", "critical"),
    (r"id_ed25519$", "SSH private key", "critical"),
    (r"\.npmrc$", "npm config (may contain tokens)", "medium"),
    (r"\.pypirc$", "PyPI config (may contain tokens)", "medium"),
]

# Compiled patterns
_COMPILED_SECRETS = [
    (re.compile(p, re.IGNORECASE), name, sev) for p, name, sev in SECRET_PATTERNS
]
_COMPILED_FILES = [
    (re.compile(p, re.IGNORECASE), name, sev) for p, name, sev in DANGEROUS_FILES
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", ".eggs", "venv", ".venv"}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1MB


@dataclass
class ScanFinding:
    file: str
    line: int
    rule: str
    severity: str
    matched_text: str
    suggestion: str = ""


@dataclass
class ScanResult:
    findings: list[ScanFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0


def _is_binary(path: Path) -> bool:
    """Check if file is binary by looking for null bytes."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
            return b"\x00" in chunk
    except OSError:
        return True


def _load_gitignore(root: Path) -> list[str]:
    """Load .gitignore patterns from the project root."""
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        return []
    return [
        line.strip()
        for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def scan_repo(
    root: Path,
    entropy_threshold: float = 4.5,
    fix: bool = False,
) -> ScanResult:
    """Scan a repository for secrets, dangerous files, and high-entropy strings."""
    result = ScanResult()

    # Load gitignore patterns
    gitignore_patterns = _load_gitignore(root)
    spec = None
    try:
        import pathspec
        spec = pathspec.PathSpec.from_lines("gitwildmatch", gitignore_patterns)
    except ImportError:
        spec = None

    seen_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        # Symlink loop detection: skip already-visited real paths
        real_dir = os.path.realpath(dirpath)
        if real_dir in seen_dirs:
            dirnames.clear()  # Do not descend into loops
            continue
        seen_dirs.add(real_dir)

        # Skip directories
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            filepath = Path(dirpath) / filename
            relpath = filepath.relative_to(root).as_posix()

            # Skip via gitignore
            if spec and spec.match_file(relpath):
                result.files_skipped += 1
                continue

            # Skip large/binary files
            try:
                if filepath.stat().st_size > MAX_FILE_SIZE:
                    result.files_skipped += 1
                    continue
            except OSError:
                result.files_skipped += 1
                continue

            if _is_binary(filepath):
                result.files_skipped += 1
                continue

            # Check dangerous file patterns
            for pat, name, sev in _COMPILED_FILES:
                if pat.search(filename):
                    result.findings.append(
                        ScanFinding(
                            file=relpath,
                            line=0,
                            rule=name,
                            severity=sev,
                            matched_text=filename,
                            suggestion=f"Add '{filename}' to .gitignore",
                        )
                    )

            # Scan file contents
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                result.files_skipped += 1
                continue

            result.files_scanned += 1

            for line_num, line in enumerate(content.splitlines(), 1):
                # Secret pattern matching
                for pat, name, sev in _COMPILED_SECRETS:
                    if pat.search(line):
                        result.findings.append(
                            ScanFinding(
                                file=relpath,
                                line=line_num,
                                rule=name,
                                severity=sev,
                                matched_text=line.strip()[:100],
                                suggestion="Remove secret and rotate the credential",
                            )
                        )

            # Entropy scan on full content
            entropy_findings = find_high_entropy_strings(
                content, threshold=entropy_threshold
            )
            for ef in entropy_findings:
                # Find approximate line number
                prefix = content[: ef.offset]
                line_num = prefix.count("\n") + 1
                result.findings.append(
                    ScanFinding(
                        file=relpath,
                        line=line_num,
                        rule=f"High entropy string ({ef.entropy:.1f} bits)",
                        severity="medium",
                        matched_text=ef.text[:100],
                        suggestion="Review if this is a secret or token",
                    )
                )

    return result
