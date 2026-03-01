"""Config loading, defaults, validation, and deep merge."""

from __future__ import annotations

import logging
from pathlib import Path

from butterfence.utils import deep_merge, load_json, save_json

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: dict = {
    "version": 2,
    "entropy_threshold": 4.5,
    "behavioral_chains": [],
    "installed_packs": [],
    "policies": [],
    "categories": {
        "destructive_shell": {
            "enabled": True,
            "severity": "critical",
            "action": "block",
            "patterns": [
                r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+.*(/|\\)|\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(-[a-zA-Z]*f[a-zA-Z]*\s+)?/\s)",
                r"rm\s+.*--no-preserve-root",
                r"mkfs\.",
                r"dd\s+if=",
                r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
                r"chmod\s+(-R\s+)?777\s+[/.]",
                r"shutdown\b",
                r"reboot\b",
                r"wipefs\b",
                r"fdisk\b",
            ],
            "safe_list": [
                r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?|(-[a-zA-Z]*f[a-zA-Z]*\s+)?-[a-zA-Z]*r[a-zA-Z]*\s+)?(node_modules|dist|build|\.next|__pycache__|\.pytest_cache|\.mypy_cache|\.cache|coverage|\.tox|\.eggs|\.egg-info)",
            ],
        },
        "secret_access": {
            "enabled": True,
            "severity": "critical",
            "action": "block",
            "patterns": [
                r"\.env($|\.)",
                r"\.pem$",
                r"id_rsa",
                r"id_ed25519",
                r"\.ssh/(config|authorized_keys|known_hosts)",
                r"credentials",
                r"\.aws/",
                r"\.docker/config\.json",
                r"\.npmrc",
                r"\.pypirc",
                r"secrets?\.(json|ya?ml|toml)",
                r"\.secret",
                r"\.key$",
            ],
            "safe_list": [],
        },
        "secret_exfil": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"AKIA[0-9A-Z]{16}",
                r"xox[baprs]-[0-9a-zA-Z-]+",
                r"ghp_[0-9a-zA-Z]{20,}",
                r"gho_[0-9a-zA-Z]{20,}",
                r"AIza[0-9A-Za-z_-]{35}",
                r"sk-[0-9a-zA-Z]{20,}",
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                r"\bAWS_SECRET_ACCESS_KEY\b",
                r"\bAWS_ACCESS_KEY_ID\b",
                r"echo\s+.*\$[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)",
            ],
            "safe_list": [],
        },
        "risky_git": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"git\s+push\s+.*--force\b",
                r"git\s+push\s+.*-f\b",
                r"git\s+push\s+.*--force-with-lease\b",
                r"git\s+reset\s+--hard\b",
                r"git\s+clean\s+.*-f",
                r"git\s+checkout\s+\.\s*$",
                r"git\s+restore\s+\.\s*$",
            ],
            "safe_list": [],
        },
        "network_exfil": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"curl\s+.*-d\s+@",
                r"curl\s+.*--data\s+@",
                r"curl\s+.*-F\s+.*@",
                r"curl\s+.*\$[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD)",
                r"wget\s+.*--post-(data|file)",
                r"nc\s+.*-e\s+",
                r"ncat\s+.*-e\s+",
                r"socat\s+.*EXEC:",
                r"ssh\s+.*cat\s+.*\.(env|pem|key)",
            ],
            "safe_list": [],
        },
        "python_dangerous": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True",
                r"\bos\.system\s*\(",
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bpickle\.loads?\s*\(",
                r"\b__import__\s*\(",
            ],
            "safe_list": [],
        },
        "sql_injection": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"""f['"]\s*SELECT\s+.*\{""",
                r"""f['"]\s*DELETE\s+.*\{""",
                r"\bDROP\s+TABLE\b",
                r"\bDROP\s+DATABASE\b",
            ],
            "safe_list": [],
        },
        "docker_escape": {
            "enabled": True,
            "severity": "critical",
            "action": "block",
            "patterns": [
                r"docker\s+run\s+.*--privileged",
                r"docker\s+run\s+.*-v\s+/:/",
                r"docker\s+run\s+.*--pid=host",
                r"docker\.sock",
            ],
            "safe_list": [],
        },
        "cloud_credentials": {
            "enabled": True,
            "severity": "critical",
            "action": "block",
            "patterns": [
                r"AZURE_[A-Z_]*(SECRET|KEY|TOKEN)",
                r"GOOGLE_APPLICATION_CREDENTIALS",
                r"gcloud\s+.*auth\s+print-access-token",
                r"az\s+account\s+get-access-token",
            ],
            "safe_list": [],
        },
        "supply_chain": {
            "enabled": True,
            "severity": "high",
            "action": "block",
            "patterns": [
                r"pip\s+install\s+.*--index-url\s+http://",
                r"curl\s+.*\|\s*(?:ba)?sh",
                r"wget\s+.*\|\s*python",
                r"npm\s+.*registry\s+http://",
            ],
            "safe_list": [],
        },
        "privilege_escalation": {
            "enabled": True,
            "severity": "critical",
            "action": "block",
            "patterns": [
                r"sudo\s+su\b",
                r"chmod\s+[u+]*s",
                r"chown\s+root\b",
                r"\bnsenter\b",
            ],
            "safe_list": [],
        },
    },
}


def get_config_path(start_dir: Path | None = None) -> Path:
    """Find .butterfence/config.json by walking up from start_dir."""
    search = start_dir or Path.cwd()
    for d in [search, *search.parents]:
        candidate = d / ".butterfence" / "config.json"
        if candidate.exists():
            return candidate
    return (start_dir or Path.cwd()) / ".butterfence" / "config.json"


def load_config(start_dir: Path | None = None) -> dict:
    """Load config from .butterfence/config.json, merged with defaults."""
    config_path = get_config_path(start_dir)
    if config_path.exists():
        user_config = load_json(config_path)
        if not user_config:
            logger.warning(
                "Config file exists but could not be loaded (corrupt?): %s "
                "Using defaults.", config_path
            )
        return deep_merge(DEFAULT_CONFIG, user_config)
    return DEFAULT_CONFIG.copy()


def save_config(config: dict, target_dir: Path | None = None) -> Path:
    """Save config to .butterfence/config.json."""
    target = target_dir or Path.cwd()
    config_path = target / ".butterfence" / "config.json"
    save_json(config_path, config)
    return config_path


def validate_config(config: dict) -> list[str]:
    """Validate config, returning list of error messages (empty if valid)."""
    errors = []
    if "categories" not in config:
        errors.append("Missing 'categories' key")
        return errors
    valid_severities = {"critical", "high", "medium", "low"}
    valid_actions = {"block", "warn", "allow"}
    for name, cat in config["categories"].items():
        if not isinstance(cat, dict):
            errors.append(f"Category '{name}' must be a dict")
            continue
        if cat.get("severity") not in valid_severities:
            errors.append(f"Category '{name}': invalid severity '{cat.get('severity')}'")
        if cat.get("action") not in valid_actions:
            errors.append(f"Category '{name}': invalid action '{cat.get('action')}'")
        if not isinstance(cat.get("patterns", []), list):
            errors.append(f"Category '{name}': patterns must be a list")
    return errors
