"""Config schema versioning and migration."""

from __future__ import annotations


def migrate_config(config: dict) -> dict:
    """Auto-upgrade config from older schema versions to current (v2).

    Returns a new config dict at the current schema version.
    """
    config = config.copy()
    version = config.get("version", 1)

    if version < 2:
        config = _migrate_v1_to_v2(config)

    return config


def _migrate_v1_to_v2(config: dict) -> dict:
    """Migrate from v1 to v2 schema.

    Adds new category defaults and new config keys.
    """
    config = config.copy()
    categories = config.get("categories", {})

    # Add new categories if not present
    new_categories = {
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
    }

    for name, cat_config in new_categories.items():
        if name not in categories:
            categories[name] = cat_config

    config["categories"] = categories
    config["version"] = 2
    config.setdefault("entropy_threshold", 4.5)
    config.setdefault("behavioral_chains", [])
    config.setdefault("installed_packs", [])

    return config
