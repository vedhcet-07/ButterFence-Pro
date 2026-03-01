"""Log file rotation for events.jsonl."""

from __future__ import annotations

from pathlib import Path


def rotate_if_needed(
    log_path: Path, max_size_mb: float = 10.0, keep: int = 3
) -> bool:
    """Rotate log file if it exceeds max_size_mb.

    Renames current to .1, .1 to .2, etc.
    Keeps at most `keep` rotated files.
    Returns True if rotation happened.
    """
    if not log_path.exists():
        return False

    size_mb = log_path.stat().st_size / (1024 * 1024)
    if size_mb < max_size_mb:
        return False

    # Rotate existing backups
    for i in range(keep, 0, -1):
        src = log_path.parent / f"{log_path.name}.{i}"
        if i == keep:
            if src.exists():
                src.unlink()
        else:
            dst = log_path.parent / f"{log_path.name}.{i + 1}"
            if src.exists():
                src.rename(dst)

    # Move current to .1
    backup = log_path.parent / f"{log_path.name}.1"
    log_path.rename(backup)

    # Create empty new log
    log_path.touch()

    return True
