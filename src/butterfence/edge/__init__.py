"""ButterFence Edge Runtime — AMD Ryzen AI NPU / CPU ONNX inference.

Provides fully offline, zero-cloud threat classification using ONNX models.
Targets AMD Ryzen AI NPU via the VitisAI execution provider, with automatic
fallback to the CPU ONNX Runtime if the NPU is unavailable.
"""

from __future__ import annotations

from pathlib import Path

# Default model path (ships with the package or generated via model_export)
DEFAULT_MODEL_PATH = Path(__file__).parent / "threat_classifier.onnx"

# Threat categories the edge model can classify
EDGE_CATEGORIES: list[str] = [
    "destructive_shell",
    "secret_exfil",
    "secret_access",
    "code_injection",
    "persistence",
    "network_exfil",
    "privilege_escalation",
    "supply_chain",
    "file_tampering",
    "obfuscation",
    "reconnaissance",
]

# Map category index → severity
CATEGORY_SEVERITY: dict[str, str] = {
    "destructive_shell": "critical",
    "secret_exfil": "critical",
    "secret_access": "high",
    "code_injection": "critical",
    "persistence": "high",
    "network_exfil": "high",
    "privilege_escalation": "critical",
    "supply_chain": "high",
    "file_tampering": "medium",
    "obfuscation": "medium",
    "reconnaissance": "low",
}


def is_edge_available() -> bool:
    """Check if ONNX Runtime is installed and edge mode can run."""
    try:
        import onnxruntime  # noqa: F401
        return True
    except ImportError:
        return False


def get_available_providers() -> list[str]:
    """List available ONNX Runtime execution providers.

    Returns provider names like 'VitisAIExecutionProvider' (AMD NPU),
    'DmlExecutionProvider' (DirectML/GPU), 'CPUExecutionProvider'.
    """
    try:
        import onnxruntime as ort
        return ort.get_available_providers()
    except ImportError:
        return []


def has_amd_npu() -> bool:
    """Check if AMD Ryzen AI NPU is available via VitisAI provider."""
    providers = get_available_providers()
    return "VitisAIExecutionProvider" in providers
