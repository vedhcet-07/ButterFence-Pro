"""ONNX-based threat classifier for ButterFence Edge Mode.

This module loads an ONNX model that classifies tool-use commands into
one of 11 threat categories (or 'benign'). It targets AMD Ryzen AI NPU
via the VitisAI execution provider and falls back to CPU ONNX Runtime
if no NPU is detected.

The classifier operates on tokenized command features — a lightweight
bag-of-keywords approach that runs in <30ms on typical hardware.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from butterfence.edge import (
    CATEGORY_SEVERITY,
    DEFAULT_MODEL_PATH,
    EDGE_CATEGORIES,
)


# ---------------------------------------------------------------------------
# Feature extraction — tokenize commands into a fixed-length feature vector
# ---------------------------------------------------------------------------

# Keywords associated with dangerous operations (order matters — index = feature)
THREAT_KEYWORDS: list[str] = [
    # Destructive shell
    "rm", "rmdir", "del", "remove", "shred", "mkfs", "dd", "format",
    "-rf", "-fr", "--force", "--recursive", "--no-preserve-root",
    # Secret / exfiltration
    "cat", "head", "tail", "less", "more", "type",
    ".env", "id_rsa", "id_ed25519", "credentials", "secret", "token",
    "password", "api_key", "apikey", "aws_access", "private_key",
    # Network exfil
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "ftp",
    "http://", "https://", "ngrok", "reverse", "exfiltrate",
    # Code injection
    "eval", "exec", "system", "subprocess", "popen", "os.system",
    "child_process", "spawn", "execSync",
    # Persistence
    "crontab", "systemctl", "launchctl", "schtasks", "startup",
    "autorun", "registry", "bashrc", "profile", "rc.local",
    # Privilege escalation
    "sudo", "su", "chmod", "chown", "setuid", "doas",
    "777", "+s", "SUID",
    # Supply chain
    "pip install", "npm install", "gem install", "go get",
    "requirements.txt", "package.json",
    # Obfuscation
    "base64", "xxd", "openssl enc", "encode", "decode", "rot13",
    "\\x", "\\u00",
    # Recon
    "whoami", "id", "uname", "hostname", "ifconfig", "ipconfig",
    "net user", "env", "printenv", "set",
    # File tampering
    "sed", "awk", "tee", "truncate", "echo", ">", ">>",
    ".git/config", ".ssh/", "authorized_keys",
    # General danger signals
    "/dev/null", "/dev/sda", "force-push", "--force",
    "git push -f", "drop table", "delete from",
]

FEATURE_DIM = len(THREAT_KEYWORDS) + 8  # keywords + derived features

# Confidence threshold — below this, fall back to regex
DEFAULT_CONFIDENCE_THRESHOLD = 0.3


@dataclass
class EdgePrediction:
    """Result from the ONNX edge classifier."""
    category: str  # "benign" or one of EDGE_CATEGORIES
    confidence: float  # 0.0 – 1.0
    severity: str  # "none", "low", "medium", "high", "critical"
    inference_ms: float  # milliseconds taken for inference
    provider: str  # "VitisAIExecutionProvider", "CPUExecutionProvider", etc.
    features_used: int  # number of non-zero features in the input


def extract_features(text: str) -> list[float]:
    """Convert a raw command string into a fixed-length feature vector.

    Features:
    - First N: binary presence of each THREAT_KEYWORD
    - N+0: total keyword count (normalized)
    - N+1: command length (normalized, max 1.0 at 500 chars)
    - N+2: pipe count (normalized)
    - N+3: semicolon count
    - N+4: has redirect (> or >>)
    - N+5: has backtick or $()
    - N+6: has base64-like long string
    - N+7: has absolute path (/etc, /root, C:\\)
    """
    text_lower = text.lower()
    features: list[float] = []

    # Keyword presence (binary)
    keyword_hits = 0
    for kw in THREAT_KEYWORDS:
        present = 1.0 if kw.lower() in text_lower else 0.0
        features.append(present)
        keyword_hits += int(present)

    # Derived features
    features.append(min(keyword_hits / max(len(THREAT_KEYWORDS), 1), 1.0))  # normalized count
    features.append(min(len(text) / 500.0, 1.0))  # normalized length
    features.append(min(text.count("|") / 5.0, 1.0))  # pipe count
    features.append(min(text.count(";") / 5.0, 1.0))  # semicolons
    features.append(1.0 if (">" in text or ">>" in text) else 0.0)  # redirect
    features.append(1.0 if ("`" in text or "$(" in text) else 0.0)  # subshell
    features.append(1.0 if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text) else 0.0)  # base64
    features.append(1.0 if re.search(r"(/etc/|/root/|/home/|C:\\\\)", text) else 0.0)  # abs path

    return features


class ONNXThreatClassifier:
    """ONNX-based threat classifier with AMD NPU support.

    Usage:
        classifier = ONNXThreatClassifier()
        classifier.load()
        result = classifier.predict("rm -rf /")
    """

    def __init__(
        self,
        model_path: Path | str | None = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        prefer_npu: bool = True,
    ):
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self.confidence_threshold = confidence_threshold
        self.prefer_npu = prefer_npu
        self.session: Any = None
        self.provider_used: str = "none"
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        """Load the ONNX model, targeting AMD NPU first, then CPU."""
        try:
            import onnxruntime as ort
        except ImportError:
            raise ImportError(
                "onnxruntime is required for edge mode. "
                "Install with: pip install butterfence[edge]"
            )

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Edge model not found at {self.model_path}. "
                "Generate one with: butterfence edge-export"
            )

        # Try providers in order of preference
        providers_to_try: list[str] = []
        available = ort.get_available_providers()

        if self.prefer_npu and "VitisAIExecutionProvider" in available:
            providers_to_try.append("VitisAIExecutionProvider")
        if "DmlExecutionProvider" in available:
            providers_to_try.append("DmlExecutionProvider")
        providers_to_try.append("CPUExecutionProvider")

        # Create session with best available provider
        for provider in providers_to_try:
            try:
                self.session = ort.InferenceSession(
                    str(self.model_path),
                    providers=[provider],
                )
                self.provider_used = provider
                break
            except Exception:
                continue

        if self.session is None:
            raise RuntimeError("Failed to create ONNX inference session with any provider")

        self._loaded = True

    def predict(self, text: str) -> EdgePrediction:
        """Classify a command string into a threat category.

        Args:
            text: The raw command or tool input to classify.

        Returns:
            EdgePrediction with category, confidence, severity, and timing.
        """
        if not self._loaded:
            raise RuntimeError("Model not loaded. Call .load() first.")

        import numpy as np

        features = extract_features(text)
        features_used = sum(1 for f in features if f > 0)

        # Run inference
        start = time.perf_counter()
        input_array = np.array([features], dtype=np.float32)
        input_name = self.session.get_inputs()[0].name
        output_name = self.session.get_outputs()[0].name

        outputs = self.session.run([output_name], {input_name: input_array})
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Parse output — softmax probabilities over [benign] + EDGE_CATEGORIES
        probs = outputs[0][0]

        # Index 0 = benign, 1..N = threat categories
        all_labels = ["benign"] + EDGE_CATEGORIES
        max_idx = int(np.argmax(probs))
        max_confidence = float(probs[max_idx])

        category = all_labels[max_idx]

        if category == "benign" or max_confidence < self.confidence_threshold:
            return EdgePrediction(
                category="benign",
                confidence=max_confidence,
                severity="none",
                inference_ms=elapsed_ms,
                provider=self.provider_used,
                features_used=features_used,
            )

        return EdgePrediction(
            category=category,
            confidence=max_confidence,
            severity=CATEGORY_SEVERITY.get(category, "medium"),
            inference_ms=elapsed_ms,
            provider=self.provider_used,
            features_used=features_used,
        )

    def predict_batch(self, texts: list[str]) -> list[EdgePrediction]:
        """Classify multiple commands in a single batch."""
        return [self.predict(t) for t in texts]


# ---------------------------------------------------------------------------
# Standalone heuristic classifier (no ONNX model required)
# ---------------------------------------------------------------------------

class HeuristicClassifier:
    """Rule-based fallback classifier that mimics ONNX model behavior.

    Used when no ONNX model file exists — provides the same interface
    as ONNXThreatClassifier but uses keyword scoring instead of neural
    inference. This allows edge mode to work out-of-the-box without
    needing to train or download a model.
    """

    CATEGORY_KEYWORDS: dict[str, list[str]] = {
        "destructive_shell": [
            "rm", "rmdir", "del", "shred", "mkfs", "dd", "format",
            "-rf", "-fr", "--no-preserve-root", "remove",
        ],
        "secret_exfil": [
            "curl", "wget", ".env", "id_rsa", "credentials", "secret",
            "token", "password", "api_key", "private_key", "exfiltrate",
        ],
        "secret_access": [
            "cat", "head", "tail", "less", "type",
            ".env", "id_rsa", "credentials", "aws_access",
        ],
        "code_injection": [
            "eval", "exec", "system", "subprocess", "popen", "os.system",
            "child_process", "spawn",
        ],
        "persistence": [
            "crontab", "systemctl", "launchctl", "schtasks",
            "bashrc", "profile", "autorun", "startup",
        ],
        "network_exfil": [
            "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp",
            "ngrok", "reverse", "http://", "https://",
        ],
        "privilege_escalation": [
            "sudo", "su", "chmod", "chown", "setuid", "doas",
            "777", "+s", "SUID",
        ],
        "supply_chain": [
            "pip install", "npm install", "gem install", "go get",
        ],
        "file_tampering": [
            "sed", "awk", "tee", "truncate",
            ".git/config", ".ssh/", "authorized_keys",
        ],
        "obfuscation": [
            "base64", "xxd", "openssl enc", "encode", "decode", "rot13",
        ],
        "reconnaissance": [
            "whoami", "id", "uname", "hostname", "ifconfig",
            "ipconfig", "net user", "printenv",
        ],
    }

    def __init__(self, confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD):
        self.confidence_threshold = confidence_threshold
        self.provider_used = "HeuristicEngine"

    @property
    def is_loaded(self) -> bool:
        return True

    def load(self) -> None:
        """No-op — heuristic classifier needs no loading."""
        pass

    def predict(self, text: str) -> EdgePrediction:
        """Classify a command using keyword matching heuristics."""
        start = time.perf_counter()
        text_lower = text.lower()

        scores: dict[str, float] = {}
        raw_hits: dict[str, int] = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            hits = sum(1 for kw in keywords if kw.lower() in text_lower)
            if hits > 0:
                scores[category] = hits / len(keywords)
                raw_hits[category] = hits

        elapsed_ms = (time.perf_counter() - start) * 1000
        features_used = sum(1 for f in extract_features(text) if f > 0)

        if not scores:
            return EdgePrediction(
                category="benign",
                confidence=0.95,
                severity="none",
                inference_ms=elapsed_ms,
                provider=self.provider_used,
                features_used=features_used,
            )

        best_cat = max(scores, key=scores.get)  # type: ignore[arg-type]
        best_hits = raw_hits[best_cat]

        # Normalize confidence: each hit adds 0.4, capped at 1.0
        # This ensures even 1 dangerous keyword (e.g. "rm", "eval") exceeds threshold
        confidence = min(best_hits * 0.4, 1.0)

        if confidence < self.confidence_threshold:
            return EdgePrediction(
                category="benign",
                confidence=1.0 - confidence,
                severity="none",
                inference_ms=elapsed_ms,
                provider=self.provider_used,
                features_used=features_used,
            )

        return EdgePrediction(
            category=best_cat,
            confidence=confidence,
            severity=CATEGORY_SEVERITY.get(best_cat, "medium"),
            inference_ms=elapsed_ms,
            provider=self.provider_used,
            features_used=features_used,
        )


def get_classifier(
    model_path: Path | str | None = None,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    prefer_npu: bool = True,
) -> ONNXThreatClassifier | HeuristicClassifier:
    """Get the best available classifier.

    Returns ONNXThreatClassifier if both onnxruntime is installed AND a
    model file exists. Otherwise falls back to HeuristicClassifier.
    """
    model_file = Path(model_path) if model_path else DEFAULT_MODEL_PATH

    try:
        import onnxruntime  # noqa: F401
        if model_file.exists():
            clf = ONNXThreatClassifier(
                model_path=model_file,
                confidence_threshold=confidence_threshold,
                prefer_npu=prefer_npu,
            )
            clf.load()
            return clf
    except (ImportError, Exception):
        pass

    clf_heuristic = HeuristicClassifier(confidence_threshold=confidence_threshold)
    clf_heuristic.load()
    return clf_heuristic
