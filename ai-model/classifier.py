"""
Inference wrapper around the trained severity model.

This is what backend/main.py imports. It loads ai-model/severity_model.joblib
once (lazily, on first use) and exposes a simple function that turns a raw
alert into an AI-assigned severity string ("Low" | "Medium" | "High" |
"Critical" — matching the fixed list in documentation/api-contract.md).

If the model file is missing (e.g. a teammate pulled the repo but hasn't
run ai-model/train_classifier.py yet), predict_severity() falls back to
"Medium" and prints a warning instead of crashing the whole API.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from features import build_feature_frame  # noqa: E402

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "severity_model.joblib")
FALLBACK_SEVERITY = "Medium"

_model = None
_model_load_failed = False


def _load_model():
    global _model, _model_load_failed
    if _model is not None or _model_load_failed:
        return _model
    try:
        import joblib

        _model = joblib.load(MODEL_PATH)
    except Exception as exc:  # noqa: BLE001 - want any load failure to fall back, not crash the API
        _model_load_failed = True
        print(
            f"[ai-model] WARNING: could not load {MODEL_PATH} ({exc}). "
            f"Run 'python3 ai-model/train_classifier.py' first. "
            f"Falling back to severity='{FALLBACK_SEVERITY}' until it exists."
        )
    return _model


def predict_severity(source, description, ip=None, hash=None, timestamp=None):
    """
    Scores a single raw alert and returns an AI-assigned severity string.
    `timestamp` is accepted for call-site convenience but not currently used
    as a feature.
    """
    model = _load_model()
    if model is None:
        return FALLBACK_SEVERITY

    record = {"source": source, "description": description, "ip": ip, "hash": hash}
    X = build_feature_frame([record])
    prediction = model.predict(X)[0]
    return str(prediction)


def predict_severity_with_confidence(source, description, ip=None, hash=None, timestamp=None):
    """
    Same as predict_severity, but also returns the model's confidence
    (probability of the predicted class) — handy for the dashboard later.
    Returns (severity: str, confidence: float | None).
    """
    model = _load_model()
    if model is None:
        return FALLBACK_SEVERITY, None

    record = {"source": source, "description": description, "ip": ip, "hash": hash}
    X = build_feature_frame([record])
    probs = model.predict_proba(X)[0]
    classes = model.classes_
    best_idx = probs.argmax()
    return str(classes[best_idx]), float(probs[best_idx])


if __name__ == "__main__":
    # Quick manual smoke test: python3 ai-model/classifier.py
    samples = [
        dict(source="Endpoint", description="Ransomware encryption activity detected on WEB-SRV02, mass file rename observed", hash="a" * 64),
        dict(source="Firewall", description="Multiple failed login attempts detected for user jdoe followed by a successful login"),
        dict(source="IDS", description="Port scan detected from internal host DB-SRV01"),
        dict(source="SIEM", description="Informational: password changed successfully for user asmith"),
    ]
    for s in samples:
        severity, confidence = predict_severity_with_confidence(**s)
        print(f"{severity:9s} (confidence={confidence:.2f})  <- {s['description']}")
