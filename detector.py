"""
detector.py — ML-powered ransomware detector
Uses the trained LSTM model (input shape: 100 timesteps x 6 features)
"""

import numpy as np
import tensorflow as tf
from collections import deque

# ── CONFIG ────────────────────────────────────────────────────
MODEL_PATH   = "model/ransomware_lstm_model.keras"
WINDOW_SIZE  = 100          # Must match model input (100 timesteps)
N_FEATURES   = 6            # lba, size, flags, duration, queue_depth, throughput
THRESHOLD    = 0.70         # Probability above this = ransomware

# Feature order must match what model was trained on
FEATURE_NAMES = ["lba", "size", "flags", "duration", "queue_depth", "throughput"]

# ── LOAD MODEL ONCE AT STARTUP ────────────────────────────────
print("Loading LSTM model...")
model = tf.keras.models.load_model(MODEL_PATH)
print(f"Model loaded. Input: {model.input_shape}")

# Rolling window of recent file events (stores feature vectors)
event_window = deque(maxlen=WINDOW_SIZE)

# Simple normalization ranges (from RanSAP dataset statistics)
# These should ideally come from your scaler.pkl
FEATURE_RANGES = {
    "lba":         (0, 1e9),
    "size":        (0, 1e6),
    "flags":       (0, 255),
    "duration":    (0, 1e6),
    "queue_depth": (0, 32),
    "throughput":  (0, 1e8),
}


def normalize_feature(name: str, value: float) -> float:
    """Scale a single feature value to [0, 1]."""
    lo, hi = FEATURE_RANGES.get(name, (0, 1))
    if hi == lo:
        return 0.0
    return float(np.clip((value - lo) / (hi - lo), 0.0, 1.0))


def extract_features_from_event(event_path: str,
                                  event_type: str) -> np.ndarray:
    """
    Extract 6 behavioral features from a file system event.
    In a real system these come from disk I/O monitoring.
    Here we approximate from file metadata.
    """
    import os
    import time

    try:
        stat = os.stat(event_path)
        size = stat.st_size
    except Exception:
        size = 0

    # Map event type to a flag value
    flag_map = {"create": 1, "modify": 2, "delete": 3, "rename": 4}
    flag = flag_map.get(event_type, 0)

    # Build feature vector approximating RanSAP features
    raw = {
        "lba":         float(hash(event_path) % int(1e9)),  # approximate disk address
        "size":        float(size),
        "flags":       float(flag),
        "duration":    float(time.time() % 1e6),            # time component
        "queue_depth": float(len(event_window)),             # current queue
        "throughput":  float(size * max(len(event_window), 1)),
    }

    # Normalize each feature
    normalized = np.array(
        [normalize_feature(name, raw[name]) for name in FEATURE_NAMES],
        dtype=np.float32
    )
    return normalized


def detect_ransomware(event_path: str, event_type: str) -> dict:
    """
    Main detection function.

    1. Extract features from the file event
    2. Add to rolling window
    3. When window is full, run LSTM prediction
    4. Return result with probability

    Returns dict:
        {
          "label": "ransomware" | "benign" | "collecting",
          "probability": float,
          "window_fill": int,
        }
    """
    if event_type not in ["create", "modify", "rename"]:
        return {"label": "benign", "probability": 0.0,
                "window_fill": len(event_window)}

    # Extract and store features
    features = extract_features_from_event(event_path, event_type)
    event_window.append(features)

    window_fill = len(event_window)

    # Need full window before we can score
    if window_fill < WINDOW_SIZE:
        return {
            "label":       "collecting",
            "probability": 0.0,
            "window_fill": window_fill,
        }

    # Build input tensor: (1, 100, 6)
    X = np.array(list(event_window), dtype=np.float32)
    X = X.reshape(1, WINDOW_SIZE, N_FEATURES)

    # Run model prediction
    prob = float(model.predict(X, verbose=0)[0][0])
    label = "ransomware" if prob >= THRESHOLD else "benign"

    return {
        "label":       label,
        "probability": prob,
        "window_fill": window_fill,
    }


def reset_window():
    """Clear the event window (call after detection/prevention)."""
    event_window.clear()