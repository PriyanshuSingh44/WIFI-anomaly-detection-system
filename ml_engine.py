"""
ml_engine.py — Self-Learning Anomaly Detection Engine
======================================================
Implements three algorithms (Isolation Forest, LOF, Autoencoder) with:
  • Rolling-window online retraining
  • Adaptive threshold that adjusts to current traffic volume
  • Feedback loop recording confirmed anomalies for future baseline exclusion
"""

import os
import time
import logging
import threading
import numpy as np
import joblib
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

import config

logger = logging.getLogger(__name__)

os.makedirs(config.MODEL_DIR, exist_ok=True)


# ──────────────────────────────────────────────────────────────────────────────
# Optional: lightweight Autoencoder (pure NumPy, no PyTorch dependency)
# ──────────────────────────────────────────────────────────────────────────────

class NumpyAutoencoder:
    """
    A minimal 3-layer autoencoder trained with gradient descent (NumPy-only).
    Reconstruction error is used as the anomaly score.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 4,
                 lr: float = 0.001, epochs: int = 50, batch: int = 32):
        self.lr      = lr
        self.epochs  = epochs
        self.batch   = batch
        rng          = np.random.default_rng(42)
        # Encoder: input → hidden
        self.W1 = rng.standard_normal((input_dim, hidden_dim)) * 0.1
        self.b1 = np.zeros(hidden_dim)
        # Decoder: hidden → input
        self.W2 = rng.standard_normal((hidden_dim, input_dim)) * 0.1
        self.b2 = np.zeros(input_dim)
        self.threshold_ = None

    @staticmethod
    def _relu(x):  return np.maximum(0, x)
    @staticmethod
    def _relu_d(x): return (x > 0).astype(float)

    def _forward(self, X):
        h  = self._relu(X @ self.W1 + self.b1)
        out = h @ self.W2 + self.b2
        return h, out

    def fit(self, X: np.ndarray, threshold_pct: int = 95):
        n = X.shape[0]
        for _ in range(self.epochs):
            idx = np.random.permutation(n)
            for start in range(0, n, self.batch):
                xb = X[idx[start:start + self.batch]]
                h, out = self._forward(xb)
                diff = out - xb                          # (batch, input)
                dW2  = h.T @ diff / xb.shape[0]
                db2  = diff.mean(axis=0)
                dh   = (diff @ self.W2.T) * self._relu_d(xb @ self.W1 + self.b1)
                dW1  = xb.T @ dh / xb.shape[0]
                db1  = dh.mean(axis=0)
                self.W2 -= self.lr * dW2
                self.b2 -= self.lr * db2
                self.W1 -= self.lr * dW1
                self.b1 -= self.lr * db1
        # Set reconstruction-error threshold
        errors = self.reconstruction_error(X)
        self.threshold_ = float(np.percentile(errors, threshold_pct))
        return self

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        _, out = self._forward(X)
        return np.mean((X - out) ** 2, axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns +1 (normal) or -1 (anomaly) to match sklearn convention."""
        errors = self.reconstruction_error(X)
        return np.where(errors > self.threshold_, -1, 1)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Negative reconstruction error so lower = more anomalous (sklearn sign)."""
        return -self.reconstruction_error(X)


# ──────────────────────────────────────────────────────────────────────────────
# Adaptive Threshold
# ──────────────────────────────────────────────────────────────────────────────

class AdaptiveThreshold:
    """
    Adjusts the anomaly score cut-off based on current traffic volume.
    High volume → relax threshold (fewer false positives in busy hours).
    Low  volume → tighten threshold (more sensitive during quiet periods).
    """

    def __init__(self, base: float = config.BASE_THRESHOLD,
                 high_mult: float = config.HIGH_VOLUME_MULTIPLIER,
                 low_mult:  float = config.LOW_VOLUME_MULTIPLIER,
                 window:    int   = 50):
        self.base      = base
        self.high_mult = high_mult
        self.low_mult  = low_mult
        self._volume_history = deque(maxlen=window)

    def update(self, n_packets: int):
        self._volume_history.append(n_packets)

    def current(self) -> float:
        if len(self._volume_history) < 5:
            return self.base
        arr   = np.array(self._volume_history)
        p_high = np.percentile(arr, config.VOLUME_HIGH_PERCENTILE)
        p_low  = np.percentile(arr, config.VOLUME_LOW_PERCENTILE)
        latest = arr[-1]
        if latest >= p_high:
            return self.base * self.high_mult
        if latest <= p_low:
            return self.base * self.low_mult
        return self.base


# ──────────────────────────────────────────────────────────────────────────────
# ML Engine
# ──────────────────────────────────────────────────────────────────────────────

class AnomalyEngine:
    """
    Central ML engine with rolling-window self-learning:
      1. Buffers incoming feature vectors.
      2. Retrains the model every N new vectors.
      3. Predicts anomaly score for each new vector.
      4. Adapts detection threshold to current traffic volume.
    """

    FEATURE_COLS = config.FEATURE_COLUMNS  # list of 11 feature names

    def __init__(self, model_name: str = config.ACTIVE_MODEL):
        self.model_name        = model_name
        self.scaler            = StandardScaler()
        self.model             = None
        self.threshold         = AdaptiveThreshold()
        self._buffer           = deque(maxlen=config.ROLLING_WINDOW_SIZE * 3)
        self._windows_seen     = 0
        self._lock             = threading.Lock()
        self._is_trained       = False
        self._dynamic_threshold = None   # set from real training-data scores

        logger.info(f"AnomalyEngine initialised | model={model_name}")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_model(self):
        if self.model_name == "IsolationForest":
            return IsolationForest(**config.ISOLATION_FOREST_CONFIG)
        elif self.model_name == "LOF":
            return LocalOutlierFactor(**config.LOF_CONFIG)
        elif self.model_name == "Autoencoder":
            cfg = config.AUTOENCODER_CONFIG
            dims = cfg["hidden_dims"]
            return NumpyAutoencoder(
                input_dim=cfg["input_dim"],
                hidden_dim=dims[len(dims) // 2],   # middle (bottleneck)
                lr=cfg["learning_rate"],
                epochs=cfg["epochs"],
                batch=cfg["batch_size"],
            )
        raise ValueError(f"Unknown model: {self.model_name}")

    def _vec_from_feature(self, feat: dict) -> np.ndarray:
        return np.array([feat.get(c, 0.0) for c in self.FEATURE_COLS], dtype=float)

    def _retrain(self):
        if len(self._buffer) < config.MIN_SAMPLES_FOR_TRAIN:
            return

        # ── Drop all-zero vectors (empty live-capture windows with no packets) ──
        valid = [
            f for f in self._buffer
            if any(abs(f.get(c, 0.0)) > 1e-9 for c in self.FEATURE_COLS)
        ]
        if len(valid) < max(30, config.MIN_SAMPLES_FOR_TRAIN // 3):
            logger.warning(f"[ML] Only {len(valid)} non-empty samples — waiting for more real traffic.")
            return

        X_raw = np.vstack([self._vec_from_feature(f) for f in valid])
        X     = self.scaler.fit_transform(X_raw)
        self.model = self._build_model()

        if self.model_name == "Autoencoder":
            self.model.fit(X, threshold_pct=config.AUTOENCODER_CONFIG["threshold_pct"])
        else:
            self.model.fit(X)

        # ── Data-driven threshold: flag only the bottom 5% of training scores ──
        # This means the model learns what YOUR traffic looks like and only
        # raises an alert when something is genuinely unusual vs that baseline.
        train_scores = self.model.score_samples(X)
        self._dynamic_threshold = float(np.percentile(train_scores, 5))

        self._is_trained = True
        logger.info(
            f"[ML] Retrained on {len(valid)} samples | "
            f"score range=[{train_scores.min():.3f}, {train_scores.max():.3f}] | "
            f"dynamic threshold={self._dynamic_threshold:.4f} (5th pct)"
        )
        self._save_model()

    def _save_model(self):
        try:
            path      = os.path.join(config.MODEL_DIR, f"{self.model_name.lower()}_model.pkl")
            meta_path = os.path.join(config.MODEL_DIR, f"{self.model_name.lower()}_meta.pkl")
            joblib.dump({
                "scaler":            self.scaler,
                "model":             self.model,
                "dynamic_threshold": self._dynamic_threshold,
            }, path)
            joblib.dump({"capture_mode": config.CAPTURE_MODE}, meta_path)
        except Exception as e:
            logger.warning(f"[ML] Could not save model: {e}")

    def load_model(self, capture_mode: str = None):
        path      = os.path.join(config.MODEL_DIR, f"{self.model_name.lower()}_model.pkl")
        meta_path = os.path.join(config.MODEL_DIR, f"{self.model_name.lower()}_meta.pkl")
        if not os.path.exists(path):
            return

        obj = joblib.load(path)

        # ── Reject model if it was trained on a different capture mode ──────────
        # A simulated-mode model must NOT be used for live traffic (and vice versa)
        # because the feature distributions are completely different.
        if os.path.exists(meta_path) and capture_mode:
            meta = joblib.load(meta_path)
            saved_mode = meta.get("capture_mode", None)
            if saved_mode and saved_mode != capture_mode:
                logger.warning(
                    f"[ML] Skipping stale model (trained on '{saved_mode}', "
                    f"current mode is '{capture_mode}'). Will retrain fresh."
                )
                return

        self.scaler            = obj["scaler"]
        self.model             = obj["model"]
        self._dynamic_threshold = obj.get("dynamic_threshold", None)
        self._is_trained       = self._dynamic_threshold is not None
        if self._is_trained:
            logger.info(
                f"[ML] Loaded persisted model from {path} | "
                f"dynamic_threshold={self._dynamic_threshold:.4f}"
            )
        else:
            logger.warning("[ML] Loaded model has no dynamic threshold — will retrain before activating.")

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, feature_vec: dict) -> dict:
        """
        Accept one feature vector from an edge node.
        Returns a result dict with anomaly flag, score, and threshold used.
        """
        with self._lock:
            # ── Skip all-zero vectors (live mode: no packets captured in window) ──
            # Feeding zeros to the model would corrupt the baseline.
            is_empty = all(abs(feature_vec.get(c, 0.0)) < 1e-9 for c in self.FEATURE_COLS)
            if is_empty:
                return {
                    "anomaly":   False,
                    "score":     None,
                    "threshold": None,
                    "status":    "empty_window",
                }

            self._buffer.append(feature_vec)
            self._windows_seen += 1
            self.threshold.update(feature_vec.get("n_packets", 50))

            # Trigger retraining on schedule
            if self._windows_seen % config.RETRAIN_EVERY_N_WINDOWS == 0:
                self._retrain()

            if not self._is_trained:
                return {
                    "anomaly":   False,
                    "score":     None,
                    "threshold": None,
                    "status":    "collecting_baseline",
                }

            # Score new vector
            vec    = self._vec_from_feature(feature_vec).reshape(1, -1)
            vec_sc = self.scaler.transform(vec)
            score  = float(self.model.score_samples(vec_sc)[0])

            # ── Use data-driven threshold (from last retrain) when available.
            #    Falls back to the adaptive threshold only before first retrain.
            thresh     = (self._dynamic_threshold
                          if self._dynamic_threshold is not None
                          else self.threshold.current())
            is_anomaly = score < thresh

            return {
                "anomaly":   bool(is_anomaly),
                "score":     round(score, 6),
                "threshold": round(thresh, 6),
                "status":    "active",
            }

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)
