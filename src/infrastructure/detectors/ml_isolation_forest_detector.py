from __future__ import annotations

from typing import List, Optional

import math
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ...domain.entities.log_entry import LogEntry
from ...domain.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult


class IsolationForestDetector(AnomalyDetector):
    """
    ML-based anomaly detector using Isolation Forest.

    - Loads a pre-trained model from disk if available.
    - If no model is found, trains unsupervised on the incoming batch
      (assumes majority are normal) and then scores.
    - Returns an aggregate batch score in [0, 1] and a threat flag when the
      maximum anomaly score in the batch exceeds the configured threshold.
    """

    def __init__(
        self,
        model_path: str = "models/isoforest.joblib",
        random_state: int = 42,
        contamination: float = 0.1,
        threshold: float = 0.7,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
    ) -> None:
        self.model_path = model_path
        self.random_state = random_state
        self.contamination = contamination
        self.threshold = threshold
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self._model: Optional[IsolationForest] = None
        self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        if self._model is not None:
            return
        if os.path.exists(self.model_path):
            try:
                self._model = joblib.load(self.model_path)
            except Exception:
                # Corrupted or incompatible model: ignore and lazily re-train when needed
                self._model = None

    def _build_model(self) -> IsolationForest:
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples=self.max_samples,
            n_jobs=-1,
        )

    def _encode_logs(self, logs: List[LogEntry]) -> np.ndarray:
        """Transform LogEntry list into numeric feature matrix.

        Minimal featurization to keep dependencies small and inference fast.
        """
        methods = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "HEAD": 5, "OPTIONS": 6}

        def ip_to_nums(ip: str) -> List[float]:
            try:
                parts = [float(p) for p in ip.split(".")]
                if len(parts) == 4:
                    return parts
            except Exception:
                pass
            return [0.0, 0.0, 0.0, 0.0]

        X: List[List[float]] = []
        for entry in logs:
            ip_nums = ip_to_nums(entry.ip)
            method_idx = float(methods.get(entry.method.upper(), -1))
            path_len = float(len(entry.path))
            has_query = 1.0 if ("?" in entry.path) else 0.0
            status = float(entry.status)
            ua_len = float(len(entry.user_agent)) if entry.user_agent else 0.0
            resp_ms = float(entry.response_time_ms) if entry.response_time_ms is not None else -1.0
            # Basic transformations
            log_status = math.log1p(status)
            log_resp = math.log1p(resp_ms) if resp_ms >= 0 else 0.0

            X.append(
                [
                    *ip_nums,           # 4
                    method_idx,         # 1
                    path_len,           # 1
                    has_query,          # 1
                    log_status,         # 1
                    ua_len,             # 1
                    log_resp,           # 1
                ]
            )

        return np.asarray(X, dtype=float)

    def _fit_if_needed(self, X: np.ndarray) -> None:
        if self._model is None:
            self._model = self._build_model()
            # Unsupervised fit assuming majority of batch is normal
            self._model.fit(X)
            # Best-effort save for reuse
            try:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump(self._model, self.model_path)
            except Exception:
                pass

    @staticmethod
    def _to_01_range(raw_scores: np.ndarray) -> np.ndarray:
        """Map IsolationForest scores to [0,1] where higher => more anomalous.

        sklearn's score_samples: higher is more normal. decision_function: higher is more normal.
        We invert and min-max within the batch for a stable [0,1] signal.
        """
        if raw_scores.size == 0:
            return raw_scores
        inverted = -raw_scores
        min_v = float(np.min(inverted))
        max_v = float(np.max(inverted))
        if max_v == min_v:
            return np.zeros_like(inverted)
        return (inverted - min_v) / (max_v - min_v)

    def analyze(self, logs: List[LogEntry]) -> AnomalyResult:
        if not logs:
            return {"is_threat": False, "score": 0.0}

        X = self._encode_logs(logs)
        self._fit_if_needed(X)
        assert self._model is not None

        # Use score_samples for better resolution; higher means more normal
        raw_scores = self._model.score_samples(X)
        scores_01 = self._to_01_range(raw_scores)
        max_score = float(np.max(scores_01)) if scores_01.size else 0.0
        is_threat = max_score >= self.threshold
        return {"is_threat": is_threat, "score": round(max_score, 4)}

    # Public training API for service/endpoint usage
    def fit(self, logs: List[LogEntry]) -> None:
        if not logs:
            return
        X = self._encode_logs(logs)
        self._model = self._build_model()
        self._model.fit(X)
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self._model, self.model_path)
        except Exception:
            pass


