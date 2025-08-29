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

        Adapted for IoT/smart systems dataset with device metrics.
        """
        # Mapeo de tipos de dispositivo a números
        device_types = {
            "thermostat": 0, "smart": 1, "sensor": 2, "camera": 3, 
            "lock": 4, "hub": 5, "appliance": 6, "wearable": 7
        }

        X: List[List[float]] = []
        for entry in logs:
            # Tipo de dispositivo
            device_type_idx = float(device_types.get(entry.device_type.lower(), -1))
            
            # Métricas de rendimiento
            cpu_usage = float(entry.cpu_usage)
            memory_usage = float(entry.memory_usage)
            
            # Métricas de red
            network_in = float(entry.network_in_kb)
            network_out = float(entry.network_out_kb)
            packet_rate = float(entry.packet_rate)
            
            # Métricas de respuesta
            response_time = float(entry.avg_response_time_ms)
            service_count = float(entry.service_access_count)
            
            # Métricas de seguridad
            failed_auth = float(entry.failed_auth_attempts)
            is_encrypted = float(entry.is_encrypted)
            geo_variation = float(entry.geo_location_variation)
            
            # Transformaciones logarítmicas para valores que pueden ser muy grandes
            log_network_in = math.log1p(network_in)
            log_network_out = math.log1p(network_out)
            log_packet_rate = math.log1p(packet_rate)
            log_response_time = math.log1p(response_time) if response_time >= 0 else 0.0
            log_service_count = math.log1p(service_count)
            log_failed_auth = math.log1p(failed_auth + 1)  # +1 para evitar log(0)
            
            # Normalización de porcentajes (CPU y memoria ya están en 0-100)
            cpu_norm = cpu_usage / 100.0
            memory_norm = memory_usage / 100.0

            X.append([
                device_type_idx,      # 1 - Tipo de dispositivo
                cpu_norm,             # 1 - CPU normalizado (0-1)
                memory_norm,          # 1 - Memoria normalizada (0-1)
                log_network_in,       # 1 - Log de tráfico de entrada
                log_network_out,      # 1 - Log de tráfico de salida
                log_packet_rate,      # 1 - Log de tasa de paquetes
                log_response_time,    # 1 - Log de tiempo de respuesta
                log_service_count,    # 1 - Log de conteo de servicios
                log_failed_auth,      # 1 - Log de intentos fallidos de autenticación
                is_encrypted,         # 1 - Indicador de encriptación
                geo_variation,        # 1 - Variación de ubicación geográfica
            ])

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


