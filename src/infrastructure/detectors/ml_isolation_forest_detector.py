from __future__ import annotations

from typing import List, Optional, Tuple

import math
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support

from ...domain.entities.log_entry import LogEntry
from ...domain.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult


class IsolationForestDetector(AnomalyDetector):
    """
    ML-based anomaly detector using Isolation Forest.

    - Loads a pre-trained model from disk if available.
    - If no model is found, trains unsupervised on the incoming batch
      (assumes majority are normal) and then scores.
    - Can use labeled data for calibration and threshold optimization.
    - Returns an aggregate batch score in [0, 1] and a threat flag when the
      maximum anomaly score in the batch exceeds the configured threshold.
    """

    def __init__(
        self,
        model_path: str = "models/isoforest.joblib",
        random_state: int = 42,
        contamination: float = 0.2,  # Aumentado de 0.1 a 0.2 para coincidir con el dataset real
        threshold: float = 0.5,      # Reducido de 0.7 a 0.5 para detectar más anomalías
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        use_labeled_calibration: bool = True,  # Nuevo: usar datos etiquetados para calibración
    ) -> None:
        self.model_path = model_path
        self.random_state = random_state
        self.contamination = contamination
        self.threshold = threshold
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.use_labeled_calibration = use_labeled_calibration
        self._model: Optional[IsolationForest] = None
        self._score_stats: Optional[dict] = None  # Para almacenar estadísticas de scores
        self._calibration_stats: Optional[dict] = None  # Nuevo: estadísticas de calibración
        self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        if self._model is not None:
            return
        if os.path.exists(self.model_path):
            try:
                self._model = joblib.load(self.model_path)
                # Intentar cargar estadísticas de scores si existen
                stats_path = self.model_path.replace('.joblib', '_stats.json')
                if os.path.exists(stats_path):
                    import json
                    with open(stats_path, 'r') as f:
                        self._score_stats = json.load(f)
                
                # Intentar cargar estadísticas de calibración si existen
                calib_path = self.model_path.replace('.joblib', '_calibration.json')
                if os.path.exists(calib_path):
                    import json
                    with open(calib_path, 'r') as f:
                        self._calibration_stats = json.load(f)
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

    def _to_01_range(self, raw_scores: np.ndarray) -> np.ndarray:
        """Map IsolationForest scores to [0,1] where higher => more anomalous.

        Mejorada para usar estadísticas globales cuando están disponibles.
        """
        if raw_scores.size == 0:
            return raw_scores
        
        # Invertir scores (sklearn: higher = more normal, queremos: higher = more anomalous)
        inverted = -raw_scores
        
        # Si tenemos estadísticas globales, usarlas para normalización más estable
        if self._score_stats is not None:
            global_min = self._score_stats.get('min_score', float(np.min(inverted)))
            global_max = self._score_stats.get('max_score', float(np.max(inverted)))
            
            # Usar rango global pero permitir valores fuera del rango
            if global_max > global_min:
                # Normalizar usando rango global, pero permitir valores > 1 para anomalías extremas
                normalized = (inverted - global_min) / (global_max - global_min)
                # Clamp a [0, 1] para evitar valores negativos
                return np.clip(normalized, 0.0, 1.0)
        
        # Fallback a normalización por batch (método original)
        min_v = float(np.min(inverted))
        max_v = float(np.max(inverted))
        if max_v == min_v:
            return np.zeros_like(inverted)
        return (inverted - min_v) / (max_v - min_v)

    def _update_score_stats(self, scores: np.ndarray) -> None:
        """Actualiza estadísticas globales de scores para mejor normalización."""
        if scores.size == 0:
            return
            
        inverted = -scores  # Invertir para que higher = more anomalous
        
        if self._score_stats is None:
            self._score_stats = {
                'min_score': float(np.min(inverted)),
                'max_score': float(np.max(inverted)),
                'count': 0
            }
        else:
            self._score_stats['min_score'] = min(self._score_stats['min_score'], float(np.min(inverted)))
            self._score_stats['max_score'] = max(self._score_stats['max_score'], float(np.max(inverted)))
            self._score_stats['count'] += 1
        
        # Guardar estadísticas junto con el modelo
        try:
            stats_path = self.model_path.replace('.joblib', '_stats.json')
            import json
            with open(stats_path, 'w') as f:
                json.dump(self._score_stats, f)
        except Exception:
            pass

    def _calibrate_with_labeled_data(self, logs: List[LogEntry]) -> None:
        """Calibra el modelo usando datos etiquetados para optimizar el threshold."""
        if not self.use_labeled_calibration or not logs:
            return
            
        # Separar logs con y sin etiquetas
        labeled_logs = [log for log in logs if log.label is not None]
        if not labeled_logs:
            return
            
        print(f"🔧 Calibrando modelo con {len(labeled_logs)} muestras etiquetadas...")
        
        # Codificar logs etiquetados
        X_labeled = self._encode_logs(labeled_logs)
        
        # Obtener scores del modelo
        raw_scores = self._model.score_samples(X_labeled)
        scores_01 = self._to_01_range(raw_scores)
        
        # Crear etiquetas binarias (Normal = 0, Anomaly = 1)
        y_true = [1 if log.label != "Normal" else 0 for log in labeled_logs]
        
        # Probar diferentes thresholds para encontrar el óptimo
        thresholds = np.arange(0.1, 1.0, 0.05)
        best_f1 = 0.0
        best_threshold = self.threshold
        
        for threshold in thresholds:
            y_pred = [1 if score >= threshold else 0 for score in scores_01]
            
            # Calcular métricas
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_true, y_pred, average='binary', zero_division=0
            )
            
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold
        
        # Actualizar threshold si encontramos uno mejor
        if best_f1 > 0.0:
            old_threshold = self.threshold
            self.threshold = best_threshold
            print(f"🎯 Threshold optimizado: {old_threshold:.3f} → {best_threshold:.3f} (F1: {best_f1:.3f})")
            
            # Guardar estadísticas de calibración
            self._calibration_stats = {
                'best_threshold': best_threshold,
                'best_f1': best_f1,
                'labeled_samples': len(labeled_logs),
                'thresholds_tested': len(thresholds),
                'precision': precision,
                'recall': recall
            }
            
            try:
                calib_path = self.model_path.replace('.joblib', '_calibration.json')
                import json
                with open(calib_path, 'w') as f:
                    json.dump(self._calibration_stats, f)
            except Exception:
                pass

    def analyze(self, logs: List[LogEntry]) -> AnomalyResult:
        if not logs:
            return {"is_threat": False, "score": 0.0}

        X = self._encode_logs(logs)
        self._fit_if_needed(X)
        assert self._model is not None

        # Calibrar con datos etiquetados si están disponibles
        self._calibrate_with_labeled_data(logs)

        # Use score_samples for better resolution; higher means more normal
        raw_scores = self._model.score_samples(X)
        
        # Actualizar estadísticas globales
        self._update_score_stats(raw_scores)
        
        # Convertir a rango [0,1]
        scores_01 = self._to_01_range(raw_scores)
        max_score = float(np.max(scores_01)) if scores_01.size else 0.0
        
        # Usar threshold calibrado si está disponible, sino usar el original
        effective_threshold = self.threshold
        
        # Ajustar threshold dinámicamente basado en la distribución de scores si no hay calibración
        if self._calibration_stats is None and scores_01.size > 1:
            # Usar percentil 75 como threshold adaptativo si no hay estadísticas globales
            adaptive_threshold = np.percentile(scores_01, 75)
            effective_threshold = min(self.threshold, adaptive_threshold)
        
        is_threat = max_score >= effective_threshold
        
        return {"is_threat": is_threat, "score": round(max_score, 4)}

    # Public training API for service/endpoint usage
    def fit(self, logs: List[LogEntry]) -> None:
        if not logs:
            return
        X = self._encode_logs(logs)
        self._model = self._build_model()
        self._model.fit(X)
        
        # Calcular estadísticas iniciales de scores
        raw_scores = self._model.score_samples(X)
        self._update_score_stats(raw_scores)
        
        # Calibrar con datos etiquetados si están disponibles
        self._calibrate_with_labeled_data(logs)
        
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self._model, self.model_path)
        except Exception:
            pass

    def get_calibration_info(self) -> Optional[dict]:
        """Retorna información sobre la calibración del modelo."""
        return self._calibration_stats


