from __future__ import annotations

from typing import List, Optional, Tuple
import math
import os
import json

# Importaciones condicionales para evitar errores
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("⚠️ joblib no disponible, el detector funcionará en modo básico")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️ numpy no disponible, el detector funcionará en modo básico")

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("⚠️ scikit-learn no disponible, el detector funcionará en modo básico")

from ...domain.entities.log_entry import LogEntry
from ...application.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult


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
        contamination: float = 0.2,
        threshold: float = 0.5,
        n_estimators: int = 200,
        max_samples: str | int = "auto",
        use_labeled_calibration: bool = True,
    ) -> None:
        self.model_path = model_path
        self.random_state = random_state
        self.contamination = contamination
        self.threshold = threshold
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.use_labeled_calibration = use_labeled_calibration
        self._model: Optional[IsolationForest] = None
        self._score_stats: Optional[dict] = None
        self._calibration_stats: Optional[dict] = None
        
        # Solo cargar modelo si las dependencias están disponibles
        if all([JOBLIB_AVAILABLE, NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        """Carga el modelo pre-entrenado si existe."""
        if self._model is not None or not JOBLIB_AVAILABLE:
            return
            
        if os.path.exists(self.model_path):
            try:
                self._model = joblib.load(self.model_path)
                print(f"✅ Modelo cargado desde: {self.model_path}")
                
                # Cargar estadísticas si existen
                stats_path = self.model_path.replace('.joblib', '_stats.json')
                if os.path.exists(stats_path):
                    with open(stats_path, 'r') as f:
                        self._score_stats = json.load(f)
                
                calib_path = self.model_path.replace('.joblib', '_calibration.json')
                if os.path.exists(calib_path):
                    with open(calib_path, 'r') as f:
                        self._calibration_stats = json.load(f)
                        
            except Exception as e:
                print(f"⚠️ Error cargando modelo: {e}")
                self._model = None

    def _build_model(self) -> Optional[IsolationForest]:
        """Construye un nuevo modelo Isolation Forest."""
        if not SKLEARN_AVAILABLE:
            print("❌ scikit-learn no disponible para construir modelo")
            return None
            
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples=self.max_samples,
            n_jobs=-1,
        )

    def _encode_logs(self, logs: List[LogEntry]) -> Optional[np.ndarray]:
        """Transforma LogEntry list en matriz de features numéricas."""
        if not NUMPY_AVAILABLE:
            print("❌ numpy no disponible para encoding")
            return None
            
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
            network_in = float(entry.network_in_kb)
            network_out = float(entry.network_out_kb)
            packet_rate = float(entry.packet_rate)
            response_time = float(entry.avg_response_time_ms)
            service_count = float(entry.service_access_count)
            auth_failures = float(entry.failed_auth_attempts)
            is_encrypted = float(entry.is_encrypted)
            geo_variation = float(entry.geo_location_variation)
            
            # Features normalizados
            features = [
                device_type_idx / 7.0,  # Normalizar tipo de dispositivo
                cpu_usage / 100.0,      # CPU ya está en porcentaje
                memory_usage / 100.0,   # Memoria ya está en porcentaje
                network_in / 10000.0,   # Normalizar tráfico de red
                network_out / 10000.0,
                packet_rate / 1000.0,   # Normalizar tasa de paquetes
                response_time / 1000.0, # Normalizar tiempo de respuesta
                service_count / 100.0,  # Normalizar conteo de servicios
                auth_failures / 10.0,   # Normalizar fallos de autenticación
                is_encrypted,           # Ya está en [0,1]
                geo_variation / 100.0   # Normalizar variación geográfica
            ]
            X.append(features)
        
        return np.array(X)

    def fit(self, logs: List[LogEntry]) -> None:
        """Entrena el modelo con los logs proporcionados."""
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para entrenamiento")
            return
            
        if not logs:
            print("⚠️ No hay logs para entrenar")
            return
            
        print(f"🚀 Entrenando modelo con {len(logs)} logs...")
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            print("❌ Error preparando features")
            return
            
        # Construir y entrenar modelo
        self._model = self._build_model()
        if self._model is None:
            print("❌ Error construyendo modelo")
            return
            
        self._model.fit(X)
        print(f"✅ Modelo entrenado con {X.shape[1]} features")
        
        # Guardar modelo si es posible
        if JOBLIB_AVAILABLE:
            try:
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump(self._model, self.model_path)
                print(f"💾 Modelo guardado en: {self.model_path}")
            except Exception as e:
                print(f"⚠️ Error guardando modelo: {e}")

    def detect_anomalies(self, logs: List[LogEntry]) -> AnomalyResult:
        """Detecta anomalías en un lote de logs."""
        if not logs:
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[],
                confidence=0.0
            )
            
        if not all([NUMPY_AVAILABLE, SKLEARN_AVAILABLE]):
            print("❌ Dependencias no disponibles para detección")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )
        
        # Preparar features
        X = self._encode_logs(logs)
        if X is None:
            print("❌ Error preparando features")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )
        
        # Si no hay modelo, entrenar uno básico
        if self._model is None:
            print("⚠️ No hay modelo, entrenando uno básico...")
            self.fit(logs)
            if self._model is None:
                print("❌ Error entrenando modelo")
                return AnomalyResult(
                    batch_score=0.0,
                    threat_detected=False,
                    anomaly_scores=[0.0] * len(logs),
                    confidence=0.0
                )
        
        # Predecir anomalías
        try:
            anomaly_scores = self._model.score_samples(X)
            # Convertir scores a probabilidades (0 = normal, 1 = anómalo)
            anomaly_probs = 1.0 - anomaly_scores
            
            # Calcular score del batch
            batch_score = float(np.mean(anomaly_probs))
            
            # Detectar amenaza si algún score supera el umbral
            threat_detected = bool(np.any(anomaly_probs > self.threshold))
            
            # Calcular confianza basada en la varianza de los scores
            confidence = float(1.0 - np.std(anomaly_probs))
            
            return AnomalyResult(
                batch_score=batch_score,
                threat_detected=threat_detected,
                anomaly_scores=anomaly_probs.tolist(),
                confidence=confidence
            )
            
        except Exception as e:
            print(f"❌ Error durante detección: {e}")
            return AnomalyResult(
                batch_score=0.0,
                threat_detected=False,
                anomaly_scores=[0.0] * len(logs),
                confidence=0.0
            )


