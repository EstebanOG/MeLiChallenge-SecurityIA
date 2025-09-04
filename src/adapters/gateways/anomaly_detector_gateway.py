"""
Gateway para detección de anomalías.

Implementa la interfaz AnomalyDetector usando el framework ML.
"""

from typing import List
from ...application.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult
from ...domain.entities.log_entry import LogEntry
from ...frameworks.ml.ml_isolation_forest_detector import IsolationForestDetector


class AnomalyDetectorGateway(AnomalyDetector):
    """Gateway que implementa AnomalyDetector usando Isolation Forest."""
    
    def __init__(self):
        self.detector = IsolationForestDetector()
    
    def detect_anomalies(self, logs: List[LogEntry]) -> AnomalyResult:
        """Detecta anomalías en una lista de logs."""
        return self.detector.detect_anomalies(logs)
    
    def fit(self, logs: List[LogEntry]) -> None:
        """Entrena el modelo con los logs proporcionados."""
        self.detector.fit(logs)
