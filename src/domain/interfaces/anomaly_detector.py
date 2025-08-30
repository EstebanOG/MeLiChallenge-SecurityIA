from abc import ABC, abstractmethod
from typing import List, TypedDict
from ..entities.log_entry import LogEntry


class AnomalyResult(TypedDict):
    batch_score: float
    threat_detected: bool
    anomaly_scores: List[float]
    confidence: float


class AnomalyDetector(ABC):
    @abstractmethod
    def detect_anomalies(self, logs: List[LogEntry]) -> AnomalyResult:
        """Return anomaly detection results for a batch of logs."""
        raise NotImplementedError
    
    @abstractmethod
    def fit(self, logs: List[LogEntry]) -> None:
        """Train the anomaly detection model with the provided logs."""
        raise NotImplementedError


