from abc import ABC, abstractmethod
from typing import List, TypedDict, Dict, Any
from ...domain.entities.log_entry import LogEntry


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
    
    @abstractmethod
    def fit_from_dataset(self, dataset_path: str) -> Dict[str, Any]:
        """Train the anomaly detection model from a dataset file."""
        raise NotImplementedError
    
    @abstractmethod
    def is_ready(self) -> bool:
        """Check if the model is ready for inference."""
        raise NotImplementedError


