from abc import ABC, abstractmethod
from typing import List, TypedDict
from ..entities.log_entry import LogEntry


class AnomalyResult(TypedDict):
    is_threat: bool
    score: float


class AnomalyDetector(ABC):
    @abstractmethod
    def analyze(self, logs: List[LogEntry]) -> AnomalyResult:
        """Return whether there is a threat in the batch and an anomaly score."""
        raise NotImplementedError


