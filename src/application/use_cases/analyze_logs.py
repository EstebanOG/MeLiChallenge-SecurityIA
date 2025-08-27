from dataclasses import dataclass
from typing import List, TypedDict
from ...domain.entities.log_entry import LogEntry
from ...domain.interfaces.anomaly_detector import AnomalyDetector


class AnalyzeResponse(TypedDict):
    is_threat: bool
    suggested_action: str
    score: float


@dataclass
class AnalyzeLogsUseCase:
    detector: AnomalyDetector

    def execute(self, logs: List[LogEntry]) -> AnalyzeResponse:
        result = self.detector.analyze(logs)
        is_threat = result["is_threat"]
        score = result["score"]
        action = "block" if is_threat else "ignore"
        return {
            "is_threat": is_threat,
            "suggested_action": action,
            "score": score,
        }


