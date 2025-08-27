from typing import List
from ...domain.entities.log_entry import LogEntry
from ...domain.interfaces.anomaly_detector import AnomalyDetector, AnomalyResult


class SimpleRuleDetector(AnomalyDetector):
    """
    Minimal detector placeholder. Flags a threat if >= 3 requests to the same path
    from the same IP within the provided batch, or status codes >= 500 present.
    Returns a simple score in [0,1].
    """

    def analyze(self, logs: List[LogEntry]) -> AnomalyResult:
        if not logs:
            return {"is_threat": False, "score": 0.0}

        ip_path_counts = {}
        has_server_error = any(entry.status >= 500 for entry in logs)

        for entry in logs:
            key = (entry.ip, entry.path)
            ip_path_counts[key] = ip_path_counts.get(key, 0) + 1

        burst = max(ip_path_counts.values()) if ip_path_counts else 0
        score = 0.0
        if burst >= 3:
            score = max(score, 0.7)
        if has_server_error:
            score = max(score, 0.6)

        return {"is_threat": score >= 0.7, "score": score}


