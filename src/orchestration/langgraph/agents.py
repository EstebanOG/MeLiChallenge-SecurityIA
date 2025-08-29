from __future__ import annotations

from typing import Any, Dict, List, TypedDict
import uuid
from datetime import datetime


class IngestionOutput(TypedDict):
    trace_id: str
    received: int
    logs: List[Dict[str, Any]]
    received_at: str


def ingestion_agent(logs: List[Dict[str, Any]], trace_id: str) -> IngestionOutput:
    """Very basic ingestion step: validate minimal keys and echo back.

    - Ensures required keys are present per existing `LogEntry` shape
    - Attaches timestamps and trace_id
    """
    required = {"timestamp", "ip", "method", "path", "status"}
    sanitized: List[Dict[str, Any]] = []
    for item in logs:
        if not required.issubset(item.keys()):
            # Skip malformed entries silently for now (could route to DLQ)
            continue
        sanitized.append({
            "timestamp": str(item["timestamp"]),
            "ip": str(item["ip"]),
            "method": str(item["method"]).upper(),
            "path": str(item["path"]),
            "status": int(item["status"]),
            "user_agent": item.get("user_agent"),
            "response_time_ms": item.get("response_time_ms"),
        })

    return {
        "trace_id": trace_id,
        "received": len(sanitized),
        "logs": sanitized,
        "received_at": datetime.utcnow().isoformat() + "Z",
    }


class DecisionOutput(TypedDict):
    trace_id: str
    is_threat: bool
    confidence: float
    action_suggested: str
    explanation: str


def decision_agent(ingestion: IngestionOutput, batch_score: float) -> DecisionOutput:
    """Simple decision rules on top of batch anomaly score.

    - Uses existing thresholding ideas; maps to action suggestion
    """
    score = float(batch_score)
    if score >= 0.9:
        action = "block"
        is_threat = True
        confidence = 0.95
    elif score >= 0.7:
        action = "alert"
        is_threat = True
        confidence = 0.85
    elif score >= 0.5:
        action = "investigate"
        is_threat = False
        confidence = 0.6
    else:
        action = "monitor"
        is_threat = False
        confidence = 0.5

    explanation = (
        f"Decision based on anomaly score={score:.3f} for batch of {ingestion['received']} logs"
    )

    return {
        "trace_id": ingestion["trace_id"],
        "is_threat": is_threat,
        "confidence": confidence,
        "action_suggested": action,
        "explanation": explanation,
    }


