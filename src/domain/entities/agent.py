from __future__ import annotations
from typing import Any, Dict, List, Optional, TypedDict
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class AgentType(Enum):
    """Tipos de agentes disponibles en el sistema."""
    INGESTION = "ingestion"
    ANALYSIS = "analysis"
    DECISION = "decision"
    NOTIFICATION = "notification"
    REMEDIATION = "remediation"


class AgentStatus(Enum):
    """Estados posibles de un agente."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AgentContext:
    """Contexto compartido entre agentes en un pipeline."""
    trace_id: str
    session_id: str
    created_at: datetime
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow()


@dataclass
class AgentResult:
    """Resultado de la ejecución de un agente."""
    agent_type: AgentType
    status: AgentStatus
    output: Dict[str, Any]
    execution_time_ms: float
    error_message: Optional[str] = None
    confidence: Optional[float] = None
    
    @property
    def is_successful(self) -> bool:
        return self.status == AgentStatus.COMPLETED
    
    @property
    def is_failed(self) -> bool:
        return self.status == AgentStatus.FAILED


class IngestionOutput(TypedDict):
    """Output específico del agente de ingesta."""
    trace_id: str
    received: int
    logs: List[Dict[str, Any]]
    received_at: str
    validation_errors: List[str]


class AnalysisOutput(TypedDict):
    """Output específico del agente de análisis."""
    trace_id: str
    batch_score: float
    individual_scores: List[float]
    threat_detected: bool
    confidence: float
    analysis_metadata: Dict[str, Any]


class DecisionOutput(TypedDict):
    """Output específico del agente de decisión."""
    trace_id: str
    is_threat: bool
    confidence: float
    action_suggested: str
    explanation: str
    risk_level: str
    recommended_actions: List[str]


class NotificationOutput(TypedDict):
    """Output específico del agente de notificación."""
    trace_id: str
    notification_sent: bool
    channels_used: List[str]
    recipients: List[str]
    message: str


class RemediationOutput(TypedDict):
    """Output específico del agente de remediación."""
    trace_id: str
    actions_taken: List[str]
    success: bool
    rollback_available: bool
    next_steps: List[str]

