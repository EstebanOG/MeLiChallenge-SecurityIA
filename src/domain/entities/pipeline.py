from __future__ import annotations
from typing import Any, Dict, List, Optional, TypedDict
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from .agent import AgentType, AgentStatus, AgentContext, AgentResult


class PipelineStatus(Enum):
    """Estados posibles de un pipeline."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineType(Enum):
    """Tipos de pipelines disponibles."""
    THREAT_DETECTION = "threat_detection"
    LOG_ANALYSIS = "log_analysis"
    INCIDENT_RESPONSE = "incident_response"
    CUSTOM = "custom"


@dataclass
class PipelineConfig:
    """Configuración de un pipeline."""
    pipeline_type: PipelineType
    agent_sequence: List[AgentType]
    timeout_seconds: int = 300
    retry_attempts: int = 3
    parallel_execution: bool = False
    fail_fast: bool = True
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class PipelineState(TypedDict):
    """Estado del pipeline para LangGraph."""
    logs: List[Dict[str, Any]]
    trace_id: str
    session_id: str
    pipeline_config: Dict[str, Any]
    context: Dict[str, Any]
    agent_results: Dict[str, AgentResult]
    current_agent: Optional[str]
    pipeline_status: str
    error_message: Optional[str]
    created_at: str
    updated_at: str


@dataclass
class PipelineExecution:
    """Ejecución completa de un pipeline."""
    execution_id: str
    pipeline_config: PipelineConfig
    context: AgentContext
    status: PipelineStatus
    agent_results: List[AgentResult]
    total_execution_time_ms: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    @property
    def is_successful(self) -> bool:
        return self.status == PipelineStatus.COMPLETED
    
    @property
    def is_failed(self) -> bool:
        return self.status == PipelineStatus.FAILED
    
    @property
    def has_failed_agents(self) -> bool:
        return any(result.is_failed for result in self.agent_results)
    
    def get_agent_result(self, agent_type: AgentType) -> Optional[AgentResult]:
        """Obtiene el resultado de un agente específico."""
        for result in self.agent_results:
            if result.agent_type == agent_type:
                return result
        return None
