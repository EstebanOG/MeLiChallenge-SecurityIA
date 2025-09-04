from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from ...domain.entities.agent import AgentContext
from ...domain.entities.pipeline import PipelineConfig, PipelineExecution, PipelineState


class PipelineOrchestrator(ABC):
    """Interfaz para la orquestación de pipelines de agentes."""
    
    @abstractmethod
    def execute_pipeline(
        self, 
        config: PipelineConfig, 
        logs: List[Dict[str, Any]], 
        context: Optional[AgentContext] = None
    ) -> PipelineExecution:
        """Ejecuta un pipeline completo con la configuración dada."""
        raise NotImplementedError
    
    @abstractmethod
    def execute_step(
        self, 
        state: PipelineState, 
        agent_type: str
    ) -> PipelineState:
        """Ejecuta un paso individual del pipeline."""
        raise NotImplementedError
    
    @abstractmethod
    def validate_pipeline_config(self, config: PipelineConfig) -> List[str]:
        """Valida la configuración de un pipeline."""
        raise NotImplementedError


class PipelineStateManager(ABC):
    """Interfaz para el manejo del estado del pipeline."""
    
    @abstractmethod
    def create_initial_state(
        self, 
        logs: List[Dict[str, Any]], 
        config: PipelineConfig, 
        context: AgentContext
    ) -> PipelineState:
        """Crea el estado inicial del pipeline."""
        raise NotImplementedError
    
    @abstractmethod
    def update_state(
        self, 
        state: PipelineState, 
        agent_result: Dict[str, Any]
    ) -> PipelineState:
        """Actualiza el estado del pipeline con el resultado de un agente."""
        raise NotImplementedError
    
    @abstractmethod
    def get_pipeline_result(self, state: PipelineState) -> Dict[str, Any]:
        """Extrae el resultado final del pipeline del estado."""
        raise NotImplementedError


class PipelineMetrics(ABC):
    """Interfaz para métricas de pipelines."""
    
    @abstractmethod
    def record_execution(
        self, 
        execution: PipelineExecution
    ) -> None:
        """Registra métricas de una ejecución de pipeline."""
        raise NotImplementedError
    
    @abstractmethod
    def get_agent_performance(self, agent_type: str) -> Dict[str, Any]:
        """Obtiene métricas de rendimiento de un agente específico."""
        raise NotImplementedError
    
    @abstractmethod
    def get_pipeline_performance(self, pipeline_type: str) -> Dict[str, Any]:
        """Obtiene métricas de rendimiento de un tipo de pipeline."""
        raise NotImplementedError
