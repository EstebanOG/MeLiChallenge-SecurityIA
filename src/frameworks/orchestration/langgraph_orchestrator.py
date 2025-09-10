"""
Orquestador LangGraph para el pipeline de detección de amenazas.

Este módulo implementa el flujo de agentes usando LangGraph:
A[Input Log] --> B[Agente Supervisado] --> C[Agente de Decisión] o D[Agente No Supervisado]
"""

from typing import Dict, Any, List, Optional, TYPE_CHECKING
from src.domain.entities.agent import AgentContext
from src.domain.entities.pipeline import PipelineExecution
from src.application.interfaces.pipeline_orchestrator import PipelineOrchestrator
from src.application.interfaces.threat_detector_interface import ThreatDetectorInterface
from .graph import LangGraphBuilder
from .execution import LangGraphPipelineExecutor

if TYPE_CHECKING:
    from src.domain.entities.pipeline import PipelineConfig, PipelineState


class LangGraphPipelineOrchestrator(PipelineOrchestrator):
    """Orquestador que usa LangGraph para ejecutar el pipeline de agentes."""
    
    def __init__(self, threat_detector: ThreatDetectorInterface):
        self.graph_builder = LangGraphBuilder(threat_detector)
        self.pipeline_executor = LangGraphPipelineExecutor()
        self._graph = None
    
    @property
    def graph(self):
        """Lazy loading del grafo."""
        if self._graph is None:
            self._graph = self.graph_builder.build_graph()
        return self._graph
    
    def execute_pipeline(
        self, 
        logs: List[Dict[str, Any]], 
        context: Optional[AgentContext] = None
    ) -> PipelineExecution:
        """Ejecuta el pipeline completo usando LangGraph."""
        return self.pipeline_executor.execute_pipeline(
            graph=self.graph,
            logs=logs,
            context=context
        )
    
    def execute_step(
        self, 
        state: 'PipelineState', 
        agent_type: str
    ) -> 'PipelineState':
        """Ejecuta un paso individual del pipeline."""
        # Esta implementación no es necesaria para LangGraph
        # ya que el grafo maneja la ejecución completa
        raise NotImplementedError("LangGraph maneja la ejecución completa del pipeline")
    
    def get_pipeline_status(self, execution_id: str) -> str:
        """Obtiene el estado de un pipeline en ejecución."""
        # Esta implementación no es necesaria para LangGraph
        # ya que la ejecución es síncrona
        raise NotImplementedError("LangGraph ejecuta pipelines de forma síncrona")
    
    def validate_pipeline_config(self, config: 'PipelineConfig') -> List[str]:
        """Valida la configuración de un pipeline."""
        # Para LangGraph, la configuración es fija, así que siempre es válida
        return []