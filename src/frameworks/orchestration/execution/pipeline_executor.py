"""
Ejecutor de pipelines LangGraph.

Esta clase es responsable de ejecutar el pipeline
y manejar los errores durante la ejecución.
"""

from typing import Dict, Any, List, Optional
from langgraph.graph import StateGraph
from src.domain.entities.agent import AgentContext
from src.domain.entities.pipeline import PipelineExecution, PipelineStatus
from ..agents import LangGraphAgentState
from .result_builder import PipelineResultBuilder


class LangGraphPipelineExecutor:
    """Ejecutor de pipelines LangGraph."""
    
    def __init__(self):
        self.result_builder = PipelineResultBuilder()
    
    def execute_pipeline(
        self, 
        graph: StateGraph, 
        logs: List[Dict[str, Any]], 
        context: Optional[AgentContext] = None
    ) -> PipelineExecution:
        """Ejecuta el pipeline completo usando LangGraph."""
        print(f"🚀 [LANGGRAPH] Iniciando pipeline con {len(logs)} logs...")
        
        # Crear estado inicial
        initial_state = self._create_initial_state(logs, context)
        
        try:
            # Ejecutar el grafo
            print("🔄 [LANGGRAPH] Ejecutando flujo de agentes...")
            final_state = graph.invoke(initial_state)
            
            # Construir resultado exitoso
            return self.result_builder.build_success_result(final_state, context)
            
        except Exception as e:
            print(f"❌ [LANGGRAPH] Error en pipeline: {str(e)}")
            return self.result_builder.build_error_result(e, context)
    
    def _create_initial_state(self, logs: List[Dict[str, Any]], context: Optional[AgentContext]) -> LangGraphAgentState:
        """Crea el estado inicial para el pipeline."""
        return {
            "logs": logs,
            "current_agent": None,
            "agent_results": {},
            "final_decision": None,
            "trace_id": context.trace_id if context else "langgraph_trace",
            "execution_path": []
        }
