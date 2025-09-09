"""
Constructor de resultados de pipeline.

Esta clase es responsable de construir los resultados
finales del pipeline en el formato esperado.
"""

from typing import Dict, Any, Optional
from datetime import datetime
from src.domain.entities.agent import AgentContext, AgentResult, AgentType
from src.domain.entities.pipeline import PipelineExecution, PipelineStatus
from ..agents import LangGraphAgentState


class PipelineResultBuilder:
    """Constructor de resultados de pipeline."""
    
    def build_success_result(self, final_state: LangGraphAgentState, context: Optional[AgentContext]) -> PipelineExecution:
        """Construye un resultado exitoso del pipeline."""
        execution_path = final_state.get("execution_path", [])
        execution_id = f"langgraph_{final_state.get('trace_id', 'unknown')}"
        
        # Crear contexto si no existe
        if not context:
            context = self._create_default_context(final_state)
        
        # Crear agent results
        agent_results = self._build_agent_results(final_state, execution_path)
        
        return PipelineExecution(
            execution_id=execution_id,
            pipeline_config=None,
            context=context,
            status=PipelineStatus.COMPLETED,
            agent_results=agent_results,
            total_execution_time_ms=100.0,
            started_at=context.created_at,
            completed_at=context.created_at
        )
    
    def build_error_result(self, error: Exception, context: Optional[AgentContext]) -> PipelineExecution:
        """Construye un resultado de error del pipeline."""
        # Crear contexto si no existe
        if not context:
            context = self._create_error_context()
        
        return PipelineExecution(
            execution_id=f"langgraph_error_{context.trace_id}",
            pipeline_config=None,
            context=context,
            status=PipelineStatus.FAILED,
            agent_results=[],
            total_execution_time_ms=0.0,
            started_at=context.created_at,
            completed_at=context.created_at,
            error_message=str(error)
        )
    
    def _create_default_context(self, final_state: LangGraphAgentState) -> AgentContext:
        """Crea un contexto por defecto."""
        return AgentContext(
            trace_id=final_state.get('trace_id', 'unknown'),
            session_id="langgraph_session",
            created_at=datetime.utcnow(),
            metadata={"source": "langgraph_orchestrator"}
        )
    
    def _create_error_context(self) -> AgentContext:
        """Crea un contexto para errores."""
        return AgentContext(
            trace_id="langgraph_error_trace",
            session_id="langgraph_error_session",
            created_at=datetime.utcnow(),
            metadata={"source": "langgraph_orchestrator", "error": True}
        )
    
    def _build_agent_results(self, final_state: LangGraphAgentState, execution_path: list) -> list:
        """Construye la lista de resultados de agentes."""
        from src.domain.entities.agent import AgentResult, AgentType
        
        agent_results = []
        agent_results_dict = final_state.get('agent_results', {})
        
        for agent_name in execution_path:
            agent_type = self._map_agent_name_to_type(agent_name)
            
            agent_results.append(AgentResult(
                agent_type=agent_type,
                status="completed",
                output=agent_results_dict.get(agent_name, {}),
                execution_time_ms=100.0,
                confidence=0.8
            ))
        
        return agent_results
    
    def _map_agent_name_to_type(self, agent_name: str) -> AgentType:
        """Mapea el nombre del agente a su tipo."""
        if "supervised" in agent_name:
            return AgentType.INGESTION
        elif "unsupervised" in agent_name:
            return AgentType.ANALYSIS
        elif "decision" in agent_name:
            return AgentType.DECISION
        elif "report" in agent_name:
            return AgentType.NOTIFICATION
        else:
            return AgentType.ANALYSIS  # Default
