"""
Implementación simple del registro de agentes.

Esta es una implementación básica para que funcione el sistema.
"""

from typing import Dict, Optional, Any, List
from ...domain.entities.agent import AgentType, AgentResult, AgentContext
from ...domain.entities.pipeline import PipelineState
from ...application.interfaces.agent_executor import AgentRegistry, AgentExecutor


class SimpleAgentExecutor(AgentExecutor):
    """Implementación simple de un ejecutor de agentes."""
    
    def __init__(self, agent_type: AgentType):
        self.agent_type = agent_type
    
    def can_handle(self, agent_type: AgentType) -> bool:
        """Verifica si puede manejar el tipo de agente."""
        return self.agent_type == agent_type
    
    def execute(
        self, 
        agent_type: AgentType, 
        state: PipelineState, 
        context: AgentContext
    ) -> AgentResult:
        """Ejecuta el agente."""
        # Implementación simple - solo retorna un resultado básico
        return AgentResult(
            agent_type=agent_type,
            status="completed",
            output={"processed": True, "agent_type": agent_type.value},
            execution_time_ms=100.0,
            confidence=0.8
        )


class SimpleAgentRegistry(AgentRegistry):
    """Implementación simple del registro de agentes."""
    
    def __init__(self):
        self._agents: Dict[AgentType, AgentExecutor] = {}
        # Registrar agentes básicos
        self._agents[AgentType.INGESTION] = SimpleAgentExecutor(AgentType.INGESTION)
        self._agents[AgentType.ANALYSIS] = SimpleAgentExecutor(AgentType.ANALYSIS)
        self._agents[AgentType.DECISION] = SimpleAgentExecutor(AgentType.DECISION)
    
    def register_agent(self, agent_type: AgentType, executor: AgentExecutor) -> None:
        """Registra un ejecutor de agente."""
        self._agents[agent_type] = executor
    
    def get_agent(self, agent_type: AgentType) -> Optional[AgentExecutor]:
        """Obtiene un ejecutor de agente."""
        return self._agents.get(agent_type)
    
    def list_agents(self) -> List[AgentType]:
        """Lista todos los tipos de agentes registrados."""
        return list(self._agents.keys())
    
    def get_executor(self, agent_type: AgentType) -> Optional[AgentExecutor]:
        """Obtiene el executor para un tipo de agente."""
        return self._agents.get(agent_type)
    
    def list_available_agents(self) -> List[AgentType]:
        """Lista todos los agentes disponibles."""
        return list(self._agents.keys())
