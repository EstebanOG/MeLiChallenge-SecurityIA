from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from ...domain.entities.agent import AgentContext, AgentResult, AgentType
from ...domain.entities.pipeline import PipelineState


class AgentExecutor(ABC):
    """Interfaz para la ejecución de agentes individuales."""
    
    @abstractmethod
    def execute(
        self, 
        agent_type: AgentType, 
        state: PipelineState, 
        context: AgentContext
    ) -> AgentResult:
        """Ejecuta un agente específico con el estado y contexto dados."""
        raise NotImplementedError
    
    @abstractmethod
    def can_handle(self, agent_type: AgentType) -> bool:
        """Verifica si este executor puede manejar el tipo de agente."""
        raise NotImplementedError


class AgentValidator(ABC):
    """Interfaz para validación de agentes."""
    
    @abstractmethod
    def validate_input(self, agent_type: AgentType, state: PipelineState) -> List[str]:
        """Valida la entrada para un agente específico."""
        raise NotImplementedError
    
    @abstractmethod
    def validate_output(self, agent_type: AgentType, result: AgentResult) -> List[str]:
        """Valida la salida de un agente específico."""
        raise NotImplementedError


class AgentRegistry(ABC):
    """Interfaz para el registro de agentes."""
    
    @abstractmethod
    def register_agent(self, agent_type: AgentType, executor: AgentExecutor) -> None:
        """Registra un executor para un tipo de agente."""
        raise NotImplementedError
    
    @abstractmethod
    def get_executor(self, agent_type: AgentType) -> Optional[AgentExecutor]:
        """Obtiene el executor para un tipo de agente."""
        raise NotImplementedError
    
    @abstractmethod
    def list_available_agents(self) -> List[AgentType]:
        """Lista todos los agentes disponibles."""
        raise NotImplementedError
