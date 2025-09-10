"""
Interfaz para agentes de detección de amenazas.

Define el contrato que deben cumplir todos los agentes
del sistema de detección de amenazas.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from ..entities.agent_state import AgentState


class AgentInterface(ABC):
    """Interfaz base para todos los agentes de detección de amenazas."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre del agente."""
        pass
    
    @abstractmethod
    def execute(self, state: AgentState) -> AgentState:
        """Ejecuta el agente con el estado dado."""
        pass
    
    @abstractmethod
    def is_ready(self) -> bool:
        """Verifica si el agente está listo para ejecutarse."""
        pass
