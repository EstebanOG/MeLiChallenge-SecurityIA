"""
Estado del agente para el pipeline de detección de amenazas.

Define la estructura de datos que se pasa entre agentes
en el pipeline de detección de amenazas.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class AgentState:
    """Estado del agente en el pipeline de detección de amenazas."""
    
    logs: List[Dict[str, Any]]
    execution_steps: List[Dict[str, Any]]
    current_agent: Optional[str] = None
    final_decision: Optional[Dict[str, Any]] = None
    
    def get(self, key: str, default: Any = None) -> Any:
        """Obtiene un valor del estado."""
        return getattr(self, key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Establece un valor en el estado."""
        setattr(self, key, value)
