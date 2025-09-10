"""
Clases base para agentes de LangGraph.

Este módulo contiene las clases y funciones base que son compartidas
por todos los agentes del pipeline.
"""

from typing import Dict, Any, List
from typing_extensions import TypedDict


class LangGraphAgentState(TypedDict):
    """Estado compartido entre agentes de LangGraph."""
    logs: List[Dict[str, Any]]
    current_agent: str
    agent_results: Dict[str, Any]
    final_decision: Any
    trace_id: str
    execution_path: List[str]


def add_execution_step(state: LangGraphAgentState, agent_name: str, result: Dict[str, Any]) -> LangGraphAgentState:
    """
    Agrega un paso de ejecución al estado.
    
    Args:
        state: Estado actual del pipeline
        agent_name: Nombre del agente que ejecutó
        result: Resultado de la ejecución
        
    Returns:
        Estado actualizado
    """
    # Agregar a la ruta de ejecución
    execution_path = state.get("execution_path", [])
    execution_path.append(agent_name)
    state["execution_path"] = execution_path
    
    # Agregar resultado
    agent_results = state.get("agent_results", {})
    agent_results[agent_name] = result
    state["agent_results"] = agent_results
    
    # Actualizar agente actual
    state["current_agent"] = agent_name
    
    return state
