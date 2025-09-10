"""
Router de flujo para LangGraph.

Esta clase maneja la lógica de routing entre agentes
basándose en los resultados de cada agente.
"""

from typing import Dict, Any
from ..agents import LangGraphAgentState


class FlowRouter:
    """Router que decide el siguiente paso en el flujo de agentes."""
    
    def route_after_supervised(self, state: LangGraphAgentState) -> str:
        """Router para decidir el siguiente paso después del agente supervisado."""
        agent_results = state.get("agent_results", {})
        supervised_result = agent_results.get("supervised_agent", {})
        decision = supervised_result.get("decision", "normal")
        
        if decision == "attack_known":
            return "decision"
        else:
            return "unsupervised"
    
    def route_after_unsupervised(self, state: LangGraphAgentState) -> str:
        """Router para decidir el siguiente paso después del agente no supervisado."""
        agent_results = state.get("agent_results", {})
        unsupervised_result = agent_results.get("unsupervised_agent", {})
        decision = unsupervised_result.get("decision", "normal")
        
        if decision == "anomalous":
            return "decision"
        else:
            return "report"
