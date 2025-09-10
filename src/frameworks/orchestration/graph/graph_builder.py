"""
Constructor de grafos LangGraph.

Esta clase es responsable de construir el grafo de LangGraph
con todos los nodos y edges necesarios para el pipeline.
"""

from typing import Dict, Any, Optional
from langgraph.graph import StateGraph, END
from ..agents import (
    LangGraphAgentState,
    SupervisedAgent,
    UnsupervisedAgent,
    DecisionAgent,
    ReportAgent
)
from .flow_router import FlowRouter
from ....application.interfaces.threat_detector_interface import ThreatDetectorInterface


class LangGraphBuilder:
    """Constructor de grafos LangGraph para el pipeline de agentes."""
    
    def __init__(self, threat_detector: ThreatDetectorInterface):
        self.agents = {
            "supervised_agent": SupervisedAgent(threat_detector),
            "unsupervised_agent": UnsupervisedAgent(),
            "decision_agent": DecisionAgent(),
            "report_agent": ReportAgent()
        }
        self.flow_router = FlowRouter()
    
    def build_graph(self) -> StateGraph:
        """Construye el grafo completo de LangGraph."""
        print("🏗️ [LANGGRAPH] Construyendo grafo de agentes...")
        
        # Crear el grafo
        workflow = StateGraph(LangGraphAgentState)
        
        # Agregar nodos (agentes)
        self._add_nodes(workflow)
        
        # Configurar flujo
        self._configure_flow(workflow)
        
        # Compilar el grafo
        return workflow.compile()
    
    def _add_nodes(self, workflow: StateGraph) -> None:
        """Agrega todos los nodos de agentes al grafo."""
        workflow.add_node("supervised_agent", self._create_node_wrapper("supervised_agent"))
        workflow.add_node("unsupervised_agent", self._create_node_wrapper("unsupervised_agent"))
        workflow.add_node("decision_agent", self._create_node_wrapper("decision_agent"))
        workflow.add_node("report_agent", self._create_node_wrapper("report_agent"))
    
    def _configure_flow(self, workflow: StateGraph) -> None:
        """Configura el flujo del grafo con edges condicionales."""
        # Punto de entrada
        workflow.set_entry_point("supervised_agent")
        
        # Edges condicionales
        workflow.add_conditional_edges(
            "supervised_agent",
            self.flow_router.route_after_supervised,
            {
                "decision": "decision_agent",
                "unsupervised": "unsupervised_agent"
            }
        )
        
        workflow.add_conditional_edges(
            "unsupervised_agent",
            self.flow_router.route_after_unsupervised,
            {
                "decision": "decision_agent",
                "report": "report_agent"
            }
        )
        
        # Edges fijos
        workflow.add_edge("decision_agent", "report_agent")
        workflow.add_edge("report_agent", END)
    
    def _create_node_wrapper(self, agent_name: str):
        """Crea un wrapper para el nodo del agente."""
        def node_wrapper(state: LangGraphAgentState) -> LangGraphAgentState:
            agent = self.agents[agent_name]
            return agent.execute(state)
        return node_wrapper
