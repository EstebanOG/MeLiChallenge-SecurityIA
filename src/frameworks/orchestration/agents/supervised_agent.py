"""
Agente Supervisado para detección de amenazas conocidas.

Este agente utiliza técnicas supervisadas para detectar ataques conocidos
usando el framework LangGraph.
"""

from typing import List, Dict, Any, Optional
from .base_agent import LangGraphAgentState, add_execution_step
from src.application.interfaces.threat_detector_interface import ThreatDetectorInterface


class SupervisedAgent:
    """Agente Supervisado - Detecta amenazas conocidas usando técnicas supervisadas."""
    
    def __init__(self, threat_detector: ThreatDetectorInterface):
        self.name = "supervised_agent"
        self.threat_detector = threat_detector
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente supervisado."""
        logs = state.get("logs", [])
        
        # Verificar si el modelo está entrenado
        if not self.threat_detector.is_ready():
            raise ValueError("El modelo ML no está entrenado. Entrena el modelo primero usando POST /train/supervised")
        
        # Usar el detector para detectar amenazas
        prediction = self.threat_detector.predict(logs)
        
        is_attack = prediction['is_attack']
        confidence = prediction['confidence']
        probability = prediction['probability']
        reasoning = prediction['reasoning']
    
        if is_attack:
            threat_level = "high" if probability > 0.8 else "medium"
            state = add_execution_step(state, self.name, {
                "decision": "attack_known",
                "confidence": confidence,
                "probability": probability,
                "threat_level": threat_level,
                "reasoning": reasoning,
                "next_agent": "decision_agent"
            })
        else:
            state = add_execution_step(state, self.name, {
                "decision": "normal",
                "confidence": confidence,
                "probability": probability,
                "threat_level": "low",
                "reasoning": reasoning,
                "next_agent": "unsupervised_agent"
            })
        
        return state
    
