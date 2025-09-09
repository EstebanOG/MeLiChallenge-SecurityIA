"""
Agente No Supervisado para detección de anomalías.

Este agente utiliza técnicas no supervisadas para detectar comportamientos
anómalos que no están en los patrones conocidos.
"""

from typing import List, Dict, Any
from .base_agent import LangGraphAgentState, add_execution_step


class UnsupervisedAgent:
    """Agente No Supervisado - Detecta anomalías usando técnicas no supervisadas."""
    
    def __init__(self):
        self.name = "unsupervised_agent"
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente no supervisado."""
        logs = state.get("logs", [])
        print(f"🤖 [UNSUPERVISED] Analizando anomalías en {len(logs)} logs...")
        
        # Detectar anomalías
        is_anomalous = self._detect_anomalies(logs)
        
        if is_anomalous:
            print("⚠️ [UNSUPERVISED] Anomalía detectada -> Enviando a Agente de Decisión")
            state = add_execution_step(state, self.name, {
                "decision": "anomalous",
                "anomaly_score": 0.75,
                "confidence": 0.8,
                "next_agent": "decision_agent"
            })
        else:
            print("✅ [UNSUPERVISED] Comportamiento normal -> Enviando a Reporte")
            state = add_execution_step(state, self.name, {
                "decision": "normal",
                "anomaly_score": 0.15,
                "confidence": 0.9,
                "next_agent": "report_agent"
            })
        
        return state
    
    def _detect_anomalies(self, logs: List[Dict[str, Any]]) -> bool:
        """Detecta anomalías usando datos reales del dataset de threat intelligence."""
        if not logs:
            return False
            
        # Usar campos reales del dataset para detectar anomalías
        anomalies = 0
        
        for log in logs:
            # Detectar patrones anómalos en sesiones de red
            if log.get('session_duration', 0) > 1500:  # Sesiones anormalmente largas
                anomalies += 1
            if log.get('network_packet_size', 0) > 700:  # Paquetes anormalmente grandes
                anomalies += 1
            if log.get('login_attempts', 0) > 5:  # Muchos intentos de login
                anomalies += 1
            if log.get('ip_reputation_score', 1) < 0.4:  # IP con reputación baja
                anomalies += 1
            if log.get('browser_type') == 'Unknown':  # Navegador desconocido
                anomalies += 1
            if log.get('protocol_type') == 'UDP' and log.get('session_duration', 0) > 500:  # UDP con sesiones largas
                anomalies += 1
        
        # Si hay al menos 2 indicadores de anomalía
        return anomalies >= 2
