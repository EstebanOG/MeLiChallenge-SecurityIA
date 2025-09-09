"""
Agente Supervisado para detección de amenazas conocidas.

Este agente utiliza técnicas supervisadas para detectar ataques conocidos
basándose en patrones predefinidos del dataset de threat intelligence.
"""

from typing import List, Dict, Any
from .base_agent import LangGraphAgentState, add_execution_step


class SupervisedAgent:
    """Agente Supervisado - Detecta amenazas conocidas usando técnicas supervisadas."""
    
    def __init__(self):
        self.name = "supervised_agent"
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente supervisado."""
        logs = state.get("logs", [])
        print(f"🔍 [SUPERVISED] Procesando {len(logs)} logs...")
        
        # Detectar amenazas conocidas
        attack_known = self._classify_attack(logs)
        
        if attack_known:
            print("🚨 [SUPERVISED] Ataque conocido detectado -> Enviando a Agente de Decisión")
            state = add_execution_step(state, self.name, {
                "decision": "attack_known",
                "confidence": 0.85,
                "threat_level": "high",
                "next_agent": "decision_agent"
            })
        else:
            print("✅ [SUPERVISED] Comportamiento normal -> Enviando a No Supervisado")
            state = add_execution_step(state, self.name, {
                "decision": "normal",
                "confidence": 0.90,
                "threat_level": "low",
                "next_agent": "unsupervised_agent"
            })
        
        return state
    
    def _classify_attack(self, logs: List[Dict[str, Any]]) -> bool:
        """Clasifica ataques conocidos usando datos reales del dataset de threat intelligence."""
        if not logs:
            return False
            
        # Usar campos reales del dataset de threat intelligence
        attack_indicators = 0
        
        for log in logs:
            # Verificar indicadores de ataque conocidos
            if log.get('failed_logins', 0) > 2:  # Muchos fallos de login
                attack_indicators += 1
            if log.get('ip_reputation_score', 1) < 0.3:  # IP con mala reputación
                attack_indicators += 1
            if log.get('unusual_time_access', 0) == 1:  # Acceso en horario inusual
                attack_indicators += 1
            if log.get('encryption_used') == 'DES':  # Encriptación débil
                attack_indicators += 1
            if log.get('session_duration', 0) > 1000:  # Sesiones muy largas
                attack_indicators += 1
            if log.get('network_packet_size', 0) > 600:  # Paquetes grandes
                attack_indicators += 1
        
        # Si hay al menos 2 indicadores de ataque
        return attack_indicators >= 2
