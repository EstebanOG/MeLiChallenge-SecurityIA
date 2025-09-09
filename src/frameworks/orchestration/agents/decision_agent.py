"""
Agente de Decisión para respuesta a amenazas.

Este agente toma decisiones de respuesta basadas en los resultados
de los agentes de detección (supervisado y no supervisado).
"""

from typing import List, Dict, Any
from .base_agent import LangGraphAgentState, add_execution_step


class DecisionAgent:
    """Agente de Decisión - Toma decisiones de respuesta a amenazas."""
    
    def __init__(self):
        self.name = "decision_agent"
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente de decisión."""
        logs = state.get("logs", [])
        agent_results = state.get("agent_results", {})
        print(f"🎯 [DECISION] Analizando amenazas y tomando decisiones...")
        
        # Obtener resultados de los agentes anteriores
        supervised_result = agent_results.get("supervised_agent", {})
        unsupervised_result = agent_results.get("unsupervised_agent", {})
        
        # Combinar información de ambos agentes
        attack_known = supervised_result.get("decision") == "attack_known"
        anomaly_detected = unsupervised_result.get("decision") == "anomalous"
        threat_level = supervised_result.get("threat_level", "low")
        anomaly_score = unsupervised_result.get("anomaly_score", 0.0)
        
        # Tomar decisión basada en amenazas y anomalías
        decision = self._make_decision(logs, attack_known, anomaly_detected, threat_level, anomaly_score)
        
        print(f"⚡ [DECISION] Decisión tomada: {decision['action']}")
        state = add_execution_step(state, self.name, {
            "decision": "action_taken",
            "action": decision["action"],
            "confidence": decision["confidence"],
            "reasoning": decision["reasoning"],
            "threat_level": threat_level,
            "anomaly_score": anomaly_score,
            "next_agent": "report_agent"
        })
        
        return state
    
    def _make_decision(self, logs: List[Dict[str, Any]], attack_known: bool, anomaly_detected: bool, threat_level: str, anomaly_score: float) -> Dict[str, Any]:
        """Toma decisiones de respuesta basadas en ataques conocidos y anomalías detectadas."""
        
        # Si no hay ataques conocidos ni anomalías
        if not attack_known and not anomaly_detected:
            return {
                "action": "monitor",
                "confidence": 0.9,
                "reasoning": "No se detectaron ataques conocidos ni anomalías. Continuar monitoreo."
            }
        
        # Si hay ataques conocidos
        if attack_known:
            threat_type = self._classify_threat_type(logs)
            if threat_type == "brute_force":
                return {
                    "action": "block_ip",
                    "confidence": 0.85,
                    "reasoning": "Detectado intento de fuerza bruta. Bloquear IP inmediatamente."
                }
            elif threat_type == "suspicious_activity":
                return {
                    "action": "alert_security_team",
                    "confidence": 0.8,
                    "reasoning": "Actividad sospechosa detectada. Notificar al equipo de seguridad."
                }
            elif threat_type == "high_risk":
                return {
                    "action": "block_and_alert",
                    "confidence": 0.9,
                    "reasoning": "Ataque de alto riesgo detectado. Bloquear y alertar inmediatamente."
                }
        
        # Si solo hay anomalías (sin ataques conocidos)
        if anomaly_detected and anomaly_score > 0.7:
            return {
                "action": "alert_security_team",
                "confidence": 0.75,
                "reasoning": f"Anomalía detectada (score: {anomaly_score:.2f}). Notificar para análisis manual."
            }
        elif anomaly_detected:
            return {
                "action": "monitor_closely",
                "confidence": 0.6,
                "reasoning": f"Anomalía menor detectada (score: {anomaly_score:.2f}). Monitorear más de cerca."
            }
        
        # Caso por defecto
        return {
            "action": "escalate",
            "confidence": 0.7,
            "reasoning": "Situación no clasificada. Escalar para análisis manual."
        }
    
    def _classify_threat_type(self, logs: List[Dict[str, Any]]) -> str:
        """Clasifica el tipo de amenaza basado en los logs."""
        if not logs:
            return "unknown"
        
        # Analizar patrones en los logs
        brute_force_indicators = 0
        suspicious_indicators = 0
        
        for log in logs:
            # Indicadores de fuerza bruta
            if log.get('failed_logins', 0) > 3:
                brute_force_indicators += 1
            if log.get('login_attempts', 0) > 5:
                brute_force_indicators += 1
            
            # Indicadores de actividad sospechosa
            if log.get('unusual_time_access', 0) == 1:
                suspicious_indicators += 1
            if log.get('ip_reputation_score', 1) < 0.3:
                suspicious_indicators += 1
            if log.get('encryption_used') == 'DES':
                suspicious_indicators += 1
        
        # Clasificar basado en indicadores
        if brute_force_indicators >= 2:
            return "brute_force"
        elif suspicious_indicators >= 2:
            return "suspicious_activity"
        elif brute_force_indicators >= 1 and suspicious_indicators >= 1:
            return "high_risk"
        else:
            return "unknown"
