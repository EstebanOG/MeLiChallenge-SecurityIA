"""
Agente de Reporte para generación de reportes finales.

Este agente genera reportes finales y notificaciones basadas en
las decisiones tomadas por el agente de decisión.
"""

from typing import List, Dict, Any
from .base_agent import LangGraphAgentState, add_execution_step


class ReportAgent:
    """Agente de Reporte - Genera reportes finales y notificaciones."""
    
    def __init__(self):
        self.name = "report_agent"
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente de reporte."""
        logs = state.get("logs", [])
        agent_results = state.get("agent_results", {})
        execution_path = state.get("execution_path", [])
        trace_id = state.get("trace_id", "unknown")
        
        print(f"📋 [REPORT] Generando reporte final...")
        
        # Obtener decisión del agente de decisión
        decision_result = agent_results.get("decision_agent", {})
        action = decision_result.get("action", "monitor")
        
        # Generar reporte basado en la acción
        report = self._generate_report(logs, agent_results, execution_path, trace_id, action)
        
        print(f"✅ [REPORT] Reporte generado: {action}")
        state = add_execution_step(state, self.name, {
            "decision": "report_generated",
            "action_taken": action,
            "report": report
        })
        
        state["final_decision"] = report
        return state
    
    def _generate_report(self, logs: List[Dict[str, Any]], agent_results: Dict[str, Any], execution_path: List[str], trace_id: str, action: str) -> Dict[str, Any]:
        """Genera reporte basado en la acción tomada."""
        supervised_result = agent_results.get("supervised_agent", {})
        unsupervised_result = agent_results.get("unsupervised_agent", {})
        decision_result = agent_results.get("decision_agent", {})
        
        return {
            "trace_id": trace_id or "generated_trace_id",
            "execution_path": execution_path,
            "action_taken": action,
            "attack_known": supervised_result.get("decision") == "attack_known",
            "anomaly_detected": unsupervised_result.get("decision") == "anomalous",
            "threat_level": supervised_result.get("threat_level", "low"),
            "anomaly_score": unsupervised_result.get("anomaly_score", 0.0),
            "confidence": decision_result.get("confidence", 0.5),
            "reasoning": decision_result.get("reasoning", "Análisis completado"),
            "report_details": {
                "timestamp": "2025-01-20T12:00:00Z",
                "severity": "high" if action in ["block_ip", "block_and_alert"] else "medium" if action == "alert_security_team" else "low",
                "logs_processed": len(logs),
                "recommended_actions": self._get_recommended_actions(action)
            },
            "agent_results": agent_results
        }
    
    def _get_recommended_actions(self, action: str) -> List[str]:
        """Obtiene acciones recomendadas basadas en la acción tomada."""
        action_map = {
            "monitor": ["Continuar monitoreo", "Revisar logs regularmente"],
            "monitor_closely": ["Aumentar frecuencia de monitoreo", "Revisar logs cada 5 minutos"],
            "alert_security_team": ["Notificar al equipo de seguridad", "Documentar incidente", "Revisar políticas de acceso"],
            "block_ip": ["Bloquear IP en firewall", "Revisar logs de la IP", "Notificar al equipo de seguridad"],
            "block_and_alert": ["Bloquear IP inmediatamente", "Alertar al equipo de seguridad", "Iniciar investigación forense"],
            "escalate": ["Escalar a analista senior", "Revisar manualmente", "Documentar para análisis futuro"]
        }
        
        return action_map.get(action, ["Revisar manualmente", "Documentar incidente"])
