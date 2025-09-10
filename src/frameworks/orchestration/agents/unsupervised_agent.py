"""
Agente No Supervisado para detección de anomalías.

Este agente utiliza técnicas no supervisadas para detectar comportamientos
anómalos que no están en los patrones conocidos usando Isolation Forest.
"""

from typing import List, Dict, Any, Optional
from .base_agent import LangGraphAgentState, add_execution_step
from src.application.interfaces.anomaly_detector import AnomalyDetector
from src.domain.entities.log_entry import LogEntry


class UnsupervisedAgent:
    """Agente No Supervisado - Detecta anomalías usando técnicas no supervisadas."""
    
    def __init__(self, anomaly_detector: Optional[AnomalyDetector] = None):
        self.name = "unsupervised_agent"
        self.anomaly_detector = anomaly_detector
    
    def execute(self, state: LangGraphAgentState) -> LangGraphAgentState:
        """Ejecuta el agente no supervisado."""
        logs = state.get("logs", [])
        print(f"🤖 [UNSUPERVISED] Analizando anomalías en {len(logs)} logs...")
        print(f"🔍 [UNSUPERVISED] Anomaly detector: {self.anomaly_detector}")
        print(f"🔍 [UNSUPERVISED] Anomaly detector ready: {self.anomaly_detector.is_ready() if self.anomaly_detector else 'None'}")
        
        # Convertir logs a LogEntry objects
        log_entries = self._convert_to_log_entries(logs)
        
        # Detectar anomalías usando el detector ML
        if self.anomaly_detector and self.anomaly_detector.is_ready():
            anomaly_result = self.anomaly_detector.detect_anomalies(log_entries)
            print(f"🔍 [UNSUPERVISED] Anomaly result type: {type(anomaly_result)}")
            print(f"🔍 [UNSUPERVISED] Anomaly result: {anomaly_result}")
            
            # AnomalyResult es un TypedDict, por lo que siempre es un diccionario
            # Extraer valores del diccionario
            is_anomalous = anomaly_result.get('threat_detected', False)
            anomaly_score = anomaly_result.get('batch_score', 0.0)
            confidence = anomaly_result.get('confidence', 0.0)
            individual_scores = anomaly_result.get('anomaly_scores', [])
            
            # Normalizar scores de Isolation Forest a rango [0, 1]
            # Los scores de Isolation Forest pueden ser negativos y necesitan normalización
            if individual_scores:
                min_score = min(individual_scores)
                max_score = max(individual_scores)
                
                # Si hay variación en los scores, normalizar
                if max_score > min_score:
                    # Normalizar a [0, 1] donde 0 = normal, 1 = muy anómalo
                    individual_scores = [(score - min_score) / (max_score - min_score) for score in individual_scores]
                    anomaly_score = sum(individual_scores) / len(individual_scores)
                    print(f"✅ [UNSUPERVISED] Scores normalizados: min={min_score:.3f}, max={max_score:.3f}, avg={anomaly_score:.3f}")
                else:
                    # Si todos los scores son iguales, usar lógica basada en el valor
                    if min_score > 0.5:  # Scores altos = anómalo
                        base_score = 0.8
                    elif min_score > 0:   # Scores medios = moderadamente anómalo
                        base_score = 0.4
                    else:                # Scores negativos o cero = normal
                        base_score = 0.1
                    
                    individual_scores = [base_score] * len(individual_scores)
                    anomaly_score = base_score
                    print(f"⚠️ [UNSUPERVISED] Scores uniformes ({min_score:.3f}), usando score base: {base_score:.3f}")
            else:
                # Si no hay scores individuales, normalizar el batch_score
                if anomaly_score > 1.0:
                    anomaly_score = min(anomaly_score, 1.0)
                elif anomaly_score < 0:
                    anomaly_score = max(anomaly_score, 0.0)
            
            # Verificar si el score normalizado sigue siendo irracionalmente alto
            if anomaly_score > 0.9:  # Threshold más conservador
                print(f"⚠️ [UNSUPERVISED] Score ML muy alto después de normalización ({anomaly_score:.3f}), usando reglas heurísticas")
                is_anomalous, anomaly_score, confidence = self._detect_anomalies_fallback(logs)
                individual_scores = [anomaly_score] * len(logs)
        else:
            # Fallback a detección basada en reglas si no hay detector ML
            print("⚠️ [UNSUPERVISED] Usando detección basada en reglas (detector ML no disponible)")
            is_anomalous, anomaly_score, confidence = self._detect_anomalies_fallback(logs)
            individual_scores = [anomaly_score] * len(logs)
        
        if is_anomalous:
            threat_level = self._determine_threat_level(anomaly_score)
            print(f"⚠️ [UNSUPERVISED] Anomalía detectada (score: {anomaly_score:.3f}) -> Enviando a Agente de Decisión")
            state = add_execution_step(state, self.name, {
                "decision": "anomalous",
                "anomaly_score": anomaly_score,
                "confidence": confidence,
                "threat_level": threat_level,
                "individual_scores": individual_scores,
                "reasoning": f"Detectadas {sum(1 for s in individual_scores if s > 0.5)} anomalías de {len(individual_scores)} logs",
                "next_agent": "decision_agent"
            })
        else:
            print(f"✅ [UNSUPERVISED] Comportamiento normal (score: {anomaly_score:.3f}) -> Enviando a Reporte")
            state = add_execution_step(state, self.name, {
                "decision": "normal",
                "anomaly_score": anomaly_score,
                "confidence": confidence,
                "threat_level": "low",
                "individual_scores": individual_scores,
                "reasoning": "No se detectaron anomalías significativas",
                "next_agent": "report_agent"
            })
        
        return state
    
    def _convert_to_log_entries(self, logs: List[Dict[str, Any]]) -> List[LogEntry]:
        """Convierte logs de diccionarios a objetos LogEntry."""
        log_entries = []
        for log in logs:
            try:
                log_entry = LogEntry(
                    session_id=log.get('session_id', ''),
                    network_packet_size=float(log.get('network_packet_size', 0)),
                    protocol_type=log.get('protocol_type', ''),
                    login_attempts=int(log.get('login_attempts', 0)),
                    session_duration=float(log.get('session_duration', 0)),
                    encryption_used=log.get('encryption_used', ''),
                    ip_reputation_score=float(log.get('ip_reputation_score', 0)),
                    failed_logins=int(log.get('failed_logins', 0)),
                    browser_type=log.get('browser_type', ''),
                    unusual_time_access=bool(log.get('unusual_time_access', False)),
                    attack_detected=bool(log.get('attack_detected', False))
                )
                log_entries.append(log_entry)
            except (ValueError, TypeError) as e:
                print(f"⚠️ [UNSUPERVISED] Error convirtiendo log: {e}")
                continue
        return log_entries
    
    def _detect_anomalies_fallback(self, logs: List[Dict[str, Any]]) -> tuple[bool, float, float]:
        """Detecta anomalías usando reglas heurísticas como fallback."""
        if not logs:
            return False, 0.0, 0.0
            
        anomaly_scores = []
        
        for log in logs:
            score = 0.0
            
            # Reglas heurísticas basadas en el dataset
            if log.get('session_duration', 0) > 1500:  # Sesiones anormalmente largas
                score += 0.3
            if log.get('network_packet_size', 0) > 700:  # Paquetes anormalmente grandes
                score += 0.2
            if log.get('login_attempts', 0) > 5:  # Muchos intentos de login
                score += 0.2
            if log.get('ip_reputation_score', 1) < 0.2:  # IP con reputación muy baja
                score += 0.4
            elif log.get('ip_reputation_score', 1) < 0.4:  # IP con reputación baja
                score += 0.2
            if log.get('browser_type') == 'Unknown':  # Navegador desconocido
                score += 0.1
            if log.get('protocol_type') == 'UDP' and log.get('session_duration', 0) > 500:  # UDP con sesiones largas
                score += 0.2
            if log.get('failed_logins', 0) > 3:  # Muchos logins fallidos
                score += 0.3
            if log.get('unusual_time_access', False):  # Acceso en horario inusual
                score += 0.1
            
            anomaly_scores.append(min(score, 1.0))  # Cap at 1.0
        
        batch_score = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0.0
        is_anomalous = batch_score > 0.3  # Threshold para detección
        confidence = 0.7 if is_anomalous else 0.9  # Confianza basada en detección
        
        return is_anomalous, batch_score, confidence
    
    def _determine_threat_level(self, anomaly_score: float) -> str:
        """Determina el nivel de amenaza basado en el score de anomalía."""
        if anomaly_score >= 0.8:
            return "critical"
        elif anomaly_score >= 0.6:
            return "high"
        elif anomaly_score >= 0.4:
            return "medium"
        else:
            return "low"
