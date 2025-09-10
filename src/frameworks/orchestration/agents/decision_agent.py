"""
Agente de Decisión para respuesta a amenazas.

Este agente toma decisiones de respuesta basadas en los resultados
de los agentes de detección (supervisado y no supervisado) y utiliza
LLM para análisis contextual con MITRE ATT&CK y STRIDE.
"""

import os
from typing import List, Dict, Any, Optional
from .base_agent import LangGraphAgentState, add_execution_step

# Cargar variables de entorno desde .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("⚠️ python-dotenv no instalado. Usando variables de entorno del sistema.")

# Importar Gemini Decision Agent si está disponible
try:
    from src.frameworks.llm.gemini_decision_agent import GeminiDecisionAgent
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️ Gemini no disponible. Usando lógica heurística.")


class DecisionAgent:
    """Agente de Decisión - Toma decisiones de respuesta a amenazas."""
    
    def __init__(self, use_llm: bool = True, gemini_api_key: Optional[str] = None):
        self.name = "decision_agent"
        self.use_llm = use_llm and GEMINI_AVAILABLE
        
        # Inicializar Gemini si está disponible
        if self.use_llm:
            try:
                self.gemini_agent = GeminiDecisionAgent()
                print("✅ Gemini Decision Agent inicializado")
            except Exception as e:
                print(f"⚠️ Error inicializando Gemini: {e}")
                self.use_llm = False
                self.gemini_agent = None
        else:
            self.gemini_agent = None
    
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
        # Usar directamente el resultado del agente no supervisado
        anomaly_detected = unsupervised_result.get("decision") == "anomalous" if unsupervised_result else False
        anomaly_score = unsupervised_result.get("anomaly_score", 0.0) if unsupervised_result else 0.0
        threat_level = supervised_result.get("threat_level", "low")
        
        # Preservar scores individuales de ambos agentes
        supervised_individual_scores = supervised_result.get("individual_scores", []) if supervised_result else []
        unsupervised_individual_scores = unsupervised_result.get("individual_scores", []) if unsupervised_result else []
        
        # Combinar scores individuales (priorizar el agente que detectó amenazas)
        if attack_known and supervised_individual_scores:
            individual_scores = supervised_individual_scores
            print(f"🔍 [DECISION] Usando scores del agente supervisado: {individual_scores}")
        elif unsupervised_individual_scores:
            individual_scores = unsupervised_individual_scores
            print(f"🔍 [DECISION] Usando scores del agente no supervisado: {individual_scores}")
        else:
            individual_scores = []
            print("⚠️ [DECISION] No se encontraron scores individuales de ningún agente")
        
        # Combinar logs sospechosos de ambos agentes
        supervised_suspicious = supervised_result.get("suspicious_logs", []) if supervised_result else []
        unsupervised_suspicious = unsupervised_result.get("suspicious_logs", []) if unsupervised_result else []
        
        # Combinar y deduplicar logs sospechosos
        all_suspicious_logs = {}
        for log_info in supervised_suspicious + unsupervised_suspicious:
            key = log_info.get("index", -1)
            if key not in all_suspicious_logs or log_info.get("threat_score", 0) > all_suspicious_logs[key].get("threat_score", 0):
                all_suspicious_logs[key] = log_info
        
        combined_suspicious_logs = list(all_suspicious_logs.values())
        
        # Debug: Mostrar resultados de agentes
        print(f"🔍 [DECISION] Resultados de agentes:")
        print(f"  - Supervisado: {supervised_result.get('decision', 'unknown')} (threat_level: {threat_level})")
        print(f"  - No supervisado: {unsupervised_result.get('decision', 'unknown')} (score: {anomaly_score:.3f})")
        print(f"  - Ataque conocido: {attack_known}")
        print(f"  - Anomalía detectada: {anomaly_detected}")
        
        # Tomar decisión basada en amenazas y anomalías
        decision = self._make_decision(logs, attack_known, anomaly_detected, threat_level, anomaly_score)
        
        print(f"⚡ [DECISION] Decisión tomada: {decision['action']}")
        
        # Extraer información de threat modeling si está disponible
        threat_modeling = self._extract_threat_modeling(decision, logs)
        
        # Debug: Mostrar threat modeling extraído
        print(f"🔍 [DECISION] Threat modeling extraído: {threat_modeling}")
        
        state = add_execution_step(state, self.name, {
            "decision": "action_taken",
            "action": decision["action"],
            "confidence": decision["confidence"],
            "reasoning": decision["reasoning"],
            "threat_level": threat_level,
            "anomaly_score": anomaly_score,
            "anomaly_detected": anomaly_detected,
            "threat_detected": attack_known,
            "threat_modeling": threat_modeling,
            "individual_scores": individual_scores,
            "suspicious_logs": combined_suspicious_logs,
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
        
        # Usar Gemini para análisis contextual si está disponible
        if self.use_llm and self.gemini_agent and logs:
            try:
                print("🤖 [DECISION] Usando Gemini para análisis contextual...")
                llm_analysis = self.gemini_agent.analyze_log(logs[0])
                
                # Debug: Mostrar análisis de Gemini
                print(f"🔍 [DECISION] Análisis Gemini:")
                print(f"  - is_anomalous: {llm_analysis.get('is_anomalous')}")
                print(f"  - confidence: {llm_analysis.get('confidence', 0):.3f}")
                print(f"  - false_alarm_risk: {llm_analysis.get('false_alarm_risk')}")
                print(f"  - false_alarm_score: {llm_analysis.get('false_alarm_score', 0):.3f}")
                print(f"  - mitre_technique: {llm_analysis.get('mitre_technique')}")
                print(f"  - threat_level: {llm_analysis.get('threat_level')}")
                
                # Si Gemini detecta falsa alarma, usar su recomendación
                false_alarm_risk = llm_analysis.get('false_alarm_risk', 'medium')
                false_alarm_score = llm_analysis.get('false_alarm_score', 0.0)
                is_false_alarm = false_alarm_risk == 'high' or false_alarm_score > 0.7
                
                if is_false_alarm:
                    print(f"✅ [DECISION] Gemini detectó falsa alarma (risk={false_alarm_risk}, score={false_alarm_score:.3f})")
                    return {
                        "action": "monitor",
                        "confidence": llm_analysis.get('confidence', 0.8),
                        "reasoning": f"LLM detectó falsa alarma: {llm_analysis.get('reasoning', 'Análisis contextual indica comportamiento normal')}",
                        "mitre_technique": llm_analysis.get('mitre_technique', 'None'),
                        "stride_category": llm_analysis.get('stride_category', 'None'),
                        "threat_level": llm_analysis.get('threat_level', 'low'),
                        "llm_analysis": llm_analysis
                    }
                
                # Si Gemini confirma amenaza, usar su análisis
                is_anomalous = llm_analysis.get('is_anomalous', False)
                confidence = llm_analysis.get('confidence', 0.0)
                is_threat_confirmed = is_anomalous and confidence > 0.7
                
                if is_threat_confirmed:
                    print(f"✅ [DECISION] Gemini confirmó amenaza (anomalous={is_anomalous}, confidence={confidence:.3f})")
                    return {
                        "action": self._map_llm_action_to_decision_action(llm_analysis.get('recommended_action', 'investigate')),
                        "confidence": llm_analysis.get('confidence', 0.8),
                        "reasoning": f"LLM confirmó amenaza: {llm_analysis.get('reasoning', 'Análisis contextual confirma actividad maliciosa')}",
                        "mitre_technique": llm_analysis.get('mitre_technique', 'Unknown'),
                        "stride_category": llm_analysis.get('stride_category', 'Unknown'),
                        "threat_level": llm_analysis.get('threat_level', 'medium'),
                        "llm_analysis": llm_analysis
                    }
                
                # Si Gemini no confirma amenaza pero los agentes detectaron algo, usar análisis de Gemini para enriquecer
                if (attack_known or anomaly_detected) and not is_false_alarm:
                    print(f"🔍 [DECISION] Agentes detectaron algo, usando análisis de Gemini para enriquecer...")
                    # Usar la técnica MITRE y categoría STRIDE de Gemini, pero mantener la decisión basada en agentes
                    enhanced_reasoning = f"Agentes detectaron {'ataque conocido' if attack_known else 'anomalía'}. {llm_analysis.get('reasoning', 'Análisis contextual adicional')}"
                    if llm_analysis.get('mitre_technique') and llm_analysis.get('mitre_technique') != 'Unknown':
                        enhanced_reasoning += f" Técnica MITRE: {llm_analysis.get('mitre_technique')}"
                    if llm_analysis.get('stride_category') and llm_analysis.get('stride_category') != 'Unknown':
                        enhanced_reasoning += f" Categoría STRIDE: {llm_analysis.get('stride_category')}"
                    
                    # Continuar con lógica heurística pero con información enriquecida
                    print(f"📊 [DECISION] Información enriquecida: {enhanced_reasoning}")
                    # No retornar aquí, continuar con lógica heurística
                
                # Gemini no pudo determinar claramente - explicar por qué
                print(f"❌ [DECISION] Gemini no pudo determinar claramente:")
                print(f"  - No es falsa alarma: {not is_false_alarm} (risk={false_alarm_risk}, score={false_alarm_score:.3f})")
                print(f"  - No es amenaza confirmada: {not is_threat_confirmed} (anomalous={is_anomalous}, confidence={confidence:.3f})")
                print(f"  - Técnica MITRE: {llm_analysis.get('mitre_technique', 'Unknown')}")
                print(f"  - Categoría STRIDE: {llm_analysis.get('stride_category', 'Unknown')}")
                print(f"  - Razón: {llm_analysis.get('reasoning', 'Sin explicación')}")
                print("🤖 [DECISION] Usando lógica heurística...")
                
            except Exception as e:
                print(f"⚠️ [DECISION] Error en análisis con Gemini: {e}. Usando lógica heurística...")
        
        # Si hay ataques conocidos
        if attack_known:
            # Verificar si es una falsa alarma antes de clasificar
            false_alarm_check = self._check_false_alarm(logs)
            if false_alarm_check["is_false_alarm"]:
                return {
                    "action": "monitor",
                    "confidence": 0.8,
                    "reasoning": f"Falsa alarma detectada: {false_alarm_check['reason']}. Continuar monitoreo normal."
                }
            
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
            else:
                # Ataque conocido pero tipo no clasificado
                return {
                    "action": "block_ip",
                    "confidence": 0.8,
                    "reasoning": "Ataque conocido detectado. Bloquear IP por seguridad."
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
    
    def _check_false_alarm(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verifica si una detección de ataque es probablemente una falsa alarma.
        
        Args:
            logs: Lista de logs a analizar
            
        Returns:
            Diccionario con resultado de la verificación
        """
        if not logs:
            return {"is_false_alarm": False, "reason": ""}
        
        log = logs[0]  # Analizar el primer log
        
        # Patrones que indican comportamiento normal (falsa alarma)
        normal_indicators = []
        
        # IP con muy buena reputación (> 0.6)
        if log.get('ip_reputation_score', 0) > 0.6:
            normal_indicators.append("IP con excelente reputación")
        
        # Sin fallos de login
        if log.get('failed_logins', 0) == 0:
            normal_indicators.append("sin fallos de login")
        
        # Horario normal
        if log.get('unusual_time_access', 1) == 0:
            normal_indicators.append("acceso en horario normal")
        
        # Encriptación fuerte
        if log.get('encryption_used') == 'AES':
            normal_indicators.append("encriptación AES")
        
        # Navegador conocido
        if log.get('browser_type') in ['Chrome', 'Firefox', 'Edge']:
            normal_indicators.append("navegador conocido")
        
        # Protocolo normal
        if log.get('protocol_type') == 'TCP':
            normal_indicators.append("protocolo TCP estándar")
        
        # Sesión de duración normal (entre 300-1800 segundos = 5-30 min)
        session_duration = log.get('session_duration', 0)
        if 300 <= session_duration <= 1800:
            normal_indicators.append("duración de sesión normal")
        
        # Si hay múltiples indicadores de comportamiento normal, es probable falsa alarma
        if len(normal_indicators) >= 4:
            reason = f"Comportamiento normal detectado: {', '.join(normal_indicators[:3])}..."
            return {"is_false_alarm": True, "reason": reason}
        
        # Caso especial: IP con reputación muy alta pero modelo detecta ataque
        if log.get('ip_reputation_score', 0) > 0.65 and len(normal_indicators) >= 3:
            reason = f"IP con reputación excepcional ({log.get('ip_reputation_score', 0):.2f}) con comportamiento normal"
            return {"is_false_alarm": True, "reason": reason}
        
        return {"is_false_alarm": False, "reason": ""}
    
    def _map_llm_action_to_decision_action(self, llm_action: str) -> str:
        """Mapea acciones del LLM a acciones del sistema de decisión."""
        action_mapping = {
            "monitor": "monitor",
            "investigate": "investigate", 
            "alert": "alert_security_team",
            "block": "block_ip",
            "block_and_alert": "block_and_alert"
        }
        return action_mapping.get(llm_action.lower(), "investigate")
    
    def _extract_threat_modeling(self, decision: Dict[str, Any], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extrae información de threat modeling (MITRE ATT&CK y STRIDE) de la decisión.
        
        Args:
            decision: Diccionario con la decisión tomada
            logs: Lista de logs analizados
            
        Returns:
            Diccionario con información de threat modeling en formato específico
        """
        # Obtener información MITRE/STRIDE de la decisión si está disponible
        mitre_technique = decision.get('mitre_technique', 'Unknown')
        stride_category = decision.get('stride_category', 'Unknown')
        
        # Si hay análisis de LLM disponible, usarlo
        llm_analysis = decision.get('llm_analysis', {})
        if llm_analysis:
            mitre_technique = llm_analysis.get('mitre_technique', mitre_technique)
            stride_category = llm_analysis.get('stride_category', stride_category)
        
        # Si no hay información en la decisión, intentar extraer de Gemini directamente
        if mitre_technique == 'Unknown' and self.use_llm and self.gemini_agent and logs:
            try:
                print("🔍 [DECISION] Extrayendo información MITRE/STRIDE de Gemini...")
                llm_analysis = self.gemini_agent.analyze_log(logs[0])
                mitre_technique = llm_analysis.get('mitre_technique', 'Unknown')
                stride_category = llm_analysis.get('stride_category', 'Unknown')
                print(f"  - Técnica MITRE: {mitre_technique}")
                print(f"  - Categoría STRIDE: {stride_category}")
            except Exception as e:
                print(f"⚠️ [DECISION] Error extrayendo información de Gemini: {e}")
        
        # Extraer técnicas MITRE en formato de lista
        mitre_attack_list = self._parse_mitre_techniques_to_list(mitre_technique)
        
        # Extraer categorías STRIDE en formato de lista
        stride_list = self._parse_stride_categories_to_list(stride_category)
        
        return {
            "mitre_attack": mitre_attack_list,
            "stride": stride_list
        }
    
    def _parse_mitre_techniques_to_list(self, mitre_technique: str) -> List[Dict[str, str]]:
        """
        Parsea técnicas MITRE en formato de lista para threat modeling.
        
        Args:
            mitre_technique: String con técnica MITRE (ej: "T1110 - Brute Force")
            
        Returns:
            Lista de diccionarios con technique_id, technique y tactic
        """
        if not mitre_technique or mitre_technique == 'Unknown':
            return [
                {
                    "technique_id": "N/A",
                    "technique": "No aplica - Sin amenazas detectadas",
                    "tactic": "N/A"
                }
            ]
        
        # Mapeo de técnicas a tácticas
        technique_to_tactic = {
            "T1110": "Credential Access",
            "T1040": "Collection", 
            "T1041": "Exfiltration",
            "T1499": "Impact",
            "T1087": "Discovery",
            "T1078": "Defense Evasion",
            "T1055": "Defense Evasion",
            "T1059": "Execution",
            "T1069": "Discovery",
            "T1071": "Command and Control",
            "T1072": "Execution",
            "T1082": "Discovery",
            "T1083": "Discovery",
            "T1090": "Defense Evasion",
            "T1095": "Command and Control",
            "T1105": "Defense Evasion"
        }
        
        # Extraer ID de técnica
        if ' - ' in mitre_technique:
            technique_id, technique_name = mitre_technique.split(' - ', 1)
            technique_id = technique_id.strip()
            technique_name = technique_name.strip()
        else:
            technique_id = mitre_technique
            technique_name = mitre_technique
        
        # Obtener táctica
        tactic = technique_to_tactic.get(technique_id, "Unknown")
        
        # Retornar solo la técnica detectada
        return [
            {
                "technique_id": technique_id,
                "technique": technique_name,
                "tactic": tactic
            }
        ]
    
    def _parse_stride_categories_to_list(self, stride_category: str) -> List[str]:
        """
        Parsea categorías STRIDE en formato de lista para threat modeling.
        
        Args:
            stride_category: String con categoría STRIDE
            
        Returns:
            Lista de categorías STRIDE
        """
        if not stride_category or stride_category == 'Unknown':
            return ["No aplica - Sin amenazas detectadas"]
        
        # Mapeo de categorías STRIDE
        stride_mapping = {
            "Spoofing": "Spoofing",
            "Tampering": "Tampering", 
            "Repudiation": "Repudiation",
            "Information Disclosure": "Information Disclosure",
            "Denial of Service": "Denial of Service",
            "Elevation of Privilege": "Elevation of Privilege"
        }
        
        # Normalizar categoría
        normalized_category = stride_mapping.get(stride_category, stride_category)
        
        # Retornar solo la categoría detectada
        return [normalized_category]
    
    def _parse_mitre_technique(self, mitre_technique: str) -> Dict[str, str]:
        """
        Parsea una técnica MITRE en sus componentes (método legacy).
        
        Args:
            mitre_technique: String con técnica MITRE (ej: "T1110 - Brute Force")
            
        Returns:
            Diccionario con technique_id, technique y tactic
        """
        if not mitre_technique or mitre_technique == 'Unknown':
            return {
                "technique_id": "Unknown",
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        
        # Mapeo de técnicas a tácticas
        technique_to_tactic = {
            "T1110": "Credential Access",
            "T1040": "Collection", 
            "T1041": "Exfiltration",
            "T1499": "Impact",
            "T1087": "Discovery",
            "T1078": "Defense Evasion",
            "T1055": "Defense Evasion",
            "T1059": "Execution",
            "T1069": "Discovery",
            "T1071": "Command and Control",
            "T1072": "Execution",
            "T1082": "Discovery",
            "T1083": "Discovery",
            "T1090": "Defense Evasion",
            "T1095": "Command and Control",
            "T1105": "Defense Evasion"
        }
        
        # Extraer ID de técnica
        if ' - ' in mitre_technique:
            technique_id, technique_name = mitre_technique.split(' - ', 1)
            technique_id = technique_id.strip()
            technique_name = technique_name.strip()
        else:
            technique_id = mitre_technique
            technique_name = mitre_technique
        
        # Obtener táctica
        tactic = technique_to_tactic.get(technique_id, "Unknown")
        
        return {
            "technique_id": technique_id,
            "technique": technique_name,
            "tactic": tactic
        }