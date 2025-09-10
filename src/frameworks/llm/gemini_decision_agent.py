"""
Agente de Decisión con Gemini LLM para análisis de amenazas.

Este módulo implementa un agente de decisión que utiliza Google Gemini
para analizar logs de seguridad con contexto MITRE ATT&CK y STRIDE.
"""

import os
import json
import re
from typing import Dict, Any, List, Optional
import google.generativeai as genai

# Cargar variables de entorno desde .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("⚠️ python-dotenv no instalado. Usando variables de entorno del sistema.")

# Cargar configuración de API keys
try:
    import sys
    sys.path.append('.')
    from api_config import get_gemini_api_key
    API_KEY_LOADER = get_gemini_api_key
except ImportError:
    print("⚠️ api_config.py no encontrado. Usando variables de entorno del sistema.")
    API_KEY_LOADER = lambda: os.getenv('GEMINI_API_KEY')
from .mitre_stride_knowledge import (
    build_mitre_context, 
    get_relevant_techniques_for_features,
    get_mitre_technique_by_id,
    get_stride_category
)

class GeminiDecisionAgent:
    """Agente de decisión que utiliza Gemini LLM para análisis de amenazas."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Inicializa el agente de decisión con Gemini.
        
        Args:
            api_key: API key de Google Gemini. Si no se proporciona,
                    se busca en la variable de entorno GEMINI_API_KEY
        """
        self.api_key = api_key or API_KEY_LOADER()
        if not self.api_key:
            raise ValueError("API key de Gemini requerida. Configura GEMINI_API_KEY o pásala como parámetro.")
        
        # Configurar Gemini
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel('gemini-1.5-flash')
        
        # Construir contexto MITRE/STRIDE
        self.mitre_context = build_mitre_context()
        
        # Configuración de análisis
        self.analysis_config = {
            "confidence_threshold": 0.7,
            "high_confidence_threshold": 0.85,
            "false_alarm_indicators": [
                "ip_reputation_score > 0.6",
                "failed_logins == 0",
                "unusual_time_access == 0",
                "encryption_used == 'AES'",
                "browser_type in ['Chrome', 'Firefox', 'Edge']"
            ]
        }
    
    def analyze_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analiza un log usando Gemini con contexto MITRE/STRIDE.
        
        Args:
            log_data: Diccionario con datos del log
            
        Returns:
            Diccionario con análisis completo
        """
        try:
            # Construir prompt de análisis
            prompt = self._build_analysis_prompt(log_data)
            
            # Llamar a Gemini
            response = self.model.generate_content(prompt)
            
            # Parsear respuesta
            analysis = self._parse_gemini_response(response.text)
            
            # Validar y enriquecer análisis
            enriched_analysis = self._enrich_analysis(analysis, log_data)
            
            return enriched_analysis
            
        except Exception as e:
            print(f"Error en análisis con Gemini: {e}")
            return self._fallback_analysis(log_data)
    
    def _build_analysis_prompt(self, log: Dict[str, Any]) -> str:
        """Construye el prompt de análisis para Gemini."""
        
        # Obtener técnicas relevantes basadas en las features del log
        log_features = list(log.keys())
        relevant_techniques = get_relevant_techniques_for_features(log_features)
        
        prompt = f"""
Eres un experto en ciberseguridad especializado en MITRE ATT&CK y STRIDE.

ANÁLISIS DE LOG DE SEGURIDAD
============================

DATOS DEL LOG:
- Session ID: {log.get('session_id', 'N/A')}
- Tamaño de Paquete: {log.get('network_packet_size', 'N/A')} bytes
- Protocolo: {log.get('protocol_type', 'N/A')}
- Intentos de Login: {log.get('login_attempts', 'N/A')}
- Duración de Sesión: {log.get('session_duration', 'N/A')} segundos
- Encriptación: {log.get('encryption_used', 'N/A')}
- Reputación IP: {log.get('ip_reputation_score', 'N/A')}
- Logins Fallidos: {log.get('failed_logins', 'N/A')}
- Navegador: {log.get('browser_type', 'N/A')}
- Acceso Inusual: {log.get('unusual_time_access', 'N/A')}

CONTEXTO DE SEGURIDAD:
{self.mitre_context}

TÉCNICAS RELEVANTES PARA ESTE LOG:
{self._format_relevant_techniques(relevant_techniques)}

INSTRUCCIONES DE ANÁLISIS:
1. Analiza si el comportamiento es anómalo o malicioso
2. Identifica la técnica MITRE ATT&CK más probable (usar técnicas mapeadas o detectar patrones nuevos)
3. Clasifica según STRIDE
4. Determina el nivel de amenaza
5. Evalúa el riesgo de falsa alarma
6. Recomienda una acción apropiada

CRITERIOS DE FALSA ALARMA:
- IP con reputación > 0.6
- Sin fallos de login (failed_logins = 0)
- Acceso en horario normal (unusual_time_access = 0)
- Encriptación AES
- Navegador conocido (Chrome, Firefox, Edge)

Responde SOLO en formato JSON válido:
{{
    "is_anomalous": true/false,
    "confidence": 0.0-1.0,
    "mitre_technique": "T1110 - Brute Force",
    "stride_category": "Spoofing",
    "threat_level": "low/medium/high/critical",
    "reasoning": "Explicación detallada del análisis",
    "recommended_action": "monitor/investigate/alert/block",
    "false_alarm_risk": "low/medium/high",
    "detected_patterns": ["patrón1", "patrón2"],
    "mitre_confidence": 0.0-1.0,
    "stride_confidence": 0.0-1.0
}}
"""
        return prompt
    
    def _format_relevant_techniques(self, techniques: List[Dict[str, Any]]) -> str:
        """Formatea las técnicas relevantes para el prompt."""
        if not techniques:
            return "No hay técnicas específicamente relevantes para este log."
        
        formatted = ""
        for technique in techniques[:5]:  # Limitar a 5 técnicas más relevantes
            formatted += f"- {technique['id']}: {technique['name']}\n"
            formatted += f"  Indicadores: {', '.join(technique['indicators'])}\n"
            formatted += f"  Severidad: {technique['severity']}\n\n"
        
        return formatted
    
    def _parse_gemini_response(self, response_text: str) -> Dict[str, Any]:
        """Parsea la respuesta de Gemini."""
        try:
            # Extraer JSON de la respuesta
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            else:
                raise ValueError("No se encontró JSON válido en la respuesta")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error parseando respuesta de Gemini: {e}")
            return self._create_default_analysis()
    
    def _enrich_analysis(self, analysis: Dict[str, Any], log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enriquece el análisis con validaciones adicionales."""
        
        # Validar técnica MITRE
        mitre_technique = analysis.get('mitre_technique', '')
        if mitre_technique and '-' in mitre_technique:
            technique_id = mitre_technique.split('-')[0].strip()
            technique_info = get_mitre_technique_by_id(technique_id)
            if technique_info:
                analysis['mitre_technique_info'] = technique_info
        
        # Validar categoría STRIDE
        stride_category = analysis.get('stride_category', '')
        if stride_category:
            stride_info = get_stride_category(stride_category)
            if stride_info:
                analysis['stride_category_info'] = stride_info
        
        # Calcular score de falsa alarma
        false_alarm_score = self._calculate_false_alarm_score(log_data)
        analysis['false_alarm_score'] = false_alarm_score
        
        # Ajustar confianza basada en falsa alarma
        if false_alarm_score > 0.7:
            analysis['confidence'] = min(analysis.get('confidence', 0.5), 0.6)
            analysis['false_alarm_risk'] = 'high'
        
        # Agregar timestamp
        analysis['analysis_timestamp'] = self._get_current_timestamp()
        
        return analysis
    
    def _calculate_false_alarm_score(self, log_data: Dict[str, Any]) -> float:
        """Calcula un score de falsa alarma basado en indicadores normales."""
        score = 0.0
        total_indicators = 0
        
        # IP con buena reputación
        if log_data.get('ip_reputation_score', 0) > 0.6:
            score += 0.2
        total_indicators += 1
        
        # Sin fallos de login
        if log_data.get('failed_logins', 0) == 0:
            score += 0.2
        total_indicators += 1
        
        # Horario normal
        if log_data.get('unusual_time_access', 1) == 0:
            score += 0.2
        total_indicators += 1
        
        # Encriptación fuerte
        if log_data.get('encryption_used') == 'AES':
            score += 0.2
        total_indicators += 1
        
        # Navegador conocido
        if log_data.get('browser_type') in ['Chrome', 'Firefox', 'Edge']:
            score += 0.2
        total_indicators += 1
        
        return score / total_indicators if total_indicators > 0 else 0.0
    
    def _get_current_timestamp(self) -> str:
        """Obtiene el timestamp actual."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _create_default_analysis(self) -> Dict[str, Any]:
        """Crea un análisis por defecto en caso de error."""
        return {
            "is_anomalous": False,
            "confidence": 0.5,
            "mitre_technique": "Unknown",
            "stride_category": "Unknown",
            "threat_level": "low",
            "reasoning": "Análisis por defecto - Error en LLM",
            "recommended_action": "monitor",
            "false_alarm_risk": "medium",
            "detected_patterns": [],
            "mitre_confidence": 0.0,
            "stride_confidence": 0.0
        }
    
    def _fallback_analysis(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Análisis de respaldo si falla el LLM."""
        return {
            "is_anomalous": False,
            "confidence": 0.3,
            "mitre_technique": "Unknown",
            "stride_category": "Unknown",
            "threat_level": "low",
            "reasoning": "Análisis de respaldo - LLM no disponible",
            "recommended_action": "monitor",
            "false_alarm_risk": "medium",
            "detected_patterns": [],
            "mitre_confidence": 0.0,
            "stride_confidence": 0.0,
            "fallback": True
        }
    
    def batch_analyze(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analiza múltiples logs en lote.
        
        Args:
            logs: Lista de logs a analizar
            
        Returns:
            Lista de análisis
        """
        analyses = []
        for log in logs:
            analysis = self.analyze_log(log)
            analyses.append(analysis)
        
        return analyses
    
    def get_analysis_summary(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Genera un resumen de múltiples análisis.
        
        Args:
            analyses: Lista de análisis
            
        Returns:
            Resumen consolidado
        """
        if not analyses:
            return {"error": "No hay análisis para resumir"}
        
        total_logs = len(analyses)
        anomalous_logs = sum(1 for a in analyses if a.get('is_anomalous', False))
        high_confidence = sum(1 for a in analyses if a.get('confidence', 0) > 0.8)
        
        # Técnicas MITRE más comunes
        mitre_techniques = [a.get('mitre_technique', 'Unknown') for a in analyses]
        technique_counts = {}
        for technique in mitre_techniques:
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        # Categorías STRIDE más comunes
        stride_categories = [a.get('stride_category', 'Unknown') for a in analyses]
        category_counts = {}
        for category in stride_categories:
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            "total_logs": total_logs,
            "anomalous_logs": anomalous_logs,
            "anomaly_rate": anomalous_logs / total_logs if total_logs > 0 else 0,
            "high_confidence_detections": high_confidence,
            "most_common_mitre_techniques": sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            "most_common_stride_categories": sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            "average_confidence": sum(a.get('confidence', 0) for a in analyses) / total_logs if total_logs > 0 else 0
        }
