"""
Base de conocimiento MITRE ATT&CK y STRIDE para el agente de decisión LLM.

Este módulo contiene las técnicas MITRE ATT&CK y categorías STRIDE
mapeadas a los features del dataset, más técnicas adicionales para
detección de patrones no mapeados.
"""

from typing import Dict, List, Any

# Técnicas MITRE ATT&CK mapeadas del dataset
MAPPED_MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "description": "Múltiples intentos de autenticación con credenciales",
        "stride": "Spoofing",
        "indicators": ["failed_logins > 3", "login_attempts > 5"],
        "features": ["failed_logins", "login_attempts", "ip_reputation_score"],
        "severity": "high"
    },
    "T1040": {
        "name": "Network Sniffing",
        "description": "Interceptación de tráfico de red sin cifrar",
        "stride": "Information Disclosure",
        "indicators": ["encryption_used == 'None'"],
        "features": ["encryption_used", "network_packet_size"],
        "severity": "medium"
    },
    "T1041": {
        "name": "Exfiltration Over C2",
        "description": "Exfiltración de datos a través de canales de comando y control",
        "stride": "Information Disclosure",
        "indicators": ["network_packet_size > p95"],
        "features": ["network_packet_size", "session_duration"],
        "severity": "high"
    },
    "T1499": {
        "name": "Endpoint DoS",
        "description": "Denegación de servicio mediante abuso de protocolo",
        "stride": "Denial of Service",
        "indicators": ["protocol_type == 'ICMP'", "network_packet_size > p95"],
        "features": ["protocol_type", "network_packet_size"],
        "severity": "medium"
    },
    "T1087": {
        "name": "Account Discovery",
        "description": "Reconocimiento y descubrimiento de cuentas de usuario",
        "stride": "Tampering",
        "indicators": ["login_attempts > 5"],
        "features": ["login_attempts", "browser_type"],
        "severity": "medium"
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Uso de cuentas válidas comprometidas",
        "stride": "Spoofing",
        "indicators": ["ip_reputation_score < 0.5", "unusual_time_access == 1"],
        "features": ["ip_reputation_score", "unusual_time_access", "browser_type"],
        "severity": "high"
    }
}

# Técnicas MITRE ATT&CK adicionales para detección de patrones
ADDITIONAL_MITRE_TECHNIQUES = {
    "T1055": {
        "name": "Process Injection",
        "description": "Inyección de código en procesos legítimos",
        "stride": "Tampering",
        "indicators": ["unusual_process_behavior", "memory_anomalies"],
        "severity": "high"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "description": "Uso de intérpretes de comandos para ejecutar código malicioso",
        "stride": "Tampering",
        "indicators": ["suspicious_commands", "script_execution"],
        "severity": "high"
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "description": "Descubrimiento de grupos de permisos y privilegios",
        "stride": "Tampering",
        "indicators": ["group_enumeration", "privilege_escalation_attempts"],
        "severity": "medium"
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "description": "Uso de protocolos de aplicación para comunicación C2",
        "stride": "Information Disclosure",
        "indicators": ["unusual_protocol_usage", "c2_communication"],
        "severity": "high"
    },
    "T1072": {
        "name": "Software Deployment Tools",
        "description": "Uso de herramientas de despliegue para distribución de malware",
        "stride": "Tampering",
        "indicators": ["deployment_tool_abuse", "mass_deployment"],
        "severity": "medium"
    },
    "T1082": {
        "name": "System Information Discovery",
        "description": "Descubrimiento de información del sistema",
        "stride": "Information Disclosure",
        "indicators": ["system_enumeration", "info_gathering"],
        "severity": "low"
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "description": "Descubrimiento de archivos y directorios",
        "stride": "Information Disclosure",
        "indicators": ["directory_enumeration", "file_discovery"],
        "severity": "low"
    },
    "T1090": {
        "name": "Proxy",
        "description": "Uso de proxies para ocultar tráfico malicioso",
        "stride": "Spoofing",
        "indicators": ["proxy_usage", "traffic_obfuscation"],
        "severity": "medium"
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "description": "Uso de protocolos no estándar para comunicación",
        "stride": "Information Disclosure",
        "indicators": ["unusual_protocols", "non_standard_communication"],
        "severity": "medium"
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "description": "Transferencia de herramientas maliciosas al sistema",
        "stride": "Tampering",
        "indicators": ["tool_downloads", "malware_transfer"],
        "severity": "high"
    }
}

# Categorías STRIDE
STRIDE_CATEGORIES = {
    "Spoofing": {
        "description": "Suplantación de identidad o recursos",
        "examples": ["IP spoofing", "User agent spoofing", "Account takeover"],
        "mitre_techniques": ["T1078", "T1090", "T1110"]
    },
    "Tampering": {
        "description": "Modificación no autorizada de datos o código",
        "examples": ["Data modification", "Code injection", "Configuration changes"],
        "mitre_techniques": ["T1055", "T1059", "T1069", "T1072", "T1105"]
    },
    "Repudiation": {
        "description": "Negación de acciones realizadas",
        "examples": ["Log deletion", "Action denial", "Audit trail modification"],
        "mitre_techniques": []
    },
    "Information Disclosure": {
        "description": "Divulgación no autorizada de información",
        "examples": ["Data exfiltration", "Network sniffing", "Information gathering"],
        "mitre_techniques": ["T1040", "T1041", "T1071", "T1082", "T1083", "T1095"]
    },
    "Denial of Service": {
        "description": "Interrupción de servicios legítimos",
        "examples": ["Resource exhaustion", "Service disruption", "Protocol abuse"],
        "mitre_techniques": ["T1499"]
    },
    "Elevation of Privilege": {
        "description": "Escalación no autorizada de privilegios",
        "examples": ["Privilege escalation", "Root access", "Admin rights"],
        "mitre_techniques": ["T1069"]
    }
}

# Patrones de comportamiento anómalo
ANOMALY_PATTERNS = {
    "temporal_anomalies": {
        "description": "Actividad en horarios inusuales",
        "indicators": ["unusual_time_access == 1", "off_hours_activity"],
        "severity": "medium"
    },
    "volume_anomalies": {
        "description": "Volúmenes de tráfico anómalos",
        "indicators": ["high_packet_volume", "unusual_session_duration"],
        "severity": "medium"
    },
    "protocol_anomalies": {
        "description": "Uso anómalo de protocolos",
        "indicators": ["unusual_protocol_combinations", "non_standard_ports"],
        "severity": "high"
    },
    "geographic_anomalies": {
        "description": "Actividad desde ubicaciones inusuales",
        "indicators": ["unusual_geo_location", "impossible_travel"],
        "severity": "high"
    },
    "behavioral_anomalies": {
        "description": "Comportamiento de usuario anómalo",
        "indicators": ["unusual_browser_usage", "rapid_succession_actions"],
        "severity": "medium"
    }
}

def get_mitre_technique_by_id(technique_id: str) -> Dict[str, Any]:
    """Obtiene una técnica MITRE por ID."""
    if technique_id in MAPPED_MITRE_TECHNIQUES:
        return MAPPED_MITRE_TECHNIQUES[technique_id]
    elif technique_id in ADDITIONAL_MITRE_TECHNIQUES:
        return ADDITIONAL_MITRE_TECHNIQUES[technique_id]
    else:
        return None

def get_stride_category(category: str) -> Dict[str, Any]:
    """Obtiene una categoría STRIDE por nombre."""
    return STRIDE_CATEGORIES.get(category, {})

def get_all_mitre_techniques() -> Dict[str, Any]:
    """Obtiene todas las técnicas MITRE disponibles."""
    return {**MAPPED_MITRE_TECHNIQUES, **ADDITIONAL_MITRE_TECHNIQUES}

def get_relevant_techniques_for_features(features: List[str]) -> List[Dict[str, Any]]:
    """Obtiene técnicas MITRE relevantes para las features dadas."""
    relevant = []
    all_techniques = get_all_mitre_techniques()
    
    for technique_id, technique in all_techniques.items():
        if any(feature in technique.get('features', []) for feature in features):
            relevant.append({
                'id': technique_id,
                **technique
            })
    
    return relevant

def build_mitre_context() -> str:
    """Construye el contexto MITRE/STRIDE para el LLM."""
    context = "TÉCNICAS MITRE ATT&CK MAPEADAS:\n"
    
    for technique_id, technique in MAPPED_MITRE_TECHNIQUES.items():
        context += f"- {technique_id}: {technique['name']} - {technique['description']}\n"
        context += f"  STRIDE: {technique['stride']}\n"
        context += f"  Indicadores: {', '.join(technique['indicators'])}\n"
        context += f"  Severidad: {technique['severity']}\n\n"
    
    context += "\nTÉCNICAS MITRE ATT&CK ADICIONALES:\n"
    for technique_id, technique in ADDITIONAL_MITRE_TECHNIQUES.items():
        context += f"- {technique_id}: {technique['name']} - {technique['description']}\n"
        context += f"  STRIDE: {technique['stride']}\n"
        context += f"  Severidad: {technique['severity']}\n\n"
    
    context += "\nCATEGORÍAS STRIDE:\n"
    for category, info in STRIDE_CATEGORIES.items():
        context += f"- {category}: {info['description']}\n"
        context += f"  Ejemplos: {', '.join(info['examples'])}\n\n"
    
    return context
